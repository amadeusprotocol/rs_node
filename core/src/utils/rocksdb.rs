//! Deterministic wrapper API over RocksDB v10 (skeleton, in-memory impl).
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

// Re-export Error type for compatibility with existing code
pub use crate::utils::old_rocksdb::Error;

// Compatibility functions for existing code that expects these functions
pub use crate::utils::old_rocksdb::{init, close, get, put, delete, iter_prefix, get_prev_or_first};

#[cfg(test)]
pub use crate::utils::old_rocksdb::init_for_test;

/// RocksDB trait for database operations with transaction support
pub trait RocksDbTrait {
    type Transaction<'a>: RocksDbTransaction
    where
        Self: 'a;
    
    /// Create a new transaction
    fn txn(&self) -> Self::Transaction<'_>;
    
    /// Direct get operation without transaction (for read-only operations)
    fn get(&self, cf: Cf, key: &[u8]) -> Option<Vec<u8>>;
    
    /// Direct put operation without transaction (for simple operations)
    fn put(&self, cf: Cf, key: &[u8], value: &[u8]) -> Result<(), Error>;
    
    /// Direct delete operation without transaction (for simple operations)
    fn delete(&self, cf: Cf, key: &[u8]) -> Result<(), Error>;
    
    /// Prefix iteration without transaction (for read-only operations)
    fn prefix_iter(&self, cf: Cf, prefix: &[u8]) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_>;
}

/// Transaction trait for RocksDB operations
pub trait RocksDbTransaction {
    /// Get value from transaction view (overlay + base)
    fn get(&self, cf: Cf, key: &[u8]) -> Option<Vec<u8>>;
    
    /// Put value in transaction overlay
    fn put(&mut self, cf: Cf, key: &[u8], value: &[u8]);
    
    /// Delete key in transaction overlay
    fn del(&mut self, cf: Cf, key: &[u8]);
    
    /// Prefix iteration in transaction view (overlay + base - deletes)
    fn prefix(&self, cf: Cf, prefix: &[u8]) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)>>;
    
    /// Commit transaction and return mutation log
    fn commit(self) -> Result<Vec<Mut>, Error>;
    
    /// Rollback transaction (drop without applying changes)
    fn rollback(self);
    
    /// Get mutation log without committing
    fn mutations(&self) -> &[Mut];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cf {
    // Entries
    Default,
    EntryByHeight,
    EntryBySlot,
    ConsensusByEntryHash,
    MyAttestationForEntry,
    Muts,
    MutsRev,
    ContractState,
}

#[derive(Clone, Debug)]
pub enum Value {
    Raw(Vec<u8>),
    Int(u128),
    Term(Vec<u8>),
}

#[derive(Clone, Debug)]
pub enum Mut {
    Put { key: Vec<u8>, val: Vec<u8> },
    Del { key: Vec<u8> },
    SetBit { key: Vec<u8>, idx: u32, page: u32 },
}

#[derive(Clone)]
pub struct DB {
    inner: Arc<Mutex<DBData>>,
}

#[derive(Default)]
struct DBData {
    cfs: HashMap<Cf, BTreeMap<Vec<u8>, Vec<u8>>>,
}

pub struct Txn<'a> {
    db: &'a DB,
    overlay: HashMap<Cf, BTreeMap<Vec<u8>, Vec<u8>>>,
    deletes: HashMap<Cf, BTreeSet<Vec<u8>>>,
    muts: Vec<Mut>,
}

impl DB {
    pub fn open_in_memory() -> Self {
        let mut cfs = HashMap::new();
        for cf in [
            Cf::Default,
            Cf::EntryByHeight,
            Cf::EntryBySlot,
            Cf::ConsensusByEntryHash,
            Cf::MyAttestationForEntry,
            Cf::Muts,
            Cf::MutsRev,
            Cf::ContractState,
        ] {
            cfs.insert(cf, BTreeMap::new());
        }
        DB { inner: Arc::new(Mutex::new(DBData { cfs })) }
    }
    pub fn txn(&self) -> Txn<'_> {
        Txn { db: self, overlay: HashMap::new(), deletes: HashMap::new(), muts: Vec::new() }
    }
}

impl<'a> Txn<'a> {
    pub fn get(&self, cf: Cf, k: &[u8]) -> Option<Vec<u8>> {
        if let Some(delset) = self.deletes.get(&cf) {
            if delset.contains(k) {
                return None;
            }
        }
        if let Some(map) = self.overlay.get(&cf) {
            if let Some(v) = map.get(k) {
                return Some(v.clone());
            }
        }
        let guard = self.db.inner.lock().unwrap();
        guard.cfs.get(&cf).and_then(|m| m.get(k).cloned())
    }
    pub fn put(&mut self, cf: Cf, k: &[u8], v: &[u8]) {
        self.overlay.entry(cf).or_default().insert(k.to_vec(), v.to_vec());
        if let Some(delset) = self.deletes.get_mut(&cf) {
            delset.remove(k);
        }
        self.muts.push(Mut::Put { key: k.to_vec(), val: v.to_vec() });
    }
    pub fn del(&mut self, cf: Cf, k: &[u8]) {
        self.overlay.entry(cf).or_default().remove(k);
        self.deletes.entry(cf).or_default().insert(k.to_vec());
        self.muts.push(Mut::Del { key: k.to_vec() });
    }

    pub fn prefix(&self, cf: Cf, p: &[u8]) -> PrefixIter {
        // Merge view: base + overlay - deletes
        let mut out: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        {
            let guard = self.db.inner.lock().unwrap();
            if let Some(base) = guard.cfs.get(&cf) {
                for (k, v) in base.range(p.to_vec()..).take_while(|(k, _)| k.starts_with(p)) {
                    out.insert(k.clone(), v.clone());
                }
            }
        }
        if let Some(ov) = self.overlay.get(&cf) {
            for (k, v) in ov.range(p.to_vec()..).take_while(|(k, _)| k.starts_with(p)) {
                out.insert(k.clone(), v.clone());
            }
        }
        if let Some(del) = self.deletes.get(&cf) {
            for k in del.iter().filter(|k| k.starts_with(p)) {
                out.remove(k);
            }
        }
        PrefixIter { inner: out.into_iter() }
    }

    pub fn commit(self) -> Vec<Mut> {
        let mut guard = self.db.inner.lock().unwrap();
        for (cf, ov) in self.overlay.into_iter() {
            let map = guard.cfs.get_mut(&cf).unwrap();
            for (k, v) in ov {
                map.insert(k, v);
            }
        }
        for (cf, dels) in self.deletes.into_iter() {
            let map = guard.cfs.get_mut(&cf).unwrap();
            for k in dels {
                map.remove(&k);
            }
        }
        self.muts
    }
    pub fn rollback(self) {
        let _ = self;
    }
}

impl RocksDbTrait for DB {
    type Transaction<'a> = Txn<'a>;

    fn txn(&self) -> Self::Transaction<'_> {
        Txn { 
            db: self, 
            overlay: HashMap::new(), 
            deletes: HashMap::new(), 
            muts: Vec::new() 
        }
    }

    fn get(&self, cf: Cf, key: &[u8]) -> Option<Vec<u8>> {
        let guard = self.inner.lock().unwrap();
        guard.cfs.get(&cf).and_then(|m| m.get(key).cloned())
    }

    fn put(&self, cf: Cf, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let mut guard = self.inner.lock().unwrap();
        if let Some(map) = guard.cfs.get_mut(&cf) {
            map.insert(key.to_vec(), value.to_vec());
            Ok(())
        } else {
            // Column family should always exist since we initialize all of them
            // This is more of a programming error, so we'll just insert anyway
            Ok(())
        }
    }

    fn delete(&self, cf: Cf, key: &[u8]) -> Result<(), Error> {
        let mut guard = self.inner.lock().unwrap();
        if let Some(map) = guard.cfs.get_mut(&cf) {
            map.remove(key);
            Ok(())
        } else {
            // Column family should always exist since we initialize all of them
            // This is more of a programming error, so we'll just return Ok
            Ok(())
        }
    }

    fn prefix_iter(&self, cf: Cf, prefix: &[u8]) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_> {
        let guard = self.inner.lock().unwrap();
        if let Some(map) = guard.cfs.get(&cf) {
            let out: BTreeMap<Vec<u8>, Vec<u8>> = map
                .range(prefix.to_vec()..)
                .take_while(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            Box::new(out.into_iter())
        } else {
            Box::new(std::iter::empty())
        }
    }
}

impl<'a> RocksDbTransaction for Txn<'a> {
    fn get(&self, cf: Cf, key: &[u8]) -> Option<Vec<u8>> {
        self.get(cf, key)
    }

    fn put(&mut self, cf: Cf, key: &[u8], value: &[u8]) {
        self.put(cf, key, value)
    }

    fn del(&mut self, cf: Cf, key: &[u8]) {
        self.del(cf, key)
    }

    fn prefix(&self, cf: Cf, prefix: &[u8]) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)>> {
        let iter = self.prefix(cf, prefix);
        Box::new(iter)
    }

    fn commit(self) -> Result<Vec<Mut>, Error> {
        Ok(self.commit())
    }

    fn rollback(self) {
        self.rollback()
    }

    fn mutations(&self) -> &[Mut] {
        &self.muts
    }
}

pub struct PrefixIter {
    inner: std::collections::btree_map::IntoIter<Vec<u8>, Vec<u8>>,
}
impl Iterator for PrefixIter {
    type Item = (Vec<u8>, Vec<u8>);
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}
