//! Deterministic wrapper API over RocksDB v10.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::path::Path;
use once_cell::sync::OnceCell;
use rust_rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, Direction, IteratorMode, MultiThreaded, 
    OptimisticTransactionDB, Options, ReadOptions, WriteOptions, OptimisticTransactionOptions
};
use tokio::fs::create_dir_all;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(test)]
thread_local! {
    static TEST_DB: std::cell::RefCell<Option<DbHandles>> = std::cell::RefCell::new(None);
}

#[cfg(test)]
pub struct TestDbGuard {
    base: String,
}

#[cfg(test)]
impl Drop for TestDbGuard {
    fn drop(&mut self) {
        // drop the thread-local DB so RocksDB files can be removed
        TEST_DB.with(|cell| {
            *cell.borrow_mut() = None;
        });
        // best-effort cleanup of the base directory
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

#[cfg(test)]
impl TestDbGuard {
    pub fn base(&self) -> &str {
        &self.base
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    RocksDb(#[from] rust_rocksdb::Error),
    #[error(transparent)]
    TokioIo(#[from] tokio::io::Error),
}

pub struct DbHandles {
    pub db: OptimisticTransactionDB<MultiThreaded>,
}

static GLOBAL_DB: OnceCell<DbHandles> = OnceCell::new();

fn cf_names() -> &'static [&'static str] {
    &[
        "default",
        "entry_by_height",
        "entry_by_slot",
        "tx",
        "tx_account_nonce",
        "tx_receiver_nonce",
        "my_seen_time_for_entry",
        "my_attestation_for_entry",
        // "my_mutations_hash_for_entry",
        "consensus",
        "consensus_by_entryhash",
        "contractstate",
        "muts",
        "muts_rev",
        "sysconf",
    ]
}

#[cfg(test)]
pub fn init_for_test(base: &str) -> Result<TestDbGuard, Error> {
    // create base/db path synchronously (tests are synchronous)
    let path = format!("{}/db", base);
    std::fs::create_dir_all(&path)?;

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);

    let cf_descs: Vec<_> = cf_names()
        .iter()
        .map(|&name| {
            let mut opts = Options::default();
            opts.set_target_file_size_base(2 * 1024 * 1024 * 1024);
            opts.set_target_file_size_multiplier(2);
            ColumnFamilyDescriptor::new(name, opts)
        })
        .collect();

    let db: OptimisticTransactionDB<MultiThreaded> =
        OptimisticTransactionDB::open_cf_descriptors(&db_opts, path, cf_descs)?;

    TEST_DB.with(|cell| {
        *cell.borrow_mut() = Some(DbHandles { db });
    });

    Ok(TestDbGuard { base: base.to_string() })
}

#[cfg(test)]
fn with_handles<F, R>(f: F) -> R
where
    F: FnOnce(&DbHandles) -> R,
{
    TEST_DB.with(|cell| {
        if let Some(h) = cell.borrow().as_ref() {
            f(h)
        } else {
            let h = get_handles();
            f(h)
        }
    })
}

#[cfg(not(test))]
fn with_handles<F, R>(f: F) -> R
where
    F: FnOnce(&DbHandles) -> R,
{
    let h = get_handles();
    f(h)
}

fn get_handles() -> &'static DbHandles {
    GLOBAL_DB.get().expect("DB not initialized")
}

/// Expects path directory to exist
pub async fn init(base: &str) -> Result<(), Error> {
    if GLOBAL_DB.get().is_some() {
        return Ok(());
    }

    let path = format!("{}/db", base);
    create_dir_all(&path).await?;

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);

    // Set RAM limits to 10MB total
    db_opts.set_db_write_buffer_size(10 * 1024 * 1024); // 10MB total write buffer size
    db_opts.set_max_write_buffer_number(3); // Maximum 3 write buffers per CF

    // Set block cache to 2MB (part of the 10MB limit)
    let cache = Cache::new_lru_cache(2 * 1024 * 1024); // 2MB block cache
    let mut block_opts = BlockBasedOptions::default();
    block_opts.set_block_cache(&cache);
    db_opts.set_block_based_table_factory(&block_opts);

    let cf_descs: Vec<_> = cf_names()
        .iter()
        .map(|&name| {
            let mut opts = Options::default();
            opts.set_target_file_size_base(2 * 1024 * 1024 * 1024);
            opts.set_target_file_size_multiplier(2);
            // Set write buffer size per CF (shared from total 10MB)
            opts.set_write_buffer_size(1024 * 1024); // 1MB per CF write buffer
            opts.set_max_write_buffer_number(2); // Max 2 buffers per CF
            ColumnFamilyDescriptor::new(name, opts)
        })
        .collect();

    let db: OptimisticTransactionDB<MultiThreaded> =
        OptimisticTransactionDB::open_cf_descriptors(&db_opts, path, cf_descs)?;
    GLOBAL_DB.set(DbHandles { db }).ok();
    Ok(())
}

pub fn close() {
    // rocksdb closes on drop, we cannot drop OnceCell contents safely here
}

pub fn get(cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    Ok(with_handles(|h| {
        let cf_h = h.db.cf_handle(cf).expect("cf name");
        h.db.get_cf(&cf_h, key)
    })?)
}

pub fn put(cf: &str, key: &[u8], value: &[u8]) -> Result<(), Error> {
    Ok(with_handles(|h| {
        let cf_h = h.db.cf_handle(cf).expect("cf name");
        h.db.put_cf(&cf_h, key, value)
    })?)
}

pub fn delete(cf: &str, key: &[u8]) -> Result<(), Error> {
    Ok(with_handles(|h| {
        let cf_h = h.db.cf_handle(cf).expect("cf name");
        h.db.delete_cf(&cf_h, key)
    })?)
}

pub fn iter_prefix(cf: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
    Ok(with_handles(|h| -> std::result::Result<Vec<(Vec<u8>, Vec<u8>)>, rust_rocksdb::Error> {
        let cf_h = h.db.cf_handle(cf).expect("cf name");
        let mut ro = ReadOptions::default();
        ro.set_prefix_same_as_start(true);
        let mode = IteratorMode::From(prefix, Direction::Forward);
        let it = h.db.iterator_cf_opt(&cf_h, ro, mode);
        let mut out = Vec::new();
        for kv in it {
            let (k, v) = kv?;
            if !k.starts_with(prefix) {
                break;
            }
            out.push((k.to_vec(), v.to_vec()));
        }
        Ok(out)
    })?)
}

/// Find the latest key-value under `prefix` with key <= `prefix || key_suffix`
/// Returns the raw key and value if found, otherwise None
pub fn get_prev_or_first(cf: &str, prefix: &str, key_suffix: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
    Ok(with_handles(|h| -> std::result::Result<Option<(Vec<u8>, Vec<u8>)>, rust_rocksdb::Error> {
        let cf_h = h.db.cf_handle(cf).expect("cf name");
        let seek_key = format!("{}{}", prefix, key_suffix);
        let mut it = h.db.iterator_cf(&cf_h, IteratorMode::From(seek_key.as_bytes(), Direction::Reverse));

        if let Some(res) = it.next() {
            let (k, v) = res?;
            if k.starts_with(prefix.as_bytes()) {
                return Ok(Some((k.to_vec(), v.to_vec())));
            }
        }
        Ok(None)
    })?)
}

// ===== New trait-based API =====

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
    inner: DBInner,
}

#[derive(Clone)]
enum DBInner {
    InMemory(Arc<Mutex<InMemoryDB>>),
    RocksDB(Arc<RocksDBWrapper>),
}

#[derive(Default)]
struct InMemoryDB {
    cfs: HashMap<Cf, BTreeMap<Vec<u8>, Vec<u8>>>,
}

struct RocksDBWrapper {
    db: OptimisticTransactionDB<MultiThreaded>,
    cf_handles: HashMap<Cf, String>,
}

pub struct Txn<'a> {
    db: &'a DB,
    inner: TxnInner<'a>,
}

enum TxnInner<'a> {
    InMemory {
        overlay: HashMap<Cf, BTreeMap<Vec<u8>, Vec<u8>>>,
        deletes: HashMap<Cf, BTreeSet<Vec<u8>>>,
        muts: Vec<Mut>,
    },
    RocksDB {
        txn: rust_rocksdb::Transaction<'a, OptimisticTransactionDB<MultiThreaded>>,
        muts: Vec<Mut>,
    },
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
        DB { 
            inner: DBInner::InMemory(Arc::new(Mutex::new(InMemoryDB { cfs })))
        }
    }
    
    pub fn open_rocksdb<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        
        // Set RAM limits to 10MB total
        db_opts.set_db_write_buffer_size(10 * 1024 * 1024);
        db_opts.set_max_write_buffer_number(3);
        
        let mut cf_handles = HashMap::new();
        cf_handles.insert(Cf::Default, "default".to_string());
        cf_handles.insert(Cf::EntryByHeight, "entry_by_height".to_string());
        cf_handles.insert(Cf::EntryBySlot, "entry_by_slot".to_string());
        cf_handles.insert(Cf::ConsensusByEntryHash, "consensus_by_entryhash".to_string());
        cf_handles.insert(Cf::MyAttestationForEntry, "my_attestation_for_entry".to_string());
        cf_handles.insert(Cf::Muts, "muts".to_string());
        cf_handles.insert(Cf::MutsRev, "muts_rev".to_string());
        cf_handles.insert(Cf::ContractState, "contractstate".to_string());
        
        let cf_descs: Vec<_> = cf_handles.values()
            .map(|name| {
                let mut opts = Options::default();
                opts.set_target_file_size_base(2 * 1024 * 1024 * 1024);
                opts.set_target_file_size_multiplier(2);
                opts.set_write_buffer_size(1024 * 1024);
                opts.set_max_write_buffer_number(2);
                ColumnFamilyDescriptor::new(name, opts)
            })
            .collect();
        
        let db = OptimisticTransactionDB::open_cf_descriptors(&db_opts, path, cf_descs)?;
        
        Ok(DB {
            inner: DBInner::RocksDB(Arc::new(RocksDBWrapper { db, cf_handles }))
        })
    }
    
    pub fn txn(&self) -> Txn<'_> {
        match &self.inner {
            DBInner::InMemory(_) => Txn {
                db: self,
                inner: TxnInner::InMemory {
                    overlay: HashMap::new(),
                    deletes: HashMap::new(),
                    muts: Vec::new(),
                },
            },
            DBInner::RocksDB(wrapper) => {
                let write_opts = WriteOptions::default();
                let otxn_opts = OptimisticTransactionOptions::default();
                let txn = wrapper.db.transaction_opt(&write_opts, &otxn_opts);
                Txn {
                    db: self,
                    inner: TxnInner::RocksDB { txn, muts: Vec::new() },
                }
            }
        }
    }
}

impl<'a> Txn<'a> {
    pub fn get(&self, cf: Cf, k: &[u8]) -> Option<Vec<u8>> {
        match &self.inner {
            TxnInner::InMemory { overlay, deletes, .. } => {
                if let Some(delset) = deletes.get(&cf) {
                    if delset.contains(k) {
                        return None;
                    }
                }
                if let Some(map) = overlay.get(&cf) {
                    if let Some(v) = map.get(k) {
                        return Some(v.clone());
                    }
                }
                match &self.db.inner {
                    DBInner::InMemory(db) => {
                        let guard = db.lock().unwrap();
                        guard.cfs.get(&cf).and_then(|m| m.get(k).cloned())
                    }
                    _ => None,
                }
            }
            TxnInner::RocksDB { txn, .. } => {
                match &self.db.inner {
                    DBInner::RocksDB(wrapper) => {
                        let cf_name = wrapper.cf_handles.get(&cf)?;
                        let cf_handle = wrapper.db.cf_handle(cf_name)?;
                        txn.get_cf(&cf_handle, k).ok().flatten()
                    }
                    _ => None,
                }
            }
        }
    }
    
    pub fn put(&mut self, cf: Cf, k: &[u8], v: &[u8]) {
        match &mut self.inner {
            TxnInner::InMemory { overlay, deletes, muts } => {
                overlay.entry(cf).or_default().insert(k.to_vec(), v.to_vec());
                if let Some(delset) = deletes.get_mut(&cf) {
                    delset.remove(k);
                }
                muts.push(Mut::Put { key: k.to_vec(), val: v.to_vec() });
            }
            TxnInner::RocksDB { txn, muts } => {
                if let DBInner::RocksDB(wrapper) = &self.db.inner {
                    if let Some(cf_name) = wrapper.cf_handles.get(&cf) {
                        if let Some(cf_handle) = wrapper.db.cf_handle(cf_name) {
                            let _ = txn.put_cf(&cf_handle, k, v);
                            muts.push(Mut::Put { key: k.to_vec(), val: v.to_vec() });
                        }
                    }
                }
            }
        }
    }
    
    pub fn del(&mut self, cf: Cf, k: &[u8]) {
        match &mut self.inner {
            TxnInner::InMemory { overlay, deletes, muts } => {
                overlay.entry(cf).or_default().remove(k);
                deletes.entry(cf).or_default().insert(k.to_vec());
                muts.push(Mut::Del { key: k.to_vec() });
            }
            TxnInner::RocksDB { txn, muts } => {
                if let DBInner::RocksDB(wrapper) = &self.db.inner {
                    if let Some(cf_name) = wrapper.cf_handles.get(&cf) {
                        if let Some(cf_handle) = wrapper.db.cf_handle(cf_name) {
                            let _ = txn.delete_cf(&cf_handle, k);
                            muts.push(Mut::Del { key: k.to_vec() });
                        }
                    }
                }
            }
        }
    }

    pub fn prefix(&self, cf: Cf, p: &[u8]) -> PrefixIter {
        match &self.inner {
            TxnInner::InMemory { overlay, deletes, .. } => {
                // Merge view: base + overlay - deletes
                let mut out: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
                if let DBInner::InMemory(db) = &self.db.inner {
                    let guard = db.lock().unwrap();
                    if let Some(base) = guard.cfs.get(&cf) {
                        for (k, v) in base.range(p.to_vec()..).take_while(|(k, _)| k.starts_with(p)) {
                            out.insert(k.clone(), v.clone());
                        }
                    }
                }
                if let Some(ov) = overlay.get(&cf) {
                    for (k, v) in ov.range(p.to_vec()..).take_while(|(k, _)| k.starts_with(p)) {
                        out.insert(k.clone(), v.clone());
                    }
                }
                if let Some(del) = deletes.get(&cf) {
                    for k in del.iter().filter(|k| k.starts_with(p)) {
                        out.remove(k);
                    }
                }
                PrefixIter { inner: PrefixIterInner::InMemory(out.into_iter()) }
            }
            TxnInner::RocksDB { txn, .. } => {
                if let DBInner::RocksDB(wrapper) = &self.db.inner {
                    if let Some(cf_name) = wrapper.cf_handles.get(&cf) {
                        if let Some(cf_handle) = wrapper.db.cf_handle(cf_name) {
                            let mut read_opts = ReadOptions::default();
                            read_opts.set_prefix_same_as_start(true);
                            let mode = IteratorMode::From(p, Direction::Forward);
                            let iter = txn.iterator_cf_opt(&cf_handle, read_opts, mode);
                            let collected: BTreeMap<Vec<u8>, Vec<u8>> = iter
                                .take_while(|result| {
                                    result.as_ref()
                                        .map(|(k, _)| k.starts_with(p))
                                        .unwrap_or(false)
                                })
                                .filter_map(|result| result.ok())
                                .map(|(k, v)| (k.to_vec(), v.to_vec()))
                                .collect();
                            return PrefixIter { inner: PrefixIterInner::InMemory(collected.into_iter()) };
                        }
                    }
                }
                PrefixIter { inner: PrefixIterInner::InMemory(BTreeMap::new().into_iter()) }
            }
        }
    }

    pub fn commit(self) -> Vec<Mut> {
        match self.inner {
            TxnInner::InMemory { overlay, deletes, muts } => {
                if let DBInner::InMemory(db) = &self.db.inner {
                    let mut guard = db.lock().unwrap();
                    for (cf, ov) in overlay.into_iter() {
                        let map = guard.cfs.get_mut(&cf).unwrap();
                        for (k, v) in ov {
                            map.insert(k, v);
                        }
                    }
                    for (cf, dels) in deletes.into_iter() {
                        let map = guard.cfs.get_mut(&cf).unwrap();
                        for k in dels {
                            map.remove(&k);
                        }
                    }
                }
                muts
            }
            TxnInner::RocksDB { txn, muts } => {
                let _ = txn.commit();
                muts
            }
        }
    }
    
    pub fn rollback(self) {
        match self.inner {
            TxnInner::InMemory { .. } => {},
            TxnInner::RocksDB { txn, .. } => {
                let _ = txn.rollback();
            }
        }
    }
}

impl RocksDbTrait for DB {
    type Transaction<'a> = Txn<'a>;

    fn txn(&self) -> Self::Transaction<'_> {
        self.txn()
    }

    fn get(&self, cf: Cf, key: &[u8]) -> Option<Vec<u8>> {
        match &self.inner {
            DBInner::InMemory(db) => {
                let guard = db.lock().unwrap();
                guard.cfs.get(&cf).and_then(|m| m.get(key).cloned())
            }
            DBInner::RocksDB(wrapper) => {
                let cf_name = wrapper.cf_handles.get(&cf)?;
                let cf_handle = wrapper.db.cf_handle(cf_name)?;
                wrapper.db.get_cf(&cf_handle, key).ok().flatten()
            }
        }
    }

    fn put(&self, cf: Cf, key: &[u8], value: &[u8]) -> Result<(), Error> {
        match &self.inner {
            DBInner::InMemory(db) => {
                let mut guard = db.lock().unwrap();
                if let Some(map) = guard.cfs.get_mut(&cf) {
                    map.insert(key.to_vec(), value.to_vec());
                }
                Ok(())
            }
            DBInner::RocksDB(wrapper) => {
                if let Some(cf_name) = wrapper.cf_handles.get(&cf) {
                    if let Some(cf_handle) = wrapper.db.cf_handle(cf_name) {
                        wrapper.db.put_cf(&cf_handle, key, value)?;
                    }
                }
                Ok(())
            }
        }
    }

    fn delete(&self, cf: Cf, key: &[u8]) -> Result<(), Error> {
        match &self.inner {
            DBInner::InMemory(db) => {
                let mut guard = db.lock().unwrap();
                if let Some(map) = guard.cfs.get_mut(&cf) {
                    map.remove(key);
                }
                Ok(())
            }
            DBInner::RocksDB(wrapper) => {
                if let Some(cf_name) = wrapper.cf_handles.get(&cf) {
                    if let Some(cf_handle) = wrapper.db.cf_handle(cf_name) {
                        wrapper.db.delete_cf(&cf_handle, key)?;
                    }
                }
                Ok(())
            }
        }
    }

    fn prefix_iter(&self, cf: Cf, prefix: &[u8]) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + '_> {
        match &self.inner {
            DBInner::InMemory(db) => {
                let guard = db.lock().unwrap();
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
            DBInner::RocksDB(wrapper) => {
                if let Some(cf_name) = wrapper.cf_handles.get(&cf) {
                    if let Some(cf_handle) = wrapper.db.cf_handle(cf_name) {
                        let mut read_opts = ReadOptions::default();
                        read_opts.set_prefix_same_as_start(true);
                        let mode = IteratorMode::From(prefix, Direction::Forward);
                        let iter = wrapper.db.iterator_cf_opt(&cf_handle, read_opts, mode);
                        let collected: Vec<(Vec<u8>, Vec<u8>)> = iter
                            .take_while(|result| {
                                result.as_ref()
                                    .map(|(k, _)| k.starts_with(prefix))
                                    .unwrap_or(false)
                            })
                            .filter_map(|result| result.ok())
                            .map(|(k, v)| (k.to_vec(), v.to_vec()))
                            .collect();
                        Box::new(collected.into_iter())
                    } else {
                        Box::new(std::iter::empty())
                    }
                } else {
                    Box::new(std::iter::empty())
                }
            }
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
        match &self.inner {
            TxnInner::InMemory { muts, .. } => muts,
            TxnInner::RocksDB { muts, .. } => muts,
        }
    }
}

pub struct PrefixIter {
    inner: PrefixIterInner,
}

enum PrefixIterInner {
    InMemory(std::collections::btree_map::IntoIter<Vec<u8>, Vec<u8>>),
}

impl Iterator for PrefixIter {
    type Item = (Vec<u8>, Vec<u8>);
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            PrefixIterInner::InMemory(iter) => iter.next(),
        }
    }
}

/// Snapshot module for deterministic export/import of column families
pub mod snapshot {
    use super::*;
    use blake3::Hasher;
    use serde::{Deserialize, Serialize};
    use std::path::Path;
    use tokio::fs::File;
    use tokio::io::{BufReader, BufWriter};

    const MAGIC: &[u8] = b"SPK1";
    const DOMAIN_SEP: &str = "statepack-v1";

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Manifest {
        pub version: u32,
        pub algo: String,
        pub cf: String,
        pub items_total: u64,
        pub root_hex: String,
        pub snapshot_seq: Option<u64>,
        pub domain_sep: String,
    }

    /// Write a varint (unsigned LEB128) to async writer
    async fn write_varint(mut value: u64, writer: &mut (impl AsyncWrite + Unpin)) -> Result<(), Error> {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            writer.write_all(&[byte]).await.map_err(Error::TokioIo)?;
            if value == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Read a varint (unsigned LEB128) from async reader
    async fn read_varint(reader: &mut (impl AsyncRead + Unpin)) -> Result<u64, Error> {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let mut buf = [0u8; 1];
            reader.read_exact(&mut buf).await.map_err(|_| {
                Error::TokioIo(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF while reading varint"
                ).into())
            })?;
            
            let byte = buf[0];
            result |= ((byte & 0x7f) as u64) << shift;
            
            if (byte & 0x80) == 0 {
                return Ok(result);
            }
            
            shift += 7;
            if shift > 63 {
                return Err(Error::TokioIo(
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "varint too large").into()
                ));
            }
        }
    }

    /// Get the exact bytes a varint would produce (for hashing)
    fn varint_bytes(mut value: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(10);
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                break;
            }
        }
        bytes
    }

    /// Export a column family to a deterministic snapshot file (.spk)
    pub async fn export_spk(cf_name: &str, output_path: &Path) -> Result<Manifest, Error> {
        let (records, total_count) = with_handles(|handles| -> Result<(Vec<(Vec<u8>, Vec<u8>)>, u64), Error> {
            let cf_handle = handles.db.cf_handle(cf_name).ok_or_else(|| {
                Error::TokioIo(
                    std::io::Error::new(std::io::ErrorKind::NotFound, format!("column family '{}' not found", cf_name))
                        .into(),
                )
            })?;

            let snapshot = handles.db.snapshot();
            let mut read_opts = ReadOptions::default();
            read_opts.set_total_order_seek(true);
            read_opts.set_snapshot(&snapshot);

            let iterator = handles.db.iterator_cf_opt(&cf_handle, read_opts, IteratorMode::From(&[], Direction::Forward));

            let mut records = Vec::new();
            let mut count = 0u64;

            for item in iterator {
                let (key, value) = item?;
                records.push((key.to_vec(), value.to_vec()));
                count += 1;
            }

            Ok((records, count))
        })?;

        // Write to file
        let file = File::create(output_path).await.map_err(Error::TokioIo)?;
        let mut writer = BufWriter::new(file);
        let mut hasher = Hasher::new();

        // Write header: magic + column family name
        writer.write_all(MAGIC).await.map_err(Error::TokioIo)?;
        hasher.update(MAGIC);
        write_varint(cf_name.len() as u64, &mut writer).await?;
        hasher.update(&varint_bytes(cf_name.len() as u64));
        writer.write_all(cf_name.as_bytes()).await.map_err(Error::TokioIo)?;
        hasher.update(cf_name.as_bytes());

        // Write records
        for (i, (key, value)) in records.into_iter().enumerate() {
            // Update hash
            hasher.update(&varint_bytes(key.len() as u64));
            hasher.update(&key);
            hasher.update(&varint_bytes(value.len() as u64));
            hasher.update(&value);

            // Write to file
            write_varint(key.len() as u64, &mut writer).await?;
            writer.write_all(&key).await.map_err(Error::TokioIo)?;
            write_varint(value.len() as u64, &mut writer).await?;
            writer.write_all(&value).await.map_err(Error::TokioIo)?;

            // Periodic flush and yield
            if i % 1000 == 0 {
                writer.flush().await.map_err(Error::TokioIo)?;
                tokio::task::yield_now().await;
            }
        }

        writer.flush().await.map_err(Error::TokioIo)?;
        let hash = hasher.finalize();
        let hash_hex = hex::encode(hash.as_bytes());

        Ok(Manifest {
            version: 1,
            algo: "blake3".to_string(),
            cf: cf_name.to_string(),
            items_total: total_count,
            root_hex: hash_hex,
            snapshot_seq: None,
            domain_sep: DOMAIN_SEP.to_string(),
        })
    }

    /// Import a snapshot file (.spk) into a column family using streaming with batching
    pub async fn import_spk(
        cf_name: &str,
        spk_in: &Path,
        manifest: &Manifest,
        batch_bytes: usize,
    ) -> Result<(), Error> {
        use tokio::sync::mpsc;

        // Verify manifest matches request
        if manifest.cf != cf_name {
            return Err(Error::TokioIo(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("manifest CF '{}' != requested CF '{}'", manifest.cf, cf_name),
                )
                .into(),
            ));
        }
        if manifest.version != 1 || manifest.algo != "blake3" || manifest.domain_sep != DOMAIN_SEP {
            return Err(Error::TokioIo(
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "manifest version/algo/domain mismatch").into(),
            ));
        }

        // Verify spk hash before ingest
        let calculated = blake3_file(spk_in).await?;
        if hex::encode(&calculated) != manifest.root_hex {
            return Err(Error::TokioIo(
                std::io::Error::new(std::io::ErrorKind::InvalidData, "SPK file hash mismatch vs manifest").into(),
            ));
        }

        // Channel for streaming records from async reader to sync DB writer
        let (tx, mut rx) = mpsc::channel::<Option<Vec<(Vec<u8>, Vec<u8>)>>>(10); // Channel of batches
        let cf_name_owned = cf_name.to_string();
        let cf_name_for_write = cf_name.to_string();
        let spk_path = spk_in.to_path_buf();

        // Spawn task to read file and send batches via channel
        let read_handle = tokio::task::spawn(async move {
            let file = File::open(&spk_path).await.map_err(|e| Error::TokioIo(e.into()))?;
            let mut r = BufReader::new(file);

            // Parse header
            let mut magic = [0u8; 4];
            r.read_exact(&mut magic).await.map_err(|e| Error::TokioIo(e.into()))?;
            if &magic != MAGIC {
                return Err(Error::TokioIo(
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "bad SPK magic").into(),
                ));
            }
            let cf_len = read_varint(&mut r).await? as usize;
            let mut cf_buf = vec![0u8; cf_len];
            r.read_exact(&mut cf_buf).await.map_err(|e| Error::TokioIo(e.into()))?;
            let cf_in_file = String::from_utf8(cf_buf).map_err(|_| {
                Error::TokioIo(std::io::Error::new(std::io::ErrorKind::InvalidData, "CF name not UTF-8").into())
            })?;
            if cf_in_file != cf_name_owned {
                return Err(Error::TokioIo(
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("SPK CF '{}' != requested '{}'", cf_in_file, cf_name_owned),
                    )
                    .into(),
                ));
            }

            // Read records in batches to control memory usage
            let mut current_batch = Vec::new();
            let mut current_batch_size = 0usize;

            loop {
                // Read next record, break on EOF cleanly
                let k_len = match read_varint(&mut r).await {
                    Ok(v) => v as usize,
                    Err(_) => break, // EOF
                };
                let mut k = vec![0u8; k_len];
                r.read_exact(&mut k).await.map_err(|e| Error::TokioIo(e.into()))?;
                let v_len = read_varint(&mut r).await? as usize;
                let mut v = vec![0u8; v_len];
                r.read_exact(&mut v).await.map_err(|e| Error::TokioIo(e.into()))?;

                current_batch.push((k, v));
                current_batch_size += k_len + v_len;

                // Send batch when it reaches size limit
                if current_batch_size >= batch_bytes {
                    if tx.send(Some(std::mem::take(&mut current_batch))).await.is_err() {
                        break; // Channel closed
                    }
                    current_batch_size = 0;
                }
            }

            // Send final batch if not empty
            if !current_batch.is_empty() {
                let _ = tx.send(Some(current_batch)).await;
            }

            // Signal end of stream
            let _ = tx.send(None).await;
            Ok::<(), Error>(())
        });

        // Process batches directly in current task to maintain DB access
        let mut _processed_batches = 0;
        while let Some(batch_opt) = rx.recv().await {
            match batch_opt {
                Some(batch) => {
                    // Write batch to database
                    with_handles(|h| -> Result<(), Error> {
                        let cf_handle = h.db.cf_handle(&cf_name_for_write).ok_or_else(|| {
                            Error::TokioIo(
                                std::io::Error::new(
                                    std::io::ErrorKind::NotFound,
                                    format!("column family '{}' not found", cf_name_for_write),
                                )
                                .into(),
                            )
                        })?;

                        for (k, v) in batch {
                            h.db.put_cf(&cf_handle, &k, &v)?;
                        }
                        Ok(())
                    })?;
                    _processed_batches += 1;
                }
                None => break, // End of stream
            }
        }

        // Wait for read task to complete
        read_handle.await.map_err(|e| Error::TokioIo(e.into()))??;

        Ok(())
    }

    /// Hash a file using Blake3
    async fn blake3_file(path: &Path) -> Result<[u8; 32], Error> {
        let file = File::open(path).await.map_err(Error::TokioIo)?;
        let mut reader = BufReader::new(file);
        let mut hasher = Hasher::new();
        let mut buffer = [0u8; 1 << 16];
        
        loop {
            let bytes_read = reader.read(&mut buffer).await.map_err(Error::TokioIo)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        
        Ok(*hasher.finalize().as_bytes())
    }

    /// Hash a column family in the database (for verification)
    pub async fn hash_cf(cf_name: &str) -> Result<[u8; 32], Error> {
        with_handles(|handles| {
            let snapshot = handles.db.snapshot();
            let mut read_opts = ReadOptions::default();
            read_opts.set_total_order_seek(true);
            read_opts.set_snapshot(&snapshot);
            
            let cf_handle = handles.db.cf_handle(cf_name).ok_or_else(|| {
                Error::TokioIo(
                    std::io::Error::new(std::io::ErrorKind::NotFound, format!("cf '{}' missing", cf_name)).into(),
                )
            })?;
            
            let iterator = handles.db.iterator_cf_opt(&cf_handle, read_opts, IteratorMode::Start);

            let mut hasher = Hasher::new();
            // Hash header same as export: MAGIC + cf_name
            hasher.update(MAGIC);
            hasher.update(&varint_bytes(cf_name.len() as u64));
            hasher.update(cf_name.as_bytes());

            // Hash records in same order as export
            for item in iterator {
                let (key, value) = item?;
                hasher.update(&varint_bytes(key.len() as u64));
                hasher.update(&key);
                hasher.update(&varint_bytes(value.len() as u64));
                hasher.update(&value);
            }

            Ok(*hasher.finalize().as_bytes())
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::any::type_name_of_val;

        fn tmp_base_for_test<F: ?Sized>(f: &F) -> String {
            let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let fq = type_name_of_val(f);
            format!("/tmp/{}{}", fq, secs)
        }

        #[tokio::test]
        async fn test_snapshot_export_import() {
            let base = tmp_base_for_test(&test_snapshot_export_import);
            let _guard = crate::utils::rocksdb::init_for_test(&base).expect("init test db");

            // Put some test data
            put("default", b"key1", b"value1").unwrap();
            put("default", b"key2", b"value2").unwrap();
            put("default", b"key3", b"value3").unwrap();

            let spk_path = std::path::PathBuf::from(format!("{}/test.spk", base));

            // Export snapshot
            let manifest = export_spk("default", &spk_path).await.unwrap();
            assert_eq!(manifest.items_total, 3);
            assert_eq!(manifest.cf, "default");
            assert_eq!(manifest.version, 1);

            // Verify hash matches
            let cf_hash = hash_cf("default").await.unwrap();
            assert_eq!(hex::encode(cf_hash), manifest.root_hex);

            // Test import functionality with small batch size
            import_spk("default", &spk_path, &manifest, 100).await.unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::any::type_name_of_val;
    
    fn tmp_base_for_test<F: ?Sized>(f: &F) -> String {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let fq = type_name_of_val(f);
        format!("/tmp/{}{}", fq, secs)
    }

    #[tokio::test]
    async fn rocksdb_basic_ops_and_iters() {
        let base = tmp_base_for_test(&rocksdb_basic_ops_and_iters);
        let _guard = init_for_test(&base).expect("init test db");

        // basic put/get on default CF
        put("default", b"a:1", b"v1").expect("put");
        let v = get("default", b"a:1").expect("get").unwrap();
        assert_eq!(v, b"v1");

        // insert a few keys with common prefix for iter_prefix
        for i in 0..5u8 {
            put("default", format!("p:{}", i).as_bytes(), &[i]).unwrap();
        }
        let items = iter_prefix("default", b"p:").expect("iter_prefix");
        assert!(!items.is_empty());
        for (k, _v) in &items {
            assert!(k.starts_with(b"p:"));
        }

        // test get_prev_or_first semantics
        put("default", b"h:001", b"x").unwrap();
        put("default", b"h:010", b"y").unwrap();
        put("default", b"h:020", b"z").unwrap();

        let r = get_prev_or_first("default", "h:", "015").unwrap().unwrap();
        assert_eq!(r.0, b"h:010");
        let r2 = get_prev_or_first("default", "h:", "000").unwrap();
        assert!(r2.is_none());
        let r3 = get_prev_or_first("default", "h:", "999").unwrap().unwrap();
        assert_eq!(r3.0, b"h:020");
    }
    
    #[test]
    fn test_in_memory_impl() {
        let db = DB::open_in_memory();
        test_db_operations(&db);
    }
    
    #[test]
    fn test_rocksdb_impl() {
        let temp_dir = format!("/tmp/test_rocksdb_{}", std::process::id());
        fs::create_dir_all(&temp_dir).unwrap();
        
        let db = DB::open_rocksdb(&temp_dir).unwrap();
        test_db_operations(&db);
        
        // cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
    
    fn test_db_operations<T: RocksDbTrait>(db: &T) {
        // Test direct operations
        assert!(db.get(Cf::Default, b"key1").is_none());
        
        db.put(Cf::Default, b"key1", b"value1").unwrap();
        assert_eq!(db.get(Cf::Default, b"key1"), Some(b"value1".to_vec()));
        
        db.delete(Cf::Default, b"key1").unwrap();
        assert!(db.get(Cf::Default, b"key1").is_none());
        
        // Test transaction operations
        let mut txn = db.txn();
        txn.put(Cf::Default, b"tx_key1", b"tx_value1");
        txn.put(Cf::Default, b"tx_key2", b"tx_value2");
        assert_eq!(txn.get(Cf::Default, b"tx_key1"), Some(b"tx_value1".to_vec()));
        
        let muts = txn.commit().unwrap();
        assert_eq!(muts.len(), 2);
        
        assert_eq!(db.get(Cf::Default, b"tx_key1"), Some(b"tx_value1".to_vec()));
        assert_eq!(db.get(Cf::Default, b"tx_key2"), Some(b"tx_value2".to_vec()));
        
        // Test prefix iteration
        db.put(Cf::Default, b"prefix:1", b"v1").unwrap();
        db.put(Cf::Default, b"prefix:2", b"v2").unwrap();
        db.put(Cf::Default, b"other:1", b"v3").unwrap();
        
        let items: Vec<_> = db.prefix_iter(Cf::Default, b"prefix:").collect();
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|(k, _)| k.starts_with(b"prefix:")));
        
        // Test transaction rollback
        let mut txn = db.txn();
        txn.put(Cf::Default, b"rollback_key", b"rollback_value");
        txn.rollback();
        
        assert!(db.get(Cf::Default, b"rollback_key").is_none());
    }
}