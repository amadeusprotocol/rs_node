use crate::consensus::doms::attestation::Attestation;
use crate::consensus::doms::entry::Entry;
use crate::utils::misc::{TermExt, bitvec_to_bools, bools_to_bitvec};
use crate::utils::rocksdb::{self, RocksDb};
use crate::utils::safe_etf::encode_safe_deterministic;
use eetf::{Atom, BigInteger, Binary, Term};
use std::collections::HashMap;
use tracing::{Instrument, debug, info};
// TODO: make the database trait that the fabric will use

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),
    #[error(transparent)]
    EtfDecode(#[from] eetf::DecodeError),
    #[error(transparent)]
    EtfEncode(#[from] eetf::EncodeError),
    #[error(transparent)]
    BinDecode(#[from] bincode::error::DecodeError),
    #[error(transparent)]
    BinEncode(#[from] bincode::error::EncodeError),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
    // #[error(transparent)]
    // Entry(#[from] consensus::entry::Error),
    #[error(transparent)]
    Att(#[from] crate::consensus::doms::attestation::Error),
    #[error("invalid kv cell: {0}")]
    KvCell(&'static str),
    #[error("invalid etf: {0}")]
    BadEtf(&'static str),
}

const CF_DEFAULT: &str = "default";
const CF_ENTRY: &str = "entry";
const CF_CONSENSUS_BY_ENTRYHASH: &str = "consensus_by_entryhash|Map<mutationshash,consensus>";
const CF_SYSCONF: &str = "sysconf";
const CF_ENTRY_BY_HEIGHT: &str = "entry_by_height|height->entryhash";
const CF_ENTRY_BY_SLOT: &str = "entry_by_slot|slot->entryhash";
const CF_MY_SEEN_TIME_FOR_ENTRY: &str = "my_seen_time_entry|entryhash->ts_sec";
const CF_MY_ATTESTATION_FOR_ENTRY: &str = "my_attestation_for_entry|entryhash->attestation";

/// Initialize Fabric DB area (creates/open RocksDB with the required CFs)
async fn init_kvdb(base: &str) -> Result<RocksDb, Error> {
    let long_init_hint = tokio::spawn(
        async {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            info!("rocksdb needs time to seal memtables to SST and compact L0 files...");
        }
        .instrument(tracing::Span::current()),
    );

    // Open instance RocksDB for fabric namespace
    let path = format!("{}/db/fabric", base);
    // Open and return the instance-oriented DB handle
    let db = RocksDb::open(path).await?;
    long_init_hint.abort();

    Ok(db)
}

/// Insert the genesis entry and initial state markers if not present yet
// pub fn insert_genesis() -> Result<(), Error> {
//     let genesis_entry = genesis::get_gen_entry();
//     if rocksdb::get(CF_DEFAULT, &genesis_entry.hash)?.is_some() {
//         return Ok(()); // already inserted, no-op
//     }
//
//     println!("🌌  Ahhh... Fresh Fabric. Marking genesis..");
//
//     let hash = genesis_entry.hash;
//     let height = genesis_entry.header.height;
//     let slot = genesis_entry.header.slot;
//     let entry_bin: Vec<u8> = genesis_entry.try_into()?;
//     insert_entry(&hash, height, slot, &entry_bin, get_unix_millis_now())?;
//
//     // insert genesis attestation aggregate (no-op until full trainers implemented)
//     let att = genesis::attestation();
//     aggregate_attestation(&att)?;
//
//     // set rooted_tip = genesis.hash and temporal_height = 0
//     set_rooted_tip(&hash)?;
//     rocksdb::put(CF_SYSCONF, b"temporal_height", &height.to_be_bytes())?;
//
//     Ok(())
// }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredConsensus {
    pub mask: Vec<bool>,
    pub agg_sig: [u8; 96],
}

fn pack_consensus_map(map: &HashMap<[u8; 32], StoredConsensus>) -> Result<Vec<u8>, Error> {
    // Encode as ETF map: key: mutations_hash (binary 32); val: map{mask: bitstring, aggsig: binary}
    let mut outer = HashMap::<Term, Term>::new();
    for (mut_hash, v) in map.iter() {
        let key = Term::from(Binary { bytes: mut_hash.to_vec() });
        // pack mask into bytes (bitstring, MSB first)
        let mask_bytes = bools_to_bitvec(&v.mask);
        let mut inner = HashMap::new();
        inner.insert(Term::Atom(Atom::from("mask")), Term::from(Binary { bytes: mask_bytes }));
        inner.insert(Term::Atom(Atom::from("aggsig")), Term::from(Binary { bytes: v.agg_sig.to_vec() }));
        outer.insert(key, Term::from(eetf::Map { map: inner }));
    }
    let term = Term::from(eetf::Map { map: outer });
    let out = encode_safe_deterministic(&term);
    Ok(out)
}

fn unpack_consensus_map(bin: &[u8]) -> Result<HashMap<[u8; 32], StoredConsensus>, Error> {
    let term = Term::decode(bin)?;
    let Some(map) = TermExt::get_term_map(&term) else { return Ok(HashMap::new()) };

    let mut out: HashMap<[u8; 32], StoredConsensus> = HashMap::new();
    for (k, v) in map.0.into_iter() {
        // key: mutations_hash (binary 32)
        let mh_bytes = TermExt::get_binary(&k).ok_or(Error::BadEtf("mutations_hash"))?;
        let mh: [u8; 32] = mh_bytes.try_into().map_err(|_| Error::KvCell("mutations_hash"))?;

        // value: map with keys mask (bitstring), agg_sig (binary)
        let inner = TermExt::get_term_map(&v).ok_or(Error::BadEtf("consensus_inner"))?;
        let mask = inner.get_binary("mask").map(bitvec_to_bools).ok_or(Error::BadEtf("mask"))?;
        let agg_sig = inner.get_binary("aggsig").ok_or(Error::BadEtf("aggsig"))?;

        out.insert(mh, StoredConsensus { mask, agg_sig });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_height_slot_indexing() {
        // initialize db for testing
        let test_path = format!("target/test_fabric_{}", std::process::id());
        let fab = Fabric::new(&test_path).await.unwrap();

        // create test entry data
        let entry_hash1: [u8; 32] = [1; 32];
        let entry_hash2: [u8; 32] = [2; 32];
        let entry_bin1 = vec![1, 2, 3, 4];
        let entry_bin2 = vec![5, 6, 7, 8];
        let height = 12345;
        let slot1 = 67890;
        let slot2 = 67891;
        let seen_time = 1234567890;

        // insert two entries with same height but different slots
        fab.insert_entry(&entry_hash1, height, slot1, &entry_bin1, seen_time).unwrap();
        fab.insert_entry(&entry_hash2, height, slot2, &entry_bin2, seen_time).unwrap();

        // test querying by height should return both entries
        let entries = fab.entries_by_height(height as u64).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&entry_bin1));
        assert!(entries.contains(&entry_bin2));

        // test querying by slot should return one entry each
        let entries_slot1 = fab.entries_by_slot(slot1).unwrap();
        assert_eq!(entries_slot1.len(), 1);
        assert_eq!(entries_slot1[0], entry_bin1);

        let entries_slot2 = fab.entries_by_slot(slot2).unwrap();
        assert_eq!(entries_slot2.len(), 1);
        assert_eq!(entries_slot2[0], entry_bin2);

        // test querying non-existent height/slot returns empty
        let empty_entries = fab.entries_by_height(99999).unwrap();
        assert!(empty_entries.is_empty());

        let empty_slot = fab.entries_by_slot(99999).unwrap();
        assert!(empty_slot.is_empty());

        println!("height/slot indexing test passed");
    }
}

// New Fabric struct that owns the RocksDb handle
#[derive(Debug, Clone)]
pub struct Fabric {
    db: RocksDb,
}

impl Fabric {
    /// Create Fabric by opening RocksDb at base/fabric
    pub async fn new(base: &str) -> Result<Self, Error> {
        // Previously init_kvdb(base) + Fabric::new(db)
        let db = init_kvdb(base).await?;
        Ok(Self { db })
    }

    /// Create Fabric from an already opened RocksDb handle
    pub fn with_db(db: RocksDb) -> Self {
        Self { db }
    }

    pub fn db(&self) -> &RocksDb {
        &self.db
    }

    // Perform a single periodic cleanup step: if an epoch is ready to be cleaned, clean it
    pub async fn cleanup(&self) {
        use crate::consensus::chain_epoch;
        let db = &self.db;

        // read progress
        let next_epoch = match db.get(CF_SYSCONF, b"finality_clean_next_epoch") {
            Ok(Some(bytes)) => match bincode::decode_from_slice::<u32, _>(&bytes, bincode::config::standard()) {
                Ok((val, _)) => val,
                Err(_) => 0u32,
            },
            _ => 0u32,
        };

        let cur_epoch = chain_epoch(db);
        if next_epoch >= cur_epoch.saturating_sub(1) {
            return; // nothing to do yet
        }

        // Clean one full epoch range [E*100_000 .. E*100_000 + 99_999]
        let start_height = next_epoch.saturating_mul(100_000);
        let _end_height = start_height + 99_999;

        // Process in 10 shards of 10_000 heights to avoid long DB stalls
        let mut handles = Vec::with_capacity(10);
        for idx in 0..10u32 {
            let s = start_height + idx * 10_000;
            let e = s + 9_999;
            // spawn blocking work inline (db is sync API; wrap in spawn_blocking if needed later)
            let fab = self.clone();
            handles.push(tokio::spawn(async move {
                fab.clean_muts_rev_range(s, e).ok();
            }));
        }
        for h in handles {
            let _ = h.await;
        }

        // advance pointer
        let bytes = bincode::encode_to_vec(&(next_epoch + 1), bincode::config::standard()).unwrap();
        let _ = db.put(CF_SYSCONF, b"finality_clean_next_epoch", &bytes);
    }

    // Methods migrated from free functions
    pub fn insert_entry(
        &self,
        hash: &[u8; 32],
        height: u32,
        slot: u32,
        entry_bin: &[u8],
        seen_millis: u64,
    ) -> Result<(), Error> {
        // store entry if not already present
        let entry_cf = CF_ENTRY;
        if self.db.get(entry_cf, hash)?.is_none() {
            self.db.put(entry_cf, hash, entry_bin)?;

            // Store seen time using ETF deterministic format like Elixir
            let seen_time_term = Term::from(BigInteger { value: seen_millis.into() });
            let seen_time_bin = encode_safe_deterministic(&seen_time_term);
            self.db.put(CF_MY_SEEN_TIME_FOR_ENTRY, hash, &seen_time_bin)?;
        }

        // ALWAYS index by height and slot, even if entry already exists
        // this is crucial for entries loaded from snapshots that aren't indexed yet
        // Key format matches Elixir: "#{height}:#{hash}" - no padding, raw hash bytes
        let mut height_key = height.to_string().into_bytes();
        height_key.push(b':');
        height_key.extend_from_slice(hash);
        self.db.put(CF_ENTRY_BY_HEIGHT, &height_key, hash)?;

        let mut slot_key = slot.to_string().into_bytes();
        slot_key.push(b':');
        slot_key.extend_from_slice(hash);
        self.db.put(CF_ENTRY_BY_SLOT, &slot_key, hash)?;

        Ok(())
    }

    pub fn entries_by_height(&self, height: u64) -> Result<Vec<Vec<u8>>, Error> {
        // Match Elixir format: "#{height}:" with no padding
        let mut height_prefix = height.to_string().into_bytes();
        height_prefix.push(b':');
        let kvs = self.db.iter_prefix(CF_ENTRY_BY_HEIGHT, &height_prefix)?;
        let mut out = Vec::new();
        let entry_cf = CF_ENTRY;
        for (_k, v) in kvs.into_iter() {
            if let Some(entry_bin) = self.db.get(entry_cf, &v)? {
                out.push(entry_bin);
            }
        }
        Ok(out)
    }

    pub fn entries_by_slot(&self, slot: u32) -> Result<Vec<Vec<u8>>, Error> {
        // Match Elixir format: "#{slot}:" with no padding
        let mut slot_prefix = slot.to_string().into_bytes();
        slot_prefix.push(b':');
        let kvs = self.db.iter_prefix(CF_ENTRY_BY_SLOT, &slot_prefix)?;
        let mut out = Vec::new();
        let entry_cf = CF_ENTRY;
        for (_k, v) in kvs.into_iter() {
            if let Some(entry_bin) = self.db.get(entry_cf, &v)? {
                out.push(entry_bin);
            }
        }
        Ok(out)
    }

    pub fn get_entry_by_hash(&self, hash: &[u8; 32]) -> Option<Entry> {
        let entry_cf = CF_ENTRY;
        let bin = self.db.get(entry_cf, hash).ok()??;
        let entry = Entry::unpack(&bin).ok()?;
        Some(entry)
    }

    pub fn get_seen_time_for_entry(&self, hash: &[u8; 32]) -> Result<Option<u64>, Error> {
        if let Some(bin) = self.db.get(CF_MY_SEEN_TIME_FOR_ENTRY, hash)? {
            let term = Term::decode(bin.as_slice())?;
            if let Some(integer_val) = TermExt::get_integer(&term) {
                let seen_millis: u64 = integer_val.try_into().map_err(|_| Error::BadEtf("seen_time"))?;
                return Ok(Some(seen_millis));
            }
            return Err(Error::BadEtf("seen_time_format"));
        }
        Ok(None)
    }

    pub fn my_attestation_by_entryhash(&self, hash: &[u8]) -> Result<Option<Attestation>, Error> {
        if let Some(bin) = self.db.get(CF_MY_ATTESTATION_FOR_ENTRY, hash)? {
            let a = Attestation::from_etf_bin(&bin)?;
            return Ok(Some(a));
        }
        Ok(None)
    }

    pub fn get_or_resign_my_attestation(
        &self,
        config: &crate::config::Config,
        entry_hash: &[u8; 32],
    ) -> Result<Option<Attestation>, Error> {
        let packed = self.db.get(CF_MY_ATTESTATION_FOR_ENTRY, entry_hash)?;
        let Some(bin) = packed else { return Ok(None) };
        let att = Attestation::from_etf_bin(&bin)?;
        if att.signer == config.get_pk() {
            return Ok(Some(att));
        }
        debug!("imported database, resigning attestation {}", bs58::encode(entry_hash).into_string());
        let pk = config.get_pk();
        let sk = config.get_sk();
        let new_a = Attestation::sign_with(&pk, &sk, entry_hash, &att.mutations_hash)?;
        let packed = new_a.to_etf_bin()?;
        self.db.put(CF_MY_ATTESTATION_FOR_ENTRY, entry_hash, packed.as_slice())?;
        Ok(Some(new_a))
    }

    pub fn insert_consensus(
        &self,
        entry_hash: [u8; 32],
        mutations_hash: [u8; 32],
        consensus_mask: Vec<bool>,
        consensus_agg_sig: [u8; 96],
        score: f64,
    ) -> Result<(), Error> {
        if score < 0.67 {
            return Ok(());
        }

        let mut map = match self.db.get(CF_CONSENSUS_BY_ENTRYHASH, &entry_hash)? {
            Some(bin) => unpack_consensus_map(&bin)?,
            None => HashMap::new(),
        };

        if let Some(existing) = map.get(&mutations_hash) {
            let old_cnt = existing.mask.iter().filter(|&&b| b).count();
            let new_cnt = consensus_mask.iter().filter(|&&b| b).count();
            if new_cnt <= old_cnt {
                return Ok(());
            }
        }

        map.insert(mutations_hash, StoredConsensus { mask: consensus_mask, agg_sig: consensus_agg_sig });
        let packed = pack_consensus_map(&map)?;
        self.db.put(CF_CONSENSUS_BY_ENTRYHASH, &entry_hash, &packed)?;
        Ok(())
    }

    pub fn best_consensus_by_entryhash(
        &self,
        trainers: &[[u8; 48]],
        entry_hash: &[u8],
    ) -> Result<(Option<[u8; 32]>, Option<f64>, Option<StoredConsensus>), Error> {
        let Some(bin) = self.db.get(CF_CONSENSUS_BY_ENTRYHASH, entry_hash)? else {
            debug!(
                "best_consensus_by_entryhash: no consensus data found for entry {}",
                bs58::encode(entry_hash).into_string()
            );
            return Ok((None, None, None));
        };
        let map = unpack_consensus_map(&bin)?;
        debug!("best_consensus_by_entryhash: unpacked consensus map with {} entries", map.len());
        let max_score = trainers.len() as f64;
        let mut best: Option<([u8; 32], f64, StoredConsensus)> = None;
        for (k, v) in map.into_iter() {
            let mut score_units = 0f64;
            for (i, bit) in v.mask.iter().enumerate() {
                if i < trainers.len() && *bit {
                    score_units += 1.0;
                }
            }
            let score = if max_score > 0.0 { score_units / max_score } else { 0.0 };
            debug!(
                "best_consensus_by_entryhash: mutations_hash={}, score={:.2}, mask_len={}",
                bs58::encode(&k).into_string(),
                score,
                v.mask.len()
            );
            match &mut best {
                None => best = Some((k, score, v)),
                Some((_bk, bs, _bv)) if score > *bs => best = Some((k, score, v)),
                _ => {}
            }
        }
        if let Some((k, s, v)) = best {
            debug!("best_consensus_by_entryhash: returning best with score {:.2}", s);
            Ok((Some(k), Some(s), Some(v)))
        } else {
            debug!("best_consensus_by_entryhash: no best found, returning None");
            Ok((None, None, None))
        }
    }

    /// Sets temporal entry hash and height
    pub fn set_temporal_hash_height(&self, entry: &Entry) -> Result<(), Error> {
        let txn = self.db.begin_transaction()?;
        txn.put(CF_SYSCONF, b"temporal_tip", &entry.hash)?;
        // Store as ETF term to match Elixir's `term: true`
        let height_term =
            encode_safe_deterministic(&Term::from(eetf::FixInteger { value: entry.header.height as i32 }));
        txn.put(CF_SYSCONF, b"temporal_height", &height_term)?;
        txn.commit()?;
        Ok(())
    }

    pub fn get_temporal_entry(&self) -> Result<Option<Entry>, Error> {
        Ok(self.get_temporal_hash()?.and_then(|h| self.get_entry_by_hash(&h)))
    }

    pub fn get_temporal_hash(&self) -> Result<Option<[u8; 32]>, Error> {
        match self.db.get(CF_SYSCONF, b"temporal_tip")? {
            Some(rt) => Ok(Some(rt.try_into().map_err(|_| Error::KvCell("temporal_tip"))?)),
            None => Ok(None),
        }
    }

    pub fn get_temporal_height(&self) -> Result<Option<u32>, Error> {
        match self.db.get(CF_SYSCONF, b"temporal_height")? {
            Some(hb) => {
                // Try u64 big-endian bytes (8 bytes)
                if hb.len() == 8 {
                    let arr: [u8; 8] = hb.try_into().map_err(|_| Error::KvCell("temporal_height"))?;
                    return Ok(Some(u64::from_be_bytes(arr) as u32));
                }
                // Try u32 big-endian bytes (4 bytes)
                if hb.len() == 4 {
                    let arr: [u8; 4] = hb.try_into().map_err(|_| Error::KvCell("temporal_height"))?;
                    return Ok(Some(u32::from_be_bytes(arr)));
                }
                // Try ETF term (for Elixir compatibility)
                if let Ok(term) = Term::decode(&mut std::io::Cursor::new(&hb)) {
                    if let Some(height) = TermExt::get_integer(&term) {
                        return Ok(Some(height as u32));
                    }
                }
                Err(Error::KvCell("temporal_height"))
            }
            None => Ok(None),
        }
    }

    /// Sets rooted entry hash and height
    pub fn set_rooted_hash_height(&self, entry: &Entry) -> Result<(), Error> {
        let txn = self.db.begin_transaction()?;
        txn.put(CF_SYSCONF, b"rooted_tip", &entry.hash)?;
        txn.put(CF_SYSCONF, b"rooted_height", &(entry.header.height as u64).to_be_bytes())?;
        txn.commit()?;
        Ok(())
    }

    pub fn get_rooted_entry(&self) -> Result<Option<Entry>, Error> {
        Ok(self.get_rooted_hash()?.and_then(|h| self.get_entry_by_hash(&h)))
    }

    pub fn get_rooted_hash(&self) -> Result<Option<[u8; 32]>, Error> {
        match self.db.get(CF_SYSCONF, b"rooted_tip")? {
            Some(rt) => Ok(Some(rt.try_into().map_err(|_| Error::KvCell("rooted_tip"))?)),
            None => Ok(None),
        }
    }

    pub fn get_rooted_height(&self) -> Result<Option<u32>, Error> {
        match self.db.get(CF_SYSCONF, b"rooted_height")? {
            Some(hb) => {
                // Try u64 big-endian bytes (8 bytes)
                if hb.len() == 8 {
                    let arr: [u8; 8] = hb.try_into().map_err(|_| Error::KvCell("rooted_height"))?;
                    return Ok(Some(u64::from_be_bytes(arr) as u32));
                }
                // Try u32 big-endian bytes (4 bytes)
                if hb.len() == 4 {
                    let arr: [u8; 4] = hb.try_into().map_err(|_| Error::KvCell("rooted_height"))?;
                    return Ok(Some(u32::from_be_bytes(arr)));
                }
                // Try ETF term (for Elixir compatibility)
                if let Ok(term) = Term::decode(&mut std::io::Cursor::new(&hb)) {
                    if let Some(height) = TermExt::get_integer(&term) {
                        return Ok(Some(height as u32));
                    }
                }
                Err(Error::KvCell("rooted_height"))
            }
            None => Ok(None),
        }
    }

    // Convenience wrappers for NodePeers and other components to avoid direct RocksDb usage
    pub fn get_temporal_height_or_0(&self) -> u32 {
        self.get_temporal_height().ok().flatten().unwrap_or(0)
    }

    pub fn get_chain_epoch_or_0(&self) -> u32 {
        self.get_temporal_height_or_0() / 100_000
    }

    pub fn trainers_for_height(&self, height: u32) -> Option<Vec<[u8; 48]>> {
        crate::bic::epoch::trainers_for_height(self.db(), height)
    }

    pub fn get_muts_rev(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.db.get("muts_rev", hash)?)
    }

    pub fn put_muts_rev(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        self.db.put("muts_rev", hash, data)?;
        Ok(())
    }

    pub fn delete_muts_rev(&self, hash: &[u8; 32]) -> Result<(), Error> {
        self.db.delete("muts_rev", hash)?;
        Ok(())
    }

    pub fn get_muts(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.db.get("muts", hash)?)
    }

    pub fn put_muts(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        self.db.put("muts", hash, data)?;
        Ok(())
    }

    pub fn put_attestation(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        self.db.put(CF_MY_ATTESTATION_FOR_ENTRY, hash, data)?;
        Ok(())
    }

    pub fn delete_attestation(&self, hash: &[u8; 32]) -> Result<(), Error> {
        self.db.delete(CF_MY_ATTESTATION_FOR_ENTRY, hash)?;
        Ok(())
    }

    pub fn put_seen_time(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        self.db.put(CF_MY_SEEN_TIME_FOR_ENTRY, hash, data)?;
        Ok(())
    }

    pub fn delete_seen_time(&self, hash: &[u8; 32]) -> Result<(), Error> {
        self.db.delete(CF_MY_SEEN_TIME_FOR_ENTRY, hash)?;
        Ok(())
    }

    pub fn delete_consensus(&self, hash: &[u8; 32]) -> Result<(), Error> {
        self.db.delete(CF_CONSENSUS_BY_ENTRYHASH, hash)?;
        Ok(())
    }

    pub fn delete_entry(&self, hash: &[u8; 32]) -> Result<(), Error> {
        let entry_cf = CF_ENTRY;
        self.db.delete(entry_cf, hash)?;
        Ok(())
    }

    pub fn delete_entry_by_height(&self, height_key: &[u8]) -> Result<(), Error> {
        self.db.delete(CF_ENTRY_BY_HEIGHT, height_key)?;
        Ok(())
    }

    pub fn delete_entry_by_slot(&self, slot_key: &[u8]) -> Result<(), Error> {
        self.db.delete(CF_ENTRY_BY_SLOT, slot_key)?;
        Ok(())
    }

    pub fn put_tx_metadata(&self, key: &[u8], tx: &[u8]) -> Result<(), Error> {
        self.db.put("tx|txhash->entryhash", key, tx)?;
        Ok(())
    }

    pub fn delete_tx_metadata(&self, hash: &[u8; 32]) -> Result<(), Error> {
        self.db.delete("tx|txhash->entryhash", hash)?;
        Ok(())
    }

    pub fn put_tx_account_nonce(&self, key: &[u8], tx_hash: &[u8; 32]) -> Result<(), Error> {
        self.db.put("tx_account_nonce|account:nonce->txhash", key, tx_hash)?;
        Ok(())
    }

    pub fn delete_tx_account_nonce(&self, key: &[u8]) -> Result<(), Error> {
        self.db.delete("tx_account_nonce|account:nonce->txhash", key)?;
        Ok(())
    }

    pub fn put_entry_raw(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        let entry_cf = CF_ENTRY;
        self.db.put(entry_cf, hash, data)?;
        Ok(())
    }

    pub fn get_entry_raw(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, Error> {
        let entry_cf = CF_ENTRY;
        Ok(self.db.get(entry_cf, hash)?)
    }

    // Helper used by Fabric::cleanup to remove muts_rev keys for entries within a height range
    fn clean_muts_rev_range(&self, start: u32, end: u32) -> Result<(), crate::utils::rocksdb::Error> {
        // Use a transaction for batching if available
        let txn = self.db.begin_transaction()?;
        let mut ops = 0usize;
        for height in start..=end {
            // Match Elixir format: "#{height}:" with no padding
            let mut height_prefix = height.to_string().into_bytes();
            height_prefix.push(b':');
            let kvs = match self.db.iter_prefix(CF_ENTRY_BY_HEIGHT, &height_prefix) {
                Ok(k) => k,
                Err(_) => continue,
            };
            for (_k, entry_hash) in kvs {
                // entry_hash is the value stored in entry_by_height index
                let _ = txn.delete("muts_rev", &entry_hash);
                ops += 1;
            }
        }
        if ops > 0 {
            let _ = txn.commit();
        }
        Ok(())
    }

    /// Return true if our trainer_pk is included in trainers_for_height(chain_height()+1)
    pub fn are_we_trainer(&self, config: &crate::config::Config) -> bool {
        let Some(h) = self.get_temporal_height().ok().flatten() else { return false };
        let Some(trainers) = self.trainers_for_height(h + 1) else { return false };
        trainers.iter().any(|pk| pk == &config.get_pk())
    }

    /// Select trainer for a slot from the roster for the corresponding height
    pub fn get_trainer_for_slot(&self, height: u32, slot: u32) -> Option<[u8; 48]> {
        let trainers = self.trainers_for_height(height)?;
        if trainers.is_empty() {
            return None;
        }
        let idx = (slot as u64).rem_euclid(trainers.len() as u64) as usize;
        trainers.get(idx).copied()
    }

    pub fn get_trainer_for_current_slot(&self) -> Option<[u8; 48]> {
        let h = self.get_temporal_height().ok()??;
        self.get_trainer_for_slot(h, h)
    }

    pub fn get_trainer_for_next_slot(&self) -> Option<[u8; 48]> {
        let h = self.get_temporal_height().ok()??;
        self.get_trainer_for_slot(h + 1, h + 1)
    }

    pub fn are_we_trainer_for_next_slot(&self, config: &crate::config::Config) -> bool {
        match self.get_trainer_for_next_slot() {
            Some(pk) => pk == config.get_pk(),
            None => false,
        }
    }

    pub fn is_in_chain(&self, target_hash: &[u8; 32]) -> bool {
        // check if entry exists
        let target_entry = match self.get_entry_by_hash(target_hash) {
            Some(e) => e,
            None => return false,
        };

        let target_height = target_entry.header.height;

        // get tip entry
        let tip_hash = match self.get_temporal_hash() {
            Ok(Some(h)) => h,
            _ => return false,
        };
        let tip_entry = match self.get_entry_by_hash(&tip_hash) {
            Some(e) => e,
            None => return false,
        };

        let tip_height = tip_entry.header.height;

        // if target is higher than tip, it can't be in chain
        if tip_height < target_height {
            return false;
        }

        // walk back from tip to target height
        self.is_in_chain_internal(&tip_entry.hash, target_hash, target_height)
    }

    fn is_in_chain_internal(&self, current_hash: &[u8; 32], target_hash: &[u8; 32], target_height: u32) -> bool {
        // check if we found the target
        if current_hash == target_hash {
            return true;
        }

        // get current entry
        let current_entry = match self.get_entry_by_hash(current_hash) {
            Some(e) => e,
            None => return false,
        };

        // if we're below target height, target is not in chain
        if current_entry.header.height <= target_height {
            return false;
        }

        // continue walking back
        self.is_in_chain_internal(&current_entry.header.prev_hash, target_hash, target_height)
    }

    /// Check if entry is in its designated slot
    pub fn validate_entry_slot_trainer(&self, entry: &Entry, prev_slot: u32) -> bool {
        let next_slot = entry.header.slot;
        let slot_trainer = self.get_trainer_for_slot(entry.header.height, next_slot);

        // check incremental slot
        if (next_slot as i64) - (prev_slot as i64) != 1 {
            return false;
        }

        // check trainer authorization
        match slot_trainer {
            Some(expected_trainer) if entry.header.signer == expected_trainer => true,
            Some(_) if entry.mask.is_some() => {
                // aggregate signature path - check if score >= 0.67
                let trainers = self.trainers_for_height(entry.header.height).unwrap_or_default();
                let score = crate::utils::misc::get_bits_percentage(entry.mask.as_ref().unwrap(), trainers.len());
                score >= 0.67
            }
            _ => false,
        }
    }
}
