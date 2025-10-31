use crate::consensus::doms::attestation::Attestation;
use crate::consensus::doms::entry::Entry;
use crate::utils::misc::{TermExt, bin_to_bitvec, bitvec_to_bin};
use crate::utils::rocksdb::RocksDb;
use crate::utils::safe_etf::{encode_safe_deterministic, u64_to_term};
use amadeus_utils::constants::{
    CF_CONSENSUS_BY_ENTRYHASH, CF_ENTRY, CF_ENTRY_BY_HEIGHT, CF_ENTRY_BY_SLOT, CF_MUTS, CF_MUTS_REV,
    CF_MY_ATTESTATION_FOR_ENTRY, CF_MY_SEEN_TIME_FOR_ENTRY, CF_SYSCONF, CF_TX, CF_TX_ACCOUNT_NONCE,
};
use amadeus_utils::misc::get_bits_percentage;
use amadeus_utils::rocksdb::{Direction, IteratorMode, ReadOptions};
use amadeus_utils::safe_etf::u32_to_term;
use bitvec::prelude::*;
use eetf::{Atom, BigInteger, Binary, Term};
use std::collections::HashMap;
use tracing::{Instrument, debug, info};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    RocksDb(#[from] amadeus_utils::rocksdb::RocksDbError),
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

/// Initialize Fabric DB area (creates/open RocksDB with the required CFs)
async fn init_kvdb(base: &str) -> Result<RocksDb, Error> {
    let long_init_hint = tokio::spawn(
        async {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            info!("rocksdb needs time to seal memtables to SST and compact L0 files...");
        }
        .instrument(tracing::Span::current()),
    );

    let path = format!("{}/db/fabric", base);
    let db = RocksDb::open(path).await.unwrap(); // nothing to do if db fails
    long_init_hint.abort();

    Ok(db)
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
        let next_epoch = if let Ok(Some(bin)) = self.db.get(CF_SYSCONF, b"finality_clean_next_epoch") {
            if let Ok(term) = Term::decode(bin.as_slice()) {
                TermExt::get_integer(&term).unwrap_or(0) as u32
            } else {
                0u32
            }
        } else {
            0u32
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
        for idx in 0..10u64 {
            let s = (start_height as u64) + idx * 10_000;
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

        let cf_sysconf = db.inner.cf_handle(CF_SYSCONF).unwrap();

        let next_epoch_term = encode_safe_deterministic(&u32_to_term(next_epoch + 1));
        let txn = db.begin_transaction();
        let _ = txn.put_cf(&cf_sysconf, b"finality_clean_next_epoch", &next_epoch_term);
        let _ = txn.commit();
    }

    // Methods migrated from free functions
    pub fn insert_entry(
        &self,
        hash: &[u8; 32],
        height: u64,
        slot: u64,
        entry_bin: &[u8],
        seen_millis: u64,
    ) -> Result<(), Error> {
        let cf_entry = self.db.inner.cf_handle(CF_ENTRY).unwrap();
        let cf_seen_time = self.db.inner.cf_handle(CF_MY_SEEN_TIME_FOR_ENTRY).unwrap();
        let cf_by_height = self.db.inner.cf_handle(CF_ENTRY_BY_HEIGHT).unwrap();
        let cf_by_slot = self.db.inner.cf_handle(CF_ENTRY_BY_SLOT).unwrap();

        let txn = self.db.begin_transaction();
        if txn.get_cf(&cf_entry, hash)?.is_none() {
            txn.put_cf(&cf_entry, hash, entry_bin)?;
            let seen_time_term = Term::from(BigInteger { value: seen_millis.into() });
            let seen_time_bin = encode_safe_deterministic(&seen_time_term);
            txn.put_cf(&cf_seen_time, hash, &seen_time_bin)?;
        }

        // ALWAYS index by height and slot, even if entry already exists, it is
        // crucial for entries loaded from snapshots that aren't indexed yet
        let mut height_key = height.to_string().into_bytes();
        height_key.push(b':');
        height_key.extend_from_slice(hash);
        txn.put_cf(&cf_by_height, &height_key, hash)?;

        let mut slot_key = slot.to_string().into_bytes();
        slot_key.push(b':');
        slot_key.extend_from_slice(hash);
        txn.put_cf(&cf_by_slot, &slot_key, hash)?;

        txn.commit()?;
        Ok(())
    }

    pub fn entries_by_height(&self, height: u64) -> Result<Vec<Vec<u8>>, Error> {
        let mut height_prefix = height.to_string().into_bytes();
        height_prefix.push(b':');
        let mut out = Vec::new();
        for (_, v) in self.db.iter_prefix(CF_ENTRY_BY_HEIGHT, &height_prefix)?.iter() {
            if let Some(entry_bin) = self.db.get(CF_ENTRY, v)? {
                out.push(entry_bin);
            }
        }

        Ok(out)
    }

    pub fn entries_by_slot(&self, slot: u64) -> Result<Vec<Vec<u8>>, Error> {
        let mut slot_prefix = slot.to_string().into_bytes();
        slot_prefix.push(b':');
        let mut out = Vec::new();
        for (_, v) in self.db.iter_prefix(CF_ENTRY_BY_SLOT, &slot_prefix)?.iter() {
            if let Some(entry_bin) = self.db.get(CF_ENTRY, &v)? {
                out.push(entry_bin);
            }
        }

        Ok(out)
    }

    pub fn get_entry_by_hash(&self, hash: &[u8; 32]) -> Option<Entry> {
        let bin = self.db.get(CF_ENTRY, hash).ok()??;
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

        let cf_attestation = self.db.inner.cf_handle(CF_MY_ATTESTATION_FOR_ENTRY).unwrap();
        let txn = self.db.begin_transaction();
        txn.put_cf(&cf_attestation, entry_hash, packed.as_slice())?;
        txn.commit()?;

        Ok(Some(new_a))
    }

    pub fn insert_consensus(&self, consensus: &crate::consensus::consensus::Consensus) -> Result<(), Error> {
        let cf_consensus = self.db.inner.cf_handle(CF_CONSENSUS_BY_ENTRYHASH).unwrap();
        let txn = self.db.begin_transaction();

        let mut map = match txn.get_cf(&cf_consensus, &consensus.entry_hash)? {
            Some(bin) => unpack_consensus_map(&bin)?,
            None => HashMap::new(),
        };

        if let Some(existing) = map.get(&consensus.mutations_hash) {
            if existing.mask.count_ones() >= consensus.mask.count_ones() {
                return Ok(());
            }
        }

        // mask in the consensus is optimized away if all trainers signed
        let mask = self.validate_consensus(&consensus)?;

        map.insert(consensus.mutations_hash, StoredConsensus { mask, agg_sig: consensus.agg_sig });
        let packed = pack_consensus_map(&map)?;

        txn.put_cf(&cf_consensus, &consensus.entry_hash, &packed)?;
        txn.commit()?;

        Ok(())
    }

    /// Validate consensus vs chain state:
    /// - Entry must exist and not be in the future vs current temporal_height
    /// - Aggregate signature must verify against the set of trainers unmasked by `mask`
    ///
    /// On success, sets consensus.score = Some(score) and returns Ok(())
    pub fn validate_consensus(
        &self,
        consensus: &crate::consensus::consensus::Consensus,
    ) -> Result<BitVec<u8, Msb0>, Error> {
        use crate::utils::bls12_381 as bls;
        use amadeus_runtime::consensus::unmask_trainers;
        use amadeus_utils::constants::DST_ATT;

        let mut to_sign = [0u8; 64];
        to_sign[..32].copy_from_slice(&consensus.entry_hash);
        to_sign[32..].copy_from_slice(&consensus.mutations_hash);

        let entry = self.get_entry_by_hash(&consensus.entry_hash).ok_or(Error::BadEtf("invalid_entry"))?;
        //let curr_h = self.get_temporal_height()?.ok_or(Error::KvCell("temporal_height_missing"))?;

        // if entry.header.height > curr_h {
        //     return Err(Error::BadEtf("too_far_in_future"));
        // }

        let trainers = self.trainers_for_height(entry.header.height).ok_or(Error::KvCell("trainers_for_height"))?;
        if trainers.is_empty() {
            return Err(Error::KvCell("trainers_for_height:empty"));
        }

        let mask =
            if consensus.mask.is_empty() { bitvec![u8, Msb0; 1; trainers.len()] } else { consensus.mask.clone() };

        let score = get_bits_percentage(&mask, trainers.len());
        if score < 0.67 {
            return Err(Error::BadEtf("consensus_too_low"));
        }

        let signed_pks = unmask_trainers(&consensus.mask, &trainers);
        let agg_pk = bls::aggregate_public_keys(&signed_pks).map_err(|_| Error::BadEtf("bls_aggregate_failed"))?;
        bls::verify(&agg_pk, &consensus.agg_sig, &to_sign, DST_ATT).map_err(|_| Error::BadEtf("invalid_signature"))?;

        Ok(mask)
    }

    pub fn best_consensus_by_entryhash(
        &self,
        trainers: &[[u8; 48]],
        entry_hash: &[u8],
    ) -> Result<(Option<[u8; 32]>, Option<f64>, Option<StoredConsensus>), Error> {
        let Some(bin) = self.db.get(CF_CONSENSUS_BY_ENTRYHASH, entry_hash)? else {
            debug!("no consensus found for entry {}", bs58::encode(entry_hash).into_string());
            return Ok((None, None, None));
        };

        let map = unpack_consensus_map(&bin)?;
        debug!("unpacked {} consensus entries", map.len());

        let best = map
            .into_iter()
            .map(|(hash, consensus)| {
                let score = get_bits_percentage(&consensus.mask, trainers.len());
                debug!("mutations_hash={}, score={:.2}", bs58::encode(&hash).into_string(), score);
                (hash, score, consensus)
            })
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        Ok(best.map_or((None, None, None), |(h, s, c)| (Some(h), Some(s), Some(c))))
    }

    /// Sets temporal entry hash and height
    pub fn set_temporal_hash_height(&self, entry: &Entry) -> Result<(), Error> {
        let cf_sysconf = self.db.inner.cf_handle(CF_SYSCONF).unwrap();

        let txn = self.db.begin_transaction();
        txn.put_cf(&cf_sysconf, b"temporal_tip", &entry.hash)?;
        let height_term = encode_safe_deterministic(&u64_to_term(entry.header.height));
        txn.put_cf(&cf_sysconf, b"temporal_height", &height_term)?;
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

    pub fn get_temporal_height(&self) -> Result<Option<u64>, Error> {
        match self.db.get(CF_SYSCONF, b"temporal_height")? {
            Some(hb) => {
                // Try u64 big-endian bytes (8 bytes)
                if hb.len() == 8 {
                    let arr: [u8; 8] = hb.try_into().map_err(|_| Error::KvCell("temporal_height"))?;
                    return Ok(Some(u64::from_be_bytes(arr)));
                }
                // Try u32 big-endian bytes (4 bytes) for backward compatibility
                if hb.len() == 4 {
                    let arr: [u8; 4] = hb.try_into().map_err(|_| Error::KvCell("temporal_height"))?;
                    return Ok(Some(u32::from_be_bytes(arr) as u64));
                }
                // Try ETF term (for Elixir compatibility)
                if let Ok(term) = Term::decode(&mut std::io::Cursor::new(&hb)) {
                    if let Some(height) = TermExt::get_integer(&term) {
                        return Ok(Some(height as u64));
                    }
                }
                Err(Error::KvCell("temporal_height"))
            }
            None => Ok(None),
        }
    }

    /// Sets rooted entry hash and height
    pub fn set_rooted_hash_height(&self, entry: &Entry) -> Result<(), Error> {
        let cf_sysconf = self.db.inner.cf_handle(CF_SYSCONF).unwrap();

        let txn = self.db.begin_transaction();
        txn.put_cf(&cf_sysconf, b"rooted_tip", &entry.hash)?;
        let height_term = encode_safe_deterministic(&u64_to_term(entry.header.height));
        txn.put_cf(&cf_sysconf, b"rooted_height", &height_term)?;
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

    pub fn get_rooted_height(&self) -> Result<Option<u64>, Error> {
        match self.db.get(CF_SYSCONF, b"rooted_height")? {
            Some(hb) => {
                // Try u64 big-endian bytes (8 bytes)
                if hb.len() == 8 {
                    let arr: [u8; 8] = hb.try_into().map_err(|_| Error::KvCell("rooted_height"))?;
                    return Ok(Some(u64::from_be_bytes(arr)));
                }
                // Try u32 big-endian bytes (4 bytes) for backward compatibility
                if hb.len() == 4 {
                    let arr: [u8; 4] = hb.try_into().map_err(|_| Error::KvCell("rooted_height"))?;
                    return Ok(Some(u32::from_be_bytes(arr) as u64));
                }
                // Try ETF term (for Elixir compatibility)
                if let Ok(term) = Term::decode(&mut std::io::Cursor::new(&hb)) {
                    if let Some(height) = TermExt::get_integer(&term) {
                        return Ok(Some(height as u64));
                    }
                }
                Err(Error::KvCell("rooted_height"))
            }
            None => Ok(None),
        }
    }

    // Convenience wrappers for NodePeers and other components to avoid direct RocksDb usage
    pub fn get_temporal_height_or_0(&self) -> u64 {
        self.get_temporal_height().ok().flatten().unwrap_or(0)
    }

    pub fn get_chain_epoch_or_0(&self) -> u64 {
        self.get_temporal_height_or_0() / 100_000
    }

    pub fn trainers_for_height(&self, height: u64) -> Option<Vec<[u8; 48]>> {
        crate::bic::epoch::trainers_for_height(self.db(), height)
    }

    pub fn get_muts_rev(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.db.get(CF_MUTS_REV, hash)?)
    }

    pub fn put_muts_rev(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        let cf_muts_rev = self.db.inner.cf_handle(CF_MUTS_REV).unwrap();

        let txn = self.db.begin_transaction();
        txn.put_cf(&cf_muts_rev, hash, data)?;
        txn.commit()?;

        Ok(())
    }

    pub fn delete_muts_rev(&self, hash: &[u8; 32]) -> Result<(), Error> {
        let cf_muts_rev = self.db.inner.cf_handle(CF_MUTS_REV).unwrap();

        let txn = self.db.begin_transaction();
        txn.delete_cf(&cf_muts_rev, hash)?;
        txn.commit()?;

        Ok(())
    }

    pub fn get_muts(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.db.get(CF_MUTS, hash)?)
    }

    pub fn put_muts(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        let cf_muts = self.db.inner.cf_handle(CF_MUTS).unwrap();

        let txn = self.db.begin_transaction();
        txn.put_cf(&cf_muts, hash, data)?;
        txn.commit()?;

        Ok(())
    }

    pub fn put_attestation(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        let cf_attestation = self.db.inner.cf_handle(CF_MY_ATTESTATION_FOR_ENTRY).unwrap();

        let txn = self.db.begin_transaction();
        txn.put_cf(&cf_attestation, hash, data)?;
        txn.commit()?;

        Ok(())
    }

    pub fn delete_attestation(&self, hash: &[u8; 32]) -> Result<(), Error> {
        let cf_attestation = self.db.inner.cf_handle(CF_MY_ATTESTATION_FOR_ENTRY).unwrap();

        let txn = self.db.begin_transaction();
        txn.delete_cf(&cf_attestation, hash)?;
        txn.commit()?;

        Ok(())
    }

    pub fn put_seen_time(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        let cf_seen_time = self.db.inner.cf_handle(CF_MY_SEEN_TIME_FOR_ENTRY).unwrap();

        let txn = self.db.begin_transaction();
        txn.put_cf(&cf_seen_time, hash, data)?;
        txn.commit()?;

        Ok(())
    }

    pub fn delete_seen_time(&self, hash: &[u8; 32]) -> Result<(), Error> {
        let cf_seen_time = self.db.inner.cf_handle(CF_MY_SEEN_TIME_FOR_ENTRY).unwrap();

        let txn = self.db.begin_transaction();
        txn.delete_cf(&cf_seen_time, hash)?;
        txn.commit()?;

        Ok(())
    }

    pub fn delete_consensus(&self, hash: &[u8; 32]) -> Result<(), Error> {
        let cf_consensus = self.db.inner.cf_handle(CF_CONSENSUS_BY_ENTRYHASH).unwrap();

        let txn = self.db.begin_transaction();
        txn.delete_cf(&cf_consensus, hash)?;
        txn.commit()?;

        Ok(())
    }

    pub fn delete_entry(&self, hash: &[u8; 32]) -> Result<(), Error> {
        let cf_entry = self.db.inner.cf_handle(CF_ENTRY).unwrap();

        let txn = self.db.begin_transaction();
        txn.delete_cf(&cf_entry, hash)?;
        txn.commit()?;

        Ok(())
    }

    pub fn delete_entry_by_height(&self, height_key: &[u8]) -> Result<(), Error> {
        let cf_by_height = self.db.inner.cf_handle(CF_ENTRY_BY_HEIGHT).unwrap();

        let txn = self.db.begin_transaction();
        txn.delete_cf(&cf_by_height, height_key)?;
        txn.commit()?;

        Ok(())
    }

    pub fn delete_entry_by_slot(&self, slot_key: &[u8]) -> Result<(), Error> {
        let cf_by_slot = self.db.inner.cf_handle(CF_ENTRY_BY_SLOT).unwrap();

        let txn = self.db.begin_transaction();
        txn.delete_cf(&cf_by_slot, slot_key)?;
        txn.commit()?;

        Ok(())
    }

    pub fn put_tx_metadata(&self, key: &[u8], tx: &[u8]) -> Result<(), Error> {
        let cf_tx = self.db.inner.cf_handle(CF_TX).unwrap();

        let txn = self.db.begin_transaction();
        txn.put_cf(&cf_tx, key, tx)?;
        txn.commit()?;

        Ok(())
    }

    pub fn delete_tx_metadata(&self, hash: &[u8; 32]) -> Result<(), Error> {
        let cf_tx = self.db.inner.cf_handle(CF_TX).unwrap();

        let txn = self.db.begin_transaction();
        txn.delete_cf(&cf_tx, hash)?;
        txn.commit()?;

        Ok(())
    }

    pub fn put_tx_account_nonce(&self, key: &[u8], tx_hash: &[u8; 32]) -> Result<(), Error> {
        let cf_nonce = self.db.inner.cf_handle(CF_TX_ACCOUNT_NONCE).unwrap();

        let txn = self.db.begin_transaction();
        txn.put_cf(&cf_nonce, key, tx_hash)?;
        txn.commit()?;

        Ok(())
    }

    pub fn delete_tx_account_nonce(&self, key: &[u8]) -> Result<(), Error> {
        let cf_nonce = self.db.inner.cf_handle(CF_TX_ACCOUNT_NONCE).unwrap();

        let txn = self.db.begin_transaction();
        txn.delete_cf(&cf_nonce, key)?;
        txn.commit()?;

        Ok(())
    }

    pub fn put_entry_raw(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        let cf_entry = self.db.inner.cf_handle(CF_ENTRY).unwrap();

        let txn = self.db.begin_transaction();
        txn.put_cf(&cf_entry, hash, data)?;
        txn.commit()?;

        Ok(())
    }

    pub fn get_entry_raw(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, Error> {
        let entry_cf = CF_ENTRY;
        Ok(self.db.get(entry_cf, hash)?)
    }

    fn clean_muts_rev_range(&self, start: u64, end: u64) -> Result<(), crate::utils::rocksdb::Error> {
        let cf_by_height = self.db.inner.cf_handle(CF_ENTRY_BY_HEIGHT).unwrap();
        let cf_muts_rev = self.db.inner.cf_handle(CF_MUTS_REV).unwrap();

        let start_key = format!("{}:", start).into_bytes();
        let end_key = format!("{}:", end + 1).into_bytes();

        let txn = self.db.begin_transaction();
        let mut opts = ReadOptions::default();
        opts.set_total_order_seek(true);
        let iter = txn.iterator_cf_opt(&cf_by_height, opts, IteratorMode::From(&start_key, Direction::Forward));

        let mut ops = 0;
        for item in iter {
            let (k, v) = item?;
            if k.as_ref() >= end_key.as_slice() {
                break;
            }
            let _ = txn.delete_cf(&cf_muts_rev, &v);
            ops += 1;
        }
        if ops > 0 {
            txn.commit()?;
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
    pub fn get_trainer_for_slot(&self, height: u64, slot: u64) -> Option<[u8; 48]> {
        let trainers = self.trainers_for_height(height)?;
        if trainers.is_empty() {
            return None;
        }
        let idx = slot.rem_euclid(trainers.len() as u64) as usize;
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

    fn is_in_chain_internal(&self, current_hash: &[u8; 32], target_hash: &[u8; 32], target_height: u64) -> bool {
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
    pub fn validate_entry_slot_trainer(&self, entry: &Entry, prev_slot: u64) -> bool {
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
                let score = get_bits_percentage(entry.mask.as_ref().unwrap(), trainers.len());
                score >= 0.67
            }
            _ => false,
        }
    }

    pub fn start_proc_consensus(&self) {
        let cf_sysconf = self.db.inner.cf_handle(CF_SYSCONF).unwrap();

        let txn = self.db.begin_transaction();
        let _ = txn.put_cf(&cf_sysconf, b"proc_consensus", &[1]);
        let _ = txn.commit();
    }

    pub fn stop_proc_consensus(&self) {
        let cf_sysconf = self.db.inner.cf_handle(CF_SYSCONF).unwrap();

        let txn = self.db.begin_transaction();
        let _ = txn.put_cf(&cf_sysconf, b"proc_consensus", &[0]);
        let _ = txn.commit();
    }

    pub fn start_proc_entries(&self) {
        let cf_sysconf = self.db.inner.cf_handle(CF_SYSCONF).unwrap();

        let txn = self.db.begin_transaction();
        let _ = txn.put_cf(&cf_sysconf, b"proc_entries", &[1]);
        let _ = txn.commit();
    }

    pub fn stop_proc_entries(&self) {
        let cf_sysconf = self.db.inner.cf_handle(CF_SYSCONF).unwrap();

        let txn = self.db.begin_transaction();
        let _ = txn.put_cf(&cf_sysconf, b"proc_entries", &[0]);
        let _ = txn.commit();
    }

    pub fn is_proc_consensus_or_entries(&self) -> bool {
        self.db.get(CF_SYSCONF, b"proc_consensus").ok().flatten().map_or(false, |v| v[0] == 1)
            || self.db.get(CF_SYSCONF, b"proc_entries").ok().flatten().map_or(false, |v| v[0] == 1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredConsensus {
    pub mask: BitVec<u8, Msb0>,
    pub agg_sig: [u8; 96],
}

fn pack_consensus_map(map: &HashMap<[u8; 32], StoredConsensus>) -> Result<Vec<u8>, Error> {
    // Encode as ETF map: key: mutations_hash (binary 32); val: map{mask: bitstring, aggsig: binary}
    let mut outer = HashMap::<Term, Term>::new();
    for (mut_hash, v) in map.iter() {
        let key = Term::from(Binary { bytes: mut_hash.to_vec() });
        // pack mask into bytes (bitstring, MSB first)
        let mask_bytes = bitvec_to_bin(&v.mask);
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
        let mask = inner.get_binary("mask").map(bin_to_bitvec).ok_or(Error::BadEtf("mask"))?;
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

    #[tokio::test]
    async fn test_clean_muts_rev_range() {
        let test_path = format!("target/test_clean_muts_{}", std::process::id());
        let fab = Fabric::new(&test_path).await.unwrap();

        let h0: [u8; 32] = [0; 32];
        let h1: [u8; 32] = [1; 32];
        let h2: [u8; 32] = [2; 32];
        let h3: [u8; 32] = [3; 32];
        let h4: [u8; 32] = [4; 32];
        fab.insert_entry(&h0, 99, 999, &[0], 0).unwrap();
        fab.insert_entry(&h1, 100, 1000, &[1], 0).unwrap();
        fab.insert_entry(&h2, 101, 1001, &[2], 0).unwrap();
        fab.insert_entry(&h3, 102, 1002, &[3], 0).unwrap();
        fab.insert_entry(&h4, 103, 1003, &[4], 0).unwrap();
        fab.db.put(CF_MUTS_REV, &h0, b"data0").unwrap();
        fab.db.put(CF_MUTS_REV, &h1, b"data1").unwrap();
        fab.db.put(CF_MUTS_REV, &h2, b"data2").unwrap();
        fab.db.put(CF_MUTS_REV, &h3, b"data3").unwrap();
        fab.db.put(CF_MUTS_REV, &h4, b"data4").unwrap();

        fab.clean_muts_rev_range(100, 102).unwrap();

        assert!(fab.db.get(CF_MUTS_REV, &h0).unwrap().is_some());
        assert!(fab.db.get(CF_MUTS_REV, &h1).unwrap().is_none());
        assert!(fab.db.get(CF_MUTS_REV, &h2).unwrap().is_none());
        assert!(fab.db.get(CF_MUTS_REV, &h3).unwrap().is_none());
        assert!(fab.db.get(CF_MUTS_REV, &h4).unwrap().is_some());
    }

    #[test]
    fn test_pack_unpack_consensus_map() {
        let mut map = HashMap::new();
        map.insert([1; 32], StoredConsensus { mask: bitvec![u8, Msb0; 1, 0, 1, 1, 0, 1, 0, 0], agg_sig: [10; 96] });
        map.insert(
            [2; 32],
            StoredConsensus {
                mask: bitvec![u8, Msb0; 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0],
                agg_sig: [20; 96],
            },
        );
        map.insert([3; 32], StoredConsensus { mask: bitvec![u8, Msb0; 0, 0, 0, 0, 1, 1, 1, 1], agg_sig: [30; 96] });

        let packed = pack_consensus_map(&map).unwrap();
        let unpacked = unpack_consensus_map(&packed).unwrap();

        assert_eq!(unpacked.len(), 3);
        assert_eq!(unpacked[&[1; 32]].agg_sig, [10; 96]);
        assert_eq!(unpacked[&[2; 32]].agg_sig, [20; 96]);
        assert_eq!(unpacked[&[3; 32]].agg_sig, [30; 96]);
        assert_eq!(map, unpacked);
    }
}
