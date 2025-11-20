use crate::consensus::doms::attestation::Attestation;
use crate::consensus::doms::entry::Entry;
use crate::utils::misc::{TermExt, bin_to_bitvec, bitvec_to_bin};
use crate::utils::rocksdb::RocksDb;
use crate::utils::safe_etf::{encode_safe_deterministic, u64_to_term};
use amadeus_utils::constants::{CF_ATTESTATION, CF_ENTRY, CF_ENTRY_META, CF_SYSCONF, CF_TX, CF_TX_ACCOUNT_NONCE};
use amadeus_utils::misc::get_bits_percentage;
use amadeus_utils::rocksdb::{Direction, IteratorMode, ReadOptions};
use amadeus_utils::safe_etf::u32_to_term;
use bitvec::prelude::*;
use eetf::{Atom, Binary, Term};
use std::collections::HashMap;
use tracing::Instrument;

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
        use amadeus_utils::database::pad_integer;

        let cf_entry = self.db.inner.cf_handle(CF_ENTRY).unwrap();
        let cf_entry_meta = self.db.inner.cf_handle(CF_ENTRY_META).unwrap();

        let txn = self.db.begin_transaction();
        if txn.get_cf(&cf_entry, hash)?.is_none() {
            txn.put_cf(&cf_entry, hash, entry_bin)?;

            let seentime_key = format!("entry:{}:seentime", hex::encode(hash));
            txn.put_cf(&cf_entry_meta, seentime_key.as_bytes(), &seen_millis.to_le_bytes())?;
        }

        // ALWAYS index by height and slot, even if entry already exists
        let height_key = format!("by_height:{}:{}", pad_integer(height), hex::encode(hash));
        txn.put_cf(&cf_entry_meta, height_key.as_bytes(), hash)?;

        let slot_key = format!("by_slot:{}:{}", pad_integer(slot), hex::encode(hash));
        txn.put_cf(&cf_entry_meta, slot_key.as_bytes(), hash)?;

        txn.commit()?;
        Ok(())
    }

    pub fn entries_by_height(&self, height: u64) -> Result<Vec<Vec<u8>>, Error> {
        use amadeus_utils::database::pad_integer;

        let height_prefix = format!("by_height:{}:", pad_integer(height));
        let mut out = Vec::new();
        for (_, v) in self.db.iter_prefix(CF_ENTRY_META, height_prefix.as_bytes())?.iter() {
            if let Some(entry_bin) = self.db.get(CF_ENTRY, &v)? {
                out.push(entry_bin);
            }
        }

        Ok(out)
    }

    pub fn entries_by_slot(&self, slot: u64) -> Result<Vec<Vec<u8>>, Error> {
        use amadeus_utils::database::pad_integer;

        let slot_prefix = format!("by_slot:{}:", pad_integer(slot));
        let mut out = Vec::new();
        for (_, v) in self.db.iter_prefix(CF_ENTRY_META, slot_prefix.as_bytes())?.iter() {
            if let Some(entry_bin) = self.db.get(CF_ENTRY, &v)? {
                out.push(entry_bin);
            }
        }

        Ok(out)
    }

    pub fn get_entry_by_hash(&self, hash: &[u8; 32]) -> Option<Entry> {
        let bin = self.db.get(CF_ENTRY, hash).ok()??;
        Entry::unpack_from_db(Some(bin))
    }

    pub fn get_seen_time_for_entry(&self, hash: &[u8; 32]) -> Result<Option<u64>, Error> {
        let key = format!("entry:{}:seentime", hex::encode(hash));
        if let Some(bin) = self.db.get(CF_ENTRY_META, key.as_bytes())? {
            if bin.len() == 8 {
                let bytes: [u8; 8] = bin.try_into().unwrap();
                return Ok(Some(u64::from_le_bytes(bytes)));
            } else if bin.len() == 16 {
                let bytes: [u8; 16] = bin.try_into().unwrap();
                return Ok(Some(u128::from_le_bytes(bytes) as u64));
            }
            // fallback: try ETF for backward compatibility
            if let Ok(term) = Term::decode(bin.as_slice()) {
                if let Some(integer_val) = TermExt::get_integer(&term) {
                    let seen_millis: u64 = integer_val.try_into().map_err(|_| Error::BadEtf("seen_time"))?;
                    return Ok(Some(seen_millis));
                }
            }
            return Err(Error::BadEtf("seen_time_format"));
        }
        Ok(None)
    }

    pub fn my_attestation_by_entryhash(&self, hash: &[u8]) -> Result<Option<Attestation>, Error> {
        use amadeus_utils::database::pad_integer;

        let entry = self.get_entry_by_hash(hash.try_into().map_err(|_| Error::BadEtf("hash_len"))?);
        let entry = entry.ok_or(Error::BadEtf("entry_not_found"))?;

        let my_signer = self.db.get(CF_SYSCONF, b"trainer_pk")?.ok_or(Error::BadEtf("no_trainer_pk"))?;

        let prefix = format!(
            "attestation:{}:{}:{}:",
            pad_integer(entry.header.height),
            hex::encode(hash),
            hex::encode(&my_signer)
        );

        for (_, value) in self.db.iter_prefix(CF_ATTESTATION, prefix.as_bytes())?.iter() {
            if let Some(att) = Attestation::unpack_from_db(value) {
                return Ok(Some(att));
            }
        }

        Ok(None)
    }

    pub fn get_or_resign_my_attestation(
        &self,
        config: &crate::config::Config,
        entry_hash: &[u8; 32],
    ) -> Result<Option<Attestation>, Error> {
        use amadeus_utils::database::pad_integer;

        let entry = self.get_entry_by_hash(entry_hash).ok_or(Error::BadEtf("entry_not_found"))?;
        let my_pk = config.get_pk();

        let prefix = format!(
            "attestation:{}:{}:{}:",
            pad_integer(entry.header.height),
            hex::encode(entry_hash),
            hex::encode(&my_pk)
        );

        for (_, value) in self.db.iter_prefix(CF_ATTESTATION, prefix.as_bytes())?.iter() {
            if let Some(att) = Attestation::unpack_from_db(value) {
                if att.signer == my_pk {
                    return Ok(Some(att));
                }
                let sk = config.get_sk();
                let new_a = Attestation::sign_with(&my_pk, &sk, entry_hash, &att.mutations_hash)?;

                let key = format!(
                    "attestation:{}:{}:{}:{}",
                    pad_integer(entry.header.height),
                    hex::encode(entry_hash),
                    hex::encode(&my_pk),
                    hex::encode(&new_a.mutations_hash)
                );
                self.db.put(CF_ATTESTATION, key.as_bytes(), &new_a.pack_for_db())?;

                return Ok(Some(new_a));
            }
        }

        Ok(None)
    }

    pub fn insert_consensus(&self, consensus: &crate::consensus::consensus::Consensus) -> Result<(), Error> {
        use amadeus_utils::vecpak::{self, Term as VTerm};

        let key =
            format!("consensus:{}:{}", hex::encode(&consensus.entry_hash), hex::encode(&consensus.mutations_hash));

        if let Some(existing_bin) = self.db.get(CF_ATTESTATION, key.as_bytes())? {
            if let Ok(existing_term) = vecpak::decode_seemingly_etf_to_vecpak(&existing_bin) {
                if let Some(existing_mask) = extract_mask_from_consensus_term(&existing_term) {
                    if existing_mask.all()
                        || (!consensus.mask.is_empty() && existing_mask.count_ones() >= consensus.mask.count_ones())
                    {
                        return Ok(());
                    }
                }
            }
        }

        let mask = self.validate_consensus(&consensus)?;

        let consensus_term = VTerm::PropList(vec![
            (VTerm::Binary(b"mask".to_vec()), VTerm::Binary(bitvec_to_bin(&mask))),
            (VTerm::Binary(b"agg_sig".to_vec()), VTerm::Binary(consensus.agg_sig.to_vec())),
        ]);

        self.db.put(CF_ATTESTATION, key.as_bytes(), &vecpak::encode(consensus_term))?;

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

        let signed_pks = unmask_trainers(&mask, &trainers);
        let agg_pk = bls::aggregate_public_keys(&signed_pks).map_err(|_| Error::BadEtf("bls_aggregate_failed"))?;
        bls::verify(&agg_pk, &consensus.agg_sig, &to_sign, DST_ATT).map_err(|_| Error::BadEtf("invalid_signature"))?;

        Ok(mask)
    }

    pub fn best_consensus_by_entryhash(
        &self,
        trainers: &[[u8; 48]],
        entry_hash: &[u8],
    ) -> Result<(Option<[u8; 32]>, Option<f64>, Option<StoredConsensus>), Error> {
        use amadeus_utils::vecpak;

        let prefix = format!("consensus:{}:", hex::encode(entry_hash));
        let items = self.db.iter_prefix(CF_ATTESTATION, prefix.as_bytes())?;

        if items.is_empty() {
            return Ok((None, None, None));
        }

        let mut consensuses = Vec::new();
        for (key, value) in items {
            if let Ok(key_str) = std::str::from_utf8(&key) {
                let parts: Vec<&str> = key_str.split(':').collect();
                if parts.len() >= 3 {
                    if let Ok(mutations_hash) = hex::decode(parts[2]) {
                        if mutations_hash.len() == 32 {
                            if let Ok(term) = vecpak::decode_seemingly_etf_to_vecpak(&value) {
                                if let Some(stored) = parse_stored_consensus_from_vecpak(term) {
                                    let mut hash_array = [0u8; 32];
                                    hash_array.copy_from_slice(&mutations_hash);
                                    consensuses.push((hash_array, stored));
                                }
                            }
                        }
                    }
                }
            }
        }

        let best = consensuses
            .into_iter()
            .map(|(hash, consensus)| {
                let score = get_bits_percentage(&consensus.mask, trainers.len());
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
        // prioritize the actual entry height over stored value (may be stale)
        if let Some(entry) = self.get_temporal_entry()? {
            return Ok(Some(entry.header.height));
        }

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
        // prioritize the actual entry height over stored value (may be stale)
        if let Some(entry) = self.get_rooted_entry()? {
            return Ok(Some(entry.header.height));
        }

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
        amadeus_runtime::consensus::bic::epoch::trainers_for_height(self.db(), height)
    }

    pub fn get_muts_rev(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, Error> {
        let key = format!("entry:{}:muts_rev", hex::encode(hash));
        Ok(self.db.get(CF_ENTRY_META, key.as_bytes())?)
    }

    pub fn put_muts_rev(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        let key = format!("entry:{}:muts_rev", hex::encode(hash));
        self.db.put(CF_ENTRY_META, key.as_bytes(), data)?;
        Ok(())
    }

    pub fn delete_muts_rev(&self, hash: &[u8; 32]) -> Result<(), Error> {
        let key = format!("entry:{}:muts_rev", hex::encode(hash));
        self.db.delete(CF_ENTRY_META, key.as_bytes())?;
        Ok(())
    }

    pub fn get_muts(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, Error> {
        let key = format!("entry:{}:muts", hex::encode(hash));
        Ok(self.db.get(CF_ENTRY_META, key.as_bytes())?)
    }

    pub fn put_muts(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        let key = format!("entry:{}:muts", hex::encode(hash));
        self.db.put(CF_ENTRY_META, key.as_bytes(), data)?;
        Ok(())
    }

    pub fn put_attestation(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        let attestation = Attestation::from_etf_bin(data)?;
        let entry = self.get_entry_by_hash(hash).ok_or(Error::BadEtf("entry_not_found"))?;

        let key = format!(
            "attestation:{}:{}:{}:{}",
            amadeus_utils::database::pad_integer(entry.header.height),
            hex::encode(hash),
            hex::encode(&attestation.signer),
            hex::encode(&attestation.mutations_hash)
        );
        self.db.put(CF_ATTESTATION, key.as_bytes(), &attestation.pack_for_db())?;

        Ok(())
    }

    pub fn delete_attestation(&self, hash: &[u8; 32]) -> Result<(), Error> {
        let entry = self.get_entry_by_hash(hash).ok_or(Error::BadEtf("entry_not_found"))?;
        let my_signer = self.db.get(CF_SYSCONF, b"trainer_pk")?.ok_or(Error::BadEtf("no_trainer_pk"))?;

        let prefix = format!(
            "attestation:{}:{}:{}:",
            amadeus_utils::database::pad_integer(entry.header.height),
            hex::encode(hash),
            hex::encode(&my_signer)
        );

        for (key, _) in self.db.iter_prefix(CF_ATTESTATION, prefix.as_bytes())?.iter() {
            self.db.delete(CF_ATTESTATION, key)?;
        }

        Ok(())
    }

    pub fn put_seen_time(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        let key = format!("entry:{}:seentime", hex::encode(hash));
        self.db.put(CF_ENTRY_META, key.as_bytes(), data)?;
        Ok(())
    }

    pub fn delete_seen_time(&self, hash: &[u8; 32]) -> Result<(), Error> {
        let key = format!("entry:{}:seentime", hex::encode(hash));
        self.db.delete(CF_ENTRY_META, key.as_bytes())?;
        Ok(())
    }

    pub fn delete_consensus(&self, hash: &[u8; 32]) -> Result<(), Error> {
        let prefix = format!("consensus:{}:", hex::encode(hash));
        for (key, _) in self.db.iter_prefix(CF_ATTESTATION, prefix.as_bytes())?.iter() {
            self.db.delete(CF_ATTESTATION, &key)?;
        }
        Ok(())
    }

    pub fn delete_entry(&self, hash: &[u8; 32]) -> Result<(), Error> {
        self.db.delete(CF_ENTRY, hash)?;
        Ok(())
    }

    pub fn delete_entry_by_height(&self, height_key: &[u8]) -> Result<(), Error> {
        self.db.delete(CF_ENTRY_META, height_key)?;
        Ok(())
    }

    pub fn delete_entry_by_slot(&self, slot_key: &[u8]) -> Result<(), Error> {
        self.db.delete(CF_ENTRY_META, slot_key)?;
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
        use amadeus_utils::database::pad_integer;

        let cf_entry_meta = self.db.inner.cf_handle(CF_ENTRY_META).unwrap();

        let start_key = format!("by_height:{}:", pad_integer(start));
        let end_key = format!("by_height:{}:", pad_integer(end + 1));

        let txn = self.db.begin_transaction();
        let mut opts = ReadOptions::default();
        opts.set_total_order_seek(true);
        let iter =
            txn.iterator_cf_opt(&cf_entry_meta, opts, IteratorMode::From(start_key.as_bytes(), Direction::Forward));

        let mut deleted_hashes = Vec::new();
        for item in iter {
            let (k, v) = item?;
            if k.as_ref() >= end_key.as_bytes() {
                break;
            }
            if let Ok(key_str) = std::str::from_utf8(&k) {
                if key_str.starts_with("by_height:") {
                    deleted_hashes.push(v.to_vec());
                }
            }
        }

        let ops = deleted_hashes.len();
        for hash in deleted_hashes {
            let muts_rev_key = format!("entry:{}:muts_rev", hex::encode(&hash));
            let _ = txn.delete_cf(&cf_entry_meta, muts_rev_key.as_bytes());
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

    pub fn is_proc_consensus(&self) -> bool {
        self.db.get(CF_SYSCONF, b"proc_consensus").ok().flatten().map_or(false, |v| v[0] == 1)
    }

    // Chain state query functions - read from CF_CONTRACTSTATE column family

    /// Get the chain nonce for a given public key
    pub fn chain_nonce(&self, public_key: &[u8]) -> Option<u64> {
        let cf = self.db.inner.cf_handle(amadeus_utils::constants::CF_CONTRACTSTATE)?;
        let key = format!("account:{}:nonce", hex::encode(public_key));
        self.db
            .inner
            .get_cf(&cf, key.as_bytes())
            .ok()
            .flatten()
            .and_then(|bytes| std::str::from_utf8(&bytes).ok().and_then(|s| s.parse::<u64>().ok()))
    }

    /// Get the chain balance for a given public key (native AMA token)
    pub fn chain_balance(&self, public_key: &[u8]) -> i128 {
        let cf = match self.db.inner.cf_handle(amadeus_utils::constants::CF_CONTRACTSTATE) {
            Some(cf) => cf,
            None => return 0,
        };
        let key = format!("bic:coin:balance:{}:AMA", hex::encode(public_key));
        self.db
            .inner
            .get_cf(&cf, key.as_bytes())
            .ok()
            .flatten()
            .and_then(|bytes| std::str::from_utf8(&bytes).ok().and_then(|s| s.parse::<i128>().ok()))
            .unwrap_or(0)
    }

    /// Get the chain difficulty bits
    pub fn chain_diff_bits(&self) -> u64 {
        let cf = match self.db.inner.cf_handle(amadeus_utils::constants::CF_CONTRACTSTATE) {
            Some(cf) => cf,
            None => return 128, // default difficulty
        };
        self.db
            .inner
            .get_cf(&cf, b"bic:sol:diff")
            .ok()
            .flatten()
            .and_then(|bytes| std::str::from_utf8(&bytes).ok().and_then(|s| s.parse::<u64>().ok()))
            .unwrap_or(128)
    }

    /// Get the chain segment VR hash
    pub fn chain_segment_vr_hash(&self) -> Option<Vec<u8>> {
        let cf = self.db.inner.cf_handle(amadeus_utils::constants::CF_CONTRACTSTATE)?;
        self.db.inner.get_cf(&cf, b"segment:vr_hash").ok().flatten()
    }

    /// Get balance for a specific account and symbol from the chain state
    pub fn chain_balance_symbol(&self, public_key: &[u8], symbol: &[u8]) -> i128 {
        let cf = match self.db.inner.cf_handle(amadeus_utils::constants::CF_CONTRACTSTATE) {
            Some(cf) => cf,
            None => return 0,
        };
        let key = format!("bic:coin:balance:{}:{}", hex::encode(public_key), std::str::from_utf8(symbol).unwrap_or(""));
        self.db
            .inner
            .get_cf(&cf, key.as_bytes())
            .ok()
            .flatten()
            .and_then(|bytes| std::str::from_utf8(&bytes).ok().and_then(|s| s.parse::<i128>().ok()))
            .unwrap_or(0)
    }

    /// Get the total number of solutions from the chain state
    pub fn chain_total_sols(&self) -> u64 {
        let cf = match self.db.inner.cf_handle(amadeus_utils::constants::CF_CONTRACTSTATE) {
            Some(cf) => cf,
            None => return 0,
        };
        self.db
            .inner
            .get_cf(&cf, b"bic:sol:total")
            .ok()
            .flatten()
            .and_then(|bytes| std::str::from_utf8(&bytes).ok().and_then(|s| s.parse::<u64>().ok()))
            .unwrap_or(0)
    }
}

// Standalone chain query functions for use when only RocksDb is available
pub mod chain_queries {
    use crate::utils::rocksdb::RocksDb;

    /// Get the chain nonce for a given public key
    pub fn chain_nonce(db: &RocksDb, public_key: &[u8]) -> Option<u64> {
        let cf = db.inner.cf_handle(amadeus_utils::constants::CF_CONTRACTSTATE)?;
        let key = format!("account:{}:nonce", hex::encode(public_key));
        db.inner
            .get_cf(&cf, key.as_bytes())
            .ok()
            .flatten()
            .and_then(|bytes| std::str::from_utf8(&bytes).ok().and_then(|s| s.parse::<u64>().ok()))
    }

    /// Get the chain balance for a given public key (native AMA token)
    pub fn chain_balance(db: &RocksDb, public_key: &[u8]) -> i128 {
        let cf = match db.inner.cf_handle(amadeus_utils::constants::CF_CONTRACTSTATE) {
            Some(cf) => cf,
            None => return 0,
        };
        let key = format!("bic:coin:balance:{}:AMA", hex::encode(public_key));
        db.inner
            .get_cf(&cf, key.as_bytes())
            .ok()
            .flatten()
            .and_then(|bytes| std::str::from_utf8(&bytes).ok().and_then(|s| s.parse::<i128>().ok()))
            .unwrap_or(0)
    }

    /// Get the chain difficulty bits
    pub fn chain_diff_bits(db: &RocksDb) -> u64 {
        let cf = match db.inner.cf_handle(amadeus_utils::constants::CF_CONTRACTSTATE) {
            Some(cf) => cf,
            None => return 128, // default difficulty
        };
        db.inner
            .get_cf(&cf, b"bic:sol:diff")
            .ok()
            .flatten()
            .and_then(|bytes| std::str::from_utf8(&bytes).ok().and_then(|s| s.parse::<u64>().ok()))
            .unwrap_or(128)
    }

    /// Get the chain segment VR hash
    pub fn chain_segment_vr_hash(db: &RocksDb) -> Option<Vec<u8>> {
        let cf = db.inner.cf_handle(amadeus_utils::constants::CF_CONTRACTSTATE)?;
        db.inner.get_cf(&cf, b"segment:vr_hash").ok().flatten()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredConsensus {
    pub mask: BitVec<u8, Msb0>,
    pub agg_sig: [u8; 96],
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

fn extract_mask_from_consensus_term(term: &amadeus_utils::vecpak::Term) -> Option<BitVec<u8, Msb0>> {
    use amadeus_utils::vecpak::Term as VTerm;

    if let VTerm::PropList(props) = term {
        for (k, v) in props {
            if let VTerm::Binary(key_bytes) = k {
                if key_bytes == b"mask" {
                    if let VTerm::Binary(mask_bytes) = v {
                        return Some(bin_to_bitvec(mask_bytes.clone()));
                    }
                }
            }
        }
    }
    None
}

fn parse_stored_consensus_from_vecpak(term: amadeus_utils::vecpak::Term) -> Option<StoredConsensus> {
    use amadeus_utils::vecpak::Term as VTerm;

    if let VTerm::PropList(props) = term {
        let mut mask = None;
        let mut agg_sig = None;

        for (k, v) in props {
            if let VTerm::Binary(key_bytes) = k {
                match key_bytes.as_slice() {
                    b"mask" => {
                        if let VTerm::Binary(m) = v {
                            mask = Some(bin_to_bitvec(m));
                        }
                    }
                    b"agg_sig" => {
                        if let VTerm::Binary(s) = v {
                            if s.len() == 96 {
                                let mut arr = [0u8; 96];
                                arr.copy_from_slice(&s);
                                agg_sig = Some(arr);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Some(StoredConsensus { mask: mask?, agg_sig: agg_sig? })
    } else {
        None
    }
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
        fab.put_muts_rev(&h0, b"data0").unwrap();
        fab.put_muts_rev(&h1, b"data1").unwrap();
        fab.put_muts_rev(&h2, b"data2").unwrap();
        fab.put_muts_rev(&h3, b"data3").unwrap();
        fab.put_muts_rev(&h4, b"data4").unwrap();

        fab.clean_muts_rev_range(100, 102).unwrap();

        assert!(fab.get_muts_rev(&h0).unwrap().is_some());
        assert!(fab.get_muts_rev(&h1).unwrap().is_none());
        assert!(fab.get_muts_rev(&h2).unwrap().is_none());
        assert!(fab.get_muts_rev(&h3).unwrap().is_none());
        assert!(fab.get_muts_rev(&h4).unwrap().is_some());
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

    #[test]
    fn test_decode_consensus_etf_height_35000100() {
        use eetf::Term;

        let consensus_bin: Vec<u8> = vec![
            131, 116, 0, 0, 0, 4, 119, 6, 97, 103, 103, 115, 105, 103, 109, 0, 0, 0, 96, 129, 73, 247, 155, 81, 197,
            226, 137, 232, 234, 70, 189, 10, 183, 32, 195, 233, 100, 128, 27, 198, 153, 182, 65, 222, 165, 190, 68, 25,
            182, 6, 56, 81, 34, 72, 177, 98, 247, 176, 97, 107, 30, 156, 41, 92, 81, 106, 158, 4, 41, 134, 73, 169, 37,
            194, 203, 181, 44, 168, 67, 160, 21, 18, 217, 107, 34, 21, 210, 4, 180, 201, 216, 72, 218, 172, 94, 56, 69,
            107, 250, 15, 86, 110, 140, 89, 203, 232, 242, 194, 156, 68, 55, 63, 63, 142, 1, 119, 10, 101, 110, 116,
            114, 121, 95, 104, 97, 115, 104, 109, 0, 0, 0, 32, 170, 146, 100, 97, 74, 77, 249, 99, 118, 155, 186, 154,
            201, 10, 249, 210, 75, 202, 14, 223, 98, 123, 229, 207, 234, 113, 249, 80, 121, 110, 65, 249, 119, 4, 109,
            97, 115, 107, 77, 0, 0, 0, 11, 3, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 224, 119, 14, 109, 117,
            116, 97, 116, 105, 111, 110, 115, 95, 104, 97, 115, 104, 109, 0, 0, 0, 32, 113, 202, 169, 206, 29, 175,
            101, 246, 73, 166, 101, 139, 36, 192, 193, 122, 10, 8, 224, 28, 53, 48, 167, 241, 201, 87, 202, 157, 37,
            75, 246, 101,
        ];

        let trainer_keys: Vec<&str> = vec![
            "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",
        ];

        let trainers: Vec<[u8; 48]> = trainer_keys
            .iter()
            .map(|k| <[u8; 48]>::try_from(&bs58::decode(k).into_vec().unwrap()[..48]).unwrap())
            .collect();

        // check what Consensus::from_etf_bin produces
        use crate::consensus::consensus::Consensus;
        let consensus_via_lib = Consensus::from_etf_bin(&consensus_bin).unwrap();

        let term = Term::decode(&consensus_bin[..]).unwrap();
        let map = term.get_term_map().unwrap();
        let entry_hash: [u8; 32] = map.get_binary("entry_hash").unwrap();
        let mutations_hash: [u8; 32] = map.get_binary("mutations_hash").unwrap();
        let agg_sig: [u8; 96] = map.get_binary("aggsig").unwrap();

        // decode BitBinary mask from raw ETF bytes (EETF library loses bit positions)
        let mask_pattern = &[119u8, 4, b'm', b'a', b's', b'k', 77];
        let mask_start = consensus_bin.windows(7).position(|w| w == mask_pattern).unwrap();
        let bitbin_start = mask_start + 6;
        let mask_len = u32::from_be_bytes([
            consensus_bin[bitbin_start + 1],
            consensus_bin[bitbin_start + 2],
            consensus_bin[bitbin_start + 3],
            consensus_bin[bitbin_start + 4],
        ]) as usize;
        let tail_bits = consensus_bin[bitbin_start + 5] as usize;
        let mask_bytes = &consensus_bin[bitbin_start + 6..bitbin_start + 6 + mask_len];
        let mut mask = BitVec::<u8, Msb0>::new();
        for byte in &mask_bytes[..mask_bytes.len() - 1] {
            mask.extend_from_bitslice(&byte.view_bits::<Msb0>());
        }
        if let Some(&last_byte) = mask_bytes.last() {
            mask.extend_from_bitslice(&last_byte.view_bits::<Msb0>()[..tail_bits]);
        }

        assert_eq!(
            entry_hash,
            [
                170, 146, 100, 97, 74, 77, 249, 99, 118, 155, 186, 154, 201, 10, 249, 210, 75, 202, 14, 223, 98, 123,
                229, 207, 234, 113, 249, 80, 121, 110, 65, 249
            ]
        );
        assert_eq!(
            mutations_hash,
            [
                113, 202, 169, 206, 29, 175, 101, 246, 73, 166, 101, 139, 36, 192, 193, 122, 10, 8, 224, 28, 53, 48,
                167, 241, 201, 87, 202, 157, 37, 75, 246, 101
            ]
        );
        assert_eq!(mask.len(), 83);
        assert_eq!(mask.count_ones(), 82);
        assert!((amadeus_utils::misc::get_bits_percentage(&mask, trainers.len()) - 0.9879).abs() < 0.001);

        // verify aggsig (1:1 logic from validate_consensus)
        use amadeus_runtime::consensus::unmask_trainers;
        use amadeus_utils::constants::DST_ATT;
        let mut to_sign = [0u8; 64];
        to_sign[..32].copy_from_slice(&entry_hash);
        to_sign[32..].copy_from_slice(&mutations_hash);
        let signed_pks = unmask_trainers(&mask, &trainers);
        let agg_pk = crate::utils::bls12_381::aggregate_public_keys(&signed_pks).unwrap();
        crate::utils::bls12_381::verify(&agg_pk, &agg_sig, &to_sign, DST_ATT).unwrap();
    }
}
