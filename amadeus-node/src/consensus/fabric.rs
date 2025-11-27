use crate::consensus::doms::attestation::Attestation;
use crate::consensus::doms::entry::Entry;
use crate::utils::misc::{TermExt, bin_to_bitvec, bitvec_to_bin};
use crate::utils::rocksdb::RocksDb;
use crate::utils::safe_etf::{encode_safe_deterministic, u64_to_term};
use crate::utils::{Hash, PublicKey, Signature};
use amadeus_utils::constants::{CF_ATTESTATION, CF_ENTRY, CF_ENTRY_META, CF_SYSCONF, CF_TX, CF_TX_ACCOUNT_NONCE};
use amadeus_utils::misc::get_bits_percentage;
use amadeus_utils::rocksdb::{Direction, IteratorMode, ReadOptions};
use amadeus_utils::vecpak::{Term, decode};
use bitvec::prelude::*;
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
        let next_epoch = if let Ok(Some(bin)) = self.db.get(CF_SYSCONF, b"finality_clean_next_epoch")
            && let Ok(bytes) = bin.try_into()
        {
            u32::from_be_bytes(bytes)
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

        let next_epoch_be = (next_epoch + 1).to_be_bytes();
        let txn = db.begin_transaction();
        let _ = txn.put_cf(&cf_sysconf, b"finality_clean_next_epoch", &next_epoch_be);
        let _ = txn.commit();
    }

    // Methods migrated from free functions
    pub fn insert_entry(
        &self,
        hash: &Hash,
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
            txn.put_cf(&cf_entry_meta, seentime_key.as_bytes(), seen_millis.to_string().as_bytes())?;
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

    pub fn get_entry_by_hash(&self, hash: &Hash) -> Option<Entry> {
        let bin = self.db.get(CF_ENTRY, hash.as_ref()).ok()??;
        Entry::from_vecpak_bin(&bin).ok()
    }

    pub fn my_attestation_by_entryhash(&self, hash: &[u8]) -> Result<Option<Attestation>, Error> {
        use amadeus_utils::database::pad_integer;

        let hash_array: [u8; 32] = hash.try_into().map_err(|_| Error::BadEtf("hash_len"))?;
        let entry = self.get_entry_by_hash(&Hash::from(hash_array));
        let entry = entry.ok_or(Error::BadEtf("entry_not_found"))?;

        let my_signer = self.db.get(CF_SYSCONF, b"trainer_pk")?.ok_or(Error::BadEtf("no_trainer_pk"))?;

        let prefix = format!(
            "attestation:{}:{}:{}:",
            pad_integer(entry.header.height),
            hex::encode(hash),
            hex::encode(&my_signer)
        );

        for (_, value) in self.db.iter_prefix(CF_ATTESTATION, prefix.as_bytes())?.iter() {
            if let Some(att) = Attestation::from_vecpak_bin(value) {
                return Ok(Some(att));
            }
        }

        Ok(None)
    }

    pub fn get_or_resign_my_attestation(
        &self,
        config: &crate::config::Config,
        entry_hash: &Hash,
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
            if let Some(att) = Attestation::from_vecpak_bin(value) {
                if att.signer.as_ref() as &[u8] == my_pk.as_ref() as &[u8] {
                    return Ok(Some(att));
                }
                let sk = config.get_sk();
                let new_a = Attestation::sign_with(my_pk.as_ref(), &sk, entry_hash, &att.mutations_hash)?;

                let key = format!(
                    "attestation:{}:{}:{}:{}",
                    pad_integer(entry.header.height),
                    hex::encode(entry_hash),
                    hex::encode(&my_pk),
                    hex::encode(&new_a.mutations_hash)
                );
                self.db.put(CF_ATTESTATION, key.as_bytes(), &new_a.to_vecpak_bin())?;

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
            if let Ok(existing_term) = decode(&existing_bin) {
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
        to_sign[..32].copy_from_slice(consensus.entry_hash.as_ref());
        to_sign[32..].copy_from_slice(consensus.mutations_hash.as_ref());

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
        bls::verify(&*agg_pk, &*consensus.agg_sig, &to_sign, DST_ATT)
            .map_err(|_| Error::BadEtf("invalid_signature"))?;

        Ok(mask)
    }

    pub fn best_consensus_by_entryhash(
        &self,
        trainers: &[PublicKey],
        entry_hash: &[u8],
    ) -> Result<(Option<[u8; 32]>, Option<f64>, Option<StoredConsensus>), Error> {
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
                            if let Some(stored) = parse_stored_consensus(&value) {
                                let mut hash_array = [0u8; 32];
                                hash_array.copy_from_slice(&mutations_hash);
                                consensuses.push((hash_array, stored));
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
        Ok(self.get_temporal_hash()?.and_then(|h| self.get_entry_by_hash(&Hash::from(h))))
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
                if let Ok(term) = eetf::Term::decode(&mut std::io::Cursor::new(&hb)) {
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
        Ok(self.get_rooted_hash()?.and_then(|h| self.get_entry_by_hash(&Hash::from(h))))
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

    pub fn trainers_for_height(&self, height: u64) -> Option<Vec<PublicKey>> {
        amadeus_runtime::consensus::bic::epoch::trainers_for_height(self.db(), height)
    }

    pub fn get_muts_rev(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Error> {
        let key = format!("entry:{}:muts_rev", hex::encode(hash));
        Ok(self.db.get(CF_ENTRY_META, key.as_bytes())?)
    }

    pub fn put_muts_rev(&self, hash: &Hash, data: &[u8]) -> Result<(), Error> {
        let key = format!("entry:{}:muts_rev", hex::encode(hash));
        self.db.put(CF_ENTRY_META, key.as_bytes(), data)?;
        Ok(())
    }

    pub fn delete_muts_rev(&self, hash: &Hash) -> Result<(), Error> {
        let key = format!("entry:{}:muts_rev", hex::encode(hash));
        self.db.delete(CF_ENTRY_META, key.as_bytes())?;
        Ok(())
    }

    pub fn get_muts(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Error> {
        let key = format!("entry:{}:muts", hex::encode(hash));
        Ok(self.db.get(CF_ENTRY_META, key.as_bytes())?)
    }

    pub fn put_muts(&self, hash: &Hash, data: &[u8]) -> Result<(), Error> {
        let key = format!("entry:{}:muts", hex::encode(hash));
        self.db.put(CF_ENTRY_META, key.as_bytes(), data)?;
        Ok(())
    }

    pub fn put_attestation(&self, hash: &Hash, data: &[u8]) -> Result<(), Error> {
        let attestation = Attestation::from_vecpak_bin(data).ok_or(Error::BadEtf("attestation_unpack_failed"))?;
        let entry = self.get_entry_by_hash(hash).ok_or(Error::BadEtf("entry_not_found"))?;

        let key = format!(
            "attestation:{}:{}:{}:{}",
            amadeus_utils::database::pad_integer(entry.header.height),
            hex::encode(hash),
            hex::encode(&attestation.signer),
            hex::encode(&attestation.mutations_hash)
        );
        self.db.put(CF_ATTESTATION, key.as_bytes(), &attestation.to_vecpak_bin())?;

        Ok(())
    }

    pub fn delete_attestation(&self, hash: &Hash) -> Result<(), Error> {
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

    pub fn put_entry_seen_time(&self, hash: &Hash, seen_time: u64) -> Result<(), Error> {
        let key = format!("entry:{}:seentime", hex::encode(hash));
        self.db.put(CF_ENTRY_META, key.as_bytes(), seen_time.to_string().as_bytes())?;
        Ok(())
    }

    pub fn delete_entry_seen_time(&self, hash: &Hash) -> Result<(), Error> {
        let key = format!("entry:{}:seentime", hex::encode(hash));
        self.db.delete(CF_ENTRY_META, key.as_bytes())?;
        Ok(())
    }

    pub fn get_entry_seen_time(&self, hash: &Hash) -> Result<Option<u64>, Error> {
        let key = format!("entry:{}:seentime", hex::encode(hash));
        if let Some(bin) = self.db.get(CF_ENTRY_META, key.as_bytes())? {
            if let Ok(s) = std::str::from_utf8(&bin) {
                if let Ok(val) = s.parse::<u64>() {
                    return Ok(Some(val));
                }
            }
            return Err(Error::BadEtf("seen_time_format"));
        }
        Ok(None)
    }

    pub fn delete_consensus(&self, hash: &Hash) -> Result<(), Error> {
        let prefix = format!("consensus:{}:", hex::encode(hash));
        for (key, _) in self.db.iter_prefix(CF_ATTESTATION, prefix.as_bytes())?.iter() {
            self.db.delete(CF_ATTESTATION, &key)?;
        }
        Ok(())
    }

    pub fn delete_entry(&self, hash: &Hash) -> Result<(), Error> {
        self.db.delete(CF_ENTRY, hash.as_ref())?;
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

    pub fn delete_tx_metadata(&self, hash: &Hash) -> Result<(), Error> {
        let cf_tx = self.db.inner.cf_handle(CF_TX).unwrap();

        let txn = self.db.begin_transaction();
        txn.delete_cf(&cf_tx, hash.as_ref() as &[u8])?;
        txn.commit()?;

        Ok(())
    }

    pub fn put_tx_account_nonce(&self, key: &[u8], tx_hash: &Hash) -> Result<(), Error> {
        let cf_nonce = self.db.inner.cf_handle(CF_TX_ACCOUNT_NONCE).unwrap();

        let txn = self.db.begin_transaction();
        txn.put_cf(&cf_nonce, key, tx_hash.as_ref() as &[u8])?;
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

    pub fn put_entry_raw(&self, hash: &Hash, data: &[u8]) -> Result<(), Error> {
        let cf_entry = self.db.inner.cf_handle(CF_ENTRY).unwrap();

        let txn = self.db.begin_transaction();
        txn.put_cf(&cf_entry, hash, data)?;
        txn.commit()?;

        Ok(())
    }

    pub fn get_entry_raw(&self, hash: &Hash) -> Result<Option<Vec<u8>>, Error> {
        let entry_cf = CF_ENTRY;
        Ok(self.db.get(entry_cf, hash.as_ref())?)
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
    pub fn get_trainer_for_slot(&self, height: u64, slot: u64) -> Option<PublicKey> {
        let trainers = self.trainers_for_height(height)?;
        if trainers.is_empty() {
            return None;
        }
        let idx = slot.rem_euclid(trainers.len() as u64) as usize;
        trainers.get(idx).copied()
    }

    pub fn get_trainer_for_current_slot(&self) -> Option<PublicKey> {
        let h = self.get_temporal_height().ok()??;
        self.get_trainer_for_slot(h, h)
    }

    pub fn get_trainer_for_next_slot(&self) -> Option<PublicKey> {
        let h = self.get_temporal_height().ok()??;
        self.get_trainer_for_slot(h + 1, h + 1)
    }

    pub fn are_we_trainer_for_next_slot(&self, config: &crate::config::Config) -> bool {
        match self.get_trainer_for_next_slot() {
            Some(pk) => pk == config.get_pk(),
            None => false,
        }
    }

    pub fn is_in_chain(&self, target_hash: &Hash) -> bool {
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
        let tip_entry = match self.get_entry_by_hash(&Hash::from(tip_hash)) {
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

    fn is_in_chain_internal(&self, current_hash: &Hash, target_hash: &Hash, target_height: u64) -> bool {
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
    pub agg_sig: Signature,
}

#[allow(dead_code)]
fn pack_consensus_map(map: &HashMap<[u8; 32], StoredConsensus>) -> Result<Vec<u8>, Error> {
    use amadeus_utils::vecpak::{self, Term as VTerm};

    let mut entries = Vec::new();
    for (mut_hash, v) in map.iter() {
        let mask_bytes = bitvec_to_bin(&v.mask);
        let consensus_data = VTerm::PropList(vec![
            (VTerm::Binary(b"mask".to_vec()), VTerm::Binary(mask_bytes)),
            (VTerm::Binary(b"agg_sig".to_vec()), VTerm::Binary(v.agg_sig.to_vec())),
        ]);
        entries.push((VTerm::Binary(mut_hash.to_vec()), consensus_data));
    }
    let term = VTerm::PropList(entries);
    Ok(vecpak::encode(term))
}

fn extract_mask_from_consensus_term(term: &Term) -> Option<BitVec<u8, Msb0>> {
    use amadeus_utils::vecpak::VecpakExt;

    let map = term.get_proplist_map()?;
    let mask_bytes: Vec<u8> = map.get_binary(b"mask")?;
    Some(bin_to_bitvec(mask_bytes))
}

fn parse_stored_consensus(bin: &[u8]) -> Option<StoredConsensus> {
    use amadeus_utils::vecpak::VecpakExt;

    let term = decode(bin).ok()?;
    let map = term.get_proplist_map()?;

    let mask_bytes: Vec<u8> = map.get_binary(b"mask")?;
    let mask = bin_to_bitvec(mask_bytes);
    let agg_sig: Signature = map.get_binary(b"agg_sig")?;

    Some(StoredConsensus { mask, agg_sig })
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
        let entry_hash1: Hash = Hash::new([1; 32]);
        let entry_hash2: Hash = Hash::new([2; 32]);
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

        let h0: Hash = Hash::new([0; 32]);
        let h1: Hash = Hash::new([1; 32]);
        let h2: Hash = Hash::new([2; 32]);
        let h3: Hash = Hash::new([3; 32]);
        let h4: Hash = Hash::new([4; 32]);
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
}
