use crate::consensus::agg_sig::{DST_ATT, DST_VRF};
use crate::consensus::doms::attestation::Attestation;
use crate::consensus::doms::entry::Entry;
use crate::consensus::doms::tx::TxU;
use crate::consensus::{self, fabric};
use crate::node::protocol::Protocol;
use crate::utils::bls12_381 as bls;
use crate::utils::misc::{TermExt, bitvec_to_bools, bools_to_bitvec, get_unix_millis_now};
use crate::utils::rocksdb::RocksDb;
use crate::utils::safe_etf::encode_safe_deterministic;
use eetf::{Atom, Binary, Term};
use std::collections::HashMap;
use tracing::warn;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong type: {0}")]
    WrongType(&'static str),
    #[error("missing: {0}")]
    Missing(&'static str),
    #[error("invalid entry")]
    InvalidEntry,
    #[error("too far in future")]
    TooFarInFuture,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error(transparent)]
    EtfDecode(#[from] eetf::DecodeError),
    #[error(transparent)]
    EtfEncode(#[from] eetf::EncodeError),
    #[error(transparent)]
    Bls(#[from] bls::Error),
    #[error(transparent)]
    RocksDb(#[from] crate::utils::rocksdb::Error),
    #[error(transparent)]
    Fabric(#[from] fabric::Error),
    #[error(transparent)]
    Attestation(#[from] crate::consensus::doms::attestation::Error),
    #[error(transparent)]
    Entry(#[from] crate::consensus::doms::entry::Error),
}

const CF_SYSCONF: &str = "sysconf";

/// Consensus message holding aggregated attestation for an entry and a particular
/// mutations_hash. Mask denotes which trainers signed the aggregate.
#[derive(Debug, Clone, PartialEq)]
pub struct Consensus {
    pub entry_hash: [u8; 32],
    pub mutations_hash: [u8; 32],
    pub mask: Option<Vec<bool>>,
    pub agg_sig: [u8; 96],
    pub score: Option<f64>,
}

impl Consensus {
    /// Decode from ETF map; supported keys: entry_hash, mutations_hash, mask (bitvec), aggsig
    pub fn from_etf_bin(bin: &[u8]) -> Result<Self, Error> {
        let map = Term::decode(bin)?.get_term_map().ok_or(Error::WrongType("consensus map"))?;
        let entry_hash = map.get_binary("entry_hash").ok_or(Error::Missing("entry_hash"))?;
        let mutations_hash = map.get_binary("mutations_hash").ok_or(Error::Missing("mutations_hash"))?;
        // Empty mask binary (0 bytes) means None (all trainers signed), not Some(empty vec)
        let mask =
            map.get_binary::<Vec<u8>>("mask").map(|bytes| bitvec_to_bools(bytes)).filter(|mask| !mask.is_empty());
        let agg_sig = map.get_binary("aggsig").ok_or(Error::Missing("aggsig"))?;
        Ok(Self { entry_hash, mutations_hash, mask, agg_sig, score: None })
    }

    /// Encode into an ETF map with deterministic field set (Elixir Map.take and term_to_binary)
    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("entry_hash")), Term::from(Binary { bytes: self.entry_hash.to_vec() }));
        m.insert(Term::Atom(Atom::from("mutations_hash")), Term::from(Binary { bytes: self.mutations_hash.to_vec() }));
        if let Some(mask) = &self.mask {
            m.insert(Term::Atom(Atom::from("mask")), Term::from(Binary { bytes: bools_to_bitvec(mask) }));
        }
        m.insert(Term::Atom(Atom::from("aggsig")), Term::from(Binary { bytes: self.agg_sig.to_vec() }));
        let term = Term::from(eetf::Map { map: m });
        let mut out = Vec::new();
        term.encode(&mut out)?;
        Ok(out)
    }

    /// Validate this consensus vs chain state:
    /// - Entry must exist and not be in the future vs current temporal_height
    /// - Aggregate signature must verify against the set of trainers unmasked by `mask`
    ///
    /// On success, sets self.score = Some(score) and returns Ok(())
    pub fn validate_vs_chain(&mut self, db: &RocksDb) -> Result<(), Error> {
        // Build message to sign: entry_hash || mutations_hash
        let mut to_sign = [0u8; 64];
        to_sign[..32].copy_from_slice(&self.entry_hash);
        to_sign[32..].copy_from_slice(&self.mutations_hash);

        // Fetch entry stub (height only for now)
        let entry = get_entry_by_hash_local(db, &self.entry_hash);
        let Some(entry) = entry else { return Err(Error::InvalidEntry) };

        // Ensure entry height is not in the future
        if let Ok(cur_h) = get_chain_height(db)
            && entry.header.height > cur_h
        {
            return Err(Error::TooFarInFuture);
        }

        // Trainers
        let trainers =
            consensus::trainers_for_height(db, entry.header.height).ok_or(Error::Missing("trainers_for_height"))?;
        if trainers.is_empty() {
            return Err(Error::Missing("trainers_for_height:empty"));
        }

        // Score by mask weight (unit weights)
        let (score, signed_pks) = if let Some(mask) = &self.mask {
            let score = score_mask_unit(mask, trainers.len());
            let signed_pks = unmask_trainers(mask, &trainers);
            (score, signed_pks)
        } else {
            // No mask means all trainers signed
            (1.0, trainers.clone())
        };
        let agg_pk = bls::aggregate_public_keys(&signed_pks)?;
        bls::verify(&agg_pk, &self.agg_sig, &to_sign, DST_ATT)?;

        self.score = Some(score);
        Ok(())
    }
}

/// Return true if our trainer_pk is included in trainers_for_height(chain_height()+1)
pub fn is_trainer(config: &crate::config::Config, db: &RocksDb) -> bool {
    let Some(h) = get_chain_height(db).ok() else { return false };
    let Some(trainers) = consensus::trainers_for_height(db, h + 1) else { return false };
    trainers.iter().any(|pk| pk == &config.get_pk())
}

/// Select trainer for a slot from the roster for the corresponding height
pub fn trainer_for_slot(db: &RocksDb, height: u32, slot: u32) -> Option<[u8; 48]> {
    let trainers = consensus::trainers_for_height(db, height)?;
    if trainers.is_empty() {
        return None;
    }
    let idx = ((slot as u64).rem_euclid(trainers.len() as u64)) as usize;
    trainers.get(idx).copied()
}

pub fn trainer_for_slot_current(db: &RocksDb) -> Option<[u8; 48]> {
    let h = get_chain_height(db).ok()?;
    trainer_for_slot(db, h, h)
}

pub fn trainer_for_slot_next(db: &RocksDb) -> Option<[u8; 48]> {
    let h = get_chain_height(db).ok()?;
    trainer_for_slot(db, h + 1, h + 1)
}

pub fn trainer_for_slot_next_me(config: &crate::config::Config, db: &RocksDb) -> bool {
    match trainer_for_slot_next(db) {
        Some(pk) => pk == config.get_pk(),
        None => false,
    }
}

/// Falls back to genesis if no entries yet
pub fn get_chain_tip_entry(db: &RocksDb) -> Result<Entry, Error> {
    match get_temporal_tip_hash(db)?.and_then(|h| get_entry_by_hash_local(db, &h)) {
        Some(entry) => Ok(entry),
        None => Err(Error::Missing("temporal_tip")),
    }
}

/// Falls back to genesis if no entries yet
pub fn get_rooted_tip_entry(db: &RocksDb) -> Result<Entry, Error> {
    match get_rooted_tip_hash(db)?.and_then(|h| get_entry_by_hash_local(db, &h)) {
        Some(entry) => Ok(entry),
        None => Err(Error::Missing("rooted_tip")),
    }
}

pub fn get_chain_height(db: &RocksDb) -> Result<u32, Error> {
    match db.get("sysconf", b"temporal_height")? {
        Some(hb) => {
            // Try u64 big-endian bytes (8 bytes)
            if hb.len() == 8 {
                let arr: [u8; 8] = hb.try_into().map_err(|_| Error::WrongType("invalid kv cell: temporal_height"))?;
                return Ok(u64::from_be_bytes(arr) as u32);
            }
            // Try u32 big-endian bytes (4 bytes)
            if hb.len() == 4 {
                let arr: [u8; 4] = hb.try_into().map_err(|_| Error::WrongType("invalid kv cell: temporal_height"))?;
                return Ok(u32::from_be_bytes(arr));
            }
            // Try ETF term (for Elixir compatibility)
            if let Ok(term) = Term::decode(&mut std::io::Cursor::new(&hb)) {
                if let Some(height) = term.get_integer() {
                    return Ok(height as u32);
                }
            }
            Err(Error::WrongType("invalid kv cell: temporal_height"))
        }
        None => Err(Error::Missing("temporal_height")),
    }
}

fn get_entry_by_hash_local(db: &RocksDb, hash: &[u8; 32]) -> Option<Entry> {
    let bin = db.get("default", hash).ok()??;
    Entry::unpack(&bin).ok()
}

fn get_temporal_tip_hash(db: &RocksDb) -> Result<Option<[u8; 32]>, Error> {
    match db.get("sysconf", b"temporal_tip")? {
        Some(rt) => {
            let arr: [u8; 32] = rt.try_into().map_err(|_| Error::Missing("temporal_tip"))?;
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

fn get_rooted_tip_hash(db: &RocksDb) -> Result<Option<[u8; 32]>, Error> {
    match db.get("sysconf", b"rooted_tip")? {
        Some(rt) => {
            let arr: [u8; 32] = rt.try_into().map_err(|_| Error::Missing("rooted_tip"))?;
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

fn unmask_trainers(mask: &[bool], trainers: &[[u8; 48]]) -> Vec<[u8; 48]> {
    mask.iter().zip(trainers.iter()).filter_map(|(&bit, pk)| if bit { Some(*pk) } else { None }).collect()
}
fn score_mask_unit(mask: &[bool], total_trainers: usize) -> f64 {
    if total_trainers == 0 {
        return 0.0;
    }
    let signed = mask.iter().filter(|&&b| b).count();
    (signed as f64) / (total_trainers as f64)
}

pub fn chain_epoch(db: &RocksDb) -> u32 {
    get_chain_height(db).ok().map(|h| h / 100_000).unwrap_or(0)
}

pub fn chain_segment_vr_hash(db: &RocksDb) -> Option<Vec<u8>> {
    db.get("contractstate", b"bic:epoch:segment_vr_hash").ok()?
}

pub fn chain_diff_bits(db: &RocksDb) -> u32 {
    db.get("contractstate", b"bic:epoch:diff_bits")
        .ok()
        .flatten()
        .and_then(|b| if b.len() == 8 { Some(u64::from_be_bytes(b.try_into().ok()?) as u32) } else { None })
        .unwrap_or(24)
}

pub fn chain_total_sols(db: &RocksDb) -> u64 {
    db.get("contractstate", b"bic:epoch:total_sols")
        .ok()
        .flatten()
        .and_then(|b| if b.len() == 8 { Some(u64::from_be_bytes(b.try_into().ok()?)) } else { None })
        .unwrap_or(0)
}

pub fn chain_pop(db: &RocksDb, pk: &[u8; 48]) -> Option<Vec<u8>> {
    let key = format!("bic:epoch:pop:{}", bs58::encode(pk).into_string());
    db.get("contractstate", key.as_bytes()).ok()?
}

pub fn chain_nonce(db: &RocksDb, pk: &[u8; 48]) -> Option<i64> {
    let key = format!("bic:base:nonce:{}", bs58::encode(pk).into_string());
    db.get("contractstate", key.as_bytes())
        .ok()
        .flatten()
        .and_then(|b| if b.len() == 8 { Some(i64::from_be_bytes(b.try_into().ok()?)) } else { None })
}

pub fn chain_balance(db: &RocksDb, pk: &[u8; 48], symbol: &str) -> u64 {
    let key = format!("bic:coin:balance:{}:{}", bs58::encode(pk).into_string(), symbol);
    db.get("contractstate", key.as_bytes())
        .ok()
        .flatten()
        .and_then(|b| if b.len() == 8 { Some(u64::from_be_bytes(b.try_into().ok()?)) } else { None })
        .unwrap_or(0)
}

pub fn chain_tip(db: &RocksDb) -> Result<Option<[u8; 32]>, Error> {
    get_temporal_tip_hash(db)
}

pub fn chain_muts_rev(db: &RocksDb, hash: &[u8; 32]) -> Option<Vec<crate::consensus::kv::Mutation>> {
    let bin = db.get("muts_rev", hash).ok()??;
    crate::consensus::kv::mutations_from_etf(&bin).ok()
}

pub fn chain_muts(db: &RocksDb, hash: &[u8; 32]) -> Option<Vec<crate::consensus::kv::Mutation>> {
    let bin = db.get("muts", hash).ok()??;
    crate::consensus::kv::mutations_from_etf(&bin).ok()
}

#[derive(Debug, Clone)]
pub struct MapEnv {
    pub readonly: bool,
    pub seed: Option<Vec<u8>>,
    pub seedf64: f64,
    pub entry_signer: [u8; 48],
    pub entry_prev_hash: [u8; 32],
    pub entry_slot: u32,
    pub entry_prev_slot: i32,
    pub entry_height: u32,
    pub entry_epoch: u32,
    pub entry_vr: [u8; 96],
    pub entry_vr_b3: [u8; 32],
    pub entry_dr: [u8; 32],
    pub tx_index: usize,
    pub tx_signer: Option<[u8; 48]>,
    pub tx_nonce: Option<i128>,
    pub tx_hash: Option<[u8; 32]>,
    pub account_origin: Option<[u8; 48]>,
    pub account_caller: Option<[u8; 48]>,
    pub account_current: Option<Vec<u8>>,
    pub attached_symbol: String,
    pub attached_amount: String,
    pub call_counter: u32,
    pub call_exec_points: u64,
    pub call_exec_points_remaining: u64,
}

pub fn make_mapenv(next_entry: &Entry) -> MapEnv {
    let entry_vr_b3 = crate::utils::blake3::hash(&next_entry.header.vr);
    MapEnv {
        readonly: false,
        seed: None,
        seedf64: 1.0,
        entry_signer: next_entry.header.signer,
        entry_prev_hash: next_entry.header.prev_hash,
        entry_slot: next_entry.header.slot,
        entry_prev_slot: next_entry.header.prev_slot,
        entry_height: next_entry.header.height,
        entry_epoch: next_entry.header.height / 100_000,
        entry_vr: next_entry.header.vr,
        entry_vr_b3,
        entry_dr: next_entry.header.dr,
        tx_index: 0,
        tx_signer: None,
        tx_nonce: None,
        tx_hash: None,
        account_origin: None,
        account_caller: None,
        account_current: None,
        attached_symbol: String::new(),
        attached_amount: String::new(),
        call_counter: 0,
        call_exec_points: 10_000_000,
        call_exec_points_remaining: 10_000_000,
    }
}

#[derive(Debug, Clone)]
pub struct TxResult {
    pub error: String,
    pub logs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ApplyResult {
    pub error: String,
    pub attestation_packed: Option<Vec<u8>>,
    pub mutations_hash: [u8; 32],
    pub logs: Vec<TxResult>,
    pub muts: Vec<crate::consensus::kv::Mutation>,
}

pub fn apply_entry(db: &RocksDb, config: &crate::config::Config, next_entry: &Entry) -> Result<ApplyResult, Error> {
    // check height validity
    let current_height = get_chain_height(db).unwrap_or(0);
    if next_entry.header.height != current_height + 1 {
        return Ok(ApplyResult {
            error: "invalid_height".to_string(),
            attestation_packed: None,
            mutations_hash: [0u8; 32],
            logs: vec![],
            muts: vec![],
        });
    }

    // reset consensus KV tracking
    crate::consensus::kv::reset();

    let _mapenv = make_mapenv(next_entry);

    // decode transactions
    let mut txus = Vec::new();
    for tx_packed in &next_entry.txs {
        match TxU::from_vanilla(tx_packed) {
            Ok(txu) => txus.push(txu),
            Err(_) => continue,
        }
    }

    // TODO: call BIC contracts with transactions
    // For now, we'll create placeholder mutations and results
    let mut tx_results = Vec::new();
    for _txu in &txus {
        tx_results.push(TxResult { error: "ok".to_string(), logs: vec![] });
    }

    // get mutations from consensus KV
    let muts = crate::consensus::kv::mutations();
    let muts_rev = crate::consensus::kv::mutations_reverse();
    let mutations_hash = crate::consensus::kv::hash_mutations(&muts);

    // sign attestation
    let pk = config.get_pk();
    let sk = config.get_sk();
    let attestation = Attestation::sign_with(&pk, &sk, &next_entry.hash, &mutations_hash)?;
    let attestation_packed = attestation.to_etf_bin()?;

    // store my attestation
    db.put("my_attestation_for_entry|entryhash", &next_entry.hash, &attestation_packed)?;

    // check if we're a trainer for this height
    let trainers =
        consensus::trainers_for_height(db, next_entry.header.height).ok_or(Error::Missing("trainers_for_height"))?;
    let is_trainer = trainers.iter().any(|t| t == &pk);

    // record seen time
    let seen_time = get_unix_millis_now();
    let seen_time_bin = encode_safe_deterministic(&Term::from(eetf::BigInteger { value: seen_time.into() }));
    db.put("my_seen_time_entry|entryhash", &next_entry.hash, &seen_time_bin)?;

    // update chain tip
    db.put("sysconf", b"temporal_tip", &next_entry.hash)?;
    // store temporal_height as u64 big-endian bytes
    db.put("sysconf", b"temporal_height", &(next_entry.header.height as u64).to_be_bytes())?;

    // store mutations reverse for potential rewind
    let muts_rev_bin = crate::consensus::kv::mutations_to_etf(&muts_rev);
    db.put("muts_rev", &next_entry.hash, &muts_rev_bin)?;

    // store entry itself if not already there
    if db.get("default", &next_entry.hash)?.is_none() {
        let entry_bin = next_entry.pack()?;
        db.put("default", &next_entry.hash, &entry_bin)?;
    }

    // always index by height and slot (even if entry already exists)
    // this ensures entries from snapshots get indexed properly
    // Key format matches Elixir: "#{height}:#{hash}" - no padding, raw hash bytes
    let mut height_key = next_entry.header.height.to_string().into_bytes();
    height_key.push(b':');
    height_key.extend_from_slice(&next_entry.hash);
    db.put("entry_by_height|height:entryhash", &height_key, &next_entry.hash)?;

    let mut slot_key = next_entry.header.slot.to_string().into_bytes();
    slot_key.push(b':');
    slot_key.extend_from_slice(&next_entry.hash);
    db.put("entry_by_slot|slot:entryhash", &slot_key, &next_entry.hash)?;

    // store transactions with results
    for (tx_packed, _result) in next_entry.txs.iter().zip(tx_results.iter()) {
        if let Ok(_txu) = TxU::from_vanilla(tx_packed) {
            // find position in entry binary for indexing
            let entry_bin = next_entry.pack()?;
            if let Some(pos) = entry_bin.windows(tx_packed.len()).position(|w| w == tx_packed) {
                let _tx_meta = HashMap::from([
                    ("entry_hash".to_string(), next_entry.hash.to_vec()),
                    ("index_start".to_string(), (pos as u32).to_be_bytes().to_vec()),
                    ("index_size".to_string(), (tx_packed.len() as u32).to_be_bytes().to_vec()),
                ]);
                // TODO: store tx_meta properly
            }
        }
    }

    Ok(ApplyResult {
        error: "ok".to_string(),
        attestation_packed: if is_trainer { Some(attestation_packed) } else { None },
        mutations_hash,
        logs: tx_results,
        muts,
    })
}

pub fn produce_entry(db: &RocksDb, config: &crate::config::Config, slot: u32) -> Result<Entry, Error> {
    let cur_entry = get_chain_tip_entry(db)?;

    // build next header
    let pk = config.get_pk();
    let sk = config.get_sk();
    let next_header = cur_entry.build_next_header(slot, &pk, &sk)?;

    // TODO: grab transactions from TXPool
    let txs = Vec::new();

    // compute txs_hash
    let txs_bin: Vec<u8> = txs.iter().flatten().cloned().collect();
    let txs_hash = crate::utils::blake3::hash(&txs_bin);

    // create entry with updated txs_hash
    let mut header = next_header;
    header.txs_hash = txs_hash;

    // sign the header
    let header_bin = header.to_etf_bin()?;
    let header_hash = crate::utils::blake3::hash(&header_bin);
    let signature = bls::sign(&sk, &header_hash, crate::consensus::agg_sig::DST_ENTRY)?;

    // compute entry hash
    let entry = Entry {
        hash: [0u8; 32], // will be computed below
        header,
        signature,
        mask: None,
        txs,
    };

    // compute proper entry hash
    let entry_bin = entry.pack()?;
    let hash = crate::utils::blake3::hash(&entry_bin);

    Ok(Entry { hash, header: entry.header, signature: entry.signature, mask: entry.mask, txs: entry.txs })
}

pub fn is_in_chain(db: &RocksDb, target_hash: &[u8; 32]) -> bool {
    // check if entry exists
    let target_entry = match get_entry_by_hash_local(db, target_hash) {
        Some(e) => e,
        None => return false,
    };

    let target_height = target_entry.header.height;

    // get tip entry
    let tip_entry = match get_chain_tip_entry(db) {
        Ok(e) => e,
        Err(_) => return false,
    };

    let tip_height = tip_entry.header.height;

    // if target is higher than tip, it can't be in chain
    if tip_height < target_height {
        return false;
    }

    // walk back from tip to target height
    is_in_chain_internal(db, &tip_entry.hash, target_hash, target_height)
}

fn is_in_chain_internal(db: &RocksDb, current_hash: &[u8; 32], target_hash: &[u8; 32], target_height: u32) -> bool {
    // check if we found the target
    if current_hash == target_hash {
        return true;
    }

    // get current entry
    let current_entry = match get_entry_by_hash_local(db, current_hash) {
        Some(e) => e,
        None => return false,
    };

    // if we're below target height, target is not in chain
    if current_entry.header.height <= target_height {
        return false;
    }

    // continue walking back
    is_in_chain_internal(db, &current_entry.header.prev_hash, target_hash, target_height)
}

pub fn chain_rewind(db: &RocksDb, target_hash: &[u8; 32]) -> Result<bool, Error> {
    // check if target is in chain
    if !is_in_chain(db, target_hash) {
        return Ok(false);
    }

    let tip_entry = get_chain_tip_entry(db)?;
    let entry = chain_rewind_internal(db, &tip_entry, target_hash)?;

    // update chain tips
    db.put("sysconf", b"temporal_tip", &entry.hash)?;
    // store temporal_height as u64 big-endian bytes
    db.put("sysconf", b"temporal_height", &(entry.header.height as u64).to_be_bytes())?;

    // update rooted tip if needed
    if let Ok(Some(rooted_hash)) = get_rooted_tip_hash(db) {
        if db.get("default", &rooted_hash)?.is_none() {
            db.put("sysconf", b"rooted_tip", &entry.hash)?;
        }
    }

    Ok(true)
}

fn chain_rewind_internal(db: &RocksDb, current_entry: &Entry, target_hash: &[u8; 32]) -> Result<Entry, Error> {
    // revert mutations for current entry
    if let Some(m_rev) = chain_muts_rev(db, &current_entry.hash) {
        crate::consensus::kv::revert(db, &m_rev);
    }

    // remove current entry from indices
    db.delete("default", &current_entry.hash)?;
    db.delete("my_seen_time_entry|entryhash", &current_entry.hash)?;

    // Match Elixir format: "#{height}:#{hash}" - no padding, raw hash bytes
    let mut height_key = current_entry.header.height.to_string().into_bytes();
    height_key.push(b':');
    height_key.extend_from_slice(&current_entry.hash);
    db.delete("entry_by_height|height:entryhash", &height_key)?;

    let mut slot_key = current_entry.header.slot.to_string().into_bytes();
    slot_key.push(b':');
    slot_key.extend_from_slice(&current_entry.hash);
    db.delete("entry_by_slot|slot:entryhash", &slot_key)?;

    db.delete("consensus_by_entryhash|Map<mutationshash,consensus>", &current_entry.hash)?;
    db.delete("my_attestation_for_entry|entryhash", &current_entry.hash)?;

    // remove transaction indices
    for tx_packed in &current_entry.txs {
        if let Ok(txu) = TxU::from_vanilla(tx_packed) {
            db.delete("tx", &txu.hash)?;
            let nonce_padded = format!("{:020}", txu.tx.nonce);
            let key = format!("{}:{}", bs58::encode(&txu.tx.signer).into_string(), nonce_padded);
            db.delete("tx_account_nonce", key.as_bytes())?;
        }
    }

    // if we reached the target, get previous entry and return it
    if current_entry.hash == *target_hash {
        let prev_entry = get_entry_by_hash_local(db, &current_entry.header.prev_hash)
            .ok_or(Error::Missing("prev_entry_in_rewind"))?;
        return Ok(prev_entry);
    }

    // continue rewinding
    let prev_entry =
        get_entry_by_hash_local(db, &current_entry.header.prev_hash).ok_or(Error::Missing("prev_entry_in_rewind"))?;
    chain_rewind_internal(db, &prev_entry, target_hash)
}

pub fn best_by_weight(
    trainers: &[[u8; 48]],
    consensuses: &HashMap<[u8; 32], Consensus>,
) -> (Option<[u8; 32]>, Option<f64>, Option<Consensus>) {
    let max_score = trainers.len() as f64;
    let mut best: Option<([u8; 32], f64, Consensus)> = None;

    for (k, v) in consensuses.iter() {
        // calculate weighted score
        let trainers_signed =
            if let Some(mask) = &v.mask { unmask_trainers(mask, trainers) } else { trainers.to_vec() };
        let mut score = 0.0;
        for _pk in trainers_signed {
            // TODO: implement ConsensusWeight.count(pk) - for now use unit weight
            score += 1.0;
        }
        score /= max_score;

        match &mut best {
            None => best = Some((*k, score, v.clone())),
            Some((_, best_score, _)) if score > *best_score => best = Some((*k, score, v.clone())),
            _ => {}
        }
    }

    match best {
        Some((k, score, v)) => (Some(k), Some(score), Some(v)),
        None => (None, None, None),
    }
}

#[derive(Debug, Clone)]
pub struct BestEntry {
    pub entry: Entry,
    pub mutations_hash: Option<[u8; 32]>,
    pub score: Option<f64>,
}

pub fn best_entry_for_height(db: &RocksDb, fabric: &fabric::Fabric, height: u32) -> Result<Vec<BestEntry>, Error> {
    let rooted_tip = get_rooted_tip_hash(db)?.unwrap_or([0u8; 32]);

    // get entries by height
    let entry_bins = fabric.entries_by_height(height as u64)?;
    let mut entries = Vec::new();

    for entry_bin in entry_bins {
        let entry = Entry::unpack(&entry_bin)?;

        // filter by prev_hash == rooted_tip
        if entry.header.prev_hash != rooted_tip {
            continue;
        }

        // get trainers for this height
        let trainers =
            consensus::trainers_for_height(db, entry.header.height).ok_or(Error::Missing("trainers_for_height"))?;

        // get best consensus for this entry
        let (mutations_hash, score, _consensus) = fabric.best_consensus_by_entryhash(&trainers, &entry.hash)?;

        if mutations_hash.is_some() {
            entries.push(BestEntry { entry, mutations_hash, score });
        }
    }

    // sort by score (descending), slot, mask presence, hash
    entries.sort_by(|a, b| {
        let score_cmp = b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal);
        if score_cmp != std::cmp::Ordering::Equal {
            return score_cmp;
        }

        let slot_cmp = a.entry.header.slot.cmp(&b.entry.header.slot);
        if slot_cmp != std::cmp::Ordering::Equal {
            return slot_cmp;
        }

        let mask_cmp = a.entry.mask.is_none().cmp(&b.entry.mask.is_none());
        if mask_cmp != std::cmp::Ordering::Equal {
            return mask_cmp;
        }

        a.entry.hash.cmp(&b.entry.hash)
    });

    Ok(entries)
}

pub fn set_rooted_tip(db: &RocksDb, hash: &[u8; 32]) -> Result<(), Error> {
    db.put("sysconf", b"rooted_tip", hash)?;
    Ok(())
}

pub fn my_attestation_by_entryhash(db: &RocksDb, entry_hash: &[u8; 32]) -> Option<Attestation> {
    let bin = db.get("my_attestation_for_entry|entryhash", entry_hash).ok()??;
    Attestation::from_etf_bin(&bin).ok()
}

pub fn proc_consensus(db: &RocksDb, fabric: &fabric::Fabric) -> Result<(), Error> {
    let initial_rooted_hash = get_rooted_tip_hash(db)?.unwrap_or([0u8; 32]);

    loop {
        let entry_root = get_rooted_tip_entry(db)?;
        let entry_temp = get_chain_tip_entry(db)?;
        let height_root = entry_root.header.height;
        let height_temp = entry_temp.header.height;

        // nothing more to process
        if height_root >= height_temp {
            warn!(
                "proc_consensus: rooted_height {} >= temporal_height {}, nothing to process",
                height_root, height_temp
            );
            break;
        }

        let next_height = height_root + 1;
        tracing::debug!(
            "proc_consensus: processing height {} (rooted={}, temporal={})",
            next_height,
            height_root,
            height_temp
        );

        let next_entries = best_entry_for_height(db, fabric, next_height)?;

        let Some(best_entry_info) = next_entries.first() else {
            warn!(
                "proc_consensus: no entries with consensus at height {} (rooted={}, temporal={})",
                next_height, height_root, height_temp
            );
            break;
        };

        let score = best_entry_info.score.unwrap_or(0.0);
        let best_entry = &best_entry_info.entry;

        // not enough consensus
        if score < 0.67 {
            warn!(
                "proc_consensus: insufficient consensus score {:.2} (need 0.67) for entry {} at height {}",
                score,
                bs58::encode(&best_entry.hash).into_string(),
                best_entry.header.height
            );
            break;
        }

        let mutations_hash = best_entry_info.mutations_hash.unwrap();

        // get our local attestation for this entry to verify we applied it with same mutations
        let my_attestation = my_attestation_by_entryhash(db, &best_entry.hash);

        match my_attestation {
            None => {
                // softfork: consensus chose entry we don't have applied, need to rewind
                warn!(
                    "proc_consensus softfork: consensus chose entry {} at height {} but we don't have it applied, rewinding",
                    bs58::encode(&best_entry.hash).into_string(),
                    best_entry.header.height
                );
                // rewind to previous entry and try again
                let prev_entry = get_rooted_tip_entry(db)?;
                chain_rewind(db, &prev_entry.hash)?;
                break; // exit after rewind
            }
            Some(my_att) => {
                if mutations_hash != my_att.mutations_hash {
                    warn!(
                        "proc_consensus EMERGENCY: consensus mutations {} differ from ours {} for entry {} at height {}",
                        bs58::encode(&mutations_hash).into_string(),
                        bs58::encode(&my_att.mutations_hash).into_string(),
                        bs58::encode(&best_entry.hash).into_string(),
                        best_entry.header.height
                    );
                    // halt consensus processing - state divergence detected
                    break;
                } else {
                    // mutations match, safe to root the entry
                    tracing::info!(
                        "proc_consensus: rooting entry {} at height {} with score {:.2}",
                        bs58::encode(&best_entry.hash).into_string(),
                        best_entry.header.height,
                        score
                    );
                    set_rooted_tip(db, &best_entry.hash)?;
                    // continue loop to process next height
                }
            }
        }
    }

    // check if rooted tip changed
    let final_rooted_hash = get_rooted_tip_hash(db)?.unwrap_or([0u8; 32]);
    if final_rooted_hash != initial_rooted_hash {
        tracing::info!(
            "proc_consensus: rooted tip changed from {} to {}",
            bs58::encode(&initial_rooted_hash).into_string(),
            bs58::encode(&final_rooted_hash).into_string()
        );
        // TODO: trigger event_consensus and NodeGen.broadcast_tip()
    }

    Ok(())
}

pub fn validate_next_entry(current_entry: &Entry, next_entry: &Entry) -> Result<(), Error> {
    let ceh = &current_entry.header;
    let neh = &next_entry.header;

    // validate slot consistency
    if ceh.slot as i32 != neh.prev_slot {
        return Err(Error::WrongType("invalid_slot"));
    }

    // validate height consistency
    if ceh.height != (neh.height - 1) {
        return Err(Error::WrongType("invalid_height"));
    }

    // validate hash consistency
    if current_entry.hash != neh.prev_hash {
        return Err(Error::WrongType("invalid_hash"));
    }

    // validate dr (deterministic random)
    let expected_dr = crate::utils::blake3::hash(&ceh.dr);
    if expected_dr != neh.dr {
        return Err(Error::WrongType("invalid_dr"));
    }

    // validate vr (verifiable random)
    if bls::verify(&neh.signer, &neh.vr, &ceh.vr, DST_VRF).is_err() {
        return Err(Error::InvalidSignature);
    }

    // TODO: validate transactions with TXPool.validate_tx
    // For now, we'll skip detailed transaction validation

    Ok(())
}

/// Stub function for checking if the node is synced with quorum
/// Returns true if the node is within X entries of the quorum (BFT threshold)
/// TODO: implement proper sync checking via FabricSyncAttestGen.isQuorumSyncedOffByX
fn is_quorum_synced_off_by_x(db: &RocksDb, x: u32) -> bool {
    // stub implementation - check if rooted tip is close to temporal tip
    let temporal_height = get_chain_height(db).unwrap_or(0);
    let rooted_entry = get_rooted_tip_entry(db).ok();
    let rooted_height = rooted_entry.map(|e| e.header.height).unwrap_or(0);

    // consider synced if within X entries of temporal tip
    temporal_height.saturating_sub(rooted_height) <= x
}

pub fn delete_transactions_from_pool(_txs: &[Vec<u8>]) {
    // TODO: integrate TXPool with Context to enable transaction removal
    // Implementation exists: TXPool::delete_packed has been implemented in node/txpool.rs
    // What's needed:
    // 1. Add TXPool field to Context struct
    // 2. Initialize TXPool in Context::with_config_and_socket
    // 3. Call ctx.txpool.delete_packed(txs).await here
    // This is critical to prevent memory leaks and double-spending
}

#[derive(Debug, Clone)]
pub struct SoftforkSettings {
    pub softfork_hash: Vec<[u8; 32]>,
    pub softfork_deny_hash: Vec<[u8; 32]>,
}

pub fn get_softfork_settings() -> SoftforkSettings {
    // TODO: read from persistent_term or config
    // For now, return empty settings
    SoftforkSettings { softfork_hash: Vec::new(), softfork_deny_hash: Vec::new() }
}

/// Helper function to check if entry is in its designated slot
fn is_entry_in_slot(db: &RocksDb, entry: &Entry, cur_slot: u32) -> bool {
    let next_slot = entry.header.slot;
    let slot_trainer = trainer_for_slot(db, entry.header.height, next_slot);

    // check incremental slot
    let slot_delta = next_slot as i64 - cur_slot as i64;
    if slot_delta != 1 {
        return false;
    }

    // check trainer authorization
    match slot_trainer {
        Some(expected_trainer) if entry.header.signer == expected_trainer => true,
        Some(_) if entry.mask.is_some() => {
            // aggregate signature path - check if score >= 0.67
            let trainers = consensus::trainers_for_height(db, entry.header.height).unwrap_or_default();
            let score = score_mask_unit(entry.mask.as_ref().unwrap(), trainers.len());
            score >= 0.67
        }
        _ => false,
    }
}

pub async fn proc_entries(
    db: &RocksDb,
    fabric: &fabric::Fabric,
    config: &crate::config::Config,
    ctx: &crate::Context,
) -> Result<(), Error> {
    let softfork_settings = get_softfork_settings();

    // use a loop instead of tail recursion (Rust doesn't optimize tail calls)
    loop {
        let cur_entry = get_chain_tip_entry(db)?;
        let cur_slot = cur_entry.header.slot;
        let next_height = cur_entry.header.height + 1;

        // filter and sort entries using functional pipeline matching Elixir logic
        let mut next_entries: Vec<Entry> = fabric
            .entries_by_height(next_height as u64)?
            .into_iter()
            .filter_map(|entry_bin| {
                Entry::unpack(&entry_bin)
                    .map_err(|e| tracing::warn!("failed to unpack entry at height {}: {}", next_height, e))
                    .ok()
            })
            .filter(|next_entry| {
                // all conditions must be true (matches Elixir cond logic)
                is_entry_in_slot(db, next_entry, cur_slot)
                    && !softfork_settings.softfork_deny_hash.contains(&next_entry.hash)
                    && validate_next_entry(&cur_entry, next_entry).is_ok()
            })
            .collect();

        // sort by tuple (matches Elixir sort_by with tuple comparison)
        next_entries.sort_by_key(|entry| {
            (
                softfork_settings.softfork_hash.contains(&entry.hash), // false (not in list) comes first
                entry.header.slot,
                entry.mask.is_some(), // false (no mask) comes first (Elixir !mask)
                entry.hash,
            )
        });

        // process first entry if available (matches Elixir pattern matching)
        let Some(entry) = next_entries.first() else {
            return Ok(());
        };

        // apply entry (matches Elixir Task.async pattern but synchronously)
        let apply_result = apply_entry(db, config, entry)?;
        if apply_result.error != "ok" {
            return Ok(());
        }

        // TODO: FabricEventGen.event_applied(entry, mutations_hash, muts, logs)
        tracing::info!("Applied entry {} at height {}", bs58::encode(&entry.hash).into_string(), entry.header.height);

        // broadcast attestation if synced and we're a trainer
        if let Some(attestation_packed) = apply_result.attestation_packed {
            if is_quorum_synced_off_by_x(db, 6) {
                broadcast_attestation(ctx, &attestation_packed, &entry.hash).await;
            }
        }

        // remove transactions from pool (matches Elixir TXPool.delete_packed)
        delete_transactions_from_pool(&entry.txs);

        // continue loop to process more entries
    }
}

/// Helper to broadcast attestation to peers and seed nodes
async fn broadcast_attestation(ctx: &crate::Context, attestation_packed: &[u8], entry_hash: &[u8; 32]) {
    use crate::consensus::doms::attestation::{Attestation, EventAttestation};

    let Ok(attestation) = Attestation::from_etf_bin(attestation_packed) else {
        tracing::warn!("failed to decode attestation for broadcast");
        return;
    };

    let event_att = EventAttestation { attestation };

    // broadcast to all peers (matches NodeGen.broadcast)
    if let Ok(peers) = ctx.node_peers.get_all().await {
        for peer in peers {
            let _ = event_att.send_to_with_metrics(ctx, peer.ip).await;
        }
    }

    // send to seed nodes for RPC updates (matches seedanrs_as_peers logic)
    for seed_ip in &ctx.config.seed_ips {
        let _ = event_att.send_to_with_metrics(ctx, *seed_ip).await;
    }

    tracing::info!("Broadcasted attestation for entry {}", bs58::encode(entry_hash).into_string());
}
