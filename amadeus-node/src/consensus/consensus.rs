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
use tracing::{info, warn};

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
    pub fn validate_vs_chain(&mut self, fabric: &fabric::Fabric) -> Result<(), Error> {
        // Build message to sign: entry_hash || mutations_hash
        let mut to_sign = [0u8; 64];
        to_sign[..32].copy_from_slice(&self.entry_hash);
        to_sign[32..].copy_from_slice(&self.mutations_hash);

        // Fetch entry stub (height only for now)
        let entry = get_entry_by_hash_local(fabric, &self.entry_hash);
        let Some(entry) = entry else { return Err(Error::InvalidEntry) };

        // Ensure entry height is not in the future
        if let Ok(Some(cur_h)) = fabric.get_temporal_height()
            && entry.header.height > cur_h
        {
            return Err(Error::TooFarInFuture);
        }

        // Trainers
        let trainers = consensus::trainers_for_height(fabric.db(), entry.header.height)
            .ok_or(Error::Missing("trainers_for_height"))?;
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
    let fabric = fabric::Fabric::with_db(db.clone());
    let Some(h) = get_chain_height(&fabric).ok() else { return false };
    let Some(trainers) = consensus::trainers_for_height(db, h + 1) else { return false };
    trainers.iter().any(|pk| pk == &config.get_pk())
}

/// Select trainer for a slot from the roster for the corresponding height
pub fn get_trainer_for_slot(db: &RocksDb, height: u32, slot: u32) -> Option<[u8; 48]> {
    let trainers = consensus::trainers_for_height(db, height)?;
    if trainers.is_empty() {
        return None;
    }
    let idx = (slot as u64).rem_euclid(trainers.len() as u64) as usize;
    trainers.get(idx).copied()
}

pub fn get_trainer_for_current_slot(db: &RocksDb) -> Option<[u8; 48]> {
    let fabric = fabric::Fabric::with_db(db.clone());
    let h = fabric.get_temporal_height().ok()??;
    get_trainer_for_slot(db, h, h)
}

pub fn get_trainer_for_next_slot(db: &RocksDb) -> Option<[u8; 48]> {
    let fabric = fabric::Fabric::with_db(db.clone());
    let h = fabric.get_temporal_height().ok()??;
    get_trainer_for_slot(db, h + 1, h + 1)
}

pub fn are_we_trainer_for_next_slot(config: &crate::config::Config, db: &RocksDb) -> bool {
    match get_trainer_for_next_slot(db) {
        Some(pk) => pk == config.get_pk(),
        None => false,
    }
}

/// Falls back to genesis if no entries yet
pub fn get_chain_tip_entry(fabric: &fabric::Fabric) -> Result<Entry, Error> {
    match fabric.get_temporal_hash()?.and_then(|h| get_entry_by_hash_local(fabric, &h)) {
        Some(entry) => Ok(entry),
        None => Err(Error::Missing("temporal_tip")),
    }
}

/// Falls back to genesis if no entries yet
pub fn get_rooted_tip_entry(fabric: &fabric::Fabric) -> Result<Entry, Error> {
    match get_rooted_tip_hash(fabric)?.and_then(|h| get_entry_by_hash_local(fabric, &h)) {
        Some(entry) => Ok(entry),
        None => Err(Error::Missing("rooted_tip")),
    }
}

pub fn get_chain_height(fabric: &fabric::Fabric) -> Result<u32, Error> {
    fabric.get_temporal_height()?.ok_or(Error::Missing("temporal_height"))
}

fn get_entry_by_hash_local(fabric: &fabric::Fabric, hash: &[u8; 32]) -> Option<Entry> {
    fabric.get_entry_by_hash(hash)
}

fn get_rooted_tip_hash(fabric: &fabric::Fabric) -> Result<Option<[u8; 32]>, Error> {
    Ok(fabric.get_rooted_hash()?)
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

pub fn chain_epoch(fabric: &fabric::Fabric) -> u32 {
    get_chain_height(fabric).ok().map(|h| h / 100_000).unwrap_or(0)
}

pub fn chain_muts_rev(fabric: &fabric::Fabric, hash: &[u8; 32]) -> Option<Vec<crate::consensus::kv::Mutation>> {
    let bin = fabric.get_muts_rev(hash).ok()??;
    crate::consensus::kv::mutations_from_etf(&bin).ok()
}

pub fn chain_muts(fabric: &fabric::Fabric, hash: &[u8; 32]) -> Option<Vec<crate::consensus::kv::Mutation>> {
    let bin = fabric.get_muts(hash).ok()??;
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

/// Execute a single transaction, routing to the appropriate contract handler
/// Returns (error, logs, mutations, mutations_reverse, mutations_gas, mutations_gas_reverse)
fn execute_transaction(
    ctx: &mut crate::consensus::kv::ApplyCtx,
    db: &RocksDb,
    next_entry: &Entry,
    txu: &TxU,
) -> (
    String,
    Vec<String>,
    Vec<crate::consensus::kv::Mutation>,
    Vec<crate::consensus::kv::Mutation>,
    Vec<crate::consensus::kv::Mutation>,
    Vec<crate::consensus::kv::Mutation>,
) {
    let action = match txu.tx.actions.first() {
        Some(a) => a,
        None => return ("no_actions".to_string(), vec![], vec![], vec![], vec![], vec![]),
    };

    ctx.reset();

    let call_env = crate::bic::epoch::CallEnv {
        entry_epoch: next_entry.header.height as u64 / 100_000,
        entry_height: next_entry.header.height as u64,
        entry_signer: next_entry.header.signer,
        entry_vr: next_entry.header.vr.to_vec(),
        tx_hash: txu.hash.to_vec(),
        tx_signer: txu.tx.signer,
        account_caller: txu.tx.signer,
        account_current: vec![],
        call_counter: 0,
        call_exec_points: 10_000_000,
        call_exec_points_remaining: 10_000_000,
        attached_symbol: action.attached_symbol.clone().unwrap_or_default(),
        attached_amount: action.attached_amount.clone().unwrap_or_default(),
        seed: next_entry.header.dr,
        seedf64: 0.5,
        readonly: false,
    };

    let (error, logs) = match action.contract.as_slice() {
        b"Epoch" => execute_epoch_call(ctx, db, &call_env, &action.function, &action.args),
        b"Coin" => execute_coin_call(ctx, db, txu.tx.signer, &action.function, &action.args),
        b"Contract" => execute_contract_call(ctx, db, txu.tx.signer, &action.function, &action.args),
        contract if contract.len() == 48 => {
            execute_wasm_call(ctx, db, &call_env, contract, &action.function, &action.args)
        }
        _ => ("invalid_contract".to_string(), vec![]),
    };

    (error, logs, ctx.mutations(), ctx.mutations_reverse(), ctx.mutations_gas(), ctx.mutations_gas_reverse())
}

fn execute_epoch_call(
    ctx: &mut crate::consensus::kv::ApplyCtx,
    db: &RocksDb,
    env: &crate::bic::epoch::CallEnv,
    function: &str,
    args: &[Vec<u8>],
) -> (String, Vec<String>) {
    parse_epoch_call(function, args)
        .and_then(|call| crate::bic::epoch::Epoch.call(ctx, call, env, db).map_err(|e| e.to_string()))
        .map(|_| ("ok".to_string(), vec![]))
        .unwrap_or_else(|e| (e, vec![]))
}

fn execute_coin_call(
    ctx: &mut crate::consensus::kv::ApplyCtx,
    db: &RocksDb,
    caller: [u8; 48],
    function: &str,
    args: &[Vec<u8>],
) -> (String, Vec<String>) {
    let env = crate::bic::coin::CallEnv { account_caller: caller };
    crate::bic::coin::call(ctx, db, function, &env, args)
        .map(|_| ("ok".to_string(), vec![]))
        .unwrap_or_else(|e| (e.to_string(), vec![]))
}

fn execute_contract_call(
    ctx: &mut crate::consensus::kv::ApplyCtx,
    db: &RocksDb,
    caller: [u8; 48],
    function: &str,
    args: &[Vec<u8>],
) -> (String, Vec<String>) {
    let env = crate::bic::contract::CallEnv { account_caller: caller };
    crate::bic::contract::call(ctx, db, function, &env, args)
        .map(|_| ("ok".to_string(), vec![]))
        .unwrap_or_else(|e| (e.to_string(), vec![]))
}

fn execute_wasm_call(
    ctx: &mut crate::consensus::kv::ApplyCtx,
    db: &RocksDb,
    env: &crate::bic::epoch::CallEnv,
    contract: &[u8],
    function: &str,
    args: &[Vec<u8>],
) -> (String, Vec<String>) {
    let contract_pk: [u8; 48] = contract.try_into().expect("contract len checked");

    // Handle attached tokens BEFORE WASM execution (regular mutations)
    if !env.attached_symbol.is_empty() && !env.attached_amount.is_empty() {
        let amount_str = String::from_utf8_lossy(&env.attached_amount);
        let amount = amount_str.parse::<i128>().unwrap_or(0);
        if amount > 0 {
            let symbol_suffix = format!(":{}", String::from_utf8_lossy(&env.attached_symbol));
            let signer_key = crate::utils::misc::build_key_with_suffix(
                b"bic:coin:balance:",
                &env.tx_signer,
                symbol_suffix.as_bytes(),
            );
            let contract_key =
                crate::utils::misc::build_key_with_suffix(b"bic:coin:balance:", &contract_pk, symbol_suffix.as_bytes());
            ctx.increment(db, &signer_key, -amount);
            ctx.increment(db, &contract_key, amount);
        }
    }

    // Execute WASM (regular mutations)
    match crate::bic::contract::bytecode(ctx, db, &contract_pk) {
        Some(wasm_bytes) => {
            match crate::wasm::runtime::execute(env, db, ctx.clone(), &wasm_bytes, function, args) {
                Ok(result) => {
                    // Save regular mutations and switch to gas context
                    let muts = ctx.mutations();
                    let muts_rev = ctx.mutations_reverse();
                    ctx.save_to_gas_and_restore(vec![], vec![]); // clear and prepare gas context

                    // Charge gas (gas mutations)
                    let exec_used = (result.exec_used * 100) as i128;
                    let signer_key =
                        crate::utils::misc::build_key_with_suffix(b"bic:coin:balance:", &env.tx_signer, b":AMA");
                    ctx.use_gas_context(true);
                    ctx.increment(db, &signer_key, -exec_used);

                    if env.entry_epoch >= 295 {
                        let half_exec_cost = exec_used / 2;
                        let entry_signer_key =
                            crate::utils::misc::build_key_with_suffix(b"bic:coin:balance:", &env.entry_signer, b":AMA");
                        let zero_pubkey = [0u8; 48];
                        let burn_key =
                            crate::utils::misc::build_key_with_suffix(b"bic:coin:balance:", &zero_pubkey, b":AMA");
                        ctx.increment(db, &entry_signer_key, half_exec_cost);
                        ctx.increment(db, &burn_key, half_exec_cost);
                    } else {
                        let entry_signer_key =
                            crate::utils::misc::build_key_with_suffix(b"bic:coin:balance:", &env.entry_signer, b":AMA");
                        ctx.increment(db, &entry_signer_key, exec_used);
                    }
                    ctx.use_gas_context(false);

                    // Restore regular mutations
                    ctx.save_to_gas_and_restore(muts, muts_rev);

                    ("ok".to_string(), result.logs)
                }
                Err(e) => (e.to_string(), vec![]),
            }
        }
        None => ("contract_not_found".to_string(), vec![]),
    }
}

fn parse_epoch_call(function: &str, args: &[Vec<u8>]) -> Result<crate::bic::epoch::EpochCall, String> {
    use crate::bic::epoch::EpochCall;

    match function {
        "submit_sol" => Ok(EpochCall::SubmitSol { sol: args.first().ok_or("missing sol arg")?.clone() }),
        "set_emission_address" => {
            let addr_bytes = args.first().ok_or("missing address arg")?;
            let address = addr_bytes.as_slice().try_into().map_err(|_| "invalid address length")?;
            Ok(EpochCall::SetEmissionAddress { address })
        }
        "slash_trainer" => {
            let epoch_bytes = args.first().ok_or("missing epoch")?;
            let epoch = u32::from_le_bytes(epoch_bytes.get(..4).ok_or("invalid epoch")?.try_into().unwrap()) as u64;
            let malicious_pk = args.get(1).ok_or("missing pk")?.as_slice().try_into().map_err(|_| "invalid pk")?;
            let signature = args.get(2).ok_or("missing signature")?.clone();
            let mask = crate::utils::misc::bitvec_to_bools(args.get(3).ok_or("missing mask")?.clone());
            Ok(EpochCall::SlashTrainer { epoch, malicious_pk, signature, mask, trainers: None })
        }
        _ => Err(format!("unknown function: {}", function)),
    }
}

/// Pre-process transactions: update nonces, deduct gas
fn call_txs_pre(ctx: &mut crate::consensus::kv::ApplyCtx, db: &RocksDb, next_entry: &Entry, txus: &[TxU]) {
    // DON'T reset here - we want to accumulate mutations from the entire entry processing

    let epoch = next_entry.header.height / 100_000;

    // Build keys with raw binary pubkey bytes (NOT base58!)
    let entry_signer_key =
        crate::utils::misc::build_key_with_suffix(b"bic:coin:balance:", &next_entry.header.signer, b":AMA");
    let zero_pubkey = [0u8; 48]; // Burn address: all zeros
    let burn_key = crate::utils::misc::build_key_with_suffix(b"bic:coin:balance:", &zero_pubkey, b":AMA");

    for txu in txus {
        // Update nonce (using raw binary key with pubkey bytes)
        let nonce_key = crate::utils::misc::build_key(b"bic:base:nonce:", &txu.tx.signer);
        // unavoidable: i128 nonce needs to fit in i64 for storage
        let nonce_i64 = i64::try_from(txu.tx.nonce).unwrap_or(i64::MAX);
        ctx.put(db, &nonce_key, &nonce_i64.to_string().into_bytes());

        // Calculate and deduct exec cost using proper unit conversion
        let bytes = txu.tx_encoded.len() + 32 + 96;
        let exec_cost = if epoch >= 295 {
            // New formula (epoch 295+): convert from AMA units to flat coins
            crate::bic::coin::to_cents(1 + bytes as u128 / 1024) as i128
        } else {
            // Old formula (epoch < 295)
            crate::bic::coin::to_cents(3 + bytes as u128 / 256 * 3) as i128
        };

        let signer_balance_key =
            crate::utils::misc::build_key_with_suffix(b"bic:coin:balance:", &txu.tx.signer, b":AMA");
        ctx.increment(db, &signer_balance_key, -exec_cost);

        // Credit entry signer and burn address
        if epoch >= 295 {
            ctx.increment(db, &entry_signer_key, exec_cost / 2);
            ctx.increment(db, &burn_key, exec_cost / 2);
        } else {
            ctx.increment(db, &entry_signer_key, exec_cost);
        }
    }
}

/// Exit logic: segment VR updates and epoch transitions
fn call_exit(ctx: &mut crate::consensus::kv::ApplyCtx, db: &RocksDb, next_entry: &Entry) {
    // DON'T reset here - we want to accumulate mutations from the entire entry processing

    // Update segment VR hash every 1000 blocks
    if next_entry.header.height % 1000 == 0 {
        ctx.put(db, b"bic:epoch:segment_vr_hash", &crate::utils::blake3::hash(&next_entry.header.vr));
    }

    // Epoch transition every 100k blocks
    if next_entry.header.height % 100_000 == 99_999 {
        let env = crate::bic::epoch::CallEnv {
            entry_epoch: next_entry.header.height as u64 / 100_000,
            entry_height: next_entry.header.height as u64,
            entry_signer: next_entry.header.signer,
            entry_vr: next_entry.header.vr.to_vec(),
            tx_hash: vec![],
            tx_signer: [0u8; 48],
            account_caller: [0u8; 48],
            account_current: vec![],
            call_counter: 0,
            call_exec_points: 0,
            call_exec_points_remaining: 0,
            attached_symbol: vec![],
            attached_amount: vec![],
            seed: [0u8; 32],
            seedf64: 0.0,
            readonly: true,
        };
        let _ = crate::bic::epoch::Epoch.next(ctx, db, &env);
    }
}

pub fn apply_entry(
    fabric: &fabric::Fabric,
    config: &crate::config::Config,
    next_entry: &Entry,
) -> Result<Option<Vec<u8>>, Error> {
    let mut ctx = crate::consensus::kv::ApplyCtx::new();

    let curr_h = fabric.get_temporal_height()?.unwrap_or(0);
    if next_entry.header.height != curr_h + 1 {
        return Err(Error::WrongType("invalid_height"));
    }

    // decode transactions
    let mut txus = Vec::new();
    for tx_packed in &next_entry.txs {
        match TxU::from_vanilla(tx_packed) {
            Ok(txu) => txus.push(txu),
            Err(_) => continue,
        }
    }

    // pre-process transactions (nonce updates, gas deduction)
    let db = fabric.db();
    call_txs_pre(&mut ctx, db, next_entry, &txus);
    // Collect mutations from pre-processing AFTER call_txs_pre
    let mut muts = ctx.mutations();
    let mut muts_rev = ctx.mutations_reverse();

    // execute transactions with gas separation (matches Elixir logic)
    let mut tx_results = Vec::new();
    for txu in &txus {
        let (error, logs, m3, m_rev3, m3_gas, m3_gas_rev) = execute_transaction(&mut ctx, db, next_entry, txu);

        if error == "ok" {
            // success: combine regular + gas mutations
            muts.extend(m3);
            muts.extend(m3_gas);
            muts_rev.extend(m_rev3);
            muts_rev.extend(m3_gas_rev);
        } else {
            // failure: revert regular mutations, keep only gas mutations
            crate::consensus::kv::revert(db, &m_rev3);
            muts.extend(m3_gas);
            muts_rev.extend(m3_gas_rev);
        }

        tx_results.push(TxResult { error, logs });
    }

    // Reset mutations before call_exit to avoid collecting the last transaction's mutations twice
    ctx.reset();

    // call exit logic (segment VR updates, epoch transitions)
    call_exit(&mut ctx, db, next_entry);

    // get exit mutations and combine
    let muts_exit = ctx.mutations();
    let muts_exit_rev = ctx.mutations_reverse();
    muts.extend(muts_exit);
    muts_rev.extend(muts_exit_rev);

    // DEBUG: Print mutations for height 34076357 to compare with Elixir
    if next_entry.header.height == 34076357 && false {
        println!("\n=== DEBUG: Rust Mutations for Entry at Height {} ===", next_entry.header.height);
        println!("Entry hash: {}", bs58::encode(&next_entry.hash).into_string());
        println!("Total mutations: {}", muts.len());

        for (idx, m) in muts.iter().enumerate() {
            println!("\n=== Mutation {} ===", idx + 1);
            match &m.op {
                crate::consensus::kv::Op::Put => println!("Op: put"),
                crate::consensus::kv::Op::Delete => println!("Op: delete"),
                crate::consensus::kv::Op::SetBit { .. } => println!("Op: set_bit"),
                crate::consensus::kv::Op::ClearBit { .. } => println!("Op: clear_bit"),
            }
            println!("Key (string): {:?}", String::from_utf8_lossy(&m.key));
            println!("Key (bytes): {:?}", m.key);
            if let Some(val) = &m.value {
                println!("Value: {:?}", String::from_utf8_lossy(val));
                println!("Value (bytes): {:?}", val);
            } else {
                match &m.op {
                    crate::consensus::kv::Op::SetBit { bit_idx, bloom_size } => {
                        println!("Value (bit_idx): {}", bit_idx);
                        println!("Bloom size: {}", bloom_size);
                    }
                    crate::consensus::kv::Op::ClearBit { bit_idx } => {
                        println!("Value (bit_idx): {}", bit_idx);
                    }
                    _ => {}
                }
            }

            // Print ETF encoding of this mutation
            use eetf::{Atom, Binary, FixInteger, Map, Term};
            use std::collections::HashMap;
            let mut map = HashMap::new();
            let op_atom = match &m.op {
                crate::consensus::kv::Op::Put => Atom::from("put"),
                crate::consensus::kv::Op::Delete => Atom::from("delete"),
                crate::consensus::kv::Op::SetBit { .. } => Atom::from("set_bit"),
                crate::consensus::kv::Op::ClearBit { .. } => Atom::from("clear_bit"),
            };
            map.insert(Term::Atom(Atom::from("op")), Term::Atom(op_atom));
            map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: m.key.clone() }));
            match (&m.op, &m.value) {
                (crate::consensus::kv::Op::Put, Some(v)) => {
                    map.insert(Term::Atom(Atom::from("value")), Term::Binary(Binary { bytes: v.clone() }));
                }
                (crate::consensus::kv::Op::SetBit { bit_idx, bloom_size }, _) => {
                    map.insert(
                        Term::Atom(Atom::from("value")),
                        Term::FixInteger(FixInteger { value: *bit_idx as i32 }),
                    );
                    map.insert(
                        Term::Atom(Atom::from("bloomsize")),
                        Term::FixInteger(FixInteger { value: *bloom_size as i32 }),
                    );
                }
                (crate::consensus::kv::Op::ClearBit { bit_idx }, _) => {
                    map.insert(
                        Term::Atom(Atom::from("value")),
                        Term::FixInteger(FixInteger { value: *bit_idx as i32 }),
                    );
                }
                _ => {}
            }
            let term = Term::Map(Map { map });
            let mut etf = Vec::new();
            match term.encode(&mut etf) {
                Ok(_) => {
                    println!("ETF (hex): {}", hex::encode(&etf).to_uppercase());
                }
                Err(e) => println!("ETF encode error: {}", e),
            }
        }

        // Print full mutations list ETF
        println!("\n=== Full ETF of mutations list ===");
        use eetf::{List, Term};
        let mut etf_muts = Vec::new();
        for m in &muts {
            use eetf::{Atom, Binary, FixInteger, Map};
            use std::collections::HashMap;
            let mut map = HashMap::new();
            let op_atom = match &m.op {
                crate::consensus::kv::Op::Put => Atom::from("put"),
                crate::consensus::kv::Op::Delete => Atom::from("delete"),
                crate::consensus::kv::Op::SetBit { .. } => Atom::from("set_bit"),
                crate::consensus::kv::Op::ClearBit { .. } => Atom::from("clear_bit"),
            };
            map.insert(Term::Atom(Atom::from("op")), Term::Atom(op_atom));
            map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: m.key.clone() }));
            match (&m.op, &m.value) {
                (crate::consensus::kv::Op::Put, Some(v)) => {
                    map.insert(Term::Atom(Atom::from("value")), Term::Binary(Binary { bytes: v.clone() }));
                }
                (crate::consensus::kv::Op::SetBit { bit_idx, bloom_size }, _) => {
                    map.insert(
                        Term::Atom(Atom::from("value")),
                        Term::FixInteger(FixInteger { value: *bit_idx as i32 }),
                    );
                    map.insert(
                        Term::Atom(Atom::from("bloomsize")),
                        Term::FixInteger(FixInteger { value: *bloom_size as i32 }),
                    );
                }
                (crate::consensus::kv::Op::ClearBit { bit_idx }, _) => {
                    map.insert(
                        Term::Atom(Atom::from("value")),
                        Term::FixInteger(FixInteger { value: *bit_idx as i32 }),
                    );
                }
                _ => {}
            }
            etf_muts.push(Term::Map(Map { map }));
        }
        let list_term = Term::List(List { elements: etf_muts });
        let mut full_etf = Vec::new();
        match list_term.encode(&mut full_etf) {
            Ok(_) => {
                println!("Length: {} bytes", full_etf.len());
                println!("Hex: {}", hex::encode(&full_etf).to_uppercase());
            }
            Err(e) => println!("Full ETF encode error: {}", e),
        }
    }

    // Hash results + mutations (matching Elixir: ConsensusKV.hash_mutations(l ++ m))
    let mutations_hash = crate::consensus::kv::hash_mutations_with_results(&tx_results, &muts);

    // sign attestation
    let pk = config.get_pk();
    let sk = config.get_sk();
    let attestation = Attestation::sign_with(&pk, &sk, &next_entry.hash, &mutations_hash)?;
    let attestation_packed = attestation.to_etf_bin()?;

    // store my attestation
    fabric.put_attestation(&next_entry.hash, &attestation_packed)?;

    // check if we're a trainer for this height
    let trainers = fabric.trainers_for_height(next_entry.header.height).ok_or(Error::Missing("trainers_for_height"))?;
    let is_trainer = trainers.iter().any(|t| t == &pk);

    // record seen time
    let seen_time = get_unix_millis_now();
    let seen_time_bin = encode_safe_deterministic(&Term::from(eetf::BigInteger { value: seen_time.into() }));
    fabric.put_seen_time(&next_entry.hash, &seen_time_bin)?;

    // update chain tip
    fabric.set_temporal(next_entry)?;

    // store mutations and reverse mutations for potential rewind
    let muts_bin = crate::consensus::kv::mutations_to_etf(&muts);
    fabric.put_muts(&next_entry.hash, &muts_bin)?;
    let muts_rev_bin = crate::consensus::kv::mutations_to_etf(&muts_rev);
    fabric.put_muts_rev(&next_entry.hash, &muts_rev_bin)?;

    // store entry itself and index it (fabric.insert_entry handles both)
    let entry_bin = next_entry.pack()?;
    fabric.insert_entry(&next_entry.hash, next_entry.header.height, next_entry.header.slot, &entry_bin, seen_time)?;

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

    Ok(if is_trainer { Some(attestation_packed) } else { None })
}

pub fn produce_entry(db: &RocksDb, config: &crate::config::Config, slot: u32) -> Result<Entry, Error> {
    let fabric = fabric::Fabric::with_db(db.clone());
    let cur_entry = get_chain_tip_entry(&fabric)?;

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
    let fabric = fabric::Fabric::with_db(db.clone());
    // check if entry exists
    let target_entry = match get_entry_by_hash_local(&fabric, target_hash) {
        Some(e) => e,
        None => return false,
    };

    let target_height = target_entry.header.height;

    // get tip entry
    let tip_entry = match get_chain_tip_entry(&fabric) {
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
    let fabric = fabric::Fabric::with_db(db.clone());
    // check if we found the target
    if current_hash == target_hash {
        return true;
    }

    // get current entry
    let current_entry = match get_entry_by_hash_local(&fabric, current_hash) {
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
    let fabric = fabric::Fabric::with_db(db.clone());
    // check if target is in chain
    if !is_in_chain(db, target_hash) {
        return Ok(false);
    }

    let tip_entry = get_chain_tip_entry(&fabric)?;
    let entry = chain_rewind_internal(db, &tip_entry, target_hash)?;

    // update chain tips
    db.put("sysconf", b"temporal_tip", &entry.hash)?;
    // store temporal_height as ETF term (matches Elixir term: true)
    use crate::utils::safe_etf::encode_safe_deterministic;
    let height_term = encode_safe_deterministic(&Term::from(eetf::FixInteger { value: entry.header.height as i32 }));
    db.put("sysconf", b"temporal_height", &height_term)?;

    // update rooted tip if needed
    if let Ok(Some(rooted_hash)) = get_rooted_tip_hash(&fabric) {
        if fabric.get_entry_raw(&rooted_hash)?.is_none() {
            db.put("sysconf", b"rooted_tip", &entry.hash)?;
        }
    }

    Ok(true)
}

fn chain_rewind_internal(db: &RocksDb, current_entry: &Entry, target_hash: &[u8; 32]) -> Result<Entry, Error> {
    let fabric = fabric::Fabric::with_db(db.clone());
    // revert mutations for current entry - create local context for rewind
    if let Some(m_rev) = chain_muts_rev(&fabric, &current_entry.hash) {
        crate::consensus::kv::revert(db, &m_rev);
    }

    // remove current entry from indices using Fabric methods
    fabric.delete_entry(&current_entry.hash)?;
    fabric.delete_seen_time(&current_entry.hash)?;

    // Match Elixir format: "#{height}:#{hash}" - no padding, raw hash bytes
    let mut height_key = current_entry.header.height.to_string().into_bytes();
    height_key.push(b':');
    height_key.extend_from_slice(&current_entry.hash);
    fabric.delete_entry_by_height(&height_key)?;

    let mut slot_key = current_entry.header.slot.to_string().into_bytes();
    slot_key.push(b':');
    slot_key.extend_from_slice(&current_entry.hash);
    fabric.delete_entry_by_slot(&slot_key)?;

    fabric.delete_consensus(&current_entry.hash)?;
    fabric.delete_attestation(&current_entry.hash)?;

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
        let prev_entry = get_entry_by_hash_local(&fabric, &current_entry.header.prev_hash)
            .ok_or(Error::Missing("prev_entry_in_rewind"))?;
        return Ok(prev_entry);
    }

    // continue rewinding
    let prev_entry = get_entry_by_hash_local(&fabric, &current_entry.header.prev_hash)
        .ok_or(Error::Missing("prev_entry_in_rewind"))?;
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

pub fn best_entry_for_height(fabric: &fabric::Fabric, height: u32) -> Result<Vec<BestEntry>, Error> {
    let rooted_tip = get_rooted_tip_hash(fabric)?.unwrap_or([0u8; 32]);

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
        let trainers = consensus::trainers_for_height(fabric.db(), entry.header.height)
            .ok_or(Error::Missing("trainers_for_height"))?;

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
    let fabric = fabric::Fabric::with_db(db.clone());
    fabric.my_attestation_by_entryhash(entry_hash).ok()?
}

pub fn proc_consensus(fabric: &fabric::Fabric) -> Result<(), Error> {
    let db = fabric.db();

    // Skip processing if no temporal_tip or if entry data not available yet
    if get_chain_tip_entry(fabric).is_err() {
        return Ok(());
    }

    let initial_rooted_hash = get_rooted_tip_hash(fabric)?.unwrap_or([0u8; 32]);

    loop {
        let entry_root = get_rooted_tip_entry(fabric)?;
        let entry_temp = get_chain_tip_entry(fabric)?;
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

        let next_entries = best_entry_for_height(fabric, next_height)?;

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
                let prev_entry = get_rooted_tip_entry(fabric)?;
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
                    info!(
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
    let final_rooted_hash = get_rooted_tip_hash(fabric)?.unwrap_or([0u8; 32]);
    if final_rooted_hash != initial_rooted_hash {
        info!(
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
fn is_quorum_synced_off_by_x(fabric: &fabric::Fabric, x: u32) -> bool {
    // stub implementation - check if rooted tip is close to temporal tip
    let temporal_height = get_chain_height(fabric).unwrap_or(0);
    let rooted_entry = get_rooted_tip_entry(fabric).ok();
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
    let slot_trainer = get_trainer_for_slot(db, entry.header.height, next_slot);

    // check incremental slot
    if (next_slot as i64) - (cur_slot as i64) != 1 {
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
    fabric: &fabric::Fabric,
    config: &crate::config::Config,
    ctx: &crate::Context,
) -> Result<(), Error> {
    // Skip processing if no temporal_tip or if entry data not available yet
    if get_chain_tip_entry(fabric).is_err() {
        return Ok(());
    }

    let softfork_settings = get_softfork_settings();
    let db = fabric.db();

    // use a loop instead of tail recursion (Rust doesn't optimize tail calls)
    loop {
        let cur_entry = get_chain_tip_entry(fabric)?;
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
        let attestation_packed = apply_entry(fabric, config, entry)?;

        // TODO: FabricEventGen.event_applied(entry, mutations_hash, muts, logs)
        tracing::info!("Applied entry {} at height {}", bs58::encode(&entry.hash).into_string(), entry.header.height);

        // broadcast attestation if synced and we're a trainer
        if let Some(attestation_packed) = attestation_packed {
            if is_quorum_synced_off_by_x(fabric, 6) {
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
