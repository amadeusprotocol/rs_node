use crate::consensus::doms::attestation::Attestation;
use crate::consensus::doms::entry::Entry;
use crate::consensus::doms::tx::TxU;
use crate::consensus::fabric;
use crate::consensus::fabric::Fabric;
use crate::node::protocol::Protocol;
use crate::utils::bls12_381 as bls;
use crate::utils::misc::{TermExt, bin_to_bitvec, bitvec_to_bin, get_unix_millis_now};
use crate::utils::rocksdb::RocksDb;
use crate::utils::safe_etf::{encode_safe_deterministic, u64_to_term};
use amadeus_runtime::consensus::consensus_apply::ApplyEnv;
use amadeus_runtime::consensus::consensus_kv;
use amadeus_runtime::consensus::consensus_muts::Mutation;
use amadeus_runtime::consensus::unmask_trainers;
use amadeus_utils::constants::{DST_ENTRY, DST_VRF};
use bitvec::prelude::*;
use eetf::{Atom, Binary, Term};
use std::collections::HashMap;
use tracing::{debug, info, warn};

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
    #[error("runtime error: {0}")]
    Runtime(&'static str),
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

/// Consensus message holding aggregated attestation for an entry and a particular
/// mutations_hash. Mask denotes which trainers signed the aggregate.
#[derive(Debug, Clone, PartialEq)]
pub struct Consensus {
    pub entry_hash: [u8; 32],
    pub mutations_hash: [u8; 32],
    pub mask: BitVec<u8, Msb0>,
    pub agg_sig: [u8; 96],
}

impl Consensus {
    /// Decode from ETF map; supported keys: entry_hash, mutations_hash, mask (bitvec), aggsig
    pub fn from_etf_bin(bin: &[u8]) -> Result<Self, Error> {
        let map = Term::decode(bin)?.get_term_map().ok_or(Error::WrongType("consensus map"))?;
        let entry_hash = map.get_binary("entry_hash").ok_or(Error::Missing("entry_hash"))?;
        let mutations_hash = map.get_binary("mutations_hash").ok_or(Error::Missing("mutations_hash"))?;
        // No mask binary means all trainers have signed - we make it as empty bitvec
        let mask = map.get_binary::<Vec<u8>>("mask").map(|bytes| bin_to_bitvec(bytes)).unwrap_or(BitVec::new());
        let agg_sig = map.get_binary("aggsig").ok_or(Error::Missing("aggsig"))?;
        Ok(Self { entry_hash, mutations_hash, mask, agg_sig })
    }

    /// Encode into an ETF map with deterministic field set (Elixir Map.take and term_to_binary)
    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("entry_hash")), Term::from(Binary { bytes: self.entry_hash.to_vec() }));
        m.insert(Term::Atom(Atom::from("mutations_hash")), Term::from(Binary { bytes: self.mutations_hash.to_vec() }));
        if self.mask.count_ones() < self.mask.len() {
            m.insert(Term::Atom(Atom::from("mask")), Term::from(Binary { bytes: bitvec_to_bin(&self.mask) }));
        }
        m.insert(Term::Atom(Atom::from("aggsig")), Term::from(Binary { bytes: self.agg_sig.to_vec() }));
        let term = Term::from(eetf::Map { map: m });
        let mut out = Vec::new();
        term.encode(&mut out)?;
        Ok(out)
    }
}

pub fn chain_muts_rev(fabric: &fabric::Fabric, hash: &[u8; 32]) -> Option<Vec<Mutation>> {
    let bin = fabric.get_muts_rev(hash).ok()??;
    mutations_from_etf(&bin).ok()
}

pub fn chain_muts(fabric: &fabric::Fabric, hash: &[u8; 32]) -> Option<Vec<Mutation>> {
    let bin = fabric.get_muts(hash).ok()??;
    mutations_from_etf(&bin).ok()
}

#[derive(Debug, Clone)]
pub struct TxResult {
    pub error: String,
    pub logs: Vec<String>,
}

impl TxResult {
    /// Convert TxResult to ETF term matching Elixir format: %{error: :ok, logs: []}
    pub fn to_term(&self) -> Term {
        let mut map = HashMap::new();

        // error field as atom
        map.insert(Term::Atom(Atom::from("error")), Term::Atom(Atom::from(self.error.as_str())));

        // logs field as list of binaries
        let logs_terms: Vec<Term> =
            self.logs.iter().map(|log| Term::from(Binary { bytes: log.as_bytes().to_vec() })).collect();
        map.insert(Term::Atom(Atom::from("logs")), Term::from(eetf::List { elements: logs_terms }));

        Term::from(eetf::Map { map })
    }
}

/// Execute a single transaction, routing to the appropriate contract handler
/// Returns (error, logs, mutations, mutations_reverse)
fn execute_transaction(
    env: &mut ApplyEnv,
    _db: &RocksDb,
    _next_entry: &Entry,
    txu: &TxU,
) -> (String, Vec<String>, Vec<Mutation>, Vec<Mutation>) {
    let action = match txu.tx.actions.first() {
        Some(a) => a,
        None => return ("no_actions".to_string(), vec![], vec![], vec![]),
    };

    env.muts.clear();
    env.muts_rev.clear();

    env.caller_env.tx_hash = txu.hash.to_vec();
    env.caller_env.tx_signer = txu.tx.signer;
    env.caller_env.account_caller = txu.tx.signer.to_vec();
    env.caller_env.attached_symbol = action.attached_symbol.clone().unwrap_or_default();
    env.caller_env.attached_amount = action.attached_amount.clone().unwrap_or_default();

    let (error, logs) = match action.contract.as_slice() {
        b"Epoch" => execute_epoch_call(env, &action.function, &action.args),
        b"Coin" => execute_coin_call(env, &action.function, &action.args),
        b"Contract" => execute_contract_call(env, &action.function, &action.args),
        contract if contract.len() == 48 => {
            // TODO: Re-enable WASM after CallEnv migration
            ("wasm_disabled_temporarily".to_string(), vec![])
        }
        _ => ("invalid_contract".to_string(), vec![]),
    };

    (error, logs, env.muts.clone(), env.muts_rev.clone())
}

fn execute_epoch_call(env: &mut ApplyEnv, function: &str, args: &[Vec<u8>]) -> (String, Vec<String>) {
    parse_epoch_call(function, args)
        .and_then(|call| crate::bic::epoch::Epoch.call(env, call).map_err(|e| e.to_string()))
        .map(|_| ("ok".to_string(), vec![]))
        .unwrap_or_else(|e| (e, vec![]))
}

fn execute_coin_call(env: &mut ApplyEnv, function: &str, args: &[Vec<u8>]) -> (String, Vec<String>) {
    crate::bic::coin::call(env, function, args)
        .map(|_| ("ok".to_string(), vec![]))
        .unwrap_or_else(|e| (e.to_string(), vec![]))
}

fn execute_contract_call(env: &mut ApplyEnv, function: &str, args: &[Vec<u8>]) -> (String, Vec<String>) {
    crate::bic::contract::call(env, function, args)
        .map(|_| ("ok".to_string(), vec![]))
        .unwrap_or_else(|e| (e.to_string(), vec![]))
}

// TODO: Re-enable after WASM module migration
#[allow(dead_code, unused_variables)]
fn execute_wasm_call(
    _apply_env: &mut ApplyEnv,
    _db: &RocksDb,
    _contract: &[u8],
    _function: &str,
    _args: &[Vec<u8>],
) -> (String, Vec<String>) {
    // WASM execution temporarily disabled during bic module migration
    ("wasm_disabled_temporarily".to_string(), vec![])
}

// Helper function to convert old Mutation type to new Mutation type
#[allow(dead_code)]
fn convert_old_mutation_to_new(old: &crate::kv::MutationLegacy) -> Mutation {
    use crate::kv::Op;
    match &old.op {
        Op::Put => {
            Mutation::Put { op: b"put".to_vec(), key: old.key.clone(), value: old.value.clone().unwrap_or_default() }
        }
        Op::Delete => Mutation::Delete { op: b"delete".to_vec(), key: old.key.clone() },
        Op::SetBit { bit_idx, bloom_size } => Mutation::SetBit {
            op: b"set_bit".to_vec(),
            key: old.key.clone(),
            value: *bit_idx as u64,
            bloomsize: *bloom_size as u64,
        },
        Op::ClearBit { bit_idx } => {
            Mutation::ClearBit { op: b"clear_bit".to_vec(), key: old.key.clone(), value: *bit_idx as u64 }
        }
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
            let mask = crate::utils::misc::bin_to_bitvec(args.get(3).ok_or("missing mask")?.clone());
            Ok(EpochCall::SlashTrainer { epoch, malicious_pk, signature, mask, trainers: None })
        }
        _ => Err(format!("unknown function: {}", function)),
    }
}

/// Pre-process transactions: update nonces, deduct gas
fn call_txs_pre(env: &mut ApplyEnv, next_entry: &Entry, txus: &[TxU]) -> Result<(), &'static str> {
    // DON'T reset here - we want to accumulate mutations from the entire entry processing

    let epoch = next_entry.header.height / 100_000;

    let entry_signer_key = crate::utils::misc::bcat(&[b"bic:coin:balance:", &next_entry.header.signer, b":AMA"]);
    let burn_address_key = crate::utils::misc::bcat(&[b"bic:coin:balance:", &crate::bic::coin::BURN_ADDRESS, b":AMA"]);

    for txu in txus {
        let nonce_key = crate::utils::misc::bcat(&[b"bic:base:nonce:", &txu.tx.signer]);
        let nonce_i64 = i64::try_from(txu.tx.nonce).unwrap_or(i64::MAX);
        consensus_kv::kv_put(env, &nonce_key, &nonce_i64.to_string().into_bytes())?;

        let bytes = txu.tx_encoded.len() + 32 + 96;
        let exec_cost = if epoch >= 295 {
            crate::bic::coin::to_cents((1 + bytes / 1024) as i128)
        } else {
            crate::bic::coin::to_cents((3 + bytes / 256 * 3) as i128)
        };

        let signer_balance_key = crate::utils::misc::bcat(&[b"bic:coin:balance:", &txu.tx.signer, b":AMA"]);
        consensus_kv::kv_increment(env, &signer_balance_key, -exec_cost)?;

        consensus_kv::kv_increment(env, &entry_signer_key, exec_cost / 2)?;
        consensus_kv::kv_increment(env, &burn_address_key, exec_cost / 2)?;
    }
    Ok(())
}

// Helper functions for Mutation type

/// Revert mutations
fn revert_mutations(db: &RocksDb, muts_rev: &[Mutation]) {
    for m in muts_rev {
        match m {
            Mutation::Put { key, value, .. } => {
                let _ = db.put("contractstate", key, value);
            }
            Mutation::Delete { key, .. } => {
                let _ = db.delete("contractstate", key);
            }
            Mutation::SetBit { key, value, .. } => {
                // implement set_bit logic similar to old version
                let _ = db.put("contractstate", key, &value.to_le_bytes());
            }
            Mutation::ClearBit { key, value, .. } => {
                // implement clear_bit logic similar to old version
                let _ = db.put("contractstate", key, &value.to_le_bytes());
            }
        }
    }
}

/// Convert Mutation type to ETF
fn mutations_to_etf(muts: &[Mutation]) -> Vec<u8> {
    use crate::utils::safe_etf::{encode_safe_deterministic, u64_to_term};
    use eetf::{Atom, Binary, List, Map, Term};
    use std::collections::HashMap;

    let mut etf_list = Vec::new();

    for m in muts {
        let mut map = HashMap::new();

        match m {
            Mutation::Put { op: _, key, value } => {
                map.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from("put")));
                map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: key.clone() }));
                map.insert(Term::Atom(Atom::from("value")), Term::Binary(Binary { bytes: value.clone() }));
            }
            Mutation::Delete { op: _, key } => {
                map.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from("delete")));
                map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: key.clone() }));
            }
            Mutation::SetBit { op: _, key, value, bloomsize } => {
                map.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from("set_bit")));
                map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: key.clone() }));
                map.insert(Term::Atom(Atom::from("value")), u64_to_term(*value));
                map.insert(Term::Atom(Atom::from("bloomsize")), u64_to_term(*bloomsize));
            }
            Mutation::ClearBit { op: _, key, value } => {
                map.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from("clear_bit")));
                map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: key.clone() }));
                map.insert(Term::Atom(Atom::from("value")), u64_to_term(*value));
            }
        }

        etf_list.push(Term::Map(Map { map }));
    }

    let list = Term::List(List { elements: etf_list });
    encode_safe_deterministic(&list)
}

/// Convert Mutation to legacy format for testing
pub fn mutation_to_legacy(m: &Mutation) -> crate::kv::MutationLegacy {
    match m {
        Mutation::Put { key, value, .. } => {
            crate::kv::MutationLegacy { op: crate::kv::Op::Put, key: key.clone(), value: Some(value.clone()) }
        }
        Mutation::Delete { key, .. } => {
            crate::kv::MutationLegacy { op: crate::kv::Op::Delete, key: key.clone(), value: None }
        }
        Mutation::SetBit { key, value, bloomsize, .. } => crate::kv::MutationLegacy {
            op: crate::kv::Op::SetBit { bit_idx: *value as u32, bloom_size: *bloomsize as u32 },
            key: key.clone(),
            value: None,
        },
        Mutation::ClearBit { key, value, .. } => crate::kv::MutationLegacy {
            op: crate::kv::Op::ClearBit { bit_idx: *value as u32 },
            key: key.clone(),
            value: None,
        },
    }
}

fn mutations_from_etf(bin: &[u8]) -> Result<Vec<Mutation>, Error> {
    use crate::utils::misc::TermExt;
    use eetf::{Atom, Term};

    let term = Term::decode(bin).map_err(|_| Error::WrongType("invalid_etf"))?;
    let list = match &term {
        Term::List(l) => &l.elements,
        _ => return Err(Error::WrongType("not_list")),
    };

    let mut muts = Vec::new();
    for elem in list {
        let map = match elem {
            Term::Map(m) => &m.map,
            _ => return Err(Error::WrongType("not_map")),
        };

        let op = map
            .get(&Term::Atom(Atom::from("op")))
            .and_then(|t| match t {
                Term::Atom(a) => Some(a),
                _ => None,
            })
            .ok_or(Error::Missing("op"))?;

        match op.name.as_str() {
            "put" => {
                let key = map
                    .get(&Term::Atom(Atom::from("key")))
                    .and_then(|t| t.get_binary())
                    .ok_or(Error::Missing("key"))?
                    .to_vec();
                let value = map
                    .get(&Term::Atom(Atom::from("value")))
                    .and_then(|t| t.get_binary())
                    .ok_or(Error::Missing("value"))?
                    .to_vec();
                muts.push(Mutation::Put { op: vec![], key, value });
            }
            "delete" => {
                let key = map
                    .get(&Term::Atom(Atom::from("key")))
                    .and_then(|t| t.get_binary())
                    .ok_or(Error::Missing("key"))?
                    .to_vec();
                muts.push(Mutation::Delete { op: vec![], key });
            }
            "set_bit" => {
                let key = map
                    .get(&Term::Atom(Atom::from("key")))
                    .and_then(|t| t.get_binary())
                    .ok_or(Error::Missing("key"))?
                    .to_vec();
                let value = map
                    .get(&Term::Atom(Atom::from("value")))
                    .and_then(|t| t.get_integer())
                    .map(|i| i as u64)
                    .ok_or(Error::Missing("value"))?;
                let bloomsize = map
                    .get(&Term::Atom(Atom::from("bloomsize")))
                    .and_then(|t| t.get_integer())
                    .map(|i| i as u64)
                    .ok_or(Error::Missing("bloomsize"))?;
                muts.push(Mutation::SetBit { op: vec![], key, value, bloomsize });
            }
            "clear_bit" => {
                let key = map
                    .get(&Term::Atom(Atom::from("key")))
                    .and_then(|t| t.get_binary())
                    .ok_or(Error::Missing("key"))?
                    .to_vec();
                let value = map
                    .get(&Term::Atom(Atom::from("value")))
                    .and_then(|t| t.get_integer())
                    .map(|i| i as u64)
                    .ok_or(Error::Missing("value"))?;
                muts.push(Mutation::ClearBit { op: vec![], key, value });
            }
            _ => return Err(Error::WrongType("unknown_op")),
        }
    }

    Ok(muts)
}

/// Exit logic: segment VR updates and epoch transitions
fn call_exit(env: &mut ApplyEnv, next_entry: &Entry, db: &RocksDb) -> Result<(), &'static str> {
    // seed random (matches Elixir: seed_random(env.entry_vr, "", "", ""))
    let vr = next_entry.header.vr.to_vec();
    let seed_hash = crate::utils::blake3::hash(&vr);
    env.caller_env.seed = seed_hash.to_vec();
    // extract f64 from first 8 bytes of seed_hash in little-endian
    let seedf64 = f64::from_le_bytes(seed_hash[0..8].try_into().unwrap_or([0u8; 8]));
    env.caller_env.seedf64 = seedf64;

    // Update segment VR hash every 1000 blocks
    if next_entry.header.height % 1000 == 0 {
        consensus_kv::kv_put(env, b"bic:epoch:segment_vr_hash", &crate::utils::blake3::hash(&next_entry.header.vr))?;
    }

    // Epoch transition every 100k blocks
    if next_entry.header.height % 100_000 == 99_999 {
        // Update caller_env for epoch transition (readonly mode)
        env.caller_env.readonly = true;
        env.caller_env.tx_hash = vec![];
        env.caller_env.tx_signer = [0u8; 48];
        env.caller_env.account_caller = vec![];
        env.caller_env.call_exec_points = 0;
        env.caller_env.call_exec_points_remaining = 0;
        env.caller_env.attached_symbol = vec![];
        env.caller_env.attached_amount = vec![];
        let _ = crate::bic::epoch::Epoch.next(env, db);
    }
    Ok(())
}

pub fn apply_entry(
    fabric: &Fabric,
    config: &crate::config::Config,
    next_entry: &Entry,
) -> Result<Option<Vec<u8>>, Error> {
    let Some(curr_h) = fabric.get_temporal_height().ok().flatten() else {
        return Err(Error::Missing("temporal_height"));
    };

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

    // Create transaction and ApplyEnv
    let db = fabric.db();
    let txn = db.begin_transaction()?;
    let entry_vr_b3 = crate::utils::blake3::hash(&next_entry.header.vr);
    let mut env = amadeus_runtime::consensus::consensus_apply::make_apply_env(
        txn,
        "contractstate".to_string(),
        &next_entry.header.signer,
        &next_entry.header.prev_hash,
        next_entry.header.slot,
        next_entry.header.prev_slot as u64,
        next_entry.header.height,
        next_entry.header.height / 100_000,
        &next_entry.header.vr,
        &entry_vr_b3,
        &next_entry.header.dr,
    );

    // pre-process transactions (nonce updates, gas deduction)
    call_txs_pre(&mut env, next_entry, &txus).map_err(Error::Runtime)?;
    // Collect mutations from pre-processing AFTER call_txs_pre
    let mut muts = env.muts.clone();
    let mut muts_rev = env.muts_rev.clone();

    // execute transactions (mutations include gas)
    let mut tx_results = Vec::new();
    for txu in &txus {
        let (error, logs, m3, m_rev3) = execute_transaction(&mut env, db, next_entry, txu);

        if error == "ok" {
            // success: add all mutations
            muts.extend(m3);
            muts_rev.extend(m_rev3);
        } else {
            // failure: revert mutations
            revert_mutations(db, &m_rev3);
        }

        tx_results.push(TxResult { error, logs });
    }

    // print actual logs when running tests
    #[cfg(test)]
    {
        println!("\n=== Actual logs from apply_entry (tx_results) ===");
        for (i, result) in tx_results.iter().enumerate() {
            println!("Transaction {} result: error={:?}, logs={:?}", i, result.error, result.logs);
        }
    }

    // Clear mutations before call_exit to avoid collecting the last transaction's mutations twice
    env.muts.clear();
    env.muts_rev.clear();

    // call exit logic (segment VR updates, epoch transitions)
    call_exit(&mut env, next_entry, db).map_err(Error::Runtime)?;

    // get exit mutations and combine
    let muts_exit = env.muts.clone();
    let muts_exit_rev = env.muts_rev.clone();
    muts.extend(muts_exit);
    muts_rev.extend(muts_exit_rev);

    // Hash results + mutations (matching Elixir: ConsensusKV.hash_mutations(l ++ m))
    let mutations_hash = crate::consensus::kv::hash_mutations_with_results(&tx_results, &muts);

    // Commit the transaction
    env.txn.commit().map_err(crate::utils::rocksdb::Error::from)?;

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

    let seen_time_ms = get_unix_millis_now();
    let seen_time_bin = encode_safe_deterministic(&Term::from(eetf::BigInteger { value: seen_time_ms.into() }));
    fabric.put_seen_time(&next_entry.hash, &seen_time_bin)?;

    // update chain tip
    fabric.set_temporal_hash_height(next_entry)?;

    // store mutations and reverse mutations for potential rewind
    let muts_bin = mutations_to_etf(&muts);
    fabric.put_muts(&next_entry.hash, &muts_bin)?;
    let muts_rev_bin = mutations_to_etf(&muts_rev);
    fabric.put_muts_rev(&next_entry.hash, &muts_rev_bin)?;

    // store entry itself and index it (fabric.insert_entry handles both)
    let entry_bin = next_entry.pack()?;
    fabric.insert_entry(
        &next_entry.hash,
        next_entry.header.height,
        next_entry.header.slot,
        &entry_bin,
        seen_time_ms,
    )?;

    // store transactions with results
    for (tx_packed, result) in next_entry.txs.iter().zip(tx_results.iter()) {
        if let Ok(txu) = TxU::from_vanilla(tx_packed) {
            // Store tx_account_nonce index: signer:nonce -> tx_hash
            let nonce_padded = format!("{:020}", txu.tx.nonce);
            let key = format!("{}:{}", bs58::encode(&txu.tx.signer).into_string(), nonce_padded);
            fabric.put_tx_account_nonce(key.as_bytes(), &txu.hash)?;

            // find position in entry binary for indexing
            let entry_bin = next_entry.pack()?;
            if let Some(pos) = entry_bin.windows(tx_packed.len()).position(|w| w == tx_packed) {
                // Build tx metadata map matching Elixir structure
                let mut tx_meta = HashMap::new();
                tx_meta.insert(
                    Term::Atom(Atom::from("entry_hash")),
                    Term::from(Binary { bytes: next_entry.hash.to_vec() }),
                );
                tx_meta.insert(Term::Atom(Atom::from("result")), result.to_term());
                tx_meta.insert(Term::Atom(Atom::from("index_start")), u64_to_term(pos as u64));
                tx_meta.insert(Term::Atom(Atom::from("index_size")), u64_to_term(tx_packed.len() as u64));

                let term = Term::Map(eetf::Map { map: tx_meta });
                let tx_meta_bin = encode_safe_deterministic(&term);
                fabric.put_tx_metadata(&txu.hash, &tx_meta_bin)?;
            }
        }
    }

    Ok(if is_trainer { Some(attestation_packed) } else { None })
}

pub fn produce_entry(fabric: &fabric::Fabric, config: &crate::config::Config, slot: u64) -> Result<Entry, Error> {
    let cur_entry = fabric.get_temporal_entry()?.ok_or(Error::Missing("temporal_tip"))?;

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
    let signature = bls::sign(&sk, &header_hash, DST_ENTRY)?;

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

pub fn chain_rewind(fabric: &fabric::Fabric, target_hash: &[u8; 32]) -> Result<bool, Error> {
    // check if target is in chain
    if !fabric.is_in_chain(target_hash) {
        return Ok(false);
    }

    let tip_entry = fabric.get_temporal_entry()?.ok_or(Error::Missing("temporal_tip"))?;
    let entry = chain_rewind_internal(fabric, &tip_entry, target_hash)?;

    // update chain tips
    let db = fabric.db();
    db.put("sysconf", b"temporal_tip", &entry.hash)?;
    // store temporal_height as ETF term (matches Elixir term: true)
    let height_term = encode_safe_deterministic(&u64_to_term(entry.header.height));
    db.put("sysconf", b"temporal_height", &height_term)?;

    // update rooted tip if needed
    if let Ok(Some(rooted_hash)) = fabric.get_rooted_hash() {
        if fabric.get_entry_raw(&rooted_hash)?.is_none() {
            db.put("sysconf", b"rooted_tip", &entry.hash)?;
        }
    }

    Ok(true)
}

fn chain_rewind_internal(
    fabric: &fabric::Fabric,
    current_entry: &Entry,
    target_hash: &[u8; 32],
) -> Result<Entry, Error> {
    let mut current = current_entry.clone();

    loop {
        // get previous entry BEFORE unapplying (since unapply deletes the entry from DB)
        let prev_entry = fabric.get_entry_by_hash(&current.header.prev_hash);

        // revert mutations for current entry
        let db = fabric.db();
        if let Some(m_rev_new) = chain_muts_rev(fabric, &current.hash) {
            let m_rev_legacy: Vec<_> = m_rev_new.iter().map(mutation_to_legacy).collect();
            crate::kv::revert(db, &m_rev_legacy[..]);
        }

        // remove current entry from indices
        fabric.delete_entry(&current.hash)?;
        fabric.delete_seen_time(&current.hash)?;

        let mut height_key = current.header.height.to_string().into_bytes();
        height_key.push(b':');
        height_key.extend_from_slice(&current.hash);
        fabric.delete_entry_by_height(&height_key)?;

        let mut slot_key = current.header.slot.to_string().into_bytes();
        slot_key.push(b':');
        slot_key.extend_from_slice(&current.hash);
        fabric.delete_entry_by_slot(&slot_key)?;

        fabric.delete_consensus(&current.hash)?;
        fabric.delete_attestation(&current.hash)?;

        // remove transaction indices
        for tx_packed in &current.txs {
            if let Ok(txu) = TxU::from_vanilla(tx_packed) {
                fabric.delete_tx_metadata(&txu.hash)?;
                let nonce_padded = format!("{:020}", txu.tx.nonce);
                let key = format!("{}:{}", bs58::encode(&txu.tx.signer).into_string(), nonce_padded);
                fabric.delete_tx_account_nonce(key.as_bytes())?;
            }
        }

        // if we just unapplied the target, return its parent
        if current.hash == *target_hash {
            return prev_entry.ok_or(Error::Missing("prev_entry_in_rewind"));
        }

        // continue rewinding
        current = prev_entry.ok_or(Error::Missing("prev_entry_in_rewind"))?;
    }
}

pub fn best_by_weight(
    trainers: &[[u8; 48]],
    consensuses: &HashMap<[u8; 32], Consensus>,
) -> (Option<[u8; 32]>, Option<f64>, Option<Consensus>) {
    let max_score = trainers.len() as f64;
    let mut best: Option<([u8; 32], f64, Consensus)> = None;

    for (k, v) in consensuses.iter() {
        // calculate weighted score
        let trainers_signed = if v.mask.is_empty() { trainers.to_vec() } else { unmask_trainers(&v.mask, trainers) };
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
pub struct ScoredEntry {
    pub entry: Entry,
    pub mutations_hash: Option<[u8; 32]>,
    pub score: Option<f64>,
}

pub fn best_entry_for_height(fabric: &fabric::Fabric, height: u64) -> Result<Vec<ScoredEntry>, Error> {
    let rooted_tip = fabric.get_rooted_hash()?.unwrap_or([0u8; 32]);

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
        let trainers = fabric.trainers_for_height(entry.header.height).ok_or(Error::Missing("trainers_for_height"))?;

        // get best consensus for this entry
        let (mutations_hash, score, _consensus) = fabric.best_consensus_by_entryhash(&trainers, &entry.hash)?;

        if mutations_hash.is_some() {
            entries.push(ScoredEntry { entry, mutations_hash, score });
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

pub fn proc_consensus(fabric: &fabric::Fabric) -> Result<(), Error> {
    // Skip processing if no temporal_tip or if entry data not available yet
    if fabric.get_temporal_entry()?.is_none() {
        return Ok(());
    }

    let initial_rooted_hash = fabric.get_rooted_hash()?.unwrap_or([0u8; 32]);

    loop {
        let entry_root = fabric.get_rooted_entry()?.ok_or(Error::Missing("rooted_tip"))?;
        let entry_temp = fabric.get_temporal_entry()?.ok_or(Error::Missing("temporal_tip"))?;
        let height_root = entry_root.header.height;
        let height_temp = entry_temp.header.height;

        // nothing more to process
        if height_root >= height_temp {
            debug!(
                "proc_consensus: rooted_height {} >= temporal_height {}, nothing to process",
                height_root, height_temp
            );
            break;
        }

        let next_height = height_root + 1;

        let next_entries = best_entry_for_height(fabric, next_height)?;

        let Some(best_entry_info) = next_entries.first() else {
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
        let my_attestation = fabric.my_attestation_by_entryhash(&best_entry.hash).ok().flatten();

        match my_attestation {
            None => {
                // softfork: consensus chose entry we don't have applied, need to rewind
                warn!(
                    "proc_consensus softfork: rewind to entry {} height {}",
                    bs58::encode(&best_entry.hash).into_string(),
                    best_entry.header.height
                );
                // get best entry for previous height to rewind to
                let rewind_hash = match best_entry_for_height(fabric, next_height - 1)?.first() {
                    Some(prev_best) => prev_best.entry.hash,
                    None => fabric.get_temporal_hash()?.unwrap_or([0u8; 32]),
                };
                chain_rewind(fabric, &rewind_hash)?;
                continue; // retry proc_consensus
            }
            Some(my_att) => {
                if mutations_hash != my_att.mutations_hash {
                    warn!(
                        "EMERGENCY: state divergence at height {}: our mutations {} != consensus {}, halting",
                        best_entry.header.height,
                        bs58::encode(&my_att.mutations_hash).into_string(),
                        bs58::encode(&mutations_hash).into_string()
                    );
                    // rewind to previous height before halting
                    if let Some(prev_best) = best_entry_for_height(fabric, next_height - 1)?.first() {
                        let _ = chain_rewind(fabric, &prev_best.entry.hash);
                    }
                    break;
                } else {
                    // mutations match, safe to root the entry
                    info!(
                        "proc_consensus: rooting entry {} at height {} with score {:.2}",
                        bs58::encode(&best_entry.hash).into_string(),
                        best_entry.header.height,
                        score
                    );
                    fabric.set_rooted_hash_height(best_entry)?;
                    // continue loop to process next height
                }
            }
        }
    }

    // check if rooted tip changed
    let final_rooted_hash = fabric.get_rooted_hash()?.unwrap_or([0u8; 32]);
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
    if ceh.slot as i64 != neh.prev_slot {
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
fn is_quorum_synced_off_by_x(fabric: &fabric::Fabric, x: u64) -> bool {
    // stub implementation - check if rooted tip is close to temporal tip
    let temporal_height = fabric.get_temporal_height().ok().flatten().unwrap_or(0);
    let rooted_height = fabric.get_rooted_height().ok().flatten().unwrap_or(0);

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

pub async fn proc_entries(fabric: &Fabric, config: &crate::config::Config, ctx: &crate::Context) -> Result<(), Error> {
    // Skip processing if no temporal_tip or if entry data not available yet
    fabric.get_temporal_entry()?.ok_or(Error::Missing("temporal_tip"))?;

    let softfork_settings = get_softfork_settings();

    // use a loop instead of tail recursion (Rust doesn't optimize tail calls)
    loop {
        let cur_entry = fabric.get_temporal_entry()?.ok_or(Error::Missing("temporal_tip"))?;
        let cur_slot = cur_entry.header.slot;
        let next_height = cur_entry.header.height + 1;

        // filter and sort entries using functional pipeline matching Elixir logic
        let mut next_entries: Vec<Entry> = fabric
            .entries_by_height(next_height as u64)?
            .into_iter()
            .filter_map(|entry_bin| {
                Entry::unpack(&entry_bin)
                    .map_err(|e| warn!("failed to unpack entry at height {}: {}", next_height, e))
                    .ok()
            })
            .filter(|next_entry| {
                // all conditions must be true (matches Elixir cond logic)
                fabric.validate_entry_slot_trainer(next_entry, cur_slot)
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
        debug!("Applied entry {} at height {}", bs58::encode(&entry.hash).into_string(), entry.header.height);

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
        warn!("failed to decode attestation for broadcast");
        return;
    };

    let event_att = EventAttestation { attestation };

    if let Ok(peers) = ctx.node_peers.get_all().await {
        for peer in peers {
            let _ = event_att.send_to_with_metrics(ctx, peer.ip).await;
        }
    }

    for seed_ip in &ctx.config.seed_ips {
        let _ = event_att.send_to_with_metrics(ctx, *seed_ip).await;
    }

    debug!("Broadcasted attestation for entry {}", bs58::encode(entry_hash).into_string());
}
