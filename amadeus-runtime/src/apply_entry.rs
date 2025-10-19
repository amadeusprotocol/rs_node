use crate::kv::{ApplyCtx, Mutation};
use amadeus_utils::rocksdb::RocksDb;
use amadeus_utils::bls12_381;
use amadeus_utils::constants::DST_ATT;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong height")]
    WrongHeight,
    #[error("invalid transaction")]
    InvalidTransaction,
    #[error("bls error: {0}")]
    Bls(#[from] bls12_381::Error),
    #[error("database error: {0}")]
    Database(#[from] amadeus_utils::rocksdb::Error),
    #[error("encode error")]
    Encode,
}

/// Entry header data needed for transaction execution
#[derive(Debug, Clone)]
pub struct EntryHeader {
    pub height: u64,
    pub epoch: u64,
    pub slot: u64,
    pub prev_slot: i64,
    pub signer: [u8; 48],
    pub prev_hash: [u8; 32],
    pub vr: Vec<u8>,
    pub vr_b3: [u8; 32],
    pub dr: [u8; 32],
    pub hash: [u8; 32],
}

/// Transaction action data
#[derive(Debug, Clone)]
pub struct TxAction {
    pub contract: Vec<u8>,
    pub function: String,
    pub args: Vec<Vec<u8>>,
    pub attached_symbol: Option<Vec<u8>>,
    pub attached_amount: Option<Vec<u8>>,
}

/// Transaction data
#[derive(Debug, Clone)]
pub struct Tx {
    pub signer: [u8; 48],
    pub nonce: u128,
    pub actions: Vec<TxAction>,
}

/// Transaction with hash and signature
#[derive(Debug, Clone)]
pub struct TxU {
    pub tx_encoded: Vec<u8>,
    pub hash: [u8; 32],
    pub signature: [u8; 96],
    pub tx: Tx,
}

/// Transaction execution result
#[derive(Debug, Clone)]
pub struct TxResult {
    pub error: String,
    pub logs: Vec<String>,
}

/// Result of applying an entry
#[derive(Debug, Clone)]
pub struct ApplyEntryResult {
    pub attestation_packed: Vec<u8>,
    pub mutations: Vec<Mutation>,
    pub mutations_reverse: Vec<Mutation>,
    pub mutations_hash: [u8; 32],
    pub tx_results: Vec<TxResult>,
}

/// Apply entry - processes transactions and returns attestation + mutations
///
/// This function ONLY writes to contractstate.
/// All other database writes (insert_entry, put_attestation, etc.) must be done by the caller.
///
/// # Arguments
/// * `db` - RocksDb database (only contractstate will be modified)
/// * `pk` - Trainer public key for signing attestation
/// * `sk` - Trainer secret key for signing attestation
/// * `entry` - Entry header with blockchain metadata
/// * `txus` - List of transactions to process
///
/// # Returns
/// ApplyEntryResult containing:
/// - attestation_packed: Signed attestation bytes
/// - mutations: Forward mutations for contractstate
/// - mutations_reverse: Reverse mutations for rewind
/// - mutations_hash: Hash of mutations for attestation
/// - tx_results: Results of each transaction execution
pub fn apply_entry(
    db: &RocksDb,
    pk: &[u8; 48],
    sk: &[u8; 64],
    entry: &EntryHeader,
    txus: &[TxU],
) -> Result<ApplyEntryResult, Error> {
    let mut ctx = ApplyCtx::new();

    // Pre-process transactions (nonce updates, gas deduction)
    call_txs_pre(&mut ctx, db, entry, txus);

    // Collect mutations from pre-processing
    let mut muts = ctx.mutations();
    let mut muts_rev = ctx.mutations_reverse();

    // Execute transactions with gas separation
    let mut tx_results = Vec::new();
    for txu in txus {
        let (error, logs, m3, m_rev3, m3_gas, m3_gas_rev) = execute_transaction(&mut ctx, db, entry, txu);

        if error == "ok" {
            // success: combine regular + gas mutations
            muts.extend(m3);
            muts.extend(m3_gas);
            muts_rev.extend(m_rev3);
            muts_rev.extend(m3_gas_rev);
        } else {
            // failure: revert regular mutations, keep only gas mutations
            crate::kv::revert(db, &m_rev3);
            muts.extend(m3_gas);
            muts_rev.extend(m3_gas_rev);
        }

        tx_results.push(TxResult { error, logs });
    }

    // Reset mutations before call_exit
    ctx.reset();

    // Call exit logic (segment VR updates, epoch transitions)
    call_exit(&mut ctx, db, entry);

    // Get exit mutations and combine
    let muts_exit = ctx.mutations();
    let muts_exit_rev = ctx.mutations_reverse();
    muts.extend(muts_exit);
    muts_rev.extend(muts_exit_rev);

    // Hash results + mutations
    let mutations_hash = hash_mutations_with_results(&tx_results, &muts);

    // Sign attestation
    let attestation_packed = sign_attestation(pk, sk, &entry.hash, &mutations_hash)?;

    Ok(ApplyEntryResult {
        attestation_packed,
        mutations: muts,
        mutations_reverse: muts_rev,
        mutations_hash,
        tx_results,
    })
}

/// Pre-process transactions: update nonces, deduct gas
fn call_txs_pre(ctx: &mut ApplyCtx, db: &RocksDb, entry: &EntryHeader, txus: &[TxU]) {
    let epoch = entry.epoch;

    // Build keys with raw binary pubkey bytes
    let entry_signer_key = bcat(&[b"bic:coin:balance:", &entry.signer, b":AMA"]);
    let zero_pubkey = [0u8; 48]; // Burn address: all zeros
    let burn_key = bcat(&[b"bic:coin:balance:", &zero_pubkey, b":AMA"]);

    for txu in txus {
        // Update nonce
        let nonce_key = bcat(&[b"bic:base:nonce:", &txu.tx.signer]);
        ctx.put(db, &nonce_key, &txu.tx.nonce.to_string().into_bytes());

        // Calculate and deduct exec cost
        let bytes = txu.tx_encoded.len() + 32 + 96;
        let exec_cost = if epoch >= 295 {
            crate::bic::coin::to_cents(1 + bytes as u128 / 1024) as i128
        } else {
            crate::bic::coin::to_cents(3 + bytes as u128 / 256 * 3) as i128
        };

        let signer_balance_key = bcat(&[b"bic:coin:balance:", &txu.tx.signer, b":AMA"]);
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

/// Execute a single transaction
fn execute_transaction(
    ctx: &mut ApplyCtx,
    db: &RocksDb,
    entry: &EntryHeader,
    txu: &TxU,
) -> (
    String,
    Vec<String>,
    Vec<Mutation>,
    Vec<Mutation>,
    Vec<Mutation>,
    Vec<Mutation>,
) {
    let action = match txu.tx.actions.first() {
        Some(a) => a,
        None => return ("no_actions".to_string(), vec![], vec![], vec![], vec![], vec![]),
    };

    ctx.reset();

    let call_env = crate::bic::epoch::CallEnv {
        entry_epoch: entry.epoch,
        entry_height: entry.height,
        entry_signer: entry.signer,
        entry_vr: entry.vr.clone(),
        tx_hash: txu.hash.to_vec(),
        tx_signer: txu.tx.signer,
        account_caller: txu.tx.signer,
        account_current: vec![],
        call_counter: 0,
        call_exec_points: 10_000_000,
        call_exec_points_remaining: 10_000_000,
        attached_symbol: action.attached_symbol.clone().unwrap_or_default(),
        attached_amount: action.attached_amount.clone().unwrap_or_default(),
        seed: entry.dr,
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
    ctx: &mut ApplyCtx,
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
    ctx: &mut ApplyCtx,
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
    ctx: &mut ApplyCtx,
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
    ctx: &mut ApplyCtx,
    db: &RocksDb,
    env: &crate::bic::epoch::CallEnv,
    contract: &[u8],
    function: &str,
    args: &[Vec<u8>],
) -> (String, Vec<String>) {
    let contract_pk: [u8; 48] = contract.try_into().expect("contract len checked");

    // Handle attached tokens BEFORE WASM execution
    if !env.attached_symbol.is_empty() && !env.attached_amount.is_empty() {
        let amount_str = String::from_utf8_lossy(&env.attached_amount);
        let amount = amount_str.parse::<i128>().unwrap_or(0);
        if amount > 0 {
            let signer_key = bcat(&[b"bic:coin:balance:", &env.tx_signer, b":", &env.attached_symbol]);
            let contract_key = bcat(&[b"bic:coin:balance:", &contract_pk, b":", &env.attached_symbol]);
            ctx.increment(db, &signer_key, -amount);
            ctx.increment(db, &contract_key, amount);
        }
    }

    // Execute WASM
    match crate::bic::contract::bytecode(ctx, db, &contract_pk) {
        Some(wasm_bytes) => {
            match crate::wasm::runtime::execute(env, db, ctx.clone(), &wasm_bytes, function, args) {
                Ok(result) => {
                    // Save regular mutations and switch to gas context
                    let muts = ctx.mutations();
                    let muts_rev = ctx.mutations_reverse();
                    ctx.save_to_gas_and_restore(vec![], vec![]);

                    // Charge gas
                    let exec_used = (result.exec_used * 100) as i128;
                    let signer_key = bcat(&[b"bic:coin:balance:", &env.tx_signer, b":AMA"]);
                    ctx.use_gas_context(true);
                    ctx.increment(db, &signer_key, -exec_used);

                    if env.entry_epoch >= 295 {
                        let half_exec_cost = exec_used / 2;
                        let entry_signer_key = bcat(&[b"bic:coin:balance:", &env.entry_signer, b":AMA"]);
                        let zero_pubkey = [0u8; 48];
                        let burn_key = bcat(&[b"bic:coin:balance:", &zero_pubkey, b":AMA"]);
                        ctx.increment(db, &entry_signer_key, half_exec_cost);
                        ctx.increment(db, &burn_key, half_exec_cost);
                    } else {
                        let entry_signer_key = bcat(&[b"bic:coin:balance:", &env.entry_signer, b":AMA"]);
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
            let mask = amadeus_utils::misc::bin_to_bitvec(args.get(3).ok_or("missing mask")?.clone());
            Ok(EpochCall::SlashTrainer { epoch, malicious_pk, signature, mask, trainers: None })
        }
        _ => Err(format!("unknown function: {}", function)),
    }
}

/// Exit logic: segment VR updates and epoch transitions
fn call_exit(ctx: &mut ApplyCtx, db: &RocksDb, entry: &EntryHeader) {
    // Update segment VR hash every 1000 blocks
    if entry.height % 1000 == 0 {
        ctx.put(db, b"bic:epoch:segment_vr_hash", &amadeus_utils::blake3::hash(&entry.vr));
    }

    // Epoch transition every 100k blocks
    if entry.height % 100_000 == 99_999 {
        let env = crate::bic::epoch::CallEnv {
            entry_epoch: entry.epoch,
            entry_height: entry.height,
            entry_signer: entry.signer,
            entry_vr: entry.vr.clone(),
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

/// Hash mutations with transaction results prepended
fn hash_mutations_with_results(results: &[TxResult], muts: &[Mutation]) -> [u8; 32] {
    use amadeus_utils::safe_etf::{encode_safe_deterministic, u32_to_term};
    use eetf::{Atom, Binary, List, Map, Term};

    let mut etf_list = Vec::new();

    // Add transaction results (error field only, no logs)
    for result in results {
        let mut map = HashMap::new();
        map.insert(Term::Atom(Atom::from("error")), Term::Atom(Atom::from(result.error.as_str())));
        etf_list.push(Term::Map(Map { map }));
    }

    // Add mutations
    for m in muts {
        let mut map = HashMap::new();

        let op_atom = match &m.op {
            crate::kv::Op::Put => Atom::from("put"),
            crate::kv::Op::Delete => Atom::from("delete"),
            crate::kv::Op::SetBit { .. } => Atom::from("set_bit"),
            crate::kv::Op::ClearBit { .. } => Atom::from("clear_bit"),
        };
        map.insert(Term::Atom(Atom::from("op")), Term::Atom(op_atom));
        map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: m.key.clone() }));

        match (&m.op, &m.value) {
            (crate::kv::Op::Put, Some(v)) => {
                map.insert(Term::Atom(Atom::from("value")), Term::Binary(Binary { bytes: v.clone() }));
            }
            (crate::kv::Op::SetBit { bit_idx, bloom_size }, _) => {
                map.insert(Term::Atom(Atom::from("value")), u32_to_term(*bit_idx));
                map.insert(Term::Atom(Atom::from("bloomsize")), u32_to_term(*bloom_size));
            }
            (crate::kv::Op::ClearBit { bit_idx }, _) => {
                map.insert(Term::Atom(Atom::from("value")), u32_to_term(*bit_idx));
            }
            _ => {}
        }

        etf_list.push(Term::Map(Map { map }));
    }

    let list_term = Term::List(List { elements: etf_list });
    let encoded = encode_safe_deterministic(&list_term);
    amadeus_utils::blake3::hash(&encoded)
}

/// Sign attestation
fn sign_attestation(pk: &[u8; 48], sk: &[u8; 64], entry_hash: &[u8; 32], mutations_hash: &[u8; 32]) -> Result<Vec<u8>, Error> {
    use eetf::{Atom, Binary, Map, Term};

    // Build message to sign: entry_hash || mutations_hash
    let mut to_sign = [0u8; 64];
    to_sign[..32].copy_from_slice(entry_hash);
    to_sign[32..].copy_from_slice(mutations_hash);

    // Sign
    let signature = bls12_381::sign(sk, &to_sign, DST_ATT)?;

    // Build attestation map
    let mut att_map = HashMap::new();
    att_map.insert(Term::Atom(Atom::from("entry_hash")), Term::from(Binary { bytes: entry_hash.to_vec() }));
    att_map.insert(Term::Atom(Atom::from("mutations_hash")), Term::from(Binary { bytes: mutations_hash.to_vec() }));
    att_map.insert(Term::Atom(Atom::from("pk")), Term::from(Binary { bytes: pk.to_vec() }));
    att_map.insert(Term::Atom(Atom::from("signature")), Term::from(Binary { bytes: signature.to_vec() }));

    let term = Term::from(Map { map: att_map });
    let mut out = Vec::new();
    term.encode(&mut out).map_err(|_| Error::Encode)?;
    Ok(out)
}

// Helper function for byte concatenation
fn bcat(slices: &[&[u8]]) -> Vec<u8> {
    amadeus_utils::misc::bcat(slices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use amadeus_utils::rocksdb::RocksDb;

    fn create_test_entry() -> EntryHeader {
        EntryHeader {
            height: 100,
            epoch: 0,
            slot: 100,
            prev_slot: 99,
            signer: [1u8; 48],
            prev_hash: [0u8; 32],
            vr: vec![2u8; 96],
            vr_b3: [3u8; 32],
            dr: [4u8; 32],
            hash: [5u8; 32],
        }
    }

    #[tokio::test]
    async fn test_apply_entry_empty() {
        let base = format!("/tmp/test_apply_entry_{}", std::process::id());
        let db = RocksDb::open(base).await.expect("open test db");

        let entry = create_test_entry();
        let pk = [1u8; 48];
        let sk = [2u8; 64];

        let result = apply_entry(&db, &pk, &sk, &entry, &[]).expect("apply entry");

        assert_eq!(result.tx_results.len(), 0);
        assert!(result.attestation_packed.len() > 0);
    }
}
