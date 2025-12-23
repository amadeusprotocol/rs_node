// Consensus application environment and entry processing
use crate::Result;
use amadeus_utils::rocksdb::{BoundColumnFamily, MultiThreaded, RocksDb, Transaction, TransactionDB};
use amadeus_utils::{Hash, PublicKey, Signature};
use std::collections::HashMap;
use std::sync::Arc;

use crate::consensus::consensus_muts;

pub struct ApplyEnv<'db> {
    pub caller_env: CallerEnv,
    pub cf: Arc<BoundColumnFamily<'db>>,
    pub txn: Transaction<'db, TransactionDB<MultiThreaded>>,
    pub muts_final: Vec<consensus_muts::Mutation>,
    pub muts_final_rev: Vec<consensus_muts::Mutation>,
    pub muts: Vec<consensus_muts::Mutation>,
    pub muts_gas: Vec<consensus_muts::Mutation>,
    pub muts_rev: Vec<consensus_muts::Mutation>,
    pub muts_rev_gas: Vec<consensus_muts::Mutation>,
    pub result_log: Vec<HashMap<&'static str, &'static str>>,
    pub exec_left: i128,
    pub logs: Vec<Vec<u8>>,
    pub logs_size: usize,
}

pub struct CallerEnv {
    pub readonly: bool,
    pub seed: Vec<u8>,
    pub seedf64: f64,
    pub entry_signer: PublicKey,
    pub entry_prev_hash: Hash,
    pub entry_slot: u64,
    pub entry_prev_slot: u64,
    pub entry_height: u64,
    pub entry_epoch: u64,
    pub entry_vr: Vec<u8>,
    pub entry_vr_b3: Hash,
    pub entry_dr: Hash,
    pub tx_hash: Vec<u8>,
    pub tx_signer: PublicKey,
    pub account_origin: Vec<u8>,
    pub account_caller: Vec<u8>,
    pub account_current: Vec<u8>,
    pub attached_symbol: Vec<u8>,
    pub attached_amount: Vec<u8>,
    pub call_counter: u32,
    pub call_exec_points: u64,
    pub call_exec_points_remaining: u64,
    pub call_return_value: Vec<u8>,
    pub tx_nonce: u64,
}

pub fn make_caller_env(
    entry_signer: &PublicKey,
    entry_prev_hash: &Hash,
    entry_slot: u64,
    entry_prev_slot: u64,
    entry_height: u64,
    entry_epoch: u64,
    entry_vr: &Signature,
    entry_vr_b3: &Hash,
    entry_dr: &Hash,
) -> CallerEnv {
    CallerEnv {
        readonly: false,
        seed: entry_dr.to_vec(),
        seedf64: 0.5,
        entry_signer: *entry_signer,
        entry_prev_hash: *entry_prev_hash,
        entry_slot,
        entry_prev_slot,
        entry_height,
        entry_epoch,
        entry_vr: entry_vr.to_vec(),
        entry_vr_b3: *entry_vr_b3,
        entry_dr: *entry_dr,
        tx_hash: vec![],
        tx_signer: PublicKey::new([0u8; 48]),
        account_origin: vec![],
        account_caller: vec![],
        account_current: vec![],
        attached_symbol: vec![],
        attached_amount: vec![],
        call_counter: 0,
        call_exec_points: 10_000_000,
        call_exec_points_remaining: 10_000_000,
        call_return_value: vec![],
        tx_nonce: 0,
    }
}

pub fn make_apply_env<'db>(
    db: &'db RocksDb,
    cf_name: &str,
    entry_signer: &PublicKey,
    entry_prev_hash: &Hash,
    entry_slot: u64,
    entry_prev_slot: u64,
    entry_height: u64,
    entry_epoch: u64,
    entry_vr: &Signature,
    entry_vr_b3: &Hash,
    entry_dr: &Hash,
) -> Result<ApplyEnv<'db>> {
    Ok(ApplyEnv {
        caller_env: make_caller_env(
            entry_signer,
            entry_prev_hash,
            entry_slot,
            entry_prev_slot,
            entry_height,
            entry_epoch,
            entry_vr,
            entry_vr_b3,
            entry_dr,
        ),
        cf: db.inner.cf_handle(cf_name).ok_or("cf_handle_failed")?,
        txn: db.begin_transaction(),
        muts_final: Vec::new(),
        muts_final_rev: Vec::new(),
        muts: Vec::new(),
        muts_gas: Vec::new(),
        muts_rev: Vec::new(),
        muts_rev_gas: Vec::new(),
        result_log: Vec::new(),
        exec_left: 0,
        logs: Vec::new(),
        logs_size: 0,
    })
}

pub fn valid_bic_action(contract: Vec<u8>, function: Vec<u8>) -> bool {
    let c = contract.as_slice();
    let f = function.as_slice();

    (c == b"Epoch" || c == b"Coin" || c == b"Contract")
        && (f == b"submit_sol"
            || f == b"set_emission_address"
            || f == b"slash_trainer"
            || f == b"transfer"
            || f == b"deploy")
}

pub fn call_bic(env: &mut ApplyEnv, contract: Vec<u8>, function: Vec<u8>, args: Vec<Vec<u8>>, _attached_symbol: Option<Vec<u8>>, _attached_amount: Option<Vec<u8>>) {
    use crate::consensus::bic::{coin, contract as contract_bic, epoch, protocol};
    use crate::consensus::consensus_kv;

    match (contract.as_slice(), function.as_slice()) {
        (b"Epoch", b"submit_sol") => {
            consensus_kv::exec_budget_decr(env, protocol::COST_PER_SOL);
            let _ = epoch::call_submit_sol(env, args);
        },
        (b"Epoch", b"set_emission_address") => { let _ = epoch::call_set_emission_address(env, args); },
        (b"Epoch", b"slash_trainer") => { let _ = epoch::call_slash_trainer(env, args); },
        (b"Coin", b"transfer") => { let _ = coin::call_transfer(env, args); },
        (b"Contract", b"deploy") => {
            consensus_kv::exec_budget_decr(env, protocol::COST_PER_DEPLOY);
            let _ = contract_bic::call_deploy(env, args);
        },
        _ => std::panic::panic_any("invalid_bic_action")
    }
}

pub fn call_wasmvm(env: &mut ApplyEnv, contract: Vec<u8>, function: Vec<u8>, args: Vec<Vec<u8>>, _attached_symbol: Option<Vec<u8>>, _attached_amount: Option<Vec<u8>>) -> Vec<u8> {
    use crate::consensus::bic::wasm;
    use crate::consensus::consensus_kv;

    let contract_key = crate::bcat(&[b"account:", contract.as_slice(), b":bytecode"]);
    let wasm_bytes = match consensus_kv::kv_get(env, &contract_key) {
        Ok(Some(bytes)) => bytes,
        _ => return b"contract_not_found".to_vec(),
    };

    let function_name = String::from_utf8_lossy(&function).to_string();
    wasm::call_contract(env, &wasm_bytes, function_name, args)
}
