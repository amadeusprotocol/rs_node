// Consensus application environment and entry processing
use amadeus_utils::rocksdb::{BoundColumnFamily, MultiThreaded, Transaction, TransactionDB};
use std::collections::HashMap;
use std::panic::panic_any;
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
}

pub struct CallerEnv {
    pub readonly: bool,
    pub seed: Vec<u8>,
    pub seedf64: f64,
    pub entry_signer: [u8; 48],
    pub entry_prev_hash: [u8; 32],
    pub entry_slot: u64,
    pub entry_prev_slot: u64,
    pub entry_height: u64,
    pub entry_epoch: u64,
    pub entry_vr: Vec<u8>,
    pub entry_vr_b3: [u8; 32],
    pub entry_dr: [u8; 32],
    pub tx_hash: Vec<u8>,
    pub tx_signer: [u8; 48],
    pub account_origin: Vec<u8>,
    pub account_caller: Vec<u8>,
    pub account_current: Vec<u8>,
    pub attached_symbol: Vec<u8>,
    pub attached_amount: Vec<u8>,
    pub call_counter: u32,
    pub call_exec_points: u64,
    pub call_exec_points_remaining: u64,
}

pub fn make_caller_env(
    entry_signer: &[u8; 48],
    entry_prev_hash: &[u8; 32],
    entry_slot: u64,
    entry_prev_slot: u64,
    entry_height: u64,
    entry_epoch: u64,
    entry_vr: &[u8; 96],
    entry_vr_b3: &[u8; 32],
    entry_dr: &[u8; 32],
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
        tx_signer: [0u8; 48],
        account_origin: vec![],
        account_caller: vec![],
        account_current: vec![],
        attached_symbol: vec![],
        attached_amount: vec![],
        call_counter: 0,
        call_exec_points: 10_000_000,
        call_exec_points_remaining: 10_000_000,
    }
}

pub fn make_apply_env<'db>(
    txn_wrapper: amadeus_utils::rocksdb::RocksDbTxn<'db>,
    cf_name: String,
    entry_signer: &[u8; 48],
    entry_prev_hash: &[u8; 32],
    entry_slot: u64,
    entry_prev_slot: u64,
    entry_height: u64,
    entry_epoch: u64,
    entry_vr: &[u8; 96],
    entry_vr_b3: &[u8; 32],
    entry_dr: &[u8; 32],
) -> ApplyEnv<'db> {
    // Extract inner transaction and get column family handle
    let inner = txn_wrapper.inner();
    let cf_handle = inner.db.cf_handle(&cf_name).expect(&format!("Column family '{}' not found", cf_name));

    // SAFETY: We're extracting the transaction from the wrapper
    // The wrapper must be consumed/leaked to avoid double-free
    // This is a temporary solution - proper fix would restructure the API
    let (raw_txn, raw_db) = unsafe {
        let inner_ptr = inner as *const amadeus_utils::rocksdb::SimpleTransaction<'db>;
        let txn = std::ptr::read(&(*inner_ptr).txn);
        let db = (*inner_ptr).db;
        (txn, db)
    };
    std::mem::forget(txn_wrapper); // Prevent double-free

    ApplyEnv {
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
        cf: cf_handle,
        txn: raw_txn,
        muts_final: Vec::new(),
        muts_final_rev: Vec::new(),
        muts: Vec::new(),
        muts_gas: Vec::new(),
        muts_rev: Vec::new(),
        muts_rev_gas: Vec::new(),
        result_log: Vec::new(),
    }
}

pub fn valid_bic_action(contract: Vec<u8>, function: Vec<u8>) -> bool {
    let c = contract.as_slice();
    let f = function.as_slice();

    (c == b"Epoch" || c == b"Coin" || c == b"Contract")
        && (f == b"submit_sol"
            || f == b"transfer"
            || f == b"set_emission_address"
            || f == b"slash_trainer"
            || f == b"deploy"
            || f == b"create_and_mint"
            || f == b"mint"
            || f == b"pause")
}
