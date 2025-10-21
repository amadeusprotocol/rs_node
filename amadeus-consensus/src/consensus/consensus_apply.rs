use crate::{
    TransactionDB, MultiThreaded, TransactionOptions, WriteOptions,
    Transaction, BoundColumnFamily,
};

use crate::consensus::bic::protocol;
use crate::consensus::consensus_kv;
use crate::consensus::consensus_muts;
use std::collections::HashMap;

pub struct CallerEnv {
    pub readonly: bool,
    pub seed: Option<Vec<u8>>,
    pub seedf64: f64,
    pub entry_signer: [u8; 48],
    pub entry_prev_hash: [u8; 32],
    pub entry_slot: u64,
    pub entry_prev_slot: u64,
    pub entry_height: u64,
    pub entry_epoch: u64,
    pub entry_vr: [u8; 96],
    pub entry_vr_b3: [u8; 32],
    pub entry_dr: [u8; 32],
    pub tx_index: u64,
    pub tx_signer: [u8; 48],
    pub tx_nonce: u64,
    pub tx_hash: [u8; 32],
    pub account_origin: Vec<u8>,
    pub account_caller: Vec<u8>,
    pub account_current: Vec<u8>,
    pub attached_symbol: String,
    pub attached_amount: String,
    pub call_counter: u32,
    pub call_exec_points: u64,
    pub call_exec_points_remaining: u64,
}

pub fn make_caller_env(
    entry_signer: &[u8; 48], entry_prev_hash: &[u8; 32],
    entry_slot: u64, entry_prev_slot: u64, entry_height: u64, entry_epoch: u64,
    entry_vr: &[u8; 96], entry_vr_b3: &[u8; 32], entry_dr: &[u8; 32],
) -> CallerEnv {
    CallerEnv {
        readonly: false,
        seed: None,
        seedf64: 1.0,
        entry_signer: *entry_signer,
        entry_prev_hash: *entry_prev_hash,
        entry_slot: entry_slot,
        entry_prev_slot: entry_prev_slot,
        entry_height: entry_height,
        entry_epoch: entry_epoch,
        entry_vr: *entry_vr,
        entry_vr_b3: *entry_vr_b3,
        entry_dr: *entry_dr,
        tx_index: 0,
        tx_signer: [0u8; 48],
        tx_nonce: 0,
        tx_hash: [0u8; 32],
        account_origin: Vec::new(),
        account_caller: Vec::new(),
        account_current: Vec::new(),
        attached_symbol: String::new(),
        attached_amount: String::new(),
        call_counter: 0,
        call_exec_points: 10_000_000,
        call_exec_points_remaining: 10_000_000,
    }
}

pub struct ApplyEnv<'db> {
    pub caller_env: CallerEnv,
    pub cf: std::sync::Arc<BoundColumnFamily<'db>>,
    pub txn: Transaction<'db, TransactionDB<MultiThreaded>>,
    pub muts: Vec<consensus_muts::Mutation>,
    pub muts_gas: Vec<consensus_muts::Mutation>,
    pub muts_rev: Vec<consensus_muts::Mutation>,
    pub muts_rev_gas: Vec<consensus_muts::Mutation>,
    pub result_log: Vec<HashMap<&'static str, &'static str>>,
}

pub fn make_apply_env<'db>(txn: Transaction<'db, TransactionDB<MultiThreaded>>, cf: std::sync::Arc<BoundColumnFamily<'db>>,
    entry_signer: &[u8; 48], entry_prev_hash: &[u8; 32],
    entry_slot: u64, entry_prev_slot: u64, entry_height: u64, entry_epoch: u64,
    entry_vr: &[u8; 96], entry_vr_b3: &[u8; 32], entry_dr: &[u8; 32],
) -> ApplyEnv<'db> {
    ApplyEnv {
        caller_env: make_caller_env(entry_signer, entry_prev_hash, entry_slot, entry_prev_slot, entry_height, entry_epoch, entry_vr, entry_vr_b3, entry_dr),
        cf: cf,
        txn: txn,
        muts: Vec::new(),
        muts_gas: Vec::new(),
        muts_rev: Vec::new(),
        muts_rev_gas: Vec::new(),
        result_log: Vec::new(),
    }
}

pub fn set_apply_env_tx<'db>(env: &mut ApplyEnv<'db>, tx_hash: &[u8; 32], tx_signer: &[u8; 48], tx_nonce: u64) {
    env.caller_env.tx_hash = *tx_hash;
    env.caller_env.tx_nonce = tx_nonce;
    env.caller_env.tx_signer = *tx_signer;
    env.caller_env.account_origin = tx_signer.to_vec();
}

pub fn apply_entry<'a>(db: &TransactionDB<MultiThreaded>, pk: &[u8], sk: &[u8],
    entry_signer: &[u8; 48], entry_prev_hash: &[u8; 32],
    entry_slot: u64, entry_prev_slot: u64, entry_height: u64, entry_epoch: u64,
    entry_vr: &[u8; 96], entry_vr_b3: &[u8; 32], entry_dr: &[u8; 32],
    txs_packed: Vec<Vec<u8>>, txus: Vec<rustler::Term<'a>>,
) {
    let txn_opts = TransactionOptions::default();
    let write_opts = WriteOptions::default();
    let txn = db.transaction_opt(&write_opts, &txn_opts);
    let cf_h = db.cf_handle("contractstate").unwrap();

    let mut applyenv = make_apply_env(txn, cf_h, entry_signer, entry_prev_hash, entry_slot, entry_prev_slot, entry_height, entry_epoch, entry_vr, entry_vr_b3, entry_dr);

    call_txs_pre_upfront_cost(&mut applyenv, &txus);

    for (i, txu) in txus.into_iter().enumerate() {

        let tx_hash = crate::fixed::<32>(txu.map_get(crate::atoms::hash()).unwrap()).unwrap();
        let tx = txu.map_get(crate::atoms::tx()).unwrap();
        let tx_signer = crate::fixed::<48>(tx.map_get(crate::atoms::signer()).unwrap()).unwrap();
        let tx_nonce = tx.map_get(crate::atoms::nonce()).unwrap().decode::<u64>().unwrap();
        let action = tx.map_get(crate::atoms::actions()).unwrap().decode::<Vec<rustler::Term<'a>>>().unwrap();

        applyenv.caller_env.tx_index = i as u64;
        applyenv.caller_env.tx_hash = tx_hash;
        applyenv.caller_env.tx_signer = tx_signer;
        applyenv.caller_env.tx_nonce = tx_nonce;
        applyenv.caller_env.account_origin = tx_signer.to_vec();
        applyenv.caller_env.account_caller = tx_signer.to_vec();

        match action.first() {
            None => {
                let mut m: HashMap<&'static str, &'static str> = HashMap::new();
                m.insert("error", "no_actions");
                applyenv.result_log.push(m);
            },
            Some(action) => {
                let op = action.map_get(crate::atoms::op()).unwrap().decode::<rustler::Binary>().unwrap().as_slice();
                let contract = action.map_get(crate::atoms::contract()).unwrap().decode::<rustler::Binary>().unwrap().to_vec();
                let function = action.map_get(crate::atoms::function()).unwrap().decode::<rustler::Binary>().unwrap().as_slice();
                let args = action.map_get(crate::atoms::args()).unwrap().decode::<Vec<Vec<u8>>>().unwrap().to_vec();
                let attached_symbol = action.map_get(crate::atoms::attached_symbol()).ok().and_then(|t| t.decode::<Option<Vec<u8>>>().unwrap());
                let attached_amount = action.map_get(crate::atoms::attached_amount()).ok().and_then(|t| t.decode::<Option<Vec<u8>>>().unwrap());

                //applyenv.caller_env.account_current = contract;
                println!("{:?} {:?} {:?} {:?} {:?}", op, contract, function, attached_amount, attached_symbol);
            }
        }
    }


/*
    {m, m_rev, l} = Enum.reduce(Enum.with_index(txus), {m_pre, m_rev_pre, []}, fn({txu, tx_idx}, {m, m_rev, l})->
        #ts_m = :os.system_time(1000)

        {m3, m_rev3, m3_gas, m3_gas_rev, result} = BIC.Base.call_tx_actions(mapenv, txu)
        #IO.inspect {:call_tx, :os.system_time(1000) - ts_m}
        if result[:error] == :ok do
            m = m ++ m3 ++ m3_gas
            m_rev = m_rev ++ m_rev3 ++ m3_gas_rev
            {m, m_rev, l ++ [result]}
        else
            ConsensusKV.revert(m_rev3)
            {m ++ m3_gas, m_rev ++ m3_gas_rev, l ++ [result]}
        end
    end)
*/


}

fn call_txs_pre_upfront_cost<'a>(env: &mut ApplyEnv, txus: &[rustler::Term<'a>]) {
    for txu in txus {
        let tx_encoded = txu.map_get(crate::atoms::tx_encoded()).unwrap().decode::<rustler::Binary>().unwrap().as_slice();
        let tx_hash = crate::fixed::<32>(txu.map_get(crate::atoms::hash()).unwrap()).unwrap();
        let tx = txu.map_get(crate::atoms::tx()).unwrap();
        let tx_signer = crate::fixed::<48>(tx.map_get(crate::atoms::signer()).unwrap()).unwrap();
        let tx_nonce = tx.map_get(crate::atoms::nonce()).unwrap().decode::<u64>().unwrap();

        set_apply_env_tx(env, &tx_hash, &tx_signer, tx_nonce);

        // Update nonce
        consensus_kv::kv_put(env, &crate::bcat(&[b"bic:base:nonce:", &tx_signer]), &tx_nonce.to_string().into_bytes());
        // Deduct tx cost
        let tx_cost = protocol::tx_cost_per_byte(env.caller_env.entry_epoch, tx_encoded.len());
        protocol::pay_cost(env, tx_cost);
    }
}
