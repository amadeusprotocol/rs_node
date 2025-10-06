use crate::consensus::doms::tx::{TxAction, TxU};
use crate::consensus::kv;
use crate::consensus::kv::Mutation;
use crate::utils::misc::pk_hex;
use crate::utils::rocksdb::RocksDb;
use blake3;
use std::cell::RefCell;
use std::collections::HashMap;

/// Compute execution cost in cents
///
/// Returns integer cost in cents
pub fn exec_cost_from_len(tx_encoded_len: usize) -> u64 {
    let bytes = tx_encoded_len + 32 + 96;
    let cost_units = 3 + (bytes / 256) * 3; // integer division
    // cost in cents
    crate::bic::coin::to_cents(cost_units as u64)
}

/// Blake3-based deterministic seed
///
/// Returns the 32-byte seed (little-endian interpretation is up to the caller where needed)
pub fn seed_random(vr: &[u8], txhash: &[u8], action_index: &[u8], call_cnt: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(vr);
    hasher.update(txhash);
    hasher.update(action_index);
    hasher.update(call_cnt);
    let hash = hasher.finalize();
    *hash.as_bytes()
}

/// Extract a deterministic f64 from the first 8 bytes of the seed (little-endian)
///
/// Note: random bytes mapped to f64 may produce NaN or infinities
pub fn seed_to_f64(seed: &[u8; 32]) -> f64 {
    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&seed[0..8]);
    f64::from_le_bytes(first8)
}

pub fn exec_cost(_epoch: u32, txu: &TxU) -> u64 {
    exec_cost_from_len(txu.tx_encoded.len())
}

/// KV mutations are not implemented yet
pub fn call_txs_pre_parallel_build_sol_cache(txus: &[TxU]) -> std::collections::HashMap<[u8; 32], bool> {
    use crate::bic::sol;
    use std::collections::HashMap;

    let mut cache: HashMap<[u8; 32], bool> = HashMap::new();

    for txu in txus {
        // find a.submit_sol with at least one arg (sol binary)
        if let Some(action) = txu.tx.actions.first()
            && action.function == "submit_sol"
            && let Some(first_arg) = action.args.first()
        {
            let hash = blake3::hash(first_arg);
            let hash32: [u8; 32] = *hash.as_bytes();
            let valid = sol::verify_with_hash(first_arg, &hash32).unwrap_or(false);
            cache.insert(hash32, valid);
        }
    }

    cache
}

// TODO: implement following
// - call_exit(env)
// - call_tx_actions(env, txu)

// thread-local cache
thread_local! {
    static SOL_VERIFIED_CACHE: RefCell<HashMap<[u8; 32], bool>> = RefCell::new(HashMap::new());
}

pub fn set_sol_verified_cache(cache: HashMap<[u8; 32], bool>) {
    SOL_VERIFIED_CACHE.with(|c| {
        *c.borrow_mut() = cache;
    });
}

pub fn get_sol_verified_cache() -> HashMap<[u8; 32], bool> {
    SOL_VERIFIED_CACHE.with(|c| c.borrow().clone())
}

fn key_balance(pk: &[u8], symbol: &str) -> String {
    format!("bic:coin:balance:{}:{}", pk_hex(pk), symbol)
}

/// Note: This function does not handle VRF/epoch-dependent sol verification flags; the
/// bic::sol::verify_with_hash handles epoch branches internally
pub fn call_txs_pre_parallel(db: &RocksDb, entry_signer: &[u8; 48], txus: &[TxU]) -> (Vec<Mutation>, Vec<Mutation>) {
    // for each txu: set nonce and move exec cost from signer to entry_signer in AMA
    for txu in txus {
        // nonce
        let key_nonce = format!("bic:base:nonce:{}", pk_hex(&txu.tx.signer));
        kv::kv_put(db, &key_nonce, txu.tx.nonce.to_string().as_bytes());

        // exec cost in cents
        let exec_cost = exec_cost(0, txu) as i64;
        // charge signer
        let key_signer = key_balance(&txu.tx.signer, "AMA");
        kv::kv_increment(db, &key_signer, -exec_cost);
        // reward entry signer
        let key_entry = key_balance(entry_signer, "AMA");
        kv::kv_increment(db, &key_entry, exec_cost);
    }

    // build and store Sol verification cache
    let cache = call_txs_pre_parallel_build_sol_cache(txus);
    set_sol_verified_cache(cache);

    (kv::mutations(), kv::mutations_reverse())
}

/// Handle epoch exit operations - matches Elixir BIC.Base.call_exit/1  
pub fn call_exit(db: &RocksDb, env: &crate::bic::epoch::CallEnv) -> (Vec<Mutation>, Vec<Mutation>) {
    kv::reset(); // Clear mutations - matches Process.delete(:mutations) etc

    // Seed randomness - matches Elixir seed_random(env.entry_vr, "", "", "")
    let _seed = seed_random(&env.entry_vr, b"", b"", b"");

    // Thank you come again - increment AMA by to_flat(1) for entry_signer
    let key_entry_signer = key_balance(&env.entry_signer, "AMA");
    let flat_reward = crate::bic::coin::to_flat(1) as i64;
    kv::kv_increment(db, &key_entry_signer, flat_reward);

    // Update epoch segment VR hash every 1000 heights
    if env.entry_height % 1000 == 0 {
        let vr_hash = blake3::hash(&env.entry_vr);
        kv::kv_put(db, "bic:epoch:segment_vr_hash", vr_hash.as_bytes());
    }

    // Handle special heights
    match env.entry_height {
        0 => {
            // Genesis: set first trainer and POP
            // For now, store trainers as simple list (can be made ETF-compatible later)
            let trainers = vec![env.entry_signer];
            let serialized =
                bincode::encode_to_vec(&trainers, bincode::config::standard()).expect("failed to serialize trainers");
            kv::kv_put(db, "bic:epoch:trainers:0", &serialized);

            // Store POP for genesis signer (placeholder implementation)
            let pop_key = format!("bic:epoch:pop:{}", bs58::encode(&env.entry_signer).into_string());
            kv::kv_put(db, &pop_key, b"genesis_pop_placeholder");
        }
        h if h % 100_000 == 99_999 => {
            // Next epoch transition - would call BIC.Epoch.next(env) in Elixir
            // For now, this is a placeholder for epoch transition logic
            // TODO: Implement BIC.Epoch.next equivalent when available
        }
        _ => {} // No special handling
    }

    (kv::mutations(), kv::mutations_reverse())
}

/// Execute transaction actions - matches Elixir BIC.Base.call_tx_actions/2
/// Returns (mutations, mutations_reverse, mutations_gas, mutations_gas_reverse, result)
pub fn call_tx_actions(
    db: &RocksDb,
    env: &crate::bic::epoch::CallEnv,
    txu: &TxU,
) -> (Vec<Mutation>, Vec<Mutation>, Vec<Mutation>, Vec<Mutation>, ActionResult) {
    kv::reset(); // Clear all mutations - matches Process.delete calls

    let result = execute_action_safe(db, env, txu);

    // Return all mutation types and result
    (kv::mutations(), kv::mutations_reverse(), vec![], vec![], result)
}

#[derive(Debug, Clone)]
pub struct ActionResult {
    pub error: String,
    pub logs: Option<Vec<String>>,
    pub exec_used: Option<u64>,
    pub result: Option<Vec<u8>>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
struct WasmCallResult {
    pub exec_used: Option<u64>,
    pub logs: Option<Vec<String>>,
    pub return_value: Option<Vec<u8>>,
}

impl Default for ActionResult {
    fn default() -> Self {
        ActionResult {
            error: "system".to_string(),
            logs: None,
            exec_used: None,
            result: None,
            reason: Some("unknown".to_string()),
        }
    }
}

fn execute_action_safe(db: &RocksDb, env: &crate::bic::epoch::CallEnv, txu: &TxU) -> ActionResult {
    // Get first action (Rust validation ensures exactly 1 action)
    let action = match txu.tx.actions.first() {
        Some(action) => action,
        None => {
            return ActionResult {
                error: "no_actions".to_string(),
                logs: None,
                exec_used: None,
                result: None,
                reason: None,
            };
        }
    };

    // Check if contract is a valid BLS public key (WASM contract)
    if crate::utils::bls12_381::validate_public_key(&action.contract).is_ok() {
        // WASM contract call
        execute_wasm_contract(db, env, txu, action)
    } else {
        // Built-in module call
        execute_builtin_module(db, env, action)
    }
}

fn execute_wasm_contract(db: &RocksDb, env: &crate::bic::epoch::CallEnv, txu: &TxU, action: &TxAction) -> ActionResult {
    // Check if contract has bytecode
    let contract_key: [u8; 48] = match action.contract.as_slice().try_into() {
        Ok(key) => key,
        Err(_) => {
            return ActionResult {
                error: "system".to_string(),
                logs: None,
                exec_used: None,
                result: None,
                reason: Some("invalid_contract_key_size".to_string()),
            };
        }
    };
    let bytecode = match crate::bic::contract::bytecode(db, &contract_key) {
        Some(bc) => bc,
        None => {
            return ActionResult {
                error: "system".to_string(),
                logs: None,
                exec_used: None,
                result: None,
                reason: Some("account_has_no_bytecode".to_string()),
            };
        }
    };

    // Generate seed for randomness
    let seed = seed_random(&env.entry_vr, &env.tx_hash, b"0", env.call_counter.to_string().as_bytes());
    let _seedf64 = seed_to_f64(&seed);

    // Handle attachments (if present)
    if let (Some(symbol), Some(amount_bytes)) = (&action.attached_symbol, &action.attached_amount) {
        let amount = match std::str::from_utf8(amount_bytes).ok().and_then(|s| s.parse::<i64>().ok()) {
            Some(amt) if amt > 0 => amt,
            _ => {
                return ActionResult {
                    error: "invalid_attached_amount".to_string(),
                    logs: None,
                    exec_used: None,
                    result: None,
                    reason: None,
                };
            }
        };

        // Check sufficient balance
        let symbol_str = std::str::from_utf8(symbol).unwrap_or("INVALID");
        let signer_balance = crate::consensus::chain_balance_symbol(db, &txu.tx.signer, symbol_str);
        if amount as u64 > signer_balance {
            return ActionResult {
                error: "attached_amount_insufficient_funds".to_string(),
                logs: None,
                exec_used: None,
                result: None,
                reason: None,
            };
        }

        // Transfer attached amount
        let contract_balance_key = key_balance(&contract_key, symbol_str);
        let signer_balance_key = key_balance(&txu.tx.signer, symbol_str);
        kv::kv_increment(db, &contract_balance_key, amount);
        kv::kv_increment(db, &signer_balance_key, -amount);
    }

    // Call WASM runtime
    let wasm_result = match crate::wasm::runtime::execute(env, db, &bytecode, &action.function, &action.args) {
        Ok(result) => WasmCallResult {
            exec_used: Some(result.exec_used),
            logs: Some(result.logs),
            return_value: result.return_value,
        },
        Err(_) => WasmCallResult { exec_used: Some(0), logs: None, return_value: None },
    };

    // Handle gas accounting for execution cost
    if let Some(exec_used) = wasm_result.exec_used {
        let gas_cost = (exec_used * 100) as i64;
        let entry_key = key_balance(&env.entry_signer, "AMA");
        let signer_key = key_balance(&txu.tx.signer, "AMA");
        kv::kv_increment(db, &entry_key, gas_cost);
        kv::kv_increment(db, &signer_key, -gas_cost);
    }

    ActionResult { error: "ok".to_string(), logs: None, exec_used: wasm_result.exec_used, result: None, reason: None }
}

fn execute_builtin_module(_db: &RocksDb, env: &crate::bic::epoch::CallEnv, action: &TxAction) -> ActionResult {
    // Generate seed for randomness
    let _seed = seed_random(&env.entry_vr, &env.tx_hash, b"0", b"");

    // Validate built-in contract and function
    let contract_str = std::str::from_utf8(&action.contract).unwrap_or("");
    if !["Epoch", "Coin", "Contract"].contains(&contract_str) {
        return ActionResult {
            error: "invalid_bic".to_string(),
            logs: None,
            exec_used: None,
            result: None,
            reason: None,
        };
    }

    if !["submit_sol", "transfer", "set_emission_address", "slash_trainer", "deploy"]
        .contains(&action.function.as_str())
    {
        return ActionResult {
            error: "invalid_function".to_string(),
            logs: None,
            exec_used: None,
            result: None,
            reason: None,
        };
    }

    // Route to appropriate module (placeholder - would need actual implementations)
    match (contract_str, action.function.as_str()) {
        ("Epoch", "submit_sol") => {
            // Would call BIC.Epoch.call(:submit_sol, env, action.args)
            // For now, return success
            ActionResult { error: "ok".to_string(), logs: None, exec_used: Some(0), result: None, reason: None }
        }
        ("Coin", "transfer") => {
            // Would call BIC.Coin.call(:transfer, env, action.args)
            // For now, return success
            ActionResult { error: "ok".to_string(), logs: None, exec_used: Some(0), result: None, reason: None }
        }
        ("Contract", "deploy") => {
            // Would call BIC.Contract.call(:deploy, env, action.args)
            // For now, return success
            ActionResult { error: "ok".to_string(), logs: None, exec_used: Some(0), result: None, reason: None }
        }
        _ => {
            // Other valid combinations
            ActionResult { error: "ok".to_string(), logs: None, exec_used: Some(0), result: None, reason: None }
        }
    }
}
