use super::super::bic::epoch::CallEnv;
use crate::kv;
use crate::wasm::opcodes::{RpcMessage, RpcResponse};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use wasmer::{Function, FunctionEnv, FunctionEnvMut, Instance, Memory, Module, Store, Value, imports};

/// WASM Runtime context shared between host and WASM
pub struct WasmContext {
    pub env: CallEnv,
    pub db: crate::utils::rocksdb::RocksDb,
    pub kv_ctx: Arc<Mutex<kv::ApplyEnvLegacy>>,
    pub logs: Arc<Mutex<Vec<String>>>,
    pub exec_used: Arc<Mutex<u64>>,
    pub rpc_tx: Option<Sender<RpcMessage>>,
    pub rpc_rx: Arc<Mutex<Option<Receiver<RpcResponse>>>>,
    pub rpc_counter: Arc<Mutex<u64>>,
    pub memory: Option<Memory>,
    pub memory_buffer: Arc<Mutex<Vec<u8>>>, // Shared buffer for memory operations
}

impl WasmContext {
    pub fn new(env: CallEnv, db: crate::utils::rocksdb::RocksDb, kv_ctx: kv::ApplyEnvLegacy) -> Self {
        Self {
            env,
            db,
            kv_ctx: Arc::new(Mutex::new(kv_ctx)),
            logs: Arc::new(Mutex::new(Vec::new())),
            exec_used: Arc::new(Mutex::new(0)),
            rpc_tx: None,
            rpc_rx: Arc::new(Mutex::new(None)),
            rpc_counter: Arc::new(Mutex::new(0)),
            memory: None,
            memory_buffer: Arc::new(Mutex::new(Vec::with_capacity(65536))),
        }
    }

    /// Allocate RPC ID
    pub fn next_rpc_id(&self) -> u64 {
        let mut counter = self.rpc_counter.lock().unwrap();
        let id = *counter;
        *counter += 1;
        id
    }

    /// Add execution cost
    pub fn add_exec_cost(&self, cost: u64) {
        let mut exec = self.exec_used.lock().unwrap();
        *exec += cost;
    }

    /// Read string from WASM memory (requires store reference)
    fn read_string_with_store(&self, store: &impl wasmer::AsStoreRef, ptr: u32, len: u32) -> Result<String, String> {
        let memory = self.memory.as_ref().ok_or("Memory not initialized")?;
        let view = memory.view(store);
        let mut buffer = vec![0u8; len as usize];
        view.read(ptr as u64, &mut buffer).map_err(|e| format!("Memory read error: {}", e))?;
        String::from_utf8(buffer).map_err(|e| format!("UTF-8 error: {}", e))
    }

    /// Read bytes from WASM memory (requires store reference)
    fn read_bytes_with_store(&self, store: &impl wasmer::AsStoreRef, ptr: u32, len: u32) -> Result<Vec<u8>, String> {
        let memory = self.memory.as_ref().ok_or("Memory not initialized")?;
        let view = memory.view(store);
        let mut buffer = vec![0u8; len as usize];
        view.read(ptr as u64, &mut buffer).map_err(|e| format!("Memory read error: {}", e))?;
        Ok(buffer)
    }

    /// Write bytes to WASM memory (requires store reference)
    fn write_bytes_with_store(&self, store: &impl wasmer::AsStoreRef, ptr: u32, data: &[u8]) -> Result<(), String> {
        let memory = self.memory.as_ref().ok_or("Memory not initialized")?;
        let view = memory.view(store);
        view.write(ptr as u64, data).map_err(|e| format!("Memory write error: {}", e))
    }
}

/// Host function implementations
mod host_functions {
    use super::*;

    /// Storage: kv_get
    pub fn storage_kv_get(mut ctx: FunctionEnvMut<WasmContext>, key_ptr: i32, key_len: i32) -> (i32, i32) {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(10);

        match context.read_bytes_with_store(&store, key_ptr as u32, key_len as u32) {
            Ok(key) => {
                let mut kv_ctx = context.kv_ctx.lock().unwrap();
                match kv_ctx.get(&context.db, &key) {
                    Some(value) => {
                        // Store value in shared buffer and return pointer
                        let mut buffer = context.memory_buffer.lock().unwrap();
                        buffer.clear();
                        buffer.extend_from_slice(&value);
                        (0, value.len() as i32)
                    }
                    None => (-1, 0),
                }
            }
            Err(_) => (-1, 0),
        }
    }

    /// Storage: kv_exists
    pub fn storage_kv_exists(mut ctx: FunctionEnvMut<WasmContext>, key_ptr: i32, key_len: i32) -> i32 {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(5);

        match context.read_bytes_with_store(&store, key_ptr as u32, key_len as u32) {
            Ok(key) => {
                let mut kv_ctx = context.kv_ctx.lock().unwrap();
                if kv_ctx.exists(&context.db, &key) { 1 } else { 0 }
            }
            Err(_) => 0,
        }
    }

    /// Storage: kv_put
    pub fn storage_kv_put(
        mut ctx: FunctionEnvMut<WasmContext>,
        key_ptr: i32,
        key_len: i32,
        val_ptr: i32,
        val_len: i32,
    ) -> i32 {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(20);

        match (
            context.read_bytes_with_store(&store, key_ptr as u32, key_len as u32),
            context.read_bytes_with_store(&store, val_ptr as u32, val_len as u32),
        ) {
            (Ok(key), Ok(value)) => {
                let mut kv_ctx = context.kv_ctx.lock().unwrap();
                kv_ctx.put(&context.db, &key, &value);
                0
            }
            _ => -1,
        }
    }

    /// Storage: kv_increment
    pub fn storage_kv_increment(mut ctx: FunctionEnvMut<WasmContext>, key_ptr: i32, key_len: i32, delta: i64) -> i64 {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(15);

        match context.read_bytes_with_store(&store, key_ptr as u32, key_len as u32) {
            Ok(key) => {
                let mut kv_ctx = context.kv_ctx.lock().unwrap();
                kv_ctx.increment_i64(&context.db, &key, delta)
            }
            Err(_) => 0,
        }
    }

    /// Storage: kv_delete
    pub fn storage_kv_delete(mut ctx: FunctionEnvMut<WasmContext>, key_ptr: i32, key_len: i32) -> i32 {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(10);

        match context.read_bytes_with_store(&store, key_ptr as u32, key_len as u32) {
            Ok(key) => {
                let mut kv_ctx = context.kv_ctx.lock().unwrap();
                kv_ctx.delete(&context.db, &key);
                0
            }
            Err(_) => -1,
        }
    }

    /// Storage: kv_clear
    pub fn storage_kv_clear(mut ctx: FunctionEnvMut<WasmContext>, prefix_ptr: i32, prefix_len: i32) -> i32 {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(50);

        match context.read_bytes_with_store(&store, prefix_ptr as u32, prefix_len as u32) {
            Ok(prefix) => {
                let mut kv_ctx = context.kv_ctx.lock().unwrap();
                kv_ctx.clear(&context.db, &prefix) as i32
            }
            Err(_) => -1,
        }
    }

    /// Environment: get block height
    pub fn env_get_block_height(ctx: FunctionEnvMut<WasmContext>) -> i64 {
        let context = ctx.data();
        context.add_exec_cost(1);
        context.env.entry_height as i64
    }

    /// Environment: get block epoch
    pub fn env_get_block_epoch(ctx: FunctionEnvMut<WasmContext>) -> i64 {
        let context = ctx.data();
        context.add_exec_cost(1);
        context.env.entry_epoch as i64
    }

    /// Environment: get block VR
    pub fn env_get_block_vr(mut ctx: FunctionEnvMut<WasmContext>, buf_ptr: i32) -> i32 {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(2);

        let vr = context.env.entry_vr.clone();
        match context.write_bytes_with_store(&store, buf_ptr as u32, &vr) {
            Ok(_) => vr.len() as i32,
            Err(_) => -1,
        }
    }

    /// Environment: get tx hash
    pub fn env_get_tx_hash(mut ctx: FunctionEnvMut<WasmContext>, buf_ptr: i32) -> i32 {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(2);

        let hash = context.env.tx_hash.clone();
        match context.write_bytes_with_store(&store, buf_ptr as u32, &hash) {
            Ok(_) => hash.len() as i32,
            Err(_) => -1,
        }
    }

    /// Environment: get seed as f64
    pub fn env_get_seed_f64(ctx: FunctionEnvMut<WasmContext>) -> f64 {
        let context = ctx.data();
        context.add_exec_cost(1);
        context.env.seedf64
    }

    /// Environment: check if readonly
    pub fn env_is_readonly(ctx: FunctionEnvMut<WasmContext>) -> i32 {
        let context = ctx.data();
        context.add_exec_cost(1);
        if context.env.readonly { 1 } else { 0 }
    }

    /// Environment: get transaction signer
    pub fn env_get_tx_signer(mut ctx: FunctionEnvMut<WasmContext>, buf_ptr: i32) -> i32 {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(2);

        let signer = context.env.tx_signer.clone();
        match context.write_bytes_with_store(&store, buf_ptr as u32, &signer) {
            Ok(_) => signer.len() as i32,
            Err(_) => -1,
        }
    }

    /// Logging: debug
    pub fn log_debug(mut ctx: FunctionEnvMut<WasmContext>, msg_ptr: i32, msg_len: i32) {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(1);

        if let Ok(message) = context.read_string_with_store(&store, msg_ptr as u32, msg_len as u32) {
            let mut logs = context.logs.lock().unwrap();
            logs.push(format!("[DEBUG] {}", message));
        }
    }

    /// Logging: info
    pub fn log_info(mut ctx: FunctionEnvMut<WasmContext>, msg_ptr: i32, msg_len: i32) {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(1);

        if let Ok(message) = context.read_string_with_store(&store, msg_ptr as u32, msg_len as u32) {
            let mut logs = context.logs.lock().unwrap();
            logs.push(format!("[INFO] {}", message));
        }
    }

    /// Memory: grow
    pub fn memory_grow(mut ctx: FunctionEnvMut<WasmContext>, delta: i32) -> i32 {
        let (context, mut store) = ctx.data_and_store_mut();
        context.add_exec_cost(10);

        if let Some(memory) = &context.memory {
            match memory.grow(&mut store, delta as u32) {
                Ok(prev_pages) => prev_pages.0 as i32,
                Err(_) => -1,
            }
        } else {
            -1
        }
    }

    /// Memory: size
    pub fn memory_size(mut ctx: FunctionEnvMut<WasmContext>) -> i32 {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(1);

        if let Some(memory) = &context.memory { memory.size(&store).0 as i32 } else { 0 }
    }

    /// System: abort
    pub fn system_abort(mut ctx: FunctionEnvMut<WasmContext>, code: i32, msg_ptr: i32) {
        let (context, store) = ctx.data_and_store_mut();
        let message = context
            .read_string_with_store(&store, msg_ptr as u32, 256)
            .unwrap_or_else(|_| format!("Abort with code {}", code));

        let mut logs = context.logs.lock().unwrap();
        logs.push(format!("[ABORT] {}", message));

        // This would typically trigger an abort in the WASM execution
        panic!("WASM abort: {}", message);
    }

    /// System: return
    pub fn system_return(mut ctx: FunctionEnvMut<WasmContext>, val_ptr: i32, val_len: i32) {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(1);

        // Store return value for later retrieval
        if let Ok(value) = context.read_bytes_with_store(&store, val_ptr as u32, val_len as u32) {
            let mut logs = context.logs.lock().unwrap();
            logs.push(format!("[RETURN] {} bytes", value.len()));
        }
    }

    /// Cross-contract call via recursive execution
    pub fn cross_contract_call(
        mut ctx: FunctionEnvMut<WasmContext>,
        contract_ptr: i32,
        contract_len: i32,
        function_ptr: i32,
        function_len: i32,
        args_ptr: i32,
        args_len: i32,
        symbol_ptr: i32,
        symbol_len: i32,
        amount_ptr: i32,
        amount_len: i32,
        exec_points: i64,
    ) -> (i32, i32) {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(100);

        // Prevent infinite recursion
        if context.env.call_counter >= 16 {
            let mut logs = context.logs.lock().unwrap();
            logs.push("[CROSS_CALL] Max call depth exceeded".to_string());
            return (-1, 0);
        }

        // Read parameters from WASM memory
        let contract = match context.read_bytes_with_store(&store, contract_ptr as u32, contract_len as u32) {
            Ok(c) => c,
            Err(_) => return (-1, 0),
        };
        let function = match context.read_string_with_store(&store, function_ptr as u32, function_len as u32) {
            Ok(f) => f,
            Err(_) => return (-1, 0),
        };

        // Read args as single blob (WASM contracts pass serialized args)
        let args_bytes = match context.read_bytes_with_store(&store, args_ptr as u32, args_len as u32) {
            Ok(a) => a,
            Err(_) => return (-1, 0),
        };
        // For simplicity, pass as single argument
        let args: Vec<Vec<u8>> = if args_bytes.is_empty() { vec![] } else { vec![args_bytes] };

        // Handle attached tokens
        let symbol = context.read_string_with_store(&store, symbol_ptr as u32, symbol_len as u32).unwrap_or_default();
        let amount_str =
            context.read_string_with_store(&store, amount_ptr as u32, amount_len as u32).unwrap_or_default();

        if !symbol.is_empty() && !amount_str.is_empty() {
            if let Ok(amount) = amount_str.parse::<i128>() {
                if amount > 0 && contract.len() == 48 {
                    let mut contract_pk = [0u8; 48];
                    contract_pk.copy_from_slice(&contract);
                    let caller_key = crate::utils::misc::bcat(&[
                        b"bic:coin:balance:",
                        &context.env.account_caller,
                        b":",
                        symbol.as_bytes(),
                    ]);
                    let contract_key =
                        crate::utils::misc::bcat(&[b"bic:coin:balance:", &contract_pk, b":", symbol.as_bytes()]);
                    let mut kv_ctx = context.kv_ctx.lock().unwrap();
                    kv_ctx.increment(&context.db, &caller_key, -amount);
                    kv_ctx.increment(&context.db, &contract_key, amount);
                }
            }
        }

        // Load target contract bytecode
        if contract.len() != 48 {
            let mut logs = context.logs.lock().unwrap();
            logs.push("[CROSS_CALL] Invalid contract address".to_string());
            return (-1, 0);
        }
        let mut contract_pk = [0u8; 48];
        contract_pk.copy_from_slice(&contract);

        // Look up bytecode directly from DB (read-only operation)
        let key = crate::utils::misc::bcat(&[b"bic:contract:account:", &contract_pk, b":bytecode"]);
        let bytecode = match context.db.get("contractstate", &key).ok().flatten() {
            Some(b) => b,
            None => {
                let mut logs = context.logs.lock().unwrap();
                logs.push("[CROSS_CALL] Contract not found".to_string());
                return (-1, 0);
            }
        };

        // Create new execution environment
        let mut new_env = context.env.clone();
        new_env.call_counter += 1;
        new_env.account_caller = context.env.account_current.clone().try_into().unwrap_or([0u8; 48]);
        new_env.account_current = contract;
        new_env.call_exec_points_remaining = exec_points as u64;

        // Execute recursively
        drop(store); // Release store reference before recursive call
        let result = match {
            // Clone the kv_ctx for the recursive call
            let kv_ctx = context.kv_ctx.lock().unwrap().clone();
            execute(&new_env, &context.db, kv_ctx, &bytecode, &function, &args)
        } {
            Ok(r) => r,
            Err(e) => {
                let mut logs = context.logs.lock().unwrap();
                logs.push(format!("[CROSS_CALL] Execution failed: {}", e));
                return (-1, 0);
            }
        };

        // Append logs from nested call
        let mut logs = context.logs.lock().unwrap();
        logs.extend(result.logs);

        // Update exec cost
        context.add_exec_cost(result.exec_used);

        // Return result (simplified - return success indicator)
        (0, 0)
    }

    /// Crypto: Blake3 hash
    pub fn crypto_blake3_hash(mut ctx: FunctionEnvMut<WasmContext>, data_ptr: i32, data_len: i32, out_ptr: i32) -> i32 {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(5);

        match context.read_bytes_with_store(&store, data_ptr as u32, data_len as u32) {
            Ok(data) => {
                let hash = crate::utils::blake3::hash(&data);
                match context.write_bytes_with_store(&store, out_ptr as u32, &hash) {
                    Ok(_) => hash.len() as i32,
                    Err(_) => -1,
                }
            }
            Err(_) => -1,
        }
    }

    /// Coin: get balance
    pub fn coin_get_balance(
        mut ctx: FunctionEnvMut<WasmContext>,
        account_ptr: i32,
        account_len: i32,
        symbol_ptr: i32,
        symbol_len: i32,
    ) -> i64 {
        let (context, store) = ctx.data_and_store_mut();
        context.add_exec_cost(5);

        match (
            context.read_bytes_with_store(&store, account_ptr as u32, account_len as u32),
            context.read_string_with_store(&store, symbol_ptr as u32, symbol_len as u32),
        ) {
            (Ok(account), Ok(symbol)) => {
                if account.len() == 48 {
                    let mut account_array = [0u8; 48];
                    account_array.copy_from_slice(&account);
                    crate::bic::chain_balance_symbol(&context.db, &account_array, symbol.as_bytes()) as i64
                } else {
                    0
                }
            }
            _ => 0,
        }
    }
}

/// Execute WASM bytecode with given function and arguments
pub fn execute(
    env: &CallEnv,
    db: &crate::utils::rocksdb::RocksDb,
    kv_ctx: kv::ApplyEnvLegacy,
    bytecode: &[u8],
    function: &str,
    args: &[Vec<u8>],
) -> Result<WasmExecutionResult, WasmError> {
    let mut store = Store::default();
    let module = Module::new(&store, bytecode).map_err(|e| WasmError::Compilation(e.to_string()))?;

    // Create context
    let context = WasmContext::new(env.clone(), db.clone(), kv_ctx);
    let func_env = FunctionEnv::new(&mut store, context);

    // Build imports with all host functions
    let import_object = imports! {
        "bic" => {
            "storage_kv_get" => Function::new_typed_with_env(&mut store, &func_env, host_functions::storage_kv_get),
            "storage_kv_exists" => Function::new_typed_with_env(&mut store, &func_env, host_functions::storage_kv_exists),
            "storage_kv_put" => Function::new_typed_with_env(&mut store, &func_env, host_functions::storage_kv_put),
            "storage_kv_increment" => Function::new_typed_with_env(&mut store, &func_env, host_functions::storage_kv_increment),
            "storage_kv_delete" => Function::new_typed_with_env(&mut store, &func_env, host_functions::storage_kv_delete),
            "storage_kv_clear" => Function::new_typed_with_env(&mut store, &func_env, host_functions::storage_kv_clear),
            "cross_contract_call" => Function::new_typed_with_env(&mut store, &func_env, host_functions::cross_contract_call),
            "crypto_blake3_hash" => Function::new_typed_with_env(&mut store, &func_env, host_functions::crypto_blake3_hash),
            "coin_get_balance" => Function::new_typed_with_env(&mut store, &func_env, host_functions::coin_get_balance),
        },
        "env" => {
            "env_get_block_height" => Function::new_typed_with_env(&mut store, &func_env, host_functions::env_get_block_height),
            "env_get_block_epoch" => Function::new_typed_with_env(&mut store, &func_env, host_functions::env_get_block_epoch),
            "env_get_block_vr" => Function::new_typed_with_env(&mut store, &func_env, host_functions::env_get_block_vr),
            "env_get_tx_hash" => Function::new_typed_with_env(&mut store, &func_env, host_functions::env_get_tx_hash),
            "env_get_tx_signer" => Function::new_typed_with_env(&mut store, &func_env, host_functions::env_get_tx_signer),
            "env_get_seed_f64" => Function::new_typed_with_env(&mut store, &func_env, host_functions::env_get_seed_f64),
            "env_is_readonly" => Function::new_typed_with_env(&mut store, &func_env, host_functions::env_is_readonly),
            "log_debug" => Function::new_typed_with_env(&mut store, &func_env, host_functions::log_debug),
            "log_info" => Function::new_typed_with_env(&mut store, &func_env, host_functions::log_info),
            "memory_grow" => Function::new_typed_with_env(&mut store, &func_env, host_functions::memory_grow),
            "memory_size" => Function::new_typed_with_env(&mut store, &func_env, host_functions::memory_size),
            "system_abort" => Function::new_typed_with_env(&mut store, &func_env, host_functions::system_abort),
            "system_return" => Function::new_typed_with_env(&mut store, &func_env, host_functions::system_return),
        }
    };

    // Instantiate module
    let instance =
        Instance::new(&mut store, &module, &import_object).map_err(|e| WasmError::Instantiation(e.to_string()))?;

    // Store memory reference in context
    if let Ok(memory) = instance.exports.get_memory("memory") {
        func_env.as_mut(&mut store).memory = Some(memory.clone());
    }

    // Get exported function
    let wasm_fn =
        instance.exports.get_function(function).map_err(|_| WasmError::FunctionNotFound(function.to_string()))?;

    // Prepare arguments with proper ABI encoding
    let mut wasm_args: Vec<Value> = Vec::new();
    let memory =
        instance.exports.get_memory("memory").map_err(|_| WasmError::Runtime("No memory export found".to_string()))?;

    let mut memory_offset = 1000u32; // Start allocating from offset 1000

    for (i, arg_data) in args.iter().enumerate() {
        match function {
            "init" => {
                // For init function, interpret as i64 directly
                if i == 0 && arg_data.len() >= 8 {
                    let value = i64::from_le_bytes([
                        arg_data[0],
                        arg_data[1],
                        arg_data[2],
                        arg_data[3],
                        arg_data[4],
                        arg_data[5],
                        arg_data[6],
                        arg_data[7],
                    ]);
                    wasm_args.push(Value::I64(value));
                } else {
                    wasm_args.push(Value::I64(0));
                }
            }
            "balance_of" => {
                // For balance_of: (account_ptr: i32, account_len: i32)
                if !arg_data.is_empty() {
                    let memory_view = memory.view(&store);
                    memory_view
                        .write(memory_offset as u64, arg_data)
                        .map_err(|e| WasmError::Runtime(format!("Memory write failed: {}", e)))?;

                    wasm_args.push(Value::I32(memory_offset as i32));
                    wasm_args.push(Value::I32(arg_data.len() as i32));
                    memory_offset += (arg_data.len() as u32 + 7) & !7; // Align to 8 bytes
                }
            }
            "transfer" => {
                // For transfer: (to_ptr: i32, to_len: i32, amount: i64)
                if i == 0 {
                    // First argument is the to_account (write to memory)
                    if !arg_data.is_empty() {
                        let memory_view = memory.view(&store);
                        memory_view
                            .write(memory_offset as u64, arg_data)
                            .map_err(|e| WasmError::Runtime(format!("Memory write failed: {}", e)))?;

                        wasm_args.push(Value::I32(memory_offset as i32));
                        wasm_args.push(Value::I32(arg_data.len() as i32));
                        memory_offset += (arg_data.len() as u32 + 7) & !7;
                    }
                } else if i == 1 {
                    // Second argument is the amount (as i64)
                    if arg_data.len() >= 8 {
                        let amount = i64::from_le_bytes([
                            arg_data[0],
                            arg_data[1],
                            arg_data[2],
                            arg_data[3],
                            arg_data[4],
                            arg_data[5],
                            arg_data[6],
                            arg_data[7],
                        ]);
                        wasm_args.push(Value::I64(amount));
                    } else {
                        wasm_args.push(Value::I64(100)); // Default transfer amount
                    }
                }
            }
            _ => {
                // Default: pass as memory pointer+length
                if !arg_data.is_empty() {
                    let memory_view = memory.view(&store);
                    memory_view
                        .write(memory_offset as u64, arg_data)
                        .map_err(|e| WasmError::Runtime(format!("Memory write failed: {}", e)))?;

                    wasm_args.push(Value::I32(memory_offset as i32));
                    wasm_args.push(Value::I32(arg_data.len() as i32));
                    memory_offset += (arg_data.len() as u32 + 7) & !7;
                }
            }
        }
    }

    // Execute function
    let result = wasm_fn.call(&mut store, &wasm_args).map_err(|e| WasmError::Execution(e.to_string()))?;

    // Extract results
    let context = func_env.as_ref(&store);
    let logs = context.logs.lock().unwrap().clone();
    let exec_used = *context.exec_used.lock().unwrap();

    Ok(WasmExecutionResult {
        return_value: result.first().map(|v| match v {
            Value::I32(i) => vec![*i as u8],
            Value::I64(i) => i.to_le_bytes().to_vec(),
            _ => vec![],
        }),
        logs,
        exec_used,
    })
}

pub fn execute_nodb(
    _env: &CallEnv,
    _bytecode: &[u8],
    _function: &str,
    _args: &[Vec<u8>],
) -> Result<WasmExecutionResult, WasmError> {
    Err(WasmError::Runtime("db_required".to_string()))
}

#[derive(Debug)]
pub struct WasmExecutionResult {
    pub return_value: Option<Vec<u8>>,
    pub logs: Vec<String>,
    pub exec_used: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum WasmError {
    #[error("WASM compilation failed: {0}")]
    Compilation(String),
    #[error("WASM instantiation failed: {0}")]
    Instantiation(String),
    #[error("Function not found: {0}")]
    FunctionNotFound(String),
    #[error("WASM execution failed: {0}")]
    Execution(String),
    #[error("WASM runtime error: {0}")]
    Runtime(String),
}
