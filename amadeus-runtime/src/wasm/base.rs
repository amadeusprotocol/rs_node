// WasmCallResult is defined locally in base_wasm since it's an internal bridge type
#[derive(Debug, Clone)]
pub struct WasmCallResult {
    pub exec_used: Option<u64>,
}
use crate::bic::epoch::CallEnv;
use crate::wasm::safe;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

/// Bridge message protocol matching Elixir's BIC.Base.WASM message types
#[derive(Debug)]
pub enum WasmBridgeMsg {
    /// Result from the WASM runtime: (error, logs, exec_remaining, return_value)
    /// error: None or Some("return_value") indicates success; other strings indicate abort/system
    Result {
        error: Option<String>,
        logs: Vec<String>,
        exec_remaining: u64,
        retv: Option<Vec<u8>>,
    },

    // Storage operations - matches Elixir message types
    StorageKvGet {
        rpc_id: u64,
        key: String,
    },
    StorageKvExists {
        rpc_id: u64,
        key: String,
    },
    StorageKvGetPrev {
        rpc_id: u64,
        suffix: String,
        key: String,
    },
    StorageKvGetNext {
        rpc_id: u64,
        suffix: String,
        key: String,
    },
    StorageKvPut {
        rpc_id: u64,
        key: String,
        value: Vec<u8>,
    },
    StorageKvIncrement {
        rpc_id: u64,
        key: String,
        value: i64,
    },
    StorageKvDelete {
        rpc_id: u64,
        key: String,
    },
    StorageKvClear {
        rpc_id: u64,
        prefix: String,
    },

    // Cross-contract calls
    CrossContractCall {
        rpc_id: u64,
        exec_remaining: u64,
        contract: Vec<u8>,
        function: String,
        args: Vec<Vec<u8>>,
        attached_symbol: String,
        attached_amount: String,
    },
}

/// WASM Runtime Bridge - matches Elixir BIC.Base.WASM.call/4
///
/// Spawns sandboxed execution and handles a full message loop for storage and cross-contract calls
pub fn call(env: &CallEnv, wasmbytes: &[u8], function: &str, args: &[Vec<u8>]) -> WasmCallResult {
    let (tx, rx): (Sender<WasmBridgeMsg>, Receiver<WasmBridgeMsg>) = mpsc::channel();

    // Spawn WASM execution in isolated thread
    safe::spawn(env.clone(), wasmbytes.to_vec(), function.to_string(), args.to_vec(), tx);

    // Initialize environment for message loop - matches Elixir mapenv setup
    let mut env = env.clone();
    env.attached_symbol = vec![]; // Clear attachments for fresh call
    env.attached_amount = vec![];

    // Start message loop with empty callstack - matches Elixir wasm_loop(mapenv, [])
    wasm_loop(&rx, env, vec![])
}

/// Call stack entry for cross-contract calls
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CallStackEntry {
    rpc_id: u64,
    last_account: Vec<u8>,
    last_caller: Vec<u8>,
}

/// WASM message loop - matches Elixir BIC.Base.WASM.wasm_loop/2
fn wasm_loop(rx: &Receiver<WasmBridgeMsg>, env: CallEnv, callstack: Vec<CallStackEntry>) -> WasmCallResult {
    match rx.recv_timeout(Duration::from_millis(1_000)) {
        Ok(msg) => match msg {
            // Storage operations - delegate to ConsensusKV
            WasmBridgeMsg::StorageKvGet { rpc_id: _, key } => {
                // TODO: Requires DB handle; placeholder no-op
                let _ = &key;
                // For now, continue loop
                wasm_loop(rx, env, callstack)
            }

            WasmBridgeMsg::StorageKvExists { rpc_id: _, key } => {
                // TODO: Requires DB handle; placeholder no-op
                let _ = &key;
                // TODO: Send response back to WASM runtime
                wasm_loop(rx, env, callstack)
            }

            WasmBridgeMsg::StorageKvPut { rpc_id: _, key, value } => {
                // TODO: Requires DB handle; placeholder no-op
                let _ = (key, value);
                // TODO: Send response back to WASM runtime
                wasm_loop(rx, env, callstack)
            }

            WasmBridgeMsg::StorageKvIncrement { rpc_id: _, key, value } => {
                // TODO: Requires DB handle; placeholder no-op
                let _ = (key, value);
                // TODO: Send response back to WASM runtime
                wasm_loop(rx, env, callstack)
            }

            WasmBridgeMsg::StorageKvDelete { rpc_id: _, key } => {
                // TODO: Requires DB handle; placeholder no-op
                let _ = key;
                // TODO: Send response back to WASM runtime
                wasm_loop(rx, env, callstack)
            }

            WasmBridgeMsg::StorageKvClear { rpc_id: _, prefix } => {
                // TODO: Requires DB handle; placeholder no-op
                let _ = prefix;
                // TODO: Send response back to WASM runtime
                wasm_loop(rx, env, callstack)
            }

            WasmBridgeMsg::StorageKvGetPrev { rpc_id: _, suffix: _, key: _ } => {
                // TODO: Implement kv_get_prev equivalent
                wasm_loop(rx, env, callstack)
            }

            WasmBridgeMsg::StorageKvGetNext { rpc_id: _, suffix: _, key: _ } => {
                // TODO: Implement kv_get_next equivalent
                wasm_loop(rx, env, callstack)
            }

            // Cross-contract calls
            WasmBridgeMsg::CrossContractCall {
                rpc_id: _,
                exec_remaining: _,
                contract: _,
                function: _,
                args: _,
                attached_symbol: _,
                attached_amount: _,
            } => {
                // TODO: Implement cross-contract call logic matching Elixir
                // For now, return error
                wasm_loop(rx, env, callstack)
            }

            // Final result from WASM execution
            WasmBridgeMsg::Result { error, logs: _, exec_remaining, retv: _ } => {
                match error.as_deref() {
                    None | Some("return_value") => {
                        if callstack.is_empty() {
                            // Top-level completion - calculate exec_used
                            let exec_used = env.call_exec_points.saturating_sub(exec_remaining);
                            WasmCallResult { exec_used: Some(exec_used) }
                        } else {
                            // Nested call completion - continue with parent call
                            // TODO: Handle callstack unwinding
                            wasm_loop(rx, env, callstack)
                        }
                    }
                    Some(_error) => {
                        // Error case - calculate exec used and return default
                        let exec_used = env.call_exec_points.saturating_sub(exec_remaining);
                        WasmCallResult { exec_used: Some(exec_used) }
                    }
                }
            }
        },

        Err(_timeout) => {
            // 1000ms timeout - matches Elixir toplevel_timeout
            tracing::warn!(target = "bic::base_wasm", "wasm bridge loop timeout (1s)");
            WasmCallResult { exec_used: Some(env.call_exec_points) } // Full execution cost on timeout
        }
    }
}
