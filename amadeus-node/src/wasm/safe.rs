use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};

use crate::wasm::base::{WasmBridgeMsg, WasmCallResult};
use crate::wasm::runtime;

#[derive(Debug, thiserror::Error)]
pub enum WasmError {
    #[error("wasm compilation failed: {0}")]
    Compilation(String),
    #[error("wasm execution failed: {0}")]
    Execution(String),
    #[error("panic during wasm execution")]
    Panic,
}

/// Spawn a sandboxed WASM execution in a separate OS thread.
/// Uses the complete WASM runtime with OP-code based host functions.
pub fn spawn(
    env: crate::bic::epoch::CallEnv,
    wasmbytes: Vec<u8>,
    function: String,
    args: Vec<Vec<u8>>,
    tx: Sender<WasmBridgeMsg>,
) -> JoinHandle<Result<WasmCallResult, WasmError>> {
    thread::spawn(move || {
        let exec = || -> Result<WasmCallResult, WasmError> {
            // Execute WASM function using the runtime
            match runtime::execute_nodb(&env, &wasmbytes, &function, &args) {
                Ok(result) => {
                    // Calculate remaining execution points
                    let exec_remaining = env.call_exec_points.saturating_sub(result.exec_used);

                    // Send result back through bridge
                    let _ = tx.send(WasmBridgeMsg::Result {
                        error: None,
                        logs: result.logs,
                        exec_remaining,
                        retv: result.return_value,
                    });

                    Ok(WasmCallResult { exec_used: Some(result.exec_used) })
                }
                Err(e) => {
                    // Send error back through bridge
                    let error_msg = match &e {
                        runtime::WasmError::Compilation(_) => "abort",
                        runtime::WasmError::FunctionNotFound(_) => "function_not_found",
                        _ => "system",
                    };

                    let _ = tx.send(WasmBridgeMsg::Result {
                        error: Some(error_msg.to_string()),
                        logs: vec![e.to_string()],
                        exec_remaining: 0,
                        retv: None,
                    });

                    Err(WasmError::Execution(e.to_string()))
                }
            }
        };

        match catch_unwind(AssertUnwindSafe(exec)) {
            Ok(res) => res,
            Err(_) => {
                let _ = tx.send(WasmBridgeMsg::Result {
                    error: Some("system".to_string()),
                    logs: vec!["panic".to_string()],
                    exec_remaining: 0,
                    retv: None,
                });
                Err(WasmError::Panic)
            }
        }
    })
}
