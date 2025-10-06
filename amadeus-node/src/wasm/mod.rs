// WASM runtime and execution modules

pub mod base;
pub mod opcodes;
pub mod runtime;
pub mod safe;

// Re-export commonly used types for convenience
pub use base::{WasmBridgeMsg, WasmCallResult, call};
pub use opcodes::{OpCode, RpcMessage, RpcPayload, RpcResponse, RpcResult};
pub use runtime::{WasmError, WasmExecutionResult, execute};
pub use safe::spawn;

// Test modules
#[cfg(test)]
mod tests;
