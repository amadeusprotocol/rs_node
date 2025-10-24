// Re-export core contract functions from runtime
pub use amadeus_runtime::consensus::bic::contract::{bytecode, call_deploy};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("wasm compilation failed: {0}")]
    Compilation(String),
    #[error("invalid function: {0}")]
    InvalidFunction(String),
    #[error("invalid arguments")]
    InvalidArgs,
    #[error("runtime error: {0}")]
    Runtime(&'static str),
}

/// Minimal validation for a contract WASM binary.
/// Mirrors Elixir BIC.Contract.validate/1 behavior at a high level:
/// - Return Ok(()) when the module compiles
/// - Return Err with reason otherwise
///
/// This is node-specific because it depends on wasmer.
pub fn validate(wasm: &[u8]) -> Result<(), ContractError> {
    // Use wasmer to attempt compilation. If it compiles, we accept it.
    // Keep implementation minimal and side-effect free to stay testable.
    let store = wasmer::Store::default();
    match wasmer::Module::new(&store, wasm) {
        Ok(_) => Ok(()),
        Err(e) => Err(ContractError::Compilation(e.to_string())),
    }
}

/// Dispatch contract module calls with validation
/// Wrapper around runtime's call_deploy that adds wasmer validation
pub fn call(
    env: &mut amadeus_runtime::consensus::consensus_apply::ApplyEnv,
    function: &str,
    args: &[Vec<u8>],
) -> Result<(), ContractError> {
    match function {
        "deploy" => {
            if args.len() != 1 {
                return Err(ContractError::InvalidArgs);
            }
            let wasmbytes = &args[0];

            // Validate WASM before deploying (node-specific validation)
            validate(wasmbytes)?;

            // Call runtime's deploy function
            call_deploy(env, args.to_vec()).map_err(ContractError::Runtime)?;
            Ok(())
        }
        other => Err(ContractError::InvalidFunction(other.to_string())),
    }
}
