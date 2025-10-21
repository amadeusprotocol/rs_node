use amadeus_consensus::consensus::consensus_apply::ApplyEnv;
use amadeus_consensus::consensus::consensus_kv;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("wasm compilation failed: {0}")]
    Compilation(String),
    #[error("invalid function: {0}")]
    InvalidFunction(String),
    #[error("invalid arguments")]
    InvalidArgs,
}

/// Minimal validation for a contract WASM binary.
/// Mirrors Elixir BIC.Contract.validate/1 behavior at a high level:
/// - Return Ok(()) when the module compiles
/// - Return Err with reason otherwise
pub fn validate(wasm: &[u8]) -> Result<(), ContractError> {
    // Use wasmer to attempt compilation. If it compiles, we accept it.
    // Keep implementation minimal and side-effect free to stay testable.
    let store = wasmer::Store::default();
    match wasmer::Module::new(&store, wasm) {
        Ok(_) => Ok(()),
        Err(e) => Err(ContractError::Compilation(e.to_string())),
    }
}

fn key_bytecode(account: &[u8; 48]) -> Vec<u8> {
    crate::utils::misc::bcat(&[b"bic:contract:account:", account, b":bytecode"])
}

/// Read stored bytecode for a given account public key
pub fn bytecode(env: &mut ApplyEnv, account: &[u8; 48]) -> Option<Vec<u8>> {
    consensus_kv::kv_get(env, &key_bytecode(account))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEnv {
    pub account_caller: [u8; 48],
}

/// Dispatch contract module calls (currently only "deploy")
pub fn call(
    env: &mut ApplyEnv,
    function: &str,
    call_env: &CallEnv,
    args: &[Vec<u8>],
) -> Result<(), ContractError> {
    match function {
        "deploy" => {
            // Expect exactly one argument: wasm bytes
            if args.len() != 1 {
                return Err(ContractError::InvalidArgs);
            }
            let wasmbytes = &args[0];
            // Store bytecode under caller's account key
            let key = key_bytecode(&call_env.account_caller);
            consensus_kv::kv_put(env, &key, wasmbytes);
            Ok(())
        }
        other => Err(ContractError::InvalidFunction(other.to_string())),
    }
}
