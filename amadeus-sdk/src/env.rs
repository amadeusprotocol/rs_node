use crate::host::env as host_env;
use crate::types::{Address, Hash};
use alloc::string::String;
use alloc::vec::Vec;

/// Get the current block height
pub fn block_height() -> u64 {
    unsafe { host_env::env_get_block_height() }
}

/// Get the current block timestamp in milliseconds
pub fn block_timestamp() -> u64 {
    unsafe { host_env::env_get_block_timestamp() }
}

/// Get the current block timestamp in seconds
pub fn block_timestamp_secs() -> u64 {
    block_timestamp() / 1000
}

/// Get the current epoch number
pub fn epoch() -> u64 {
    unsafe { host_env::env_get_epoch() }
}

/// Get the current slot number within the epoch
pub fn slot() -> u64 {
    unsafe { host_env::env_get_slot() }
}

/// Get the transaction signer's public key (48 bytes BLS key)
pub fn tx_signer() -> Address {
    let mut buffer = [0u8; 48];
    unsafe {
        host_env::env_get_tx_signer(buffer.as_mut_ptr() as i32);
    }
    Address(buffer)
}

/// Get the transaction hash (32 bytes)
pub fn tx_hash() -> Hash {
    let mut buffer = [0u8; 32];
    unsafe {
        host_env::env_get_tx_hash(buffer.as_mut_ptr() as i32);
    }
    Hash(buffer)
}

/// Get the immediate caller's address
pub fn caller() -> Address {
    let mut buffer = [0u8; 48];
    unsafe {
        host_env::env_get_caller(buffer.as_mut_ptr() as i32);
    }
    Address(buffer)
}

/// Get the current contract's own address
pub fn self_address() -> Address {
    let mut buffer = [0u8; 48];
    unsafe {
        host_env::env_get_self(buffer.as_mut_ptr() as i32);
    }
    Address(buffer)
}

/// Get the amount of tokens attached to this transaction
pub fn attached_amount() -> i64 {
    unsafe { host_env::env_get_attached_amount() }
}

/// Get the symbol of the token attached to this transaction
pub fn attached_symbol() -> Vec<u8> {
    let mut buffer = [0u8; 32];
    unsafe {
        let len = host_env::env_get_attached_symbol(buffer.as_mut_ptr() as i32);
        buffer[..len as usize].to_vec()
    }
}

/// Get a random seed derived from block VRF (32 bytes)
pub fn random_seed() -> Hash {
    let mut buffer = [0u8; 32];
    unsafe {
        host_env::env_get_random_seed(buffer.as_mut_ptr() as i32);
    }
    Hash(buffer)
}

/// Get a random f64 in range [0, 1)
pub fn random_f64() -> f64 {
    unsafe { host_env::env_get_random_f64() }
}

/// Get a random u64 in range [0, max)
pub fn random_u64(max: u64) -> u64 {
    (random_f64() * max as f64) as u64
}

/// Get remaining execution points (gas)
pub fn remaining_gas() -> u64 {
    unsafe { host_env::env_get_remaining_gas() }
}

/// Log an info message
pub fn log(msg: &str) {
    unsafe {
        host_env::log_info(msg.as_ptr() as i32, msg.len() as i32);
    }
}

/// Log an info message
pub fn log_info(msg: &str) {
    log(msg)
}

/// Log a warning message
pub fn log_warn(msg: &str) {
    unsafe {
        host_env::log_warn(msg.as_ptr() as i32, msg.len() as i32);
    }
}

/// Log an error message
pub fn log_error(msg: &str) {
    unsafe {
        host_env::log_error(msg.as_ptr() as i32, msg.len() as i32);
    }
}

/// Return data from the contract call
pub fn return_data(data: &[u8]) {
    unsafe {
        host_env::system_return(data.as_ptr() as i32, data.len() as i32);
    }
}

/// Return a string from the contract call
pub fn return_string(s: &str) {
    return_data(s.as_bytes())
}

/// Return a u64 from the contract call
pub fn return_u64(v: u64) {
    return_data(&v.to_le_bytes())
}

/// Return an i64 from the contract call
pub fn return_i64(v: i64) {
    return_data(&v.to_le_bytes())
}

/// Revert the transaction with an error message
pub fn revert(msg: &str) -> ! {
    unsafe {
        host_env::system_revert(msg.as_ptr() as i32, msg.len() as i32);
    }
}

/// Assert a condition, reverting with a message if false
pub fn require(condition: bool, msg: &str) {
    if !condition {
        revert(msg);
    }
}

/// Emit an event
pub fn emit_event(name: &str, data: &[u8]) {
    unsafe {
        host_env::emit_event(name.as_ptr() as i32, name.len() as i32, data.as_ptr() as i32, data.len() as i32);
    }
}

/// Emit an event with string data
pub fn emit_event_str(name: &str, data: &str) {
    emit_event(name, data.as_bytes())
}

/// Compute Blake3 hash of data
pub fn blake3(data: &[u8]) -> Hash {
    let mut buffer = [0u8; 32];
    unsafe {
        host_env::hash_blake3(data.as_ptr() as i32, data.len() as i32, buffer.as_mut_ptr() as i32);
    }
    Hash(buffer)
}

/// Verify a BLS signature
pub fn verify_bls_signature(msg: &[u8], signature: &[u8; 96], pubkey: &Address) -> bool {
    unsafe {
        host_env::verify_bls_signature(
            msg.as_ptr() as i32,
            msg.len() as i32,
            signature.as_ptr() as i32,
            pubkey.0.as_ptr() as i32,
        ) == 1
    }
}

/// Call another contract
pub fn call_contract(contract: &Address, function: &str, args: &[u8]) -> Result<Vec<u8>, String> {
    let mut buffer = [0u8; 4096];
    unsafe {
        let result = host_env::call_contract(
            contract.0.as_ptr() as i32,
            function.as_ptr() as i32,
            function.len() as i32,
            args.as_ptr() as i32,
            args.len() as i32,
            buffer.as_mut_ptr() as i32,
        );

        if result < 0 {
            Err(String::from("Contract call failed"))
        } else {
            Ok(buffer[..result as usize].to_vec())
        }
    }
}

pub mod coin {
    use super::*;
    use crate::host::bic;

    /// Get the balance of an account for a specific token
    pub fn balance_of(account: &Address, symbol: &[u8]) -> i64 {
        unsafe {
            bic::coin_get_balance(
                account.0.as_ptr() as i32,
                account.0.len() as i32,
                symbol.as_ptr() as i32,
                symbol.len() as i32,
            )
        }
    }

    /// Transfer tokens from the caller to another account
    pub fn transfer(to: &Address, symbol: &[u8], amount: i64) -> bool {
        unsafe {
            bic::coin_transfer(
                to.0.as_ptr() as i32,
                to.0.len() as i32,
                symbol.as_ptr() as i32,
                symbol.len() as i32,
                amount,
            ) == 0
        }
    }

    /// Get the caller's balance of a specific token
    pub fn caller_balance(symbol: &[u8]) -> i64 {
        balance_of(&super::caller(), symbol)
    }
}
