use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv::{kv_delete, kv_get, kv_increment, kv_put};
use crate::{Result, bcat};

/// Create a lock vault for a receiver with a specified amount and unlock epoch
pub fn create_lock(env: &mut ApplyEnv, receiver: &[u8], symbol: &[u8], amount: i128, unlock_epoch: u64) -> Result<()> {
    if amount <= 0 {
        return Err("invalid_amount");
    }

    let vault_index = kv_increment(env, b"bic:lockup:unique_index", 1)?;
    let vault_value = bcat(&[unlock_epoch.to_string().as_bytes(), b"-", amount.to_string().as_bytes(), b"-", symbol]);
    kv_put(env, &bcat(&[b"bic:lockup:vault:", receiver, b":", vault_index.to_string().as_bytes()]), &vault_value)?;
    Ok(())
}

/// Unlock a vault and transfer funds to caller
pub fn call_unlock(env: &mut ApplyEnv, args: Vec<Vec<u8>>) -> Result<()> {
    if args.len() != 1 {
        return Err("invalid_args");
    }
    let vault_index = args[0].as_slice();

    let vault_key = bcat(&[b"bic:lockup:vault:", &env.caller_env.account_caller, b":", vault_index]);

    let vault = kv_get(env, &vault_key)?.ok_or("invalid_vault")?;

    let vault_parts: Vec<Vec<u8>> = vault.split(|&b| b == b'-').map(|seg| seg.to_vec()).collect();
    if vault_parts.len() < 3 {
        return Err("invalid_vault_format");
    }

    let unlock_epoch =
        std::str::from_utf8(&vault_parts[0]).ok().and_then(|s| s.parse::<u64>().ok()).ok_or("invalid_unlock_epoch")?;
    let amount = std::str::from_utf8(&vault_parts[1])
        .ok()
        .and_then(|s| s.parse::<i128>().ok())
        .ok_or("invalid_unlock_amount")?;
    let symbol = &vault_parts[2];

    if env.caller_env.entry_epoch < unlock_epoch {
        return Err("vault_is_locked");
    }

    kv_increment(env, &bcat(&[b"account:", &env.caller_env.account_caller, b":balance:", symbol]), amount)?;
    kv_delete(env, &vault_key)?;
    Ok(())
}
