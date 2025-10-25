use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv::{kv_get, kv_increment, kv_put};
use crate::{Result, bcat, consensus};

pub const DECIMALS: u32 = 9;
pub const BURN_ADDRESS: [u8; 48] = [0u8; 48];

pub fn to_flat(coins: i128) -> i128 {
    coins.saturating_mul(1_000_000_000)
}
pub fn to_cents(coins: i128) -> i128 {
    coins.saturating_mul(10_000_000)
}
pub fn to_tenthousandth(coins: i128) -> i128 {
    coins.saturating_mul(100_000)
}
pub fn from_flat(coins: i128) -> f64 {
    let whole = (coins / 1_000_000_000) as f64;
    let frac = ((coins % 1_000_000_000).abs() as f64) / 1_000_000_000.0;
    let x = if coins >= 0 { whole + frac } else { whole - frac };
    (x * 1e9).round() / 1e9
}

pub fn balance_burnt(env: &ApplyEnv, symbol: &[u8]) -> Result<i128> {
    balance(env, &BURN_ADDRESS, symbol)
}

pub fn balance(env: &ApplyEnv, address: &[u8], symbol: &[u8]) -> Result<i128> {
    match kv_get(env, &bcat(&[b"bic:coin:balance:", address, b":", symbol]))? {
        Some(amount) => {
            let s = std::str::from_utf8(&amount).map_err(|_| "invalid_utf8")?;
            let parsed = s.parse::<i128>().map_err(|_| "invalid_balance")?;
            Ok(parsed)
        }
        None => Ok(0),
    }
}

pub fn mintable(env: &ApplyEnv, symbol: &[u8]) -> Result<bool> {
    match kv_get(env, &bcat(&[b"bic:coin:mintable:", symbol]))?.as_deref() {
        Some(b"true") => Ok(true),
        _ => Ok(false),
    }
}

pub fn pausable(env: &ApplyEnv, symbol: &[u8]) -> Result<bool> {
    match kv_get(env, &bcat(&[b"bic:coin:pausable:", symbol]))?.as_deref() {
        Some(b"true") => Ok(true),
        _ => Ok(false),
    }
}

pub fn paused(env: &ApplyEnv, symbol: &[u8]) -> Result<bool> {
    match kv_get(env, &bcat(&[b"bic:coin:paused:", symbol]))?.as_deref() {
        Some(b"true") => pausable(env, symbol),
        _ => Ok(false),
    }
}

pub fn total_supply(env: &ApplyEnv, symbol: &[u8]) -> Result<i128> {
    match kv_get(env, &bcat(&[b"bic:coin:totalSupply:", symbol]))? {
        Some(amount) => {
            let s = std::str::from_utf8(&amount).map_err(|_| "invalid_utf8")?;
            let parsed = s.parse::<i128>().map_err(|_| "invalid_total_supply")?;
            Ok(parsed)
        }
        None => Ok(0),
    }
}

pub fn exists(env: &ApplyEnv, symbol: &[u8]) -> Result<bool> {
    match kv_get(env, &bcat(&[b"bic:coin:totalSupply:", symbol]))? {
        Some(_) => Ok(true),
        None => Ok(false),
    }
}

pub fn has_permission(env: &ApplyEnv, symbol: &[u8], signer: &[u8]) -> Result<bool> {
    match kv_get(env, &bcat(&[b"bic:coin:permission:", symbol]))? {
        None => Ok(false),
        Some(permission_list) => {
            let cursor = std::io::Cursor::new(permission_list.as_slice());
            let term_permission_list = eetf::Term::decode(cursor).map_err(|_| "invalid_eetf")?;
            match term_permission_list {
                eetf::Term::List(term_permission_list) => Ok(term_permission_list
                    .elements
                    .iter()
                    .any(|el| matches!(el, eetf::Term::Binary(b) if b.bytes.as_slice() == signer))),
                _ => Ok(false),
            }
        }
    }
}

pub fn call_transfer(env: &mut ApplyEnv, args: Vec<Vec<u8>>) -> Result<()> {
    if args.len() != 3 {
        return Err("invalid_args");
    }
    let receiver = args[0].as_slice();
    let amount = args[1].as_slice();
    let amount = std::str::from_utf8(&amount).ok().and_then(|s| s.parse::<i128>().ok()).ok_or("invalid_amount")?;
    let symbol = args[2].as_slice();

    if receiver.len() != 48 {
        return Err("invalid_receiver_pk");
    }
    if !(consensus::bls12_381::validate_public_key(receiver) || receiver == &BURN_ADDRESS) {
        return Err("invalid_receiver_pk");
    }
    if amount <= 0 {
        return Err("invalid_amount");
    }
    if amount > balance(env, env.caller_env.account_caller.as_slice(), &symbol)? {
        return Err("insufficient_funds");
    }

    if paused(env, symbol)? {
        return Err("paused");
    }

    kv_increment(env, &bcat(&[b"bic:coin:balance:", env.caller_env.account_caller.as_slice(), b":", symbol]), -amount)?;
    kv_increment(env, &bcat(&[b"bic:coin:balance:", receiver, b":", symbol]), amount)?;
    Ok(())
}

pub fn call_create_and_mint(env: &mut ApplyEnv, args: Vec<Vec<u8>>) -> Result<()> {
    if args.len() != 4 {
        return Err("invalid_args");
    }
    let symbol_original = args[0].as_slice();
    let amount = args[1].as_slice();
    let mintable = args[2].as_slice();
    let pausable = args[3].as_slice();

    let symbol: Vec<u8> = symbol_original.iter().copied().filter(u8::is_ascii_alphanumeric).collect();
    if symbol_original != symbol.as_slice() {
        return Err("invalid_symbol");
    }
    if symbol.len() < 1 {
        return Err("symbol_too_short");
    }
    if symbol.len() > 32 {
        return Err("symbol_too_long");
    }

    let amount = std::str::from_utf8(&amount).ok().and_then(|s| s.parse::<i128>().ok()).ok_or("invalid_amount")?;
    if amount <= 0 {
        return Err("invalid_amount");
    }

    if !consensus::bic::coin_symbol_reserved::is_free(&symbol, &env.caller_env.account_caller) {
        return Err("symbol_reserved");
    }
    if exists(env, &symbol)? {
        return Err("symbol_exists");
    }

    kv_increment(env, &bcat(&[b"bic:coin:balance:", env.caller_env.account_caller.as_slice(), b":", &symbol]), amount)?;
    kv_increment(env, &bcat(&[b"bic:coin:totalSupply:", &symbol]), amount)?;

    let mut admin = Vec::new();
    admin.push(env.caller_env.account_caller.to_vec());
    let term_admins = amadeus_utils::misc::eetf_list_of_binaries(admin).map_err(|_| "eetf_encoding_failed")?;
    kv_put(env, &bcat(&[b"bic:coin:permission:", &symbol]), &term_admins)?;

    if mintable == b"true" {
        kv_put(env, &bcat(&[b"bic:coin:mintable:", &symbol]), b"true")?;
    }
    if pausable == b"true" {
        kv_put(env, &bcat(&[b"bic:coin:pausable:", &symbol]), b"true")?;
    }
    Ok(())
}

pub fn call_mint(env: &mut ApplyEnv, args: Vec<Vec<u8>>) -> Result<()> {
    if args.len() != 2 {
        return Err("invalid_args");
    }
    let symbol = args[0].as_slice();
    let amount = args[1].as_slice();

    let amount = std::str::from_utf8(&amount).ok().and_then(|s| s.parse::<i128>().ok()).ok_or("invalid_amount")?;
    if amount <= 0 {
        return Err("invalid_amount");
    }

    if !exists(env, &symbol)? {
        return Err("symbol_doesnt_exist");
    }
    if !has_permission(env, &symbol, env.caller_env.account_caller.as_slice())? {
        return Err("no_permissions");
    }
    if !mintable(env, &symbol)? {
        return Err("not_mintable");
    }
    if paused(env, &symbol)? {
        return Err("paused");
    }

    kv_increment(env, &bcat(&[b"bic:coin:balance:", env.caller_env.account_caller.as_slice(), b":", symbol]), amount)?;
    kv_increment(env, &bcat(&[b"bic:coin:totalSupply:", symbol]), amount)?;
    Ok(())
}

pub fn call_pause(env: &mut ApplyEnv, args: Vec<Vec<u8>>) -> Result<()> {
    if args.len() != 2 {
        return Err("invalid_args");
    }
    let symbol = args[0].as_slice();
    let direction = args[1].as_slice();

    if direction != b"true" && direction != b"false" {
        return Err("invalid_direction");
    }

    if !exists(env, &symbol)? {
        return Err("symbol_doesnt_exist");
    }
    if !has_permission(env, &symbol, env.caller_env.account_caller.as_slice())? {
        return Err("no_permissions");
    }
    if !pausable(env, &symbol)? {
        return Err("not_pausable");
    }

    kv_put(env, &bcat(&[b"bic:coin:paused:", &symbol]), &direction)?;
    Ok(())
}

// Compatibility wrappers for amadeus-node
pub fn burn_address() -> [u8; 48] {
    BURN_ADDRESS
}

pub fn call(env: &mut ApplyEnv, function: &str, args: &[Vec<u8>]) -> Result<()> {
    match function {
        "transfer" => call_transfer(env, args.to_vec()),
        "create_and_mint" => call_create_and_mint(env, args.to_vec()),
        "mint" => call_mint(env, args.to_vec()),
        "pause" => call_pause(env, args.to_vec()),
        _ => Err("unimplemented_function"),
    }
}
