use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv::{kv_get, kv_increment, kv_put};
use crate::{Result, bcat, consensus};
use amadeus_utils::vecpak::{self, Term};

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
    match kv_get(env, &bcat(&[b"account:", address, b":balance:", symbol]))? {
        Some(amount) => {
            let s = std::str::from_utf8(&amount).map_err(|_| "invalid_utf8")?;
            let parsed = s.parse::<i128>().map_err(|_| "invalid_balance")?;
            Ok(parsed)
        }
        None => Ok(0),
    }
}

pub fn mintable(env: &ApplyEnv, symbol: &[u8]) -> Result<bool> {
    match kv_get(env, &bcat(&[b"coin:", symbol, b":mintable"]))?.as_deref() {
        Some(b"true") => Ok(true),
        _ => Ok(false),
    }
}

pub fn pausable(env: &ApplyEnv, symbol: &[u8]) -> Result<bool> {
    match kv_get(env, &bcat(&[b"coin:", symbol, b":pausable"]))?.as_deref() {
        Some(b"true") => Ok(true),
        _ => Ok(false),
    }
}

pub fn paused(env: &ApplyEnv, symbol: &[u8]) -> Result<bool> {
    match kv_get(env, &bcat(&[b"coin:", symbol, b":paused"]))?.as_deref() {
        Some(b"true") => pausable(env, symbol),
        _ => Ok(false),
    }
}

pub fn soulbound(env: &ApplyEnv, symbol: &[u8]) -> Result<bool> {
    match kv_get(env, &bcat(&[b"coin:", symbol, b":soulbound"]))?.as_deref() {
        Some(b"true") => Ok(true),
        _ => Ok(false),
    }
}

pub fn total_supply(env: &ApplyEnv, symbol: &[u8]) -> Result<i128> {
    match kv_get(env, &bcat(&[b"coin:", symbol, b":totalSupply"]))? {
        Some(amount) => {
            let s = std::str::from_utf8(&amount).map_err(|_| "invalid_utf8")?;
            let parsed = s.parse::<i128>().map_err(|_| "invalid_total_supply")?;
            Ok(parsed)
        }
        None => Ok(0),
    }
}

pub fn exists(env: &ApplyEnv, symbol: &[u8]) -> Result<bool> {
    match kv_get(env, &bcat(&[b"coin:", symbol, b":totalSupply"]))? {
        Some(_) => Ok(true),
        None => Ok(false),
    }
}

pub fn has_permission(env: &ApplyEnv, symbol: &[u8], signer: &[u8]) -> Result<bool> {
    match kv_get(env, &bcat(&[b"coin:", symbol, b":permission"]))? {
        None => Ok(false),
        Some(permission_list) => {
            let term = vecpak::decode(permission_list.as_slice()).map_err(|_| "invalid_vecpak")?;
            match term {
                Term::List(term_list) => Ok(term_list
                    .iter()
                    .any(|el| matches!(el, Term::Binary(b) if b.as_slice() == signer))),
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
    if !(amadeus_utils::bls12_381::validate_public_key(receiver).is_ok() || receiver == &BURN_ADDRESS) {
        return Err("invalid_receiver_pk");
    }
    if amount <= 0 {
        return Err("invalid_amount");
    }
    if amount > balance(env, env.caller_env.account_caller.as_slice(), symbol)? {
        return Err("insufficient_funds");
    }

    if paused(env, symbol)? {
        return Err("paused");
    }
    if soulbound(env, symbol)? {
        return Err("soulbound");
    }

    kv_increment(env, &bcat(&[b"account:", env.caller_env.account_caller.as_slice(), b":balance:", symbol]), -amount)?;
    kv_increment(env, &bcat(&[b"account:", receiver, b":balance:", symbol]), amount)?;

    // Account burnt coins
    if symbol != b"AMA" && receiver == &BURN_ADDRESS {
        kv_increment(env, &bcat(&[b"coin:", symbol, b":totalSupply"]), -amount)?;
    }
    Ok(())
}

pub fn call_create_and_mint(env: &mut ApplyEnv, args: Vec<Vec<u8>>) -> Result<()> {
    if args.len() < 2 {
        return Err("invalid_args");
    }
    let symbol_original = args[0].as_slice();
    let amount = args[1].as_slice();
    let decimals = args.get(2).and_then(|v| if v.is_empty() { None } else { Some(v.as_slice()) }).unwrap_or(b"9");
    let mintable = args.get(3).and_then(|v| if v.is_empty() { None } else { Some(v.as_slice()) }).unwrap_or(b"false");
    let pausable = args.get(4).and_then(|v| if v.is_empty() { None } else { Some(v.as_slice()) }).unwrap_or(b"false");
    let soulbound_arg = args.get(5).and_then(|v| if v.is_empty() { None } else { Some(v.as_slice()) }).unwrap_or(b"false");

    let symbol: Vec<u8> = symbol_original.iter().copied().filter(u8::is_ascii_alphanumeric).collect();
    if symbol_original != symbol.as_slice() {
        return Err("invalid_symbol");
    }
    if symbol.is_empty() {
        return Err("symbol_too_short");
    }
    if symbol.len() > 32 {
        return Err("symbol_too_long");
    }

    if !consensus::bic::coin_symbol_reserved::is_free(&symbol, &env.caller_env.account_caller) {
        return Err("symbol_reserved");
    }
    if exists(env, &symbol)? {
        return Err("symbol_exists");
    }

    let amount = std::str::from_utf8(&amount).ok().and_then(|s| s.parse::<i128>().ok()).ok_or("invalid_amount")?;
    if amount <= 0 {
        return Err("invalid_amount");
    }

    let decimals = std::str::from_utf8(decimals).ok().and_then(|s| s.parse::<u64>().ok()).ok_or("invalid_decimals")?;
    if decimals >= 10 {
        return Err("invalid_decimals");
    }

    kv_increment(env, &bcat(&[b"account:", env.caller_env.account_caller.as_slice(), b":balance:", &symbol]), amount)?;
    kv_increment(env, &bcat(&[b"coin:", &symbol, b":totalSupply"]), amount)?;

    let admin = vec![Term::Binary(env.caller_env.account_caller.to_vec())];
    let buf = vecpak::encode(Term::List(admin));
    kv_put(env, &bcat(&[b"coin:", &symbol, b":permission"]), &buf)?;

    if mintable == b"true" {
        kv_put(env, &bcat(&[b"coin:", &symbol, b":mintable"]), b"true")?;
    }
    if pausable == b"true" {
        kv_put(env, &bcat(&[b"coin:", &symbol, b":pausable"]), b"true")?;
    }
    if soulbound_arg == b"true" {
        kv_put(env, &bcat(&[b"coin:", &symbol, b":soulbound"]), b"true")?;
    }
    Ok(())
}

pub fn call_mint(env: &mut ApplyEnv, args: Vec<Vec<u8>>) -> Result<()> {
    if args.len() != 3 {
        return Err("invalid_args");
    }
    let symbol = args[0].as_slice();
    let amount = args[1].as_slice();
    let amount = std::str::from_utf8(&amount).ok().and_then(|s| s.parse::<i128>().ok()).ok_or("invalid_amount")?;
    let receiver = args[2].as_slice();
    if receiver.len() != 48 {
        return Err("invalid_receiver_pk");
    }

    if !has_permission(env, symbol, env.caller_env.account_caller.as_slice())? {
        return Err("no_permissions");
    }

    mint(env, symbol, amount, receiver)
}

pub fn mint(env: &mut ApplyEnv, symbol: &[u8], amount: i128, receiver: &[u8]) -> Result<()> {
    if !amadeus_utils::bls12_381::validate_public_key(receiver).is_ok() {
        return Err("invalid_receiver_pk");
    }
    if amount <= 0 {
        return Err("invalid_amount");
    }

    if !exists(env, symbol)? {
        return Err("symbol_doesnt_exist");
    }
    if !mintable(env, symbol)? {
        return Err("not_mintable");
    }
    if paused(env, symbol)? {
        return Err("paused");
    }

    kv_increment(env, &bcat(&[b"account:", receiver, b":balance:", symbol]), amount)?;
    kv_increment(env, &bcat(&[b"coin:", symbol, b":totalSupply"]), amount)?;
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

    if !exists(env, symbol)? {
        return Err("symbol_doesnt_exist");
    }
    if !has_permission(env, symbol, env.caller_env.account_caller.as_slice())? {
        return Err("no_permissions");
    }
    if !pausable(env, symbol)? {
        return Err("not_pausable");
    }

    kv_put(env, &bcat(&[b"coin:", symbol, b":paused"]), direction)?;
    Ok(())
}

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
