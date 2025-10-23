use std::panic::panic_any;
use crate::{bcat, consensus};
use crate::consensus::consensus_kv::{kv_get, kv_put, kv_increment};

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
    let frac  = ((coins % 1_000_000_000).abs() as f64) / 1_000_000_000.0;
    let x = if coins >= 0 { whole + frac } else { whole - frac };
    (x * 1e9).round() / 1e9
}

pub fn balance_burnt(env: &crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8]) -> i128 {
    balance(env, &BURN_ADDRESS, symbol)
}

pub fn balance(env: &crate::consensus::consensus_apply::ApplyEnv, address: &[u8], symbol: &[u8]) -> i128 {
    match kv_get(env, &bcat(&[b"bic:coin:balance:", address, b":", symbol])) {
        Some(amount) => std::str::from_utf8(&amount).unwrap().parse::<i128>().unwrap_or_else(|_| panic_any("invalid_balance")),
        None => 0
    }
}

pub fn mintable(env: &crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8]) -> bool {
    match kv_get(env, &bcat(&[b"bic:coin:mintable:", symbol])).as_deref() {
        Some(b"true") => true,
        _ => false
    }
}

pub fn pausable(env: &crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8]) -> bool {
    match kv_get(env, &bcat(&[b"bic:coin:pausable:", symbol])).as_deref() {
        Some(b"true") => true,
        _ => false
    }
}

pub fn paused(env: &crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8]) -> bool {
    match kv_get(env, &bcat(&[b"bic:coin:paused:", symbol])).as_deref() {
        Some(b"true") => pausable(env, symbol),
        _ => false
    }
}

pub fn total_supply(env: &crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8]) -> i128 {
    match kv_get(env, &bcat(&[b"bic:coin:totalSupply:", symbol])) {
        Some(amount) => std::str::from_utf8(&amount).unwrap().parse::<i128>().unwrap_or_else(|_| panic_any("invalid_total_supply")),
        None => 0
    }
}

pub fn exists(env: &crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8]) -> bool {
    match kv_get(env, &bcat(&[b"bic:coin:totalSupply:", symbol])) {
        Some(_) => true,
        None => false
    }
}

pub fn has_permission(env: &crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8], signer: &[u8]) -> bool {
    match kv_get(env, &bcat(&[b"bic:coin:permission:", symbol])) {
        None => false,
        Some(permission_list) => {
            let cursor = std::io::Cursor::new(permission_list.as_slice());
            let term_permission_list = eetf::Term::decode(cursor).unwrap();
            match term_permission_list {
                eetf::Term::List(term_permission_list) => term_permission_list.elements.iter().any(|el| {
                    matches!(el, eetf::Term::Binary(b) if b.bytes.as_slice() == signer)
                }),
                _ => false
            }
        }
    }
}

pub fn call_transfer(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 3 { panic_any("invalid_args") }
    let receiver = args[0].as_slice();
    let amount = args[1].as_slice();
    let amount = std::str::from_utf8(&amount).unwrap().parse::<i128>().unwrap_or_else(|_| panic_any("invalid_amount"));
    let symbol = args[2].as_slice();

    if receiver.len() != 48 { panic_any("invalid_address_pk") }
    if !(consensus::bls12_381::validate_public_key(receiver) || receiver == &BURN_ADDRESS) { panic_any("invalid_receiver_pk") }
    if amount <= 0 { panic_any("invalid_amount") }
    if amount > balance(env, env.caller_env.account_caller.as_slice(), &symbol) { panic_any("insufficient_funds") }

    if paused(env, symbol) { panic_any("paused") }

    kv_increment(env, &bcat(&[b"bic:coin:balance:", env.caller_env.account_caller.as_slice(), b":", symbol]), -amount);
    kv_increment(env, &bcat(&[b"bic:coin:balance:", receiver, b":", symbol]), amount);
}

pub fn call_create_and_mint(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 4 { panic_any("invalid_args") }
    let symbol_original = args[0].as_slice();
    let amount = args[1].as_slice();
    let mintable = args[2].as_slice();
    let pausable = args[3].as_slice();

    let symbol: Vec<u8> = symbol_original.iter().copied().filter(u8::is_ascii_alphanumeric).collect();
    if symbol_original != symbol.as_slice() { panic_any("invalid_symbol") }
    if symbol.len() < 1 { panic_any("symbol_too_short") }
    if symbol.len() > 32 { panic_any("symbol_too_long") }

    let amount = std::str::from_utf8(&amount).unwrap().parse::<i128>().unwrap_or_else(|_| panic_any("invalid_amount"));
    if amount <= 0 { panic_any("invalid_amount") }

    if !consensus::bic::coin_symbol_reserved::is_free(&symbol, b"") { panic_any("symbol_reserved") }
    if exists(env, &symbol) { panic_any("symbol_exists") }

    kv_increment(env, &bcat(&[b"bic:coin:balance:", env.caller_env.account_caller.as_slice(), b":", &symbol]), amount);
    kv_increment(env, &bcat(&[b"bic:coin:totalSupply:", &symbol]), amount);

    let mut admin = Vec::new();
    admin.push(env.caller_env.account_caller.to_vec());
    let term_admins = consensus::bic::eetf_list_of_binaries(admin).unwrap();
    kv_put(env, &bcat(&[b"bic:coin:permission:", &symbol]), &term_admins);

    if mintable == b"true" { kv_put(env, &bcat(&[b"bic:coin:mintable:", &symbol]), b"true") }
    if pausable == b"true" { kv_put(env, &bcat(&[b"bic:coin:pausable:", &symbol]), b"true") }
}

pub fn call_mint(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 2 { panic_any("invalid_args") }
    let symbol = args[0].as_slice();
    let amount = args[1].as_slice();

    let amount = std::str::from_utf8(&amount).unwrap().parse::<i128>().unwrap_or_else(|_| panic_any("invalid_amount"));
    if amount <= 0 { panic_any("invalid_amount") }

    if !exists(env, &symbol) { panic_any("symbol_doesnt_exist") }
    if !mintable(env, &symbol) { panic_any("not_mintable") }
    if paused(env, &symbol) { panic_any("paused") }
    if !has_permission(env, &symbol, env.caller_env.account_caller.as_slice()) { panic_any("no_permissions") }

    kv_increment(env, &bcat(&[b"bic:coin:balance:", env.caller_env.account_caller.as_slice(), b":", symbol]), amount);
    kv_increment(env, &bcat(&[b"bic:coin:totalSupply:", symbol]), amount);
}

pub fn call_pause(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 2 { panic_any("invalid_args") }
    let symbol = args[0].as_slice();
    let direction = args[1].as_slice();

    if direction != b"true" && direction != b"false" { panic_any("invalid_direction") }

    if !exists(env, &symbol) { panic_any("symbol_doesnt_exist") }
    if !pausable(env, &symbol) { panic_any("not_pausable") }
    if !has_permission(env, &symbol, env.caller_env.account_caller.as_slice()) { panic_any("no_permissions") }

    kv_put(env, &bcat(&[b"bic:coin:paused:", &symbol]), &direction);
}
