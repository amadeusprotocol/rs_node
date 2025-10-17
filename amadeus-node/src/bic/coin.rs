use crate::consensus::kv;
use crate::utils::bls12_381;
use crate::utils::rocksdb::RocksDb;

pub const DECIMALS: u32 = 9;
pub const BURN_ADDRESS: [u8; 48] = [0u8; 48];

pub fn to_flat(coins: u64) -> u64 {
    coins.saturating_mul(1_000_000_000)
}
pub fn to_cents(coins: u64) -> u64 {
    coins.saturating_mul(10_000_000)
}
pub fn to_tenthousandth(coins: u64) -> u64 {
    coins.saturating_mul(100_000)
}

pub fn from_flat(coins: u64) -> f64 {
    (coins as f64) / 1_000_000_000.0
}

pub fn burn_address() -> [u8; 48] {
    BURN_ADDRESS
}

fn key_balance(pk: &[u8; 48], symbol: &str) -> Vec<u8> {
    crate::utils::misc::build_key_with_suffix(b"bic:coin:balance:", pk, format!(":{}", symbol).as_bytes())
}
fn key_total_supply(symbol: &str) -> Vec<u8> {
    format!("bic:coin:totalSupply:{}", symbol).into_bytes()
}
fn key_pausable(symbol: &str) -> Vec<u8> {
    format!("bic:coin:pausable:{}", symbol).into_bytes()
}
fn key_paused(symbol: &str) -> Vec<u8> {
    format!("bic:coin:paused:{}", symbol).into_bytes()
}
fn key_mintable(symbol: &str) -> Vec<u8> {
    format!("bic:coin:mintable:{}", symbol).into_bytes()
}
fn key_permission_admin(symbol: &str, pk: &[u8; 48]) -> Vec<u8> {
    let prefix = format!("bic:coin:permission:{}:admin:", symbol);
    let mut key = prefix.into_bytes();
    key.extend_from_slice(pk);
    key
}

pub fn balance(ctx: &mut kv::ApplyCtx, db: &RocksDb, pubkey: &[u8; 48], symbol: &str) -> u64 {
    kv::kv_get_to_i64(ctx, db, &key_balance(pubkey, symbol)).unwrap_or(0).max(0) as u64
}

pub fn burn_balance(ctx: &mut kv::ApplyCtx, db: &RocksDb, symbol: &str) -> u64 {
    balance(ctx, db, &BURN_ADDRESS, symbol)
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CoinError {
    #[error("invalid receiver pk")]
    InvalidReceiverPk,
    #[error("invalid amount")]
    InvalidAmount,
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("paused")]
    Paused,
    #[error("invalid symbol")]
    InvalidSymbol,
    #[error("symbol too short")]
    SymbolTooShort,
    #[error("symbol too long")]
    SymbolTooLong,
    #[error("symbol reserved")]
    SymbolReserved,
    #[error("symbol exists")]
    SymbolExists,
    #[error("symbol doesn't exist")]
    SymbolDoesntExist,
    #[error("no permissions")]
    NoPermissions,
    #[error("not mintable")]
    NotMintable,
    #[error("invalid direction")]
    InvalidDirection,
    #[error("not pausable")]
    NotPausable,
    #[error("unimplemented (requires KV/state)")]
    Unimplemented,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoinCall {
    Transfer { receiver: [u8; 48], amount: u64, symbol: String },
    CreateAndMint { symbol: String, amount: u64, mintable: bool, pausable: bool },
    Mint { symbol: String, amount: u64 },
    Pause { symbol: String, direction: bool },
}

/// Environment subset used by Coin calls
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEnv {
    pub account_caller: [u8; 48],
}

fn parse_u64_ascii_decimal(bytes: &[u8]) -> Result<u64, CoinError> {
    if bytes.is_empty() {
        return Err(CoinError::InvalidAmount);
    }
    let s = std::str::from_utf8(bytes).map_err(|_| CoinError::InvalidAmount)?;
    s.parse::<u64>().map_err(|_| CoinError::InvalidAmount)
}

fn is_alphanumeric_ascii(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphanumeric())
}

fn to_fixed_48(arr: &[u8]) -> Option<[u8; 48]> {
    if arr.len() != 48 {
        return None;
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(arr);
    Some(out)
}

fn validate_receiver_pk(receiver: &[u8]) -> Result<[u8; 48], CoinError> {
    let pk = to_fixed_48(receiver).ok_or(CoinError::InvalidReceiverPk)?;
    if pk == BURN_ADDRESS {
        return Ok(pk);
    }
    if bls12_381::validate_public_key(&pk).is_ok() { Ok(pk) } else { Err(CoinError::InvalidReceiverPk) }
}

fn parse_bool_str(bytes: &[u8]) -> Option<bool> {
    match bytes {
        b"true" => Some(true),
        b"false" => Some(false),
        _ => None,
    }
}

impl CoinCall {
    /// Parse function name and byte args (decoded from ETF) into a typed CoinCall,
    /// performing the same front-end validations as Elixir before touching state.
    pub fn parse(function: &str, args: &[Vec<u8>]) -> Result<CoinCall, CoinError> {
        match function {
            // transfer(receiver, amount) => default symbol "AMA"
            // transfer(receiver, amount, symbol)
            // Special Elixir case: if first arg == "AMA" then args are ["AMA", receiver, amount]
            "transfer" => {
                match args {
                    // [receiver, amount]
                    [receiver, amount] => {
                        let receiver = validate_receiver_pk(receiver)?;
                        let amount = parse_u64_ascii_decimal(amount)?;
                        Ok(CoinCall::Transfer { receiver, amount, symbol: "AMA".to_string() })
                    }
                    // ["AMA", receiver, amount]
                    [ama, receiver, amount] if std::str::from_utf8(ama).ok() == Some("AMA") => {
                        let receiver = validate_receiver_pk(receiver)?;
                        let amount = parse_u64_ascii_decimal(amount)?;
                        Ok(CoinCall::Transfer { receiver, amount, symbol: "AMA".to_string() })
                    }
                    // [receiver, amount, symbol]
                    [receiver, amount, symbol] => {
                        let receiver = validate_receiver_pk(receiver)?;
                        let amount = parse_u64_ascii_decimal(amount)?;
                        let symbol_str = std::str::from_utf8(symbol).map_err(|_| CoinError::InvalidSymbol)?;
                        if !is_alphanumeric_ascii(symbol_str) {
                            return Err(CoinError::InvalidSymbol);
                        }
                        if symbol_str.is_empty() {
                            return Err(CoinError::SymbolTooShort);
                        }
                        if symbol_str.len() > 32 {
                            return Err(CoinError::SymbolTooLong);
                        }
                        Ok(CoinCall::Transfer { receiver, amount, symbol: symbol_str.to_string() })
                    }
                    _ => Err(CoinError::InvalidAmount),
                }
            }
            "create_and_mint" => {
                // args: [symbol, amount, mintable, pausable]
                if args.len() != 4 {
                    return Err(CoinError::InvalidSymbol);
                }
                let symbol_b = &args[0];
                let amount_b = &args[1];
                let mintable_b = &args[2];
                let pausable_b = &args[3];

                let symbol = std::str::from_utf8(symbol_b).map_err(|_| CoinError::InvalidSymbol)?;
                if !is_alphanumeric_ascii(symbol) {
                    return Err(CoinError::InvalidSymbol);
                }
                if symbol.is_empty() {
                    return Err(CoinError::SymbolTooShort);
                }
                if symbol.len() > 32 {
                    return Err(CoinError::SymbolTooLong);
                }
                let amount = parse_u64_ascii_decimal(amount_b)?;
                if amount == 0 {
                    return Err(CoinError::InvalidAmount);
                }
                let mintable = parse_bool_str(mintable_b).ok_or(CoinError::InvalidDirection)?; // reuse error kind
                let pausable = parse_bool_str(pausable_b).ok_or(CoinError::InvalidDirection)?;

                Ok(CoinCall::CreateAndMint { symbol: symbol.to_string(), amount, mintable, pausable })
            }
            "mint" => {
                // args: [symbol, amount]
                if args.len() != 2 {
                    return Err(CoinError::InvalidSymbol);
                }
                let symbol = std::str::from_utf8(&args[0]).map_err(|_| CoinError::InvalidSymbol)?;
                if !is_alphanumeric_ascii(symbol) {
                    return Err(CoinError::InvalidSymbol);
                }
                if symbol.is_empty() {
                    return Err(CoinError::SymbolTooShort);
                }
                if symbol.len() > 32 {
                    return Err(CoinError::SymbolTooLong);
                }
                let amount = parse_u64_ascii_decimal(&args[1])?;
                if amount == 0 {
                    return Err(CoinError::InvalidAmount);
                }
                Ok(CoinCall::Mint { symbol: symbol.to_string(), amount })
            }
            "pause" => {
                // args: [symbol, direction]
                if args.len() != 2 {
                    return Err(CoinError::InvalidSymbol);
                }
                let symbol = std::str::from_utf8(&args[0]).map_err(|_| CoinError::InvalidSymbol)?;
                if !is_alphanumeric_ascii(symbol) {
                    return Err(CoinError::InvalidSymbol);
                }
                if symbol.is_empty() {
                    return Err(CoinError::SymbolTooShort);
                }
                if symbol.len() > 32 {
                    return Err(CoinError::SymbolTooLong);
                }
                let direction = parse_bool_str(&args[1]).ok_or(CoinError::InvalidDirection)?;
                Ok(CoinCall::Pause { symbol: symbol.to_string(), direction })
            }
            _ => Err(CoinError::Unimplemented),
        }
    }
}

pub fn call(ctx: &mut kv::ApplyCtx, db: &RocksDb, function: &str, env: &CallEnv, args: &[Vec<u8>]) -> Result<(), CoinError> {
    let parsed = CoinCall::parse(function, args)?;
    match parsed {
        CoinCall::Transfer { receiver, amount, symbol } => {
            if kv::kv_get(ctx, db, &key_pausable(&symbol)) == Some(b"true".to_vec())
                && kv::kv_get(ctx, db, &key_paused(&symbol)) == Some(b"true".to_vec())
            {
                return Err(CoinError::Paused);
            }
            // balance check
            let bal = balance(ctx, db, &env.account_caller, &symbol);
            if amount as i128 <= 0 || (amount as u128) == 0 {
                return Err(CoinError::InvalidAmount);
            }
            if bal < amount {
                return Err(CoinError::InsufficientFunds);
            }
            // apply
            let amt_i64 = amount as i64; // NOTE: may overflow if > i64::MAX; assumed safe in current use
            kv::kv_increment(ctx, db, &key_balance(&env.account_caller, &symbol), -(amt_i64));
            kv::kv_increment(ctx, db, &key_balance(&receiver, &symbol), amt_i64);
            Ok(())
        }
        CoinCall::CreateAndMint { symbol, amount, mintable, pausable } => {
            // symbol checks already in parse
            if kv::kv_exists(ctx, db, &key_total_supply(&symbol)) {
                return Err(CoinError::SymbolExists);
            }
            if amount == 0 {
                return Err(CoinError::InvalidAmount);
            }
            let amt_i64 = amount as i64;
            kv::kv_increment(ctx, db, &key_balance(&env.account_caller, &symbol), amt_i64);
            kv::kv_increment(ctx, db, &key_total_supply(&symbol), amt_i64);
            // permissions: mark caller as admin
            kv::kv_put(ctx, db, &key_permission_admin(&symbol, &env.account_caller), b"1");
            if mintable {
                kv::kv_put(ctx, db, &key_mintable(&symbol), b"true");
            }
            if pausable {
                kv::kv_put(ctx, db, &key_pausable(&symbol), b"true");
            }
            Ok(())
        }
        CoinCall::Mint { symbol, amount } => {
            if !kv::kv_exists(ctx, db, &key_total_supply(&symbol)) {
                return Err(CoinError::SymbolDoesntExist);
            }
            if kv::kv_get(ctx, db, &key_mintable(&symbol)) != Some(b"true".to_vec()) {
                return Err(CoinError::NotMintable);
            }
            if kv::kv_get(ctx, db, &key_pausable(&symbol)) == Some(b"true".to_vec())
                && kv::kv_get(ctx, db, &key_paused(&symbol)) == Some(b"true".to_vec())
            {
                return Err(CoinError::Paused);
            }
            // permission check: caller must be admin
            if !kv::kv_exists(ctx, db, &key_permission_admin(&symbol, &env.account_caller)) {
                return Err(CoinError::NoPermissions);
            }
            if amount == 0 {
                return Err(CoinError::InvalidAmount);
            }
            let amt_i64 = amount as i64;
            kv::kv_increment(ctx, db, &key_balance(&env.account_caller, &symbol), amt_i64);
            kv::kv_increment(ctx, db, &key_total_supply(&symbol), amt_i64);
            Ok(())
        }
        CoinCall::Pause { symbol, direction } => {
            if !kv::kv_exists(ctx, db, &key_total_supply(&symbol)) {
                return Err(CoinError::SymbolDoesntExist);
            }
            if kv::kv_get(ctx, db, &key_pausable(&symbol)) != Some(b"true".to_vec()) {
                return Err(CoinError::NotPausable);
            }
            if !kv::kv_exists(ctx, db, &key_permission_admin(&symbol, &env.account_caller)) {
                return Err(CoinError::NoPermissions);
            }
            kv::kv_put(ctx, db, &key_paused(&symbol), if direction { b"true" } else { b"false" });
            Ok(())
        }
    }
}
