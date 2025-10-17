use crate::consensus::kv;
use crate::utils::bls12_381;
use crate::utils::rocksdb::RocksDb;

pub const DECIMALS: u32 = 9;
pub const BURN_ADDRESS: [u8; 48] = [0u8; 48];

pub fn to_flat(coins: u128) -> u128 {
    coins.saturating_mul(1_000_000_000)
}
pub fn to_cents(coins: u128) -> u128 {
    coins.saturating_mul(10_000_000)
}
pub fn to_tenthousandth(coins: u128) -> u128 {
    coins.saturating_mul(100_000)
}

/// DANGER: floating points
/// Don't use in smart contracts, only for display purposes
pub fn from_flat(coins: u128) -> f64 {
    let value = (coins as f64) / 1_000_000_000.0;
    (value * 1_000_000_000.0).round() / 1_000_000_000.0
}

pub fn burn_address() -> [u8; 48] {
    BURN_ADDRESS
}

fn key_balance(pk: &[u8; 48], symbol: &str) -> Vec<u8> {
    crate::utils::misc::bcat(&[b"bic:coin:balance:", pk, b":", symbol.as_bytes()])
}
fn key_total_supply(symbol: &str) -> Vec<u8> {
    crate::utils::misc::bcat(&[b"bic:coin:totalSupply:", symbol.as_bytes()])
}
fn key_pausable(symbol: &str) -> Vec<u8> {
    crate::utils::misc::bcat(&[b"bic:coin:pausable:", symbol.as_bytes()])
}
fn key_paused(symbol: &str) -> Vec<u8> {
    crate::utils::misc::bcat(&[b"bic:coin:paused:", symbol.as_bytes()])
}
fn key_mintable(symbol: &str) -> Vec<u8> {
    crate::utils::misc::bcat(&[b"bic:coin:mintable:", symbol.as_bytes()])
}
fn key_permission(symbol: &str) -> Vec<u8> {
    crate::utils::misc::bcat(&[b"bic:coin:permission:", symbol.as_bytes()])
}

pub fn balance(ctx: &mut kv::ApplyCtx, db: &RocksDb, pubkey: &[u8; 48], symbol: &str) -> i128 {
    ctx.get_to_i128(db, &key_balance(pubkey, symbol)).unwrap_or(0)
}

pub fn burn_balance(ctx: &mut kv::ApplyCtx, db: &RocksDb, symbol: &str) -> i128 {
    balance(ctx, db, &BURN_ADDRESS, symbol)
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CoinError {
    #[error("invalid_receiver_pk")]
    InvalidReceiverPk,
    #[error("invalid_amount")]
    InvalidAmount,
    #[error("insufficient_funds")]
    InsufficientFunds,
    #[error("paused")]
    Paused,
    #[error("invalid_symbol")]
    InvalidSymbol,
    #[error("symbol_too_short")]
    SymbolTooShort,
    #[error("symbol_too_long")]
    SymbolTooLong,
    #[error("symbol_reserved")]
    SymbolReserved,
    #[error("symbol_exists")]
    SymbolExists,
    #[error("symbol_doesnt_exist")]
    SymbolDoesntExist,
    #[error("no_permissions")]
    NoPermissions,
    #[error("not_mintable")]
    NotMintable,
    #[error("invalid_direction")]
    InvalidDirection,
    #[error("not_pausable")]
    NotPausable,
    #[error("unimplemented")]
    Unimplemented,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoinCall {
    Transfer { receiver: [u8; 48], amount: i128, symbol: String },
    CreateAndMint { symbol: String, amount: i128, mintable: bool, pausable: bool },
    Mint { symbol: String, amount: i128 },
    Pause { symbol: String, direction: bool },
}

/// Environment subset used by Coin calls
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEnv {
    pub account_caller: [u8; 48],
}

fn parse_i128_ascii_decimal(bytes: &[u8]) -> Result<i128, CoinError> {
    if bytes.is_empty() {
        return Err(CoinError::InvalidAmount);
    }
    let s = std::str::from_utf8(bytes).map_err(|_| CoinError::InvalidAmount)?;
    s.parse::<i128>().map_err(|_| CoinError::InvalidAmount)
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

/// Encode a list of public keys as ETF term (matching Elixir's term storage)
fn encode_pk_list(pks: &[[u8; 48]]) -> Vec<u8> {
    use crate::utils::safe_etf::encode_safe;
    use eetf::{Binary, List, Term};
    let elements: Vec<Term> = pks.iter().map(|pk| Term::Binary(Binary { bytes: pk.to_vec() })).collect();
    let list = Term::List(List { elements });
    encode_safe(&list)
}

/// Decode ETF term to list of public keys
fn decode_pk_list(bytes: &[u8]) -> Result<Vec<[u8; 48]>, CoinError> {
    use eetf::Term;
    let term = Term::decode(&bytes[..]).map_err(|_| CoinError::NoPermissions)?;
    match term {
        Term::List(list) => {
            let mut pks = Vec::new();
            for elem in list.elements {
                match elem {
                    Term::Binary(bin) => {
                        let pk = to_fixed_48(&bin.bytes).ok_or(CoinError::NoPermissions)?;
                        pks.push(pk);
                    }
                    _ => return Err(CoinError::NoPermissions),
                }
            }
            Ok(pks)
        }
        _ => Err(CoinError::NoPermissions),
    }
}

/// Check if a public key is in the admin list for a symbol
fn is_admin(ctx: &mut kv::ApplyCtx, db: &RocksDb, symbol: &str, pk: &[u8; 48]) -> bool {
    match ctx.get(db, &key_permission(symbol)) {
        Some(bytes) => decode_pk_list(&bytes).map(|admins| admins.contains(pk)).unwrap_or(false),
        None => false,
    }
}

/// Add a public key to the admin list for a symbol
fn add_admin(ctx: &mut kv::ApplyCtx, db: &RocksDb, symbol: &str, pk: &[u8; 48]) {
    let mut admins = match ctx.get(db, &key_permission(symbol)) {
        Some(bytes) => decode_pk_list(&bytes).unwrap_or_default(),
        None => Vec::new(),
    };
    if !admins.contains(pk) {
        admins.push(*pk);
    }
    ctx.put(db, &key_permission(symbol), &encode_pk_list(&admins));
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
                        let amount = parse_i128_ascii_decimal(amount)?;
                        if amount == 0 {
                            return Err(CoinError::InvalidAmount);
                        }
                        Ok(CoinCall::Transfer { receiver, amount, symbol: "AMA".to_string() })
                    }
                    // ["AMA", receiver, amount]
                    [ama, receiver, amount] if std::str::from_utf8(ama).ok() == Some("AMA") => {
                        let receiver = validate_receiver_pk(receiver)?;
                        let amount = parse_i128_ascii_decimal(amount)?;
                        if amount == 0 {
                            return Err(CoinError::InvalidAmount);
                        }
                        Ok(CoinCall::Transfer { receiver, amount, symbol: "AMA".to_string() })
                    }
                    // [receiver, amount, symbol]
                    [receiver, amount, symbol] => {
                        let receiver = validate_receiver_pk(receiver)?;
                        let amount = parse_i128_ascii_decimal(amount)?;
                        if amount == 0 {
                            return Err(CoinError::InvalidAmount);
                        }
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
                let amount = parse_i128_ascii_decimal(amount_b)?;
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
                let amount = parse_i128_ascii_decimal(&args[1])?;
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

pub fn call(
    ctx: &mut kv::ApplyCtx,
    db: &RocksDb,
    function: &str,
    env: &CallEnv,
    args: &[Vec<u8>],
) -> Result<(), CoinError> {
    let parsed = CoinCall::parse(function, args)?;
    match parsed {
        CoinCall::Transfer { receiver, amount, symbol } => {
            // check if paused
            if ctx.get(db, &key_pausable(&symbol)) == Some(b"true".to_vec())
                && ctx.get(db, &key_paused(&symbol)) == Some(b"true".to_vec())
            {
                return Err(CoinError::Paused);
            }
            // balance check
            let bal = balance(ctx, db, &env.account_caller, &symbol);
            if bal < amount {
                return Err(CoinError::InsufficientFunds);
            }
            // apply
            ctx.increment(db, &key_balance(&env.account_caller, &symbol), -amount);
            ctx.increment(db, &key_balance(&receiver, &symbol), amount);
            Ok(())
        }
        CoinCall::CreateAndMint { symbol, amount, mintable, pausable } => {
            // symbol checks already in parse
            if ctx.exists(db, &key_total_supply(&symbol)) {
                return Err(CoinError::SymbolExists);
            }
            ctx.increment(db, &key_balance(&env.account_caller, &symbol), amount);
            ctx.increment(db, &key_total_supply(&symbol), amount);
            // permissions: add caller to admin list
            add_admin(ctx, db, &symbol, &env.account_caller);
            if mintable {
                ctx.put(db, &key_mintable(&symbol), b"true");
            }
            if pausable {
                ctx.put(db, &key_pausable(&symbol), b"true");
            }
            Ok(())
        }
        CoinCall::Mint { symbol, amount } => {
            if !ctx.exists(db, &key_total_supply(&symbol)) {
                return Err(CoinError::SymbolDoesntExist);
            }
            // permission check: caller must be admin
            if !is_admin(ctx, db, &symbol, &env.account_caller) {
                return Err(CoinError::NoPermissions);
            }
            if ctx.get(db, &key_mintable(&symbol)) != Some(b"true".to_vec()) {
                return Err(CoinError::NotMintable);
            }
            if ctx.get(db, &key_pausable(&symbol)) == Some(b"true".to_vec())
                && ctx.get(db, &key_paused(&symbol)) == Some(b"true".to_vec())
            {
                return Err(CoinError::Paused);
            }
            ctx.increment(db, &key_balance(&env.account_caller, &symbol), amount);
            ctx.increment(db, &key_total_supply(&symbol), amount);
            Ok(())
        }
        CoinCall::Pause { symbol, direction } => {
            if !ctx.exists(db, &key_total_supply(&symbol)) {
                return Err(CoinError::SymbolDoesntExist);
            }
            // permission check: caller must be admin
            if !is_admin(ctx, db, &symbol, &env.account_caller) {
                return Err(CoinError::NoPermissions);
            }
            if ctx.get(db, &key_pausable(&symbol)) != Some(b"true".to_vec()) {
                return Err(CoinError::NotPausable);
            }
            ctx.put(db, &key_paused(&symbol), if direction { b"true" } else { b"false" });
            Ok(())
        }
    }
}
