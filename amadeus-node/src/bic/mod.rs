// Local BIC modules
pub mod coin;
pub mod coin_symbol_reserved;
pub mod contract;
pub mod epoch;
pub mod sol;
pub mod sol_bloom;
pub mod sol_difficulty;

use crate::utils::rocksdb::RocksDb;

// Re-export common bic functions
pub use epoch::trainers_for_height;

// Node-specific extensions
pub mod sol_protocol;

// Chain query functions
pub fn chain_balance(db: &RocksDb, pk: &[u8; 48], symbol: &str) -> i128 {
    let key = crate::utils::misc::bcat(&[b"bic:coin:balance:", pk, b":", symbol.as_bytes()]);
    db.get("contractstate", &key)
        .ok()
        .flatten()
        .and_then(|v| std::str::from_utf8(&v).ok().and_then(|s| s.parse::<i128>().ok()))
        .unwrap_or(0)
}

pub fn chain_balance_symbol(db: &RocksDb, pk: &[u8; 48], symbol: &[u8]) -> i128 {
    let key = crate::utils::misc::bcat(&[b"bic:coin:balance:", pk, b":", symbol]);
    db.get("contractstate", &key)
        .ok()
        .flatten()
        .and_then(|v| std::str::from_utf8(&v).ok().and_then(|s| s.parse::<i128>().ok()))
        .unwrap_or(0)
}

pub fn chain_pop(db: &RocksDb, pk: &[u8; 48]) -> Vec<u8> {
    let key = crate::utils::misc::bcat(&[b"bic:base:pop:", pk]);
    db.get("contractstate", &key).ok().flatten().unwrap_or_default()
}

pub fn chain_nonce(db: &RocksDb, pk: &[u8; 48]) -> i128 {
    let key = crate::utils::misc::bcat(&[b"bic:base:nonce:", pk]);
    db.get("contractstate", &key)
        .ok()
        .flatten()
        .and_then(|v| std::str::from_utf8(&v).ok().and_then(|s| s.parse::<i128>().ok()))
        .unwrap_or(0)
}

pub fn chain_diff_bits(db: &RocksDb) -> Vec<u8> {
    db.get("contractstate", b"bic:epoch:difficulty_bits").ok().flatten().unwrap_or_default()
}

pub fn chain_segment_vr_hash(db: &RocksDb) -> Vec<u8> {
    db.get("contractstate", b"bic:epoch:segment_vr_hash").ok().flatten().unwrap_or_default()
}

pub fn chain_total_sols(db: &RocksDb) -> i128 {
    db.get("contractstate", b"bic:epoch:total_sols")
        .ok()
        .flatten()
        .and_then(|v| std::str::from_utf8(&v).ok().and_then(|s| s.parse::<i128>().ok()))
        .unwrap_or(0)
}

pub fn is_reserved(symbol: &str) -> bool {
    coin_symbol_reserved::is_free(symbol, &[0u8; 48])
}
