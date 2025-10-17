pub mod coin;
pub mod coin_symbol_reserved;
pub mod contract;
pub mod epoch;
pub mod sol;
pub mod sol_bloom;
pub mod sol_difficulty;

use crate::utils::rocksdb::RocksDb;

/// Blake3-based deterministic seed
///
/// Returns the 32-byte seed (little-endian interpretation is up to the caller where needed)
pub fn get_deterministic_seed(vr: &[u8], txhash: &[u8], action_index: &[u8], call_cnt: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(vr);
    hasher.update(txhash);
    hasher.update(action_index);
    hasher.update(call_cnt);
    let hash = hasher.finalize();
    *hash.as_bytes()
}

pub fn get_deterministic_f64(vr: &[u8], txhash: &[u8], action_index: &[u8], call_cnt: &[u8]) -> f64 {
    let seed = get_deterministic_seed(vr, txhash, action_index, call_cnt);
    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&seed[0..8]);
    f64::from_le_bytes(first8)
}

/// Latest observed nonce for a signer
/// Returns the highest nonce used by this signer
pub fn chain_nonce(db: &RocksDb, signer: &[u8]) -> Option<i128> {
    let key = crate::utils::misc::bcat(&[b"bic:base:nonce:", signer]);
    match db.get("contractstate", &key) {
        Ok(Some(bytes)) => {
            // Stored as ASCII string by kv.rs put() / Elixir stores with to_integer
            let s = std::str::from_utf8(&bytes).ok()?;
            s.parse::<i128>().ok()
        }
        _ => None,
    }
}

/// Balance accessor (defaults to "AMA")
pub fn chain_balance(db: &RocksDb, signer: &[u8]) -> u128 {
    chain_balance_symbol(db, signer, "AMA")
}

/// Balance accessor with specific symbol
pub fn chain_balance_symbol(db: &RocksDb, signer: &[u8], symbol: &str) -> u128 {
    let key = crate::utils::misc::bcat(&[b"bic:coin:balance:", signer, b":", symbol.as_bytes()]);
    match db.get("contractstate", &key) {
        Ok(Some(bytes)) => {
            // Stored as ASCII string by kv.rs increment() / Elixir uses to_integer
            let s = std::str::from_utf8(&bytes).ok();
            s.and_then(|s| s.parse::<i128>().ok()).map(|balance| balance.max(0) as u128).unwrap_or(0)
        }
        _ => 0, // default to 0 if no balance found
    }
}

/// Get current segment VR hash for epoch validation
pub fn chain_segment_vr_hash(db: &RocksDb) -> Option<Vec<u8>> {
    db.get("contractstate", b"bic:epoch:segment_vr_hash").ok().flatten()
}

/// Get current difficulty bits for solution validation
pub fn chain_diff_bits(db: &RocksDb) -> u32 {
    db.get("contractstate", b"bic:epoch:diff_bits")
        .ok()
        .flatten()
        .and_then(|bytes| {
            // Stored as ASCII string with to_integer
            let s = std::str::from_utf8(&bytes).ok()?;
            s.parse::<u32>().ok()
        })
        .unwrap_or(24)
}

/// Get total solutions count for epoch
pub fn chain_total_sols(db: &RocksDb) -> u64 {
    db.get("contractstate", b"bic:epoch:total_sols")
        .ok()
        .flatten()
        .and_then(|bytes| {
            // Stored as ASCII string with to_integer
            let s = std::str::from_utf8(&bytes).ok()?;
            s.parse::<u64>().ok()
        })
        .unwrap_or(0)
}

/// Get proof-of-possession for a public key
pub fn chain_pop(db: &RocksDb, pk: &[u8; 48]) -> Option<Vec<u8>> {
    let key = crate::utils::misc::bcat(&[b"bic:epoch:pop:", pk]);
    db.get("contractstate", &key).ok().flatten()
}
