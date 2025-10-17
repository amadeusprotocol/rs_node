pub mod coin;
pub mod coin_symbol_reserved; // TODO: implement logic; currently stubbed
pub mod contract;
pub mod epoch;
pub mod sol;
pub mod sol_bloom;
pub mod sol_difficulty;

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
