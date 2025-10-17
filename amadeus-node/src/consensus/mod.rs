#![allow(clippy::module_inception)]
pub mod agg_sig;
pub mod consensus;
pub mod doms;
pub mod fabric;
pub mod genesis;
pub mod kv;

#[cfg(test)]
mod test_34076357 {
    include!("tests/34076357.rs");
}

#[cfg(test)]
mod test_34076383 {
    include!("tests/34076383.rs");
}

pub use agg_sig::{
    AggSig, DST, DST_ANR, DST_ANR_CHALLENGE, DST_ATT, DST_ENTRY, DST_MOTION, DST_NODE, DST_POP, DST_TX, DST_VRF,
};

use crate::utils::misc::TermExt;
use crate::utils::rocksdb::RocksDb;
use eetf::Term;

// Re-export from bic module for backward compatibility
pub use crate::bic::epoch::trainers_for_height;
pub use crate::bic::{
    chain_balance, chain_balance_symbol, chain_diff_bits, chain_nonce, chain_pop, chain_segment_vr_hash,
    chain_total_sols,
};

/// Chain epoch accessor (Elixir: Consensus.chain_epoch/0)
/// Returns current epoch calculated as height / 100_000
pub fn chain_epoch(db: &RocksDb) -> u32 {
    chain_height(db) / 100_000
}

/// Chain height accessor - gets current blockchain height
pub fn chain_height(db: &RocksDb) -> u32 {
    match db.get("sysconf", b"temporal_height") {
        Ok(Some(bytes)) => {
            // Elixir stores as ETF term with `term: true`
            match Term::decode(&bytes[..]) {
                Ok(term) => TermExt::get_integer(&term).unwrap_or(0) as u32,
                Err(_) => 0, // fallback if deserialization fails
            }
        }
        _ => 0, // fallback if key not found
    }
}
