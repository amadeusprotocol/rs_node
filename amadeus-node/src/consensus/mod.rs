#![allow(clippy::module_inception)]
pub mod consensus;
pub mod doms;
pub mod fabric;
pub mod genesis;
pub mod tx_filter;

// Re-export DST constants from amadeus_utils
pub use amadeus_utils::constants::{
    DST, DST_ANR, DST_ANR_CHALLENGE, DST_ATT, DST_ENTRY, DST_MOTION, DST_NODE, DST_POP, DST_TX, DST_VRF,
};

use crate::utils::misc::TermExt;
use crate::utils::rocksdb::RocksDb;
use amadeus_utils::constants::CF_SYSCONF;
use eetf::Term;

/// Chain epoch accessor (Elixir: Consensus.chain_epoch/0)
/// Returns current epoch calculated as height / 100_000
pub fn chain_epoch(db: &RocksDb) -> u32 {
    chain_height(db) / 100_000
}

/// Chain height accessor - gets current blockchain height
pub fn chain_height(db: &RocksDb) -> u32 {
    match db.get(CF_SYSCONF, b"temporal_height") {
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
