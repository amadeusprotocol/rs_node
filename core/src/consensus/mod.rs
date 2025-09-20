#![allow(clippy::module_inception)]
pub mod agg_sig;
pub mod consensus;
pub mod doms;
pub mod fabric;
pub mod fabric_cleaner;
pub mod genesis;
pub mod kv;

pub use agg_sig::{
    AggSig, DST, DST_ANR, DST_ANR_CHALLENGE, DST_ATT, DST_ENTRY, DST_MOTION, DST_NODE, DST_POP, DST_TX, DST_VRF,
};

use crate::utils::misc::TermExt;
use crate::utils::rocksdb;
use eetf::Term;

/// Return trainers for the given height, reading from contractstate CF.
/// Keys: "bic:epoch:trainers:height:{:012}" (ASCII), values: ETF list of 48-byte PKs.
/// Special case: heights in 3195570..=3195575 map to fixed key "000000319557".
pub fn trainers_for_height(height: u32) -> Option<Vec<[u8; 48]>> {
    let cf = "contractstate";
    let value: Option<Vec<u8>> = if (3_195_570..=3_195_575).contains(&height) {
        match rocksdb::get(cf, b"bic:epoch:trainers:height:000000319557") {
            Ok(v) => v,
            Err(_) => return None,
        }
    } else {
        let key_suffix = format!("{:012}", height);
        match rocksdb::get_prev_or_first(cf, "bic:epoch:trainers:height:", &key_suffix) {
            Ok(Some((_k, v))) => Some(v),
            Ok(None) => None,
            Err(_) => return None,
        }
    };

    let bytes = value?;
    let term = Term::decode(&bytes[..]).ok()?;
    let list = term.get_list()?;
    let mut out = Vec::with_capacity(list.len());
    for t in list {
        let pk = t.get_binary()?;
        if pk.len() != 48 {
            return None;
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(pk);
        out.push(arr);
    }
    Some(out)
}

/// Chain epoch accessor (Elixir: Consensus.chain_epoch/0)
/// Returns current epoch calculated as height / 100_000
pub fn chain_epoch() -> u32 {
    chain_height() / 100_000
}

/// Chain height accessor - gets current blockchain height
pub fn chain_height() -> u32 {
    match rocksdb::get("sysconf", b"temporal_height") {
        Ok(Some(bytes)) => {
            // deserialize the height stored as erlang term
            match bincode::decode_from_slice::<u32, _>(&bytes, bincode::config::standard()) {
                Ok((height, _)) => height,
                Err(_) => 0, // fallback if deserialization fails
            }
        }
        _ => 0, // fallback if key not found
    }
}

/// Latest observed nonce for a signer (Elixir: Consensus.chain_nonce/1)
/// Returns the highest nonce used by this signer
pub fn chain_nonce(signer: &[u8]) -> Option<i128> {
    let key = format!("bic:base:nonce:{}", bs58::encode(signer).into_string());
    match rocksdb::get("contractstate", key.as_bytes()) {
        Ok(Some(bytes)) => {
            // Try to deserialize as i128 (nonce value)
            match bincode::decode_from_slice::<i128, _>(&bytes, bincode::config::standard()) {
                Ok((nonce, _)) => Some(nonce),
                Err(_) => None,
            }
        }
        _ => None,
    }
}

/// Balance accessor (Elixir: Consensus.chain_balance/1)
/// Returns the balance for a given signer and symbol (defaults to "AMA")
pub fn chain_balance(signer: &[u8]) -> u64 {
    chain_balance_symbol(signer, "AMA")
}

/// Balance accessor with specific symbol
pub fn chain_balance_symbol(signer: &[u8], symbol: &str) -> u64 {
    let key = format!("bic:coin:balance:{}:{}", bs58::encode(signer).into_string(), symbol);
    match rocksdb::get("contractstate", key.as_bytes()) {
        Ok(Some(bytes)) => {
            // Try to deserialize as u64 (balance value)
            match bincode::decode_from_slice::<u64, _>(&bytes, bincode::config::standard()) {
                Ok((balance, _)) => balance,
                Err(_) => 0,
            }
        }
        _ => 0, // default to 0 if no balance found
    }
}

/// Get current segment VRF hash for validation
/// TODO: Implement proper segment VRF hash retrieval
pub fn chain_segment_vr_hash() -> [u8; 32] {
    // Stub implementation - returns zeros for now
    [0u8; 32]
}

/// Get current difficulty bits
/// TODO: Implement proper difficulty bits retrieval
pub fn chain_diff_bits() -> u32 {
    // Stub implementation - returns default difficulty
    30
}
