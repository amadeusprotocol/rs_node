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

/// Return trainers for the given height, reading from contractstate CF
/// Special case: heights in 3195570..=3195575 map to fixed key "000000319557"
pub fn trainers_for_height(db: &RocksDb, height: u32) -> Option<Vec<[u8; 48]>> {
    let cf = "contractstate";
    let value: Option<Vec<u8>> = if (3_195_570..=3_195_575).contains(&height) {
        match db.get(cf, b"bic:epoch:trainers:height:000000319557") {
            Ok(v) => v,
            Err(_) => return None,
        }
    } else {
        let key_suffix = format!("{:012}", height);
        match db.get_prev_or_first(cf, "bic:epoch:trainers:height:", &key_suffix) {
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
pub fn chain_epoch(db: &RocksDb) -> u32 {
    chain_height(db) / 100_000
}

/// Chain height accessor - gets current blockchain height
pub fn chain_height(db: &RocksDb) -> u32 {
    match db.get("sysconf", b"temporal_height") {
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
pub fn chain_nonce(db: &RocksDb, signer: &[u8]) -> Option<i128> {
    let key = crate::utils::misc::build_key(b"bic:base:nonce:", signer);
    match db.get("contractstate", &key) {
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
pub fn chain_balance(db: &RocksDb, signer: &[u8]) -> u128 {
    chain_balance_symbol(db, signer, "AMA")
}

/// Balance accessor with specific symbol
pub fn chain_balance_symbol(db: &RocksDb, signer: &[u8], symbol: &str) -> u128 {
    let key =
        crate::utils::misc::build_key_with_suffix(b"bic:coin:balance:", signer, format!(":{}", symbol).as_bytes());
    match db.get("contractstate", &key) {
        Ok(Some(bytes)) => {
            // Try to deserialize as i64 then convert to u128 (balance value stored as i64)
            match bincode::decode_from_slice::<i64, _>(&bytes, bincode::config::standard()) {
                Ok((balance, _)) => balance.max(0) as u128,
                Err(_) => 0,
            }
        }
        _ => 0, // default to 0 if no balance found
    }
}
