use crate::Result;
use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_muts::Mutation;
use amadeus_utils::rocksdb::{BoundColumnFamily, MultiThreaded, RocksDb, RocksDbTxn, Transaction, TransactionDB};
use std::sync::Arc;

pub fn kv_put(env: &mut ApplyEnv, key: &[u8], value: &[u8]) -> Result<()> {
    let old_value = env.txn.get_cf(&env.cf, key).map_err(|_| "kv_get_failed")?;
    env.txn.put_cf(&env.cf, key, value).map_err(|_| "kv_put_failed")?;

    env.muts.push(Mutation::Put { op: b"put".to_vec(), key: key.to_vec(), value: value.to_vec() });
    match old_value {
        None => env.muts_rev.push(Mutation::Delete { op: b"delete".to_vec(), key: key.to_vec() }),
        Some(old) => env.muts_rev.push(Mutation::Put { op: b"put".to_vec(), key: key.to_vec(), value: old }),
    }
    Ok(())
}

pub fn kv_increment(env: &mut ApplyEnv, key: &[u8], value: i128) -> Result<i128> {
    match env.txn.get_cf(&env.cf, key).map_err(|_| "kv_get_failed")? {
        None => {
            env.muts.push(Mutation::Put {
                op: b"put".to_vec(),
                key: key.to_vec(),
                value: value.to_string().into_bytes(),
            });
            env.muts_rev.push(Mutation::Delete { op: b"delete".to_vec(), key: key.to_vec() });
            env.txn.put_cf(&env.cf, key, value.to_string().into_bytes()).map_err(|_| "kv_put_failed")?;
            Ok(value)
        }
        Some(old) => {
            let new_value: i128 = atoi::atoi::<i128>(&old).ok_or("invalid_integer")? + value;
            env.muts.push(Mutation::Put {
                op: b"put".to_vec(),
                key: key.to_vec(),
                value: new_value.to_string().into_bytes(),
            });
            env.muts_rev.push(Mutation::Put { op: b"put".to_vec(), key: key.to_vec(), value: old });
            env.txn.put_cf(&env.cf, key, new_value.to_string().into_bytes()).map_err(|_| "kv_put_failed")?;
            Ok(new_value)
        }
    }
}

pub fn kv_delete(env: &mut ApplyEnv, key: &[u8]) -> Result<()> {
    match env.txn.get_cf(&env.cf, key).map_err(|_| "kv_get_failed")? {
        None => (),
        Some(old) => {
            env.muts.push(Mutation::Delete { op: b"delete".to_vec(), key: key.to_vec() });
            env.muts_rev.push(Mutation::Put { op: b"put".to_vec(), key: key.to_vec(), value: old.to_vec() })
        }
    }
    env.txn.delete_cf(&env.cf, key).map_err(|_| "kv_delete_failed")?;
    Ok(())
}

pub fn kv_set_bit(env: &mut ApplyEnv, key: &[u8], bit_idx: u64) -> Result<bool> {
    let (mut old, exists) = match env.txn.get_cf(&env.cf, key).map_err(|_| "kv_get_failed")? {
        None => (vec![0u8; crate::consensus::bic::sol_bloom::PAGE_SIZE as usize], false),
        Some(value) => (value, true),
    };

    let byte_idx = (bit_idx / 8) as usize;
    let bit_in = (bit_idx % 8) as u8;

    let mask: u8 = 1u8 << (7 - bit_in);

    if (old[byte_idx] & mask) != 0 {
        Ok(false)
    } else {
        env.muts.push(Mutation::SetBit {
            op: b"set_bit".to_vec(),
            key: key.to_vec(),
            value: bit_idx,
            bloomsize: crate::consensus::bic::sol_bloom::PAGE_SIZE,
        });
        match exists {
            true => {
                env.muts_rev.push(Mutation::ClearBit { op: b"clear_bit".to_vec(), key: key.to_vec(), value: bit_idx })
            }
            false => env.muts_rev.push(Mutation::Delete { op: b"delete".to_vec(), key: key.to_vec() }),
        };
        old[byte_idx] |= mask;
        env.txn.put_cf(&env.cf, key, &old).map_err(|_| "kv_put_failed")?;
        Ok(true)
    }
}

pub fn kv_exists(env: &mut ApplyEnv, key: &[u8]) -> Result<bool> {
    Ok(env.txn.get_cf(&env.cf, key).map_err(|_| "kv_get_failed")?.is_some())
}

pub fn kv_get(env: &ApplyEnv, key: &[u8]) -> Result<Option<Vec<u8>>> {
    env.txn.get_cf(&env.cf, key).map_err(|_| "kv_get_failed")
}

pub fn kv_get_next(env: &mut ApplyEnv, prefix: &[u8], key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut seek = Vec::with_capacity(prefix.len() + key.len());
    seek.extend_from_slice(prefix);
    seek.extend_from_slice(key);

    let mut iter = env.txn.raw_iterator_cf(&env.cf);
    iter.seek(&seek);

    if !iter.valid() {
        return None;
    }

    // skip the exact match key if found
    if let Some(k) = iter.key() {
        if k == &seek[..] {
            iter.next();
        }
    }

    match (iter.key(), iter.value()) {
        (Some(k), Some(v)) if k.starts_with(prefix) => {
            // return key without prefix
            let next_key_wo_prefix = k[prefix.len()..].to_vec();
            Some((next_key_wo_prefix, v.to_vec()))
        }
        _ => None,
    }
}

pub fn kv_get_prev(env: &mut ApplyEnv, prefix: &[u8], key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut seek = Vec::with_capacity(prefix.len() + key.len());
    seek.extend_from_slice(prefix);
    seek.extend_from_slice(key);

    let mut iter = env.txn.raw_iterator_cf(&env.cf);
    iter.seek_for_prev(&seek);

    if !iter.valid() {
        return None;
    }

    if let Some(k) = iter.key() {
        if k == &seek[..] {
            iter.prev();
        }
    }

    match (iter.key(), iter.value()) {
        (Some(k), Some(v)) if k.starts_with(prefix) => {
            let prev_key_wo_prefix = k[prefix.len()..].to_vec();
            Some((prev_key_wo_prefix, v.to_vec()))
        }
        _ => None,
    }
}

pub fn kv_get_prev_or_exact(env: &ApplyEnv, prefix: &[u8], key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut seek = Vec::with_capacity(prefix.len() + key.len());
    seek.extend_from_slice(prefix);
    seek.extend_from_slice(key);

    let mut iter = env.txn.raw_iterator_cf(&env.cf);
    iter.seek_for_prev(&seek);

    match (iter.key(), iter.value()) {
        (Some(k), Some(v)) if k.starts_with(prefix) => {
            let key_wo_prefix = k[prefix.len()..].to_vec();
            Some((key_wo_prefix, v.to_vec()))
        }
        _ => None,
    }
}

/// Get all key-value pairs with the given prefix
/// Returns vector of (key_without_prefix, value_bytes)
pub fn kv_get_prefix(env: &ApplyEnv, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut results = Vec::new();
    let mut iter = env.txn.raw_iterator_cf(&env.cf);
    iter.seek(prefix);

    while iter.valid() {
        if let (Some(key), Some(value)) = (iter.key(), iter.value())
            && key.starts_with(prefix)
        {
            // extract key without prefix
            let key_without_prefix = key[prefix.len()..].to_vec();
            results.push((key_without_prefix, value.to_vec()));

            iter.next();
        } else {
            break;
        }
    }

    results
}

/// Clear all keys with the given prefix, tracking mutations for revert
pub fn kv_clear_prefix(env: &mut ApplyEnv, prefix: &[u8]) -> Result<()> {
    // collect all keys with this prefix in a separate scope to drop the iterator
    let mut keys_to_delete = Vec::new();
    let mut iter = env.txn.raw_iterator_cf(&env.cf);
    iter.seek(prefix);

    while iter.valid() {
        if let Some(key) = iter.key()
            && key.starts_with(prefix)
        {
            keys_to_delete.push(key.to_vec());
            iter.next();
        } else {
            break;
        }
    }

    drop(iter); // must explicitly go out of scope before modifying env

    // now we can delete each key and track mutations
    for key in keys_to_delete {
        let _ = kv_delete(env, &key)?;
    }

    Ok(())
}

pub fn revert(env: &mut ApplyEnv) -> Result<()> {
    for m in env.muts_rev.clone() {
        match m {
            Mutation::Put { op: _, key, value } => {
                kv_put(env, key.as_slice(), value.as_slice())?;
            }
            Mutation::Delete { op: _, key } => {
                kv_delete(env, key.as_slice())?;
            }
            Mutation::SetBit { op: _, key: _, value: _, bloomsize: _ } => {
                panic!("SetBit should not be in reverse mutations");
            }
            Mutation::ClearBit { op: _, key, value } => {
                let bit_idx = value;
                if let Some(mut old) = kv_get(env, key.as_slice())? {
                    let byte_idx = (bit_idx / 8) as usize;
                    let bit_in = (bit_idx % 8) as u8;
                    if byte_idx < old.len() {
                        let mask: u8 = 1u8 << (7 - bit_in);
                        old[byte_idx] &= !mask;
                        kv_put(env, key.as_slice(), old.as_slice())?;
                    }
                }
            }
        }
    }

    Ok(())
}

pub fn apply_mutations(db: &RocksDb, cf_name: &str, muts_rev: &[Mutation]) -> Result<()> {
    let cf = db.inner.cf_handle(cf_name).ok_or("cf_handle_failed")?;
    let txn = db.begin_transaction();

    for m in muts_rev {
        match m {
            Mutation::Put { op: _, key, value } => {
                txn.put_cf(&cf, key, value).map_err(|_| "kv_put_failed")?;
            }
            Mutation::Delete { op: _, key } => {
                txn.delete_cf(&cf, key).map_err(|_| "kv_delete_failed")?;
            }
            Mutation::SetBit { op: _, key: _, value: _, bloomsize: _ } => {
                panic!("SetBit should not be in reverse mutations");
            }
            Mutation::ClearBit { op: _, key, value } => {
                let bit_idx = value;
                if let Some(mut old) = txn.get_cf(&cf, key).map_err(|_| "kv_get_failed")? {
                    let byte_idx = (bit_idx / 8) as usize;
                    let bit_in = (bit_idx % 8) as u8;
                    if byte_idx < old.len() {
                        let mask: u8 = 1u8 << (7 - bit_in);
                        old[byte_idx] &= !mask;
                        txn.put_cf(&cf, key, old).map_err(|_| "kv_put_failed")?;
                    }
                }
            }
        }
    }

    Ok(())
}
