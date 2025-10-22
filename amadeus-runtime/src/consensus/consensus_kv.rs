use crate::consensus::consensus_apply;
use consensus_apply::ApplyEnv;

use crate::consensus::consensus_muts;
use consensus_muts::Mutation;

pub fn kv_put<'db>(env: &mut ApplyEnv<'db>, key: &[u8], value: &[u8]) {
    let old_value = env.txn.get(&env.cf, key).unwrap();
    let _ = env.txn.put(&env.cf, key, value);

    env.muts.push(Mutation::Put { op: b"put".to_vec(), key: key.to_vec(), value: value.to_vec() });
    match old_value {
        None => env.muts_rev.push(Mutation::Delete { op: b"delete".to_vec(), key: key.to_vec() }),
        Some(old) => env.muts_rev.push(Mutation::Put { op: b"put".to_vec(), key: key.to_vec(), value: old.to_vec() }),
    }
}

pub fn kv_increment<'db>(env: &mut ApplyEnv<'db>, key: &[u8], value: i128) -> i128 {
    match env.txn.get(&env.cf, key).unwrap() {
        None => {
            env.muts.push(Mutation::Put {
                op: b"put".to_vec(),
                key: key.to_vec(),
                value: value.to_string().into_bytes(),
            });
            env.muts_rev.push(Mutation::Delete { op: b"delete".to_vec(), key: key.to_vec() });
            let _ = env.txn.put(&env.cf, key, &value.to_string().into_bytes());
            value
        }
        Some(old) => {
            let new_value: i128 = atoi::atoi::<i128>(&old).ok_or("invalid_integer").unwrap() + value;
            env.muts.push(Mutation::Put {
                op: b"put".to_vec(),
                key: key.to_vec(),
                value: new_value.to_string().into_bytes(),
            });
            env.muts_rev.push(Mutation::Put { op: b"put".to_vec(), key: key.to_vec(), value: old });
            let _ = env.txn.put(&env.cf, key, &new_value.to_string().into_bytes());
            new_value
        }
    }
}

pub fn kv_delete<'db>(env: &mut ApplyEnv<'db>, key: &[u8]) {
    match env.txn.get(&env.cf, key).unwrap() {
        None => (),
        Some(old) => {
            env.muts.push(Mutation::Delete { op: b"delete".to_vec(), key: key.to_vec() });
            env.muts_rev.push(Mutation::Put { op: b"put".to_vec(), key: key.to_vec(), value: old.to_vec() })
        }
    }
    let _ = env.txn.delete(&env.cf, key);
}

pub fn kv_set_bit<'db>(env: &mut ApplyEnv<'db>, key: &[u8], bit_idx: u64) -> bool {
    let (mut old, exists) = match env.txn.get(&env.cf, key).unwrap() {
        None => (vec![0u8; crate::consensus::bic::sol_bloom::PAGE_SIZE as usize], false),
        Some(value) => (value, true),
    };

    let byte_idx = (bit_idx / 8) as usize;
    let bit_in_byte = (bit_idx % 8) as u8;
    let mask: u8 = 1u8 << (7 - bit_in_byte);

    if (old[byte_idx] & mask) != 0 {
        false
    } else {
        env.muts.push(Mutation::SetBit {
            op: b"set_bit".to_vec(),
            key: key.to_vec(),
            value: bit_idx,
            bloomsize: crate::consensus::bic::sol_bloom::PAGE_SIZE,
        });
        match exists {
            true => env.muts.push(Mutation::ClearBit { op: b"clear_bit".to_vec(), key: key.to_vec(), value: bit_idx }),
            false => env.muts.push(Mutation::Delete { op: b"delete".to_vec(), key: key.to_vec() }),
        };
        old[byte_idx] |= mask;
        let _ = env.txn.put(&env.cf, key, &old).unwrap();
        true
    }
}

pub fn kv_exists<'db>(env: &mut ApplyEnv<'db>, key: &[u8]) -> bool {
    match env.txn.get(&env.cf, key).unwrap() {
        None => false,
        Some(_) => true,
    }
}

pub fn kv_get<'db>(env: &mut ApplyEnv<'db>, key: &[u8]) -> Option<Vec<u8>> {
    env.txn.get(&env.cf, key).unwrap()
}

pub fn kv_get_next<'db>(env: &mut ApplyEnv<'db>, prefix: &[u8], key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut seek = Vec::with_capacity(prefix.len() + key.len());
    seek.extend_from_slice(prefix);
    seek.extend_from_slice(key);

    let mut it = env.txn.raw_iterator_cf(&env.cf).unwrap();
    it.seek(&seek);
    let it_valid = it.valid();
    if !it_valid {
        return None;
    };
    if let Some(k) = it.key() {
        if k == &seek {
            it.next();
        }
    }

    match it.item() {
        Some((k, v)) if k.starts_with(prefix) => {
            let next_key_wo_prefix = k[prefix.len()..].to_vec();
            Some((next_key_wo_prefix, v.to_vec()))
        }
        _ => None,
    }
}

pub fn kv_get_prev<'db>(env: &mut ApplyEnv<'db>, prefix: &[u8], key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut seek = Vec::with_capacity(prefix.len() + key.len());
    seek.extend_from_slice(prefix);
    seek.extend_from_slice(key);

    let mut it = env.txn.raw_iterator_cf(&env.cf).unwrap();
    it.seek_for_prev(&seek);
    let it_valid = it.valid();
    if !it_valid {
        return None;
    };
    if let Some(k) = it.key() {
        if k == &seek {
            it.prev();
        }
    }

    match it.item() {
        Some((k, v)) if k.starts_with(prefix) => {
            let next_key_wo_prefix = k[prefix.len()..].to_vec();
            Some((next_key_wo_prefix, v.to_vec()))
        }
        _ => None,
    }
}
