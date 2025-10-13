use crate::utils::rocksdb::RocksDb;
use blake3;
use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Put,
    Delete,
    SetBit { bit_idx: u32, bloom_size: u32 },
    ClearBit { bit_idx: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mutation {
    pub op: Op,
    pub key: String,
    pub value: Option<Vec<u8>>, // for Put original/new values or for revert
}

#[derive(Default, Debug, Clone)]
struct KvCtx {
    mutations: VecDeque<Mutation>,
    mutations_reverse: VecDeque<Mutation>,
    mutations_gas: VecDeque<Mutation>,
    mutations_gas_reverse: VecDeque<Mutation>,
    use_gas_context: bool,
}

use std::cell::RefCell;

thread_local! {
    static CTX: RefCell<KvCtx> = RefCell::new(KvCtx::default());
}

fn get_store_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut KvCtx) -> R,
{
    CTX.with(|c| f(&mut c.borrow_mut()))
}

fn get_store<F, R>(f: F) -> R
where
    F: FnOnce(&KvCtx) -> R,
{
    CTX.with(|c| f(&c.borrow()))
}

fn ascii_i64(bytes: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(bytes).ok()?;
    s.parse::<i64>().ok()
}

fn i64_ascii(n: i64) -> Vec<u8> {
    n.to_string().into_bytes()
}

pub fn reset() {
    get_store_mut(|ctx| {
        ctx.mutations.clear();
        ctx.mutations_reverse.clear();
        ctx.mutations_gas.clear();
        ctx.mutations_gas_reverse.clear();
        ctx.use_gas_context = false;
    });
}

/// Switch to gas mutation context - all subsequent mutations will go to gas context
pub fn use_gas_context(enable: bool) {
    get_store_mut(|ctx| ctx.use_gas_context = enable);
}

/// Clear only gas mutations (used when starting gas tracking after WASM execution)
pub fn reset_gas_mutations() {
    get_store_mut(|ctx| {
        ctx.mutations_gas.clear();
        ctx.mutations_gas_reverse.clear();
    });
}

/// Save current mutations to gas context and restore previous mutations
pub fn save_to_gas_and_restore(saved_muts: Vec<Mutation>, saved_muts_rev: Vec<Mutation>) {
    get_store_mut(|ctx| {
        // Save current mutations to gas
        ctx.mutations_gas = ctx.mutations.clone();
        ctx.mutations_gas_reverse = ctx.mutations_reverse.clone();
        // Restore saved mutations
        ctx.mutations = saved_muts.into();
        ctx.mutations_reverse = saved_muts_rev.into();
    });
}

#[cfg(test)]
pub fn reset_for_tests(db: &RocksDb) {
    reset(); // Clear mutations

    loop {
        let items = match db.iter_prefix("sysconf", b"") {
            Ok(items) => items,
            Err(_) => break,
        };
        if items.is_empty() {
            break;
        }
        for (k, _v) in items {
            let _ = db.delete("sysconf", &k);
        }
    }
}

pub fn kv_put(db: &RocksDb, key: &str, value: &[u8]) {
    get_store_mut(|ctx| {
        // Get existing value from RocksDB for reverse mutation
        let existed = db.get("sysconf", key.as_bytes()).unwrap_or(None);

        // Store in RocksDB
        let _ = db.put("sysconf", key.as_bytes(), value);

        // Choose mutation context based on flag
        let (fwd, rev) = if ctx.use_gas_context {
            (&mut ctx.mutations_gas, &mut ctx.mutations_gas_reverse)
        } else {
            (&mut ctx.mutations, &mut ctx.mutations_reverse)
        };

        // forward mutation tracks new value
        fwd.push_back(Mutation { op: Op::Put, key: key.to_string(), value: Some(value.to_vec()) });
        // reverse mutation: if existed put old value, else delete
        match existed {
            Some(old) => rev.push_back(Mutation { op: Op::Put, key: key.to_string(), value: Some(old) }),
            None => rev.push_back(Mutation { op: Op::Delete, key: key.to_string(), value: None }),
        }
    });
}

pub fn kv_increment(db: &RocksDb, key: &str, delta: i64) -> i64 {
    get_store_mut(|ctx| {
        // Get current value from RocksDB
        let cur = db.get("sysconf", key.as_bytes()).unwrap_or(None).and_then(|v| ascii_i64(&v)).unwrap_or(0);
        let newv = cur.saturating_add(delta);
        let new_bytes = i64_ascii(newv);
        let old_bytes = db.get("sysconf", key.as_bytes()).unwrap_or(None);

        // Store updated value in RocksDB
        let _ = db.put("sysconf", key.as_bytes(), &new_bytes);

        // Choose mutation context based on flag
        let (fwd, rev) = if ctx.use_gas_context {
            (&mut ctx.mutations_gas, &mut ctx.mutations_gas_reverse)
        } else {
            (&mut ctx.mutations, &mut ctx.mutations_reverse)
        };

        fwd.push_back(Mutation { op: Op::Put, key: key.to_string(), value: Some(new_bytes) });
        match old_bytes {
            Some(old) => rev.push_back(Mutation { op: Op::Put, key: key.to_string(), value: Some(old) }),
            None => rev.push_back(Mutation { op: Op::Delete, key: key.to_string(), value: None }),
        }
        newv
    })
}

pub fn kv_delete(db: &RocksDb, key: &str) {
    get_store_mut(|ctx| {
        if let Some(old) = db.get("sysconf", key.as_bytes()).unwrap_or(None) {
            let _ = db.delete("sysconf", key.as_bytes());

            let (fwd, rev) = if ctx.use_gas_context {
                (&mut ctx.mutations_gas, &mut ctx.mutations_gas_reverse)
            } else {
                (&mut ctx.mutations, &mut ctx.mutations_reverse)
            };

            fwd.push_back(Mutation { op: Op::Delete, key: key.to_string(), value: None });
            rev.push_back(Mutation { op: Op::Put, key: key.to_string(), value: Some(old) });
        }
    });
}

pub fn kv_get(db: &RocksDb, key: &str) -> Option<Vec<u8>> {
    db.get("sysconf", key.as_bytes()).unwrap_or(None)
}

pub fn kv_get_to_i64(db: &RocksDb, key: &str) -> Option<i64> {
    kv_get(db, key).and_then(|v| ascii_i64(&v))
}

pub fn kv_exists(db: &RocksDb, key: &str) -> bool {
    db.get("sysconf", key.as_bytes()).unwrap_or(None).is_some()
}

pub fn kv_get_prefix(db: &RocksDb, prefix: &str) -> Vec<(String, Vec<u8>)> {
    match db.iter_prefix("sysconf", prefix.as_bytes()) {
        Ok(items) => items
            .into_iter()
            .filter_map(|(k, v)| {
                let key_str = String::from_utf8(k).ok()?;
                if key_str.starts_with(prefix) { Some((key_str[prefix.len()..].to_string(), v)) } else { None }
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

pub fn kv_clear(db: &RocksDb, prefix: &str) -> usize {
    get_store_mut(|ctx| {
        // Get all keys with this prefix from RocksDB
        let items = match db.iter_prefix("sysconf", prefix.as_bytes()) {
            Ok(items) => items,
            Err(_) => return 0,
        };

        let mut count = 0usize;
        for (k, v) in items {
            let key_str = match String::from_utf8(k.clone()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if key_str.starts_with(prefix) {
                // Delete from RocksDB
                let _ = db.delete("sysconf", &k);

                let (fwd, rev) = if ctx.use_gas_context {
                    (&mut ctx.mutations_gas, &mut ctx.mutations_gas_reverse)
                } else {
                    (&mut ctx.mutations, &mut ctx.mutations_reverse)
                };

                fwd.push_back(Mutation { op: Op::Delete, key: key_str.clone(), value: None });
                rev.push_back(Mutation { op: Op::Put, key: key_str, value: Some(v) });
                count += 1;
            }
        }
        count
    })
}

/// Set a bit at bit_idx within a bitstring page. If the bit changes 0->1, returns true;
/// otherwise returns false. Page size defaults to BIC sol bloom size (65_536 bits) when None.
pub fn kv_set_bit(db: &RocksDb, key: &str, bit_idx: u32, bloom_size_opt: Option<u32>) -> bool {
    let bloom_size = bloom_size_opt.unwrap_or(65_536);
    let byte_len = (bloom_size as usize).div_ceil(8);
    get_store_mut(|ctx| {
        // Get existing page from RocksDB or create new one
        let mut page = db.get("sysconf", key.as_bytes()).unwrap_or(None).unwrap_or_else(|| vec![0u8; byte_len]);

        let byte_i = (bit_idx / 8) as usize;
        let bit_in_byte = (bit_idx % 8) as u8; // LSB first to match Elixir bitstring semantics
        let mask = 1u8 << bit_in_byte;
        let old_set = (page[byte_i] & mask) != 0;
        if old_set {
            return false;
        }

        // Record mutations (forward: set_bit; reverse: clear_bit or delete if not existed)
        let existed = db.get("sysconf", key.as_bytes()).unwrap_or(None).is_some();

        let (fwd, rev) = if ctx.use_gas_context {
            (&mut ctx.mutations_gas, &mut ctx.mutations_gas_reverse)
        } else {
            (&mut ctx.mutations, &mut ctx.mutations_reverse)
        };

        fwd.push_back(Mutation { op: Op::SetBit { bit_idx, bloom_size }, key: key.to_string(), value: None });
        if existed {
            rev.push_back(Mutation { op: Op::ClearBit { bit_idx }, key: key.to_string(), value: None });
        } else {
            rev.push_back(Mutation { op: Op::Delete, key: key.to_string(), value: None });
        }

        // Set the bit and store in RocksDB
        page[byte_i] |= mask;
        let _ = db.put("sysconf", key.as_bytes(), &page);
        true
    })
}

pub fn hash_mutations(muts: &[Mutation]) -> [u8; 32] {
    // Deterministic compact encoding: [op_code,u32(len(key)),key_bytes, ...]
    // op codes: 0=Put,1=Delete,2=SetBit,3=ClearBit; value included only for Put as length+bytes
    let mut buf = Vec::new();
    for m in muts {
        match &m.op {
            Op::Put => buf.push(0u8),
            Op::Delete => buf.push(1u8),
            Op::SetBit { .. } => buf.push(2u8),
            Op::ClearBit { .. } => buf.push(3u8),
        }
        let k = m.key.as_bytes();
        buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
        buf.extend_from_slice(k);
        match (&m.op, &m.value) {
            (Op::Put, Some(v)) => {
                buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
                buf.extend_from_slice(v);
            }
            (Op::SetBit { bit_idx, bloom_size }, _) => {
                buf.extend_from_slice(&bit_idx.to_le_bytes());
                buf.extend_from_slice(&bloom_size.to_le_bytes());
            }
            (Op::ClearBit { bit_idx }, _) => {
                buf.extend_from_slice(&bit_idx.to_le_bytes());
            }
            _ => {}
        }
    }
    let h = blake3::hash(&buf);
    *h.as_bytes()
}

pub fn mutations_to_etf(muts: &[Mutation]) -> Vec<u8> {
    let mut buf = Vec::new();
    for m in muts {
        match &m.op {
            Op::Put => buf.push(0u8),
            Op::Delete => buf.push(1u8),
            Op::SetBit { .. } => buf.push(2u8),
            Op::ClearBit { .. } => buf.push(3u8),
        }
        let k = m.key.as_bytes();
        buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
        buf.extend_from_slice(k);
        match (&m.op, &m.value) {
            (Op::Put, Some(v)) => {
                buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
                buf.extend_from_slice(v);
            }
            (Op::SetBit { bit_idx, bloom_size }, _) => {
                buf.extend_from_slice(&bit_idx.to_le_bytes());
                buf.extend_from_slice(&bloom_size.to_le_bytes());
            }
            (Op::ClearBit { bit_idx }, _) => {
                buf.extend_from_slice(&bit_idx.to_le_bytes());
            }
            _ => {}
        }
    }
    buf
}

pub fn mutations_from_etf(bin: &[u8]) -> Result<Vec<Mutation>, std::io::Error> {
    let mut mutations = Vec::new();
    let mut cursor = 0;

    while cursor < bin.len() {
        let op_code = bin[cursor];
        cursor += 1;

        let key_len = u32::from_le_bytes([bin[cursor], bin[cursor + 1], bin[cursor + 2], bin[cursor + 3]]) as usize;
        cursor += 4;

        let key = String::from_utf8(bin[cursor..cursor + key_len].to_vec())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid UTF-8 in key"))?;
        cursor += key_len;

        let (op, value) = match op_code {
            0 => {
                let value_len =
                    u32::from_le_bytes([bin[cursor], bin[cursor + 1], bin[cursor + 2], bin[cursor + 3]]) as usize;
                cursor += 4;
                let value = bin[cursor..cursor + value_len].to_vec();
                cursor += value_len;
                (Op::Put, Some(value))
            }
            1 => (Op::Delete, None),
            2 => {
                let bit_idx = u32::from_le_bytes([bin[cursor], bin[cursor + 1], bin[cursor + 2], bin[cursor + 3]]);
                cursor += 4;
                let bloom_size = u32::from_le_bytes([bin[cursor], bin[cursor + 1], bin[cursor + 2], bin[cursor + 3]]);
                cursor += 4;
                (Op::SetBit { bit_idx, bloom_size }, None)
            }
            3 => {
                let bit_idx = u32::from_le_bytes([bin[cursor], bin[cursor + 1], bin[cursor + 2], bin[cursor + 3]]);
                cursor += 4;
                (Op::ClearBit { bit_idx }, None)
            }
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid op code")),
        };

        mutations.push(Mutation { op, key, value });
    }

    Ok(mutations)
}

pub fn mutations() -> Vec<Mutation> {
    get_store(|ctx| ctx.mutations.iter().cloned().collect())
}
pub fn mutations_reverse() -> Vec<Mutation> {
    get_store(|ctx| ctx.mutations_reverse.iter().cloned().collect())
}
pub fn mutations_gas() -> Vec<Mutation> {
    get_store(|ctx| ctx.mutations_gas.iter().cloned().collect())
}
pub fn mutations_gas_reverse() -> Vec<Mutation> {
    get_store(|ctx| ctx.mutations_gas_reverse.iter().cloned().collect())
}

pub fn revert(db: &RocksDb, m_rev: &[Mutation]) {
    get_store_mut(|_ctx| {
        for m in m_rev.iter().rev() {
            match &m.op {
                Op::Put => {
                    if let Some(v) = &m.value {
                        let _ = db.put("sysconf", m.key.as_bytes(), v);
                    }
                }
                Op::Delete => {
                    let _ = db.delete("sysconf", m.key.as_bytes());
                }
                Op::ClearBit { bit_idx } => {
                    if let Some(mut page) = db.get("sysconf", m.key.as_bytes()).unwrap_or(None) {
                        let byte_i = (*bit_idx / 8) as usize;
                        let bit_in_byte = (*bit_idx % 8) as u8;
                        let mask = 1u8 << bit_in_byte;
                        page[byte_i] &= !mask;
                        let _ = db.put("sysconf", m.key.as_bytes(), &page);
                    }
                }
                Op::SetBit { bit_idx, .. } => {
                    if let Some(mut page) = db.get("sysconf", m.key.as_bytes()).unwrap_or(None) {
                        let byte_i = (*bit_idx / 8) as usize;
                        let bit_in_byte = (*bit_idx % 8) as u8;
                        let mask = 1u8 << bit_in_byte;
                        page[byte_i] |= mask;
                        let _ = db.put("sysconf", m.key.as_bytes(), &page);
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::rocksdb::RocksDb;
    use std::any::type_name_of_val;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_base_for_test<F: ?Sized>(f: &F) -> String {
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let fq = type_name_of_val(f);
        format!("/tmp/{}{}", fq, secs)
    }

    #[tokio::test]
    async fn increment_and_get() {
        let base = tmp_base_for_test(&increment_and_get);
        let db = RocksDb::open(base.clone()).await.expect("open test db");
        reset_for_tests(&db);
        assert_eq!(kv_get_to_i64(&db, "a:1"), None);
        let v = kv_increment(&db, "a:1", 5);
        assert_eq!(v, 5);
        assert_eq!(kv_get_to_i64(&db, "a:1"), Some(5));
        let v2 = kv_increment(&db, "a:1", -2);
        assert_eq!(v2, 3);
        assert_eq!(kv_get(&db, "a:1").unwrap(), b"3".to_vec());
    }

    #[tokio::test]
    async fn prefix_and_clear() {
        let base = tmp_base_for_test(&prefix_and_clear);
        let db = RocksDb::open(base.clone()).await.expect("open test db");
        reset_for_tests(&db);
        kv_put(&db, "p:x", b"1");
        kv_put(&db, "p:y", b"2");
        kv_put(&db, "q:z", b"3");
        let got = kv_get_prefix(&db, "p:");
        assert_eq!(got.len(), 2);
        let cnt = kv_clear(&db, "p:");
        assert_eq!(cnt, 2);
        assert!(!kv_exists(&db, "p:x"));
        assert!(kv_exists(&db, "q:z"));
    }

    #[tokio::test]
    async fn set_bit() {
        let base = tmp_base_for_test(&set_bit);
        let db = RocksDb::open(base.clone()).await.expect("open test db");
        reset_for_tests(&db);
        let changed = kv_set_bit(&db, "bloom:1", 9, Some(16)); // 2 bytes
        assert!(changed);
        let changed2 = kv_set_bit(&db, "bloom:1", 9, Some(16));
        assert!(!changed2);
    }
}
