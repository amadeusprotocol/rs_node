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
    pub key: Vec<u8>,           // Raw binary key (NOT String) to support non-UTF8 pubkeys
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
        let items = match db.iter_prefix("contractstate", b"") {
            Ok(items) => items,
            Err(_) => break,
        };
        if items.is_empty() {
            break;
        }
        for (k, _v) in items {
            let _ = db.delete("contractstate", &k);
        }
    }
}

pub fn kv_put(db: &RocksDb, key: &[u8], value: &[u8]) {
    get_store_mut(|ctx| {
        // Get existing value from RocksDB for reverse mutation
        let existed = db.get("contractstate", key).unwrap_or(None);

        // Store in RocksDB
        let _ = db.put("contractstate", key, value);

        // Choose mutation context based on flag
        let (fwd, rev) = if ctx.use_gas_context {
            (&mut ctx.mutations_gas, &mut ctx.mutations_gas_reverse)
        } else {
            (&mut ctx.mutations, &mut ctx.mutations_reverse)
        };

        // forward mutation tracks new value
        fwd.push_back(Mutation { op: Op::Put, key: key.to_vec(), value: Some(value.to_vec()) });
        // reverse mutation: if existed put old value, else delete
        match existed {
            Some(old) => rev.push_back(Mutation { op: Op::Put, key: key.to_vec(), value: Some(old) }),
            None => rev.push_back(Mutation { op: Op::Delete, key: key.to_vec(), value: None }),
        }
    });
}

pub fn kv_increment(db: &RocksDb, key: &[u8], delta: i64) -> i64 {
    get_store_mut(|ctx| {
        // Get current value from RocksDB
        let cur = db.get("contractstate", key).unwrap_or(None).and_then(|v| ascii_i64(&v)).unwrap_or(0);
        let newv = cur.saturating_add(delta);
        let new_bytes = i64_ascii(newv);
        let old_bytes = db.get("contractstate", key).unwrap_or(None);

        // Store updated value in RocksDB
        let _ = db.put("contractstate", key, &new_bytes);

        // Choose mutation context based on flag
        let (fwd, rev) = if ctx.use_gas_context {
            (&mut ctx.mutations_gas, &mut ctx.mutations_gas_reverse)
        } else {
            (&mut ctx.mutations, &mut ctx.mutations_reverse)
        };

        fwd.push_back(Mutation { op: Op::Put, key: key.to_vec(), value: Some(new_bytes) });
        match old_bytes {
            Some(old) => rev.push_back(Mutation { op: Op::Put, key: key.to_vec(), value: Some(old) }),
            None => rev.push_back(Mutation { op: Op::Delete, key: key.to_vec(), value: None }),
        }
        newv
    })
}

pub fn kv_delete(db: &RocksDb, key: &[u8]) {
    get_store_mut(|ctx| {
        if let Some(old) = db.get("contractstate", key).unwrap_or(None) {
            let _ = db.delete("contractstate", key);

            let (fwd, rev) = if ctx.use_gas_context {
                (&mut ctx.mutations_gas, &mut ctx.mutations_gas_reverse)
            } else {
                (&mut ctx.mutations, &mut ctx.mutations_reverse)
            };

            fwd.push_back(Mutation { op: Op::Delete, key: key.to_vec(), value: None });
            rev.push_back(Mutation { op: Op::Put, key: key.to_vec(), value: Some(old) });
        }
    });
}

pub fn kv_get(db: &RocksDb, key: &[u8]) -> Option<Vec<u8>> {
    db.get("contractstate", key).unwrap_or(None)
}

pub fn kv_get_to_i64(db: &RocksDb, key: &[u8]) -> Option<i64> {
    kv_get(db, key).and_then(|v| ascii_i64(&v))
}

pub fn kv_exists(db: &RocksDb, key: &[u8]) -> bool {
    db.get("contractstate", key).unwrap_or(None).is_some()
}

pub fn kv_get_prefix(db: &RocksDb, prefix: &str) -> Vec<(String, Vec<u8>)> {
    match db.iter_prefix("contractstate", prefix.as_bytes()) {
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

pub fn kv_clear(db: &RocksDb, prefix: &[u8]) -> usize {
    get_store_mut(|ctx| {
        // Get all keys with this prefix from RocksDB
        let items = match db.iter_prefix("contractstate", prefix) {
            Ok(items) => items,
            Err(_) => return 0,
        };

        let mut count = 0usize;
        for (k, v) in items {
            if k.starts_with(prefix) {
                // Delete from RocksDB
                let _ = db.delete("contractstate", &k);

                let (fwd, rev) = if ctx.use_gas_context {
                    (&mut ctx.mutations_gas, &mut ctx.mutations_gas_reverse)
                } else {
                    (&mut ctx.mutations, &mut ctx.mutations_reverse)
                };

                fwd.push_back(Mutation { op: Op::Delete, key: k.clone(), value: None });
                rev.push_back(Mutation { op: Op::Put, key: k.clone(), value: Some(v) });
                count += 1;
            }
        }
        count
    })
}

/// Set a bit at bit_idx within a bitstring page. If the bit changes 0->1, returns true;
/// otherwise returns false. Page size defaults to BIC sol bloom size (65_536 bits) when None.
pub fn kv_set_bit(db: &RocksDb, key: &[u8], bit_idx: u32, bloom_size_opt: Option<u32>) -> bool {
    let bloom_size = bloom_size_opt.unwrap_or(65_536);
    let byte_len = (bloom_size as usize).div_ceil(8);
    get_store_mut(|ctx| {
        // Get existing page from RocksDB or create new one
        let mut page = db.get("contractstate", key).unwrap_or(None).unwrap_or_else(|| vec![0u8; byte_len]);

        let byte_i = (bit_idx / 8) as usize;
        let bit_in_byte = (bit_idx % 8) as u8; // LSB first to match Elixir bitstring semantics
        let mask = 1u8 << bit_in_byte;
        let old_set = (page[byte_i] & mask) != 0;
        if old_set {
            // Bit is already set, return false WITHOUT recording mutations (matching Elixir behavior)
            return false;
        }

        // Record mutations ONLY when bit actually changes (forward: set_bit; reverse: clear_bit or delete if not existed)
        let existed = db.get("contractstate", key).unwrap_or(None).is_some();

        let (fwd, rev) = if ctx.use_gas_context {
            (&mut ctx.mutations_gas, &mut ctx.mutations_gas_reverse)
        } else {
            (&mut ctx.mutations, &mut ctx.mutations_reverse)
        };

        fwd.push_back(Mutation { op: Op::SetBit { bit_idx, bloom_size }, key: key.to_vec(), value: None });
        if existed {
            rev.push_back(Mutation { op: Op::ClearBit { bit_idx }, key: key.to_vec(), value: None });
        } else {
            rev.push_back(Mutation { op: Op::Delete, key: key.to_vec(), value: None });
        }

        // Set the bit and store in RocksDB
        page[byte_i] |= mask;
        let _ = db.put("contractstate", key, &page);
        true
    })
}

pub fn hash_mutations(muts: &[Mutation]) -> [u8; 32] {
    use crate::utils::safe_etf::encode_safe_deterministic;
    use eetf::{Atom, Binary, FixInteger, List, Map, Term};
    use std::collections::HashMap;

    // Convert mutations to ETF format (list of maps) matching Elixir structure
    let mut etf_muts = Vec::new();
    for m in muts {
        let mut map = HashMap::new();

        // Add op key
        let op_atom = match &m.op {
            Op::Put => Atom::from("put"),
            Op::Delete => Atom::from("delete"),
            Op::SetBit { .. } => Atom::from("set_bit"),
            Op::ClearBit { .. } => Atom::from("clear_bit"),
        };
        map.insert(Term::Atom(Atom::from("op")), Term::Atom(op_atom));

        // Add key
        map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: m.key.clone() }));

        // Add value field based on op type
        match (&m.op, &m.value) {
            (Op::Put, Some(v)) => {
                map.insert(Term::Atom(Atom::from("value")), Term::Binary(Binary { bytes: v.clone() }));
            }
            (Op::SetBit { bit_idx, bloom_size }, _) => {
                map.insert(Term::Atom(Atom::from("value")), Term::FixInteger(FixInteger { value: *bit_idx as i32 }));
                map.insert(
                    Term::Atom(Atom::from("bloomsize")),
                    Term::FixInteger(FixInteger { value: *bloom_size as i32 }),
                );
            }
            (Op::ClearBit { bit_idx }, _) => {
                map.insert(Term::Atom(Atom::from("value")), Term::FixInteger(FixInteger { value: *bit_idx as i32 }));
            }
            _ => {}
        }

        etf_muts.push(Term::Map(Map { map }));
    }

    // Create list term
    let list_term = Term::List(List { elements: etf_muts });

    // Encode with deterministic ETF encoding (matching Elixir's :erlang.term_to_binary(m, [:deterministic]))
    let encoded = encode_safe_deterministic(&list_term);

    // Hash the encoded bytes
    let h = blake3::hash(&encoded);
    *h.as_bytes()
}

/// Hash mutations with transaction results prepended (matching Elixir: hash_mutations(l ++ m))
/// where l is the list of transaction results and m is the list of mutations
pub fn hash_mutations_with_results(results: &[crate::consensus::consensus::TxResult], muts: &[Mutation]) -> [u8; 32] {
    use crate::utils::safe_etf::encode_safe_deterministic;
    use eetf::{Atom, Binary, FixInteger, List, Map, Term};
    use std::collections::HashMap;

    let mut etf_list = Vec::new();

    // First, add transaction results to the list (matching Elixir's l)
    // Elixir ONLY includes %{error: :ok} or %{error: :some_error} - NO logs field
    for result in results {
        let mut map = HashMap::new();
        map.insert(Term::Atom(Atom::from("error")), Term::Atom(Atom::from(result.error.as_str())));
        etf_list.push(Term::Map(Map { map }));
    }

    // Then, add mutations to the list (matching Elixir's m)
    for m in muts {
        let mut map = HashMap::new();

        // Add op key
        let op_atom = match &m.op {
            Op::Put => Atom::from("put"),
            Op::Delete => Atom::from("delete"),
            Op::SetBit { .. } => Atom::from("set_bit"),
            Op::ClearBit { .. } => Atom::from("clear_bit"),
        };
        map.insert(Term::Atom(Atom::from("op")), Term::Atom(op_atom));

        // Add key
        map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: m.key.clone() }));

        // Add value field based on op type
        match (&m.op, &m.value) {
            (Op::Put, Some(v)) => {
                map.insert(Term::Atom(Atom::from("value")), Term::Binary(Binary { bytes: v.clone() }));
            }
            (Op::SetBit { bit_idx, bloom_size }, _) => {
                map.insert(Term::Atom(Atom::from("value")), Term::FixInteger(FixInteger { value: *bit_idx as i32 }));
                map.insert(
                    Term::Atom(Atom::from("bloomsize")),
                    Term::FixInteger(FixInteger { value: *bloom_size as i32 }),
                );
            }
            (Op::ClearBit { bit_idx }, _) => {
                map.insert(Term::Atom(Atom::from("value")), Term::FixInteger(FixInteger { value: *bit_idx as i32 }));
            }
            _ => {}
        }

        etf_list.push(Term::Map(Map { map }));
    }

    // Create list term
    let list_term = Term::List(List { elements: etf_list });

    // Encode with deterministic ETF encoding
    let encoded = encode_safe_deterministic(&list_term);

    // Hash the encoded bytes
    let h = blake3::hash(&encoded);
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
        buf.extend_from_slice(&(m.key.len() as u32).to_le_bytes());
        buf.extend_from_slice(&m.key);
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

        let key = bin[cursor..cursor + key_len].to_vec();
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
                        let _ = db.put("contractstate", &m.key, v);
                    }
                }
                Op::Delete => {
                    let _ = db.delete("contractstate", &m.key);
                }
                Op::ClearBit { bit_idx } => {
                    if let Some(mut page) = db.get("contractstate", &m.key).unwrap_or(None) {
                        let byte_i = (*bit_idx / 8) as usize;
                        let bit_in_byte = (*bit_idx % 8) as u8;
                        let mask = 1u8 << bit_in_byte;
                        page[byte_i] &= !mask;
                        let _ = db.put("contractstate", &m.key, &page);
                    }
                }
                Op::SetBit { bit_idx, .. } => {
                    if let Some(mut page) = db.get("contractstate", &m.key).unwrap_or(None) {
                        let byte_i = (*bit_idx / 8) as usize;
                        let bit_in_byte = (*bit_idx % 8) as u8;
                        let mask = 1u8 << bit_in_byte;
                        page[byte_i] |= mask;
                        let _ = db.put("contractstate", &m.key, &page);
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
        assert_eq!(kv_get_to_i64(&db, b"a:1"), None);
        let v = kv_increment(&db, b"a:1", 5);
        assert_eq!(v, 5);
        assert_eq!(kv_get_to_i64(&db, b"a:1"), Some(5));
        let v2 = kv_increment(&db, b"a:1", -2);
        assert_eq!(v2, 3);
        assert_eq!(kv_get(&db, b"a:1").unwrap(), b"3".to_vec());
    }

    #[tokio::test]
    async fn prefix_and_clear() {
        let base = tmp_base_for_test(&prefix_and_clear);
        let db = RocksDb::open(base.clone()).await.expect("open test db");
        reset_for_tests(&db);
        kv_put(&db, b"p:x", b"1");
        kv_put(&db, b"p:y", b"2");
        kv_put(&db, b"q:z", b"3");
        let got = kv_get_prefix(&db, "p:");
        assert_eq!(got.len(), 2);
        let cnt = kv_clear(&db, b"p:");
        assert_eq!(cnt, 2);
        assert!(!kv_exists(&db, b"p:x"));
        assert!(kv_exists(&db, b"q:z"));
    }

    #[tokio::test]
    async fn set_bit() {
        let base = tmp_base_for_test(&set_bit);
        let db = RocksDb::open(base.clone()).await.expect("open test db");
        reset_for_tests(&db);
        let changed = kv_set_bit(&db, b"bloom:1", 9, Some(16)); // 2 bytes
        assert!(changed);
        let changed2 = kv_set_bit(&db, b"bloom:1", 9, Some(16));
        assert!(!changed2);
    }
}
