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
pub struct ApplyCtx {
    mutations: VecDeque<Mutation>,
    mutations_reverse: VecDeque<Mutation>,
    mutations_gas: VecDeque<Mutation>,
    mutations_gas_reverse: VecDeque<Mutation>,
    use_gas_context: bool,
}

impl ApplyCtx {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all mutations and gas context flag
    pub fn reset(&mut self) {
        self.mutations.clear();
        self.mutations_reverse.clear();
        self.mutations_gas.clear();
        self.mutations_gas_reverse.clear();
        self.use_gas_context = false;
    }

    /// Switch to gas mutation context - all subsequent mutations will go to gas context
    pub fn use_gas_context(&mut self, enable: bool) {
        self.use_gas_context = enable;
    }

    /// Clear only gas mutations (used when starting gas tracking after WASM execution)
    pub fn reset_gas_mutations(&mut self) {
        self.mutations_gas.clear();
        self.mutations_gas_reverse.clear();
    }

    /// Save current mutations to gas context and restore previous mutations
    pub fn save_to_gas_and_restore(&mut self, saved_muts: Vec<Mutation>, saved_muts_rev: Vec<Mutation>) {
        // Save current mutations to gas
        self.mutations_gas = self.mutations.clone();
        self.mutations_gas_reverse = self.mutations_reverse.clone();
        // Restore saved mutations
        self.mutations = saved_muts.into();
        self.mutations_reverse = saved_muts_rev.into();
    }

    /// Test helper to reset context and clear all DB data
    #[cfg(test)]
    pub fn reset_for_tests(&mut self, db: &RocksDb) {
        self.reset();

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

    /// Put a key-value pair
    pub fn put(&mut self, db: &RocksDb, key: &[u8], value: &[u8]) {
        // Get existing value from RocksDB for reverse mutation
        let existed = db.get("contractstate", key).unwrap_or(None);

        // Store in RocksDB
        let _ = db.put("contractstate", key, value);

        // Choose mutation context based on flag
        let (fwd, rev) = if self.use_gas_context {
            (&mut self.mutations_gas, &mut self.mutations_gas_reverse)
        } else {
            (&mut self.mutations, &mut self.mutations_reverse)
        };

        // forward mutation tracks new value
        fwd.push_back(Mutation { op: Op::Put, key: key.to_vec(), value: Some(value.to_vec()) });
        // reverse mutation: if existed put old value, else delete
        match existed {
            Some(old) => rev.push_back(Mutation { op: Op::Put, key: key.to_vec(), value: Some(old) }),
            None => rev.push_back(Mutation { op: Op::Delete, key: key.to_vec(), value: None }),
        }
    }

    /// Increment a value by delta (i128 version for arbitrary-size integers)
    /// Uses ASCII string encoding to match Elixir's :erlang.integer_to_binary
    pub fn increment(&mut self, db: &RocksDb, key: &[u8], delta: i128) -> i128 {
        // Get current value from RocksDB (try ASCII string format)
        let cur = db.get("contractstate", key).unwrap_or(None).and_then(|v| ascii_i128(&v)).unwrap_or(0);
        let newv = cur.saturating_add(delta);
        let new_bytes = i128_ascii(newv);
        let old_bytes = db.get("contractstate", key).unwrap_or(None);

        // Store updated value in RocksDB
        let _ = db.put("contractstate", key, &new_bytes);

        // Choose mutation context based on flag
        let (fwd, rev) = if self.use_gas_context {
            (&mut self.mutations_gas, &mut self.mutations_gas_reverse)
        } else {
            (&mut self.mutations, &mut self.mutations_reverse)
        };

        fwd.push_back(Mutation { op: Op::Put, key: key.to_vec(), value: Some(new_bytes) });
        match old_bytes {
            Some(old) => rev.push_back(Mutation { op: Op::Put, key: key.to_vec(), value: Some(old) }),
            None => rev.push_back(Mutation { op: Op::Delete, key: key.to_vec(), value: None }),
        }
        newv
    }

    /// Legacy increment for i64 (kept for backward compatibility)
    pub fn increment_i64(&mut self, db: &RocksDb, key: &[u8], delta: i64) -> i64 {
        let result = self.increment(db, key, i128::from(delta));
        i64::try_from(result).unwrap_or_else(|_| if result > 0 { i64::MAX } else { i64::MIN })
    }

    /// Delete a key
    pub fn delete(&mut self, db: &RocksDb, key: &[u8]) {
        if let Some(old) = db.get("contractstate", key).unwrap_or(None) {
            let _ = db.delete("contractstate", key);

            let (fwd, rev) = if self.use_gas_context {
                (&mut self.mutations_gas, &mut self.mutations_gas_reverse)
            } else {
                (&mut self.mutations, &mut self.mutations_reverse)
            };

            fwd.push_back(Mutation { op: Op::Delete, key: key.to_vec(), value: None });
            rev.push_back(Mutation { op: Op::Put, key: key.to_vec(), value: Some(old) });
        }
    }

    /// Get a value by key
    pub fn get(&mut self, db: &RocksDb, key: &[u8]) -> Option<Vec<u8>> {
        db.get("contractstate", key).unwrap_or(None)
    }

    /// Get a value as i128
    pub fn get_to_i128(&mut self, db: &RocksDb, key: &[u8]) -> Option<i128> {
        self.get(db, key).and_then(|v| ascii_i128(&v))
    }

    /// Legacy get as i64 (kept for backward compatibility)
    pub fn get_to_i64(&mut self, db: &RocksDb, key: &[u8]) -> Option<i64> {
        self.get_to_i128(db, key).and_then(|v| i64::try_from(v).ok())
    }

    /// Check if a key exists
    pub fn exists(&mut self, db: &RocksDb, key: &[u8]) -> bool {
        db.get("contractstate", key).unwrap_or(None).is_some()
    }

    /// Clear all keys with a given prefix
    pub fn clear(&mut self, db: &RocksDb, prefix: &[u8]) -> usize {
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

                let (fwd, rev) = if self.use_gas_context {
                    (&mut self.mutations_gas, &mut self.mutations_gas_reverse)
                } else {
                    (&mut self.mutations, &mut self.mutations_reverse)
                };

                fwd.push_back(Mutation { op: Op::Delete, key: k.clone(), value: None });
                rev.push_back(Mutation { op: Op::Put, key: k.clone(), value: Some(v) });
                count += 1;
            }
        }
        count
    }

    /// Set a bit at bit_idx within a bitstring page
    pub fn set_bit(&mut self, db: &RocksDb, key: &[u8], bit_idx: u32, bloom_size_opt: Option<u32>) -> bool {
        let bloom_size = bloom_size_opt.unwrap_or(65_536);
        let byte_len = (bloom_size as usize).div_ceil(8);

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

        let (fwd, rev) = if self.use_gas_context {
            (&mut self.mutations_gas, &mut self.mutations_gas_reverse)
        } else {
            (&mut self.mutations, &mut self.mutations_reverse)
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
    }

    /// Get mutations
    pub fn mutations(&self) -> Vec<Mutation> {
        self.mutations.iter().cloned().collect()
    }

    /// Get reverse mutations
    pub fn mutations_reverse(&self) -> Vec<Mutation> {
        self.mutations_reverse.iter().cloned().collect()
    }

    /// Get gas mutations
    pub fn mutations_gas(&self) -> Vec<Mutation> {
        self.mutations_gas.iter().cloned().collect()
    }

    /// Get reverse gas mutations
    pub fn mutations_gas_reverse(&self) -> Vec<Mutation> {
        self.mutations_gas_reverse.iter().cloned().collect()
    }
}

// Helper functions for i128 conversion (matching Elixir's :erlang.integer_to_binary)
fn ascii_i128(bytes: &[u8]) -> Option<i128> {
    let s = std::str::from_utf8(bytes).ok()?;
    s.parse::<i128>().ok()
}

fn i128_ascii(n: i128) -> Vec<u8> {
    n.to_string().into_bytes()
}

// Legacy i64 helpers (kept for backward compatibility)
fn ascii_i64(bytes: &[u8]) -> Option<i64> {
    ascii_i128(bytes).and_then(|v| i64::try_from(v).ok())
}

fn i64_ascii(n: i64) -> Vec<u8> {
    i128_ascii(i128::from(n))
}

// Static utility function - doesn't need context
pub fn get_prefix(db: &RocksDb, prefix: &str) -> Vec<(String, Vec<u8>)> {
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

pub fn hash_mutations(muts: &[Mutation]) -> [u8; 32] {
    use crate::utils::safe_etf::{encode_safe_deterministic, u32_to_term};
    use eetf::{Atom, Binary, List, Map, Term};
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
                map.insert(Term::Atom(Atom::from("value")), u32_to_term(*bit_idx));
                map.insert(Term::Atom(Atom::from("bloomsize")), u32_to_term(*bloom_size));
            }
            (Op::ClearBit { bit_idx }, _) => {
                map.insert(Term::Atom(Atom::from("value")), u32_to_term(*bit_idx));
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
    use crate::utils::safe_etf::{encode_safe_deterministic, u32_to_term};
    use eetf::{Atom, Binary, List, Map, Term};
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
                map.insert(Term::Atom(Atom::from("value")), u32_to_term(*bit_idx));
                map.insert(Term::Atom(Atom::from("bloomsize")), u32_to_term(*bloom_size));
            }
            (Op::ClearBit { bit_idx }, _) => {
                map.insert(Term::Atom(Atom::from("value")), u32_to_term(*bit_idx));
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
        if cursor + 1 > bin.len() {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "incomplete op_code"));
        }
        let op_code = bin[cursor];
        cursor += 1;

        if cursor + 4 > bin.len() {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "incomplete key_len"));
        }
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

// Static utility function - doesn't operate on context
pub fn revert(db: &RocksDb, m_rev: &[Mutation]) {
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
        let mut ctx = ApplyCtx::new();
        ctx.reset_for_tests(&db);
        assert_eq!(ctx.get_to_i64(&db, b"a:1"), None);
        let v = ctx.increment(&db, b"a:1", 5);
        assert_eq!(v, 5);
        assert_eq!(ctx.get_to_i64(&db, b"a:1"), Some(5));
        let v2 = ctx.increment(&db, b"a:1", -2);
        assert_eq!(v2, 3);
        assert_eq!(ctx.get(&db, b"a:1").unwrap(), b"3".to_vec());
    }

    #[tokio::test]
    async fn prefix_and_clear() {
        let base = tmp_base_for_test(&prefix_and_clear);
        let db = RocksDb::open(base.clone()).await.expect("open test db");
        let mut ctx = ApplyCtx::new();
        ctx.reset_for_tests(&db);
        ctx.put(&db, b"p:x", b"1");
        ctx.put(&db, b"p:y", b"2");
        ctx.put(&db, b"q:z", b"3");
        let got = get_prefix(&db, "p:");
        assert_eq!(got.len(), 2);
        let cnt = ctx.clear(&db, b"p:");
        assert_eq!(cnt, 2);
        assert!(!ctx.exists(&db, b"p:x"));
        assert!(ctx.exists(&db, b"q:z"));
    }

    #[tokio::test]
    async fn set_bit() {
        let base = tmp_base_for_test(&set_bit);
        let db = RocksDb::open(base.clone()).await.expect("open test db");
        let mut ctx = ApplyCtx::new();
        ctx.reset_for_tests(&db);
        let changed = ctx.set_bit(&db, b"bloom:1", 9, Some(16)); // 2 bytes
        assert!(changed);
        let changed2 = ctx.set_bit(&db, b"bloom:1", 9, Some(16));
        assert!(!changed2);
    }
}
