// Re-export from local kv module (legacy - used only for WASM and old code)
pub use crate::kv::{ApplyCtx, Mutation as MutationLegacy, Op, hash_mutations, mutations_from_etf, mutations_to_etf, revert};

// Re-export from amadeus-consensus (primary API)
pub use amadeus_consensus::consensus::consensus_apply::{ApplyEnv, CallerEnv};
pub use amadeus_consensus::consensus::consensus_kv;
pub use amadeus_consensus::consensus::consensus_muts::Mutation;
use amadeus_utils::rocksdb::RocksDb;
use crate::utils::blake3;

// Consensus-specific utilities that depend on consensus types

/// Static utility function - doesn't need context
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

/// Hash mutations with transaction results prepended (matching Elixir: hash_mutations(l ++ m))
/// where l is the list of transaction results and m is the list of mutations
/// Note: This uses the old Mutation type for backward compatibility
pub fn hash_mutations_with_results(results: &[crate::consensus::consensus::TxResult], muts: &[MutationLegacy]) -> [u8; 32] {
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
    blake3::hash(&encoded)
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
        let changed = ctx.set_bit(&db, b"bloom:1", 9, Some(16)); // 2 bytes
        assert!(changed);
        let changed2 = ctx.set_bit(&db, b"bloom:1", 9, Some(16));
        assert!(!changed2);
    }
}
