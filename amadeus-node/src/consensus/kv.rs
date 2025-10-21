// Re-export from amadeus-runtime (primary API)
use crate::utils::blake3;
pub use amadeus_runtime::consensus::consensus_apply::{ApplyEnv, CallerEnv};
pub use amadeus_runtime::consensus::consensus_kv;
pub use amadeus_runtime::consensus::consensus_muts::Mutation;
use amadeus_utils::rocksdb::RocksDb;

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
pub fn hash_mutations_with_results(
    results: &[crate::consensus::consensus::TxResult],
    muts: &[Mutation],
) -> [u8; 32] {
    use crate::utils::safe_etf::{encode_safe_deterministic, u64_to_term};
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

        match m {
            Mutation::Put { op: _, key, value } => {
                map.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from("put")));
                map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: key.clone() }));
                map.insert(Term::Atom(Atom::from("value")), Term::Binary(Binary { bytes: value.clone() }));
            }
            Mutation::Delete { op: _, key } => {
                map.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from("delete")));
                map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: key.clone() }));
            }
            Mutation::SetBit { op: _, key, value, bloomsize } => {
                map.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from("set_bit")));
                map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: key.clone() }));
                map.insert(Term::Atom(Atom::from("value")), u64_to_term(*value));
                map.insert(Term::Atom(Atom::from("bloomsize")), u64_to_term(*bloomsize));
            }
            Mutation::ClearBit { op: _, key, value } => {
                map.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from("clear_bit")));
                map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: key.clone() }));
                map.insert(Term::Atom(Atom::from("value")), u64_to_term(*value));
            }
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

