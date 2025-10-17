#![allow(clippy::module_inception)]
pub mod agg_sig;
pub mod consensus;
pub mod doms;
pub mod fabric;
pub mod genesis;
pub mod kv;

pub use agg_sig::{
    AggSig, DST, DST_ANR, DST_ANR_CHALLENGE, DST_ATT, DST_ENTRY, DST_MOTION, DST_NODE, DST_POP, DST_TX, DST_VRF,
};

use crate::utils::misc::TermExt;
use crate::utils::rocksdb::RocksDb;
use eetf::Term;

// Re-export from bic module for backward compatibility
pub use crate::bic::epoch::trainers_for_height;
pub use crate::bic::{
    chain_balance, chain_balance_symbol, chain_diff_bits, chain_nonce, chain_pop, chain_segment_vr_hash,
    chain_total_sols,
};

/// Chain epoch accessor (Elixir: Consensus.chain_epoch/0)
/// Returns current epoch calculated as height / 100_000
pub fn chain_epoch(db: &RocksDb) -> u32 {
    chain_height(db) / 100_000
}

/// Chain height accessor - gets current blockchain height
pub fn chain_height(db: &RocksDb) -> u32 {
    match db.get("sysconf", b"temporal_height") {
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

#[cfg(test)]
mod tests {
    use crate::consensus::consensus::apply_entry;
    use crate::consensus::fabric::Fabric;
    use crate::consensus::kv;
    use eetf::Term;
    use std::path::Path;

    #[tokio::test]
    async fn test_apply_entry_34076357() -> Result<(), Box<dyn std::error::Error>> {
        let hash = bs58::decode("DEYRMxK3rCgVvwFagmpJQecbreiLUeYjRxrVfs6yKiJ5").into_vec()?;
        test_apply_entry_at_height(34076436, hash.try_into().map_err(|_| "invalid hash")?).await
    }

    #[tokio::test]
    async fn test_apply_entry_34076383() -> Result<(), Box<dyn std::error::Error>> {
        let hash = bs58::decode("53NtszVMj5nBA7PnaDsLtiSZAX6T6LvmH74BngSVtp6C").into_vec()?;
        test_apply_entry_at_height(34076382, hash.try_into().map_err(|_| "invalid hash")?).await
    }

    #[tokio::test]
    async fn test_apply_entry_34076433() -> Result<(), Box<dyn std::error::Error>> {
        let hash = bs58::decode("12mVLz4waDiBb9qqqnD5KLJMxRvAMaDz6W1pidXA1cm6").into_vec()?;
        test_apply_entry_at_height(34076432, hash.try_into().map_err(|_| "invalid hash")?).await
    }

    async fn test_apply_entry_at_height(
        height: u32,
        expected_muts_hash: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let db_path = format!("../assets/rocksdb/{}", height);
        if !Path::new(&db_path).exists() {
            return Ok(());
        }

        // copy db to temp
        let temp = format!("/tmp/test-rocksdb-{}-{}", height, std::process::id());
        let temp_db = format!("{}/db/fabric", temp);
        if Path::new(&temp).exists() {
            std::fs::remove_dir_all(&temp)?;
        }
        copy_dir(&format!("{}/fabric", db_path), &temp_db)?;

        // open fabric
        let fabric = Fabric::new(&temp).await?;

        // get entry at height+1 from db
        let next_height = height + 1;
        let entries = fabric.entries_by_height(next_height as u64)?;
        let entry = crate::consensus::doms::entry::Entry::unpack(&entries[0])?;

        // read and print expected logs from next_logs file
        let expected_logs_path = format!("{}/next_logs", db_path);
        if Path::new(&expected_logs_path).exists() {
            let expected_logs_bin = std::fs::read(&expected_logs_path)?;
            println!("\n=== Expected logs from next_logs file ===");
            match decode_logs(&expected_logs_bin) {
                Ok(logs) => {
                    for (i, (error, log_list)) in logs.iter().enumerate() {
                        println!("Transaction {}: error={:?}, logs={:?}", i, error, log_list);
                    }
                }
                Err(e) => println!("Failed to decode expected logs: {}", e),
            }
        } else {
            println!("\n=== No next_logs file found ===");
        }

        // apply entry
        let config = create_test_config();
        apply_entry(&fabric, &config, &entry)?;

        // get results
        let muts = crate::consensus::consensus::chain_muts(&fabric, &entry.hash).ok_or("no muts")?;
        let muts_rev = crate::consensus::consensus::chain_muts_rev(&fabric, &entry.hash).ok_or("no muts_rev")?;

        // decode expected from elixir
        let exp_muts = decode_muts(&std::fs::read(format!("{}/next_muts", db_path))?)?;
        let exp_muts_rev = decode_muts(&std::fs::read(format!("{}/next_muts_rev", db_path))?)?;

        // compare mutations
        assert_eq!(muts.len(), exp_muts.len(), "muts count");
        assert_eq!(muts_rev.len(), exp_muts_rev.len(), "muts_rev count");

        for (i, (r, e)) in muts.iter().zip(exp_muts.iter()).enumerate() {
            assert_eq!(r, e, "muts[{}] mismatch", i);
        }

        // verify mutations hash
        let my_att = fabric.my_attestation_by_entryhash(&entry.hash)?.ok_or("no attestation")?;
        assert_eq!(my_att.mutations_hash, expected_muts_hash, "mutations hash mismatch");

        std::fs::remove_dir_all(&temp).ok();
        Ok(())
    }

    fn decode_logs(bin: &[u8]) -> Result<Vec<(String, Vec<String>)>, Box<dyn std::error::Error>> {
        use crate::utils::misc::TermExt;
        let term = Term::decode(bin)?;
        let outer_list = match &term {
            Term::List(l) => l,
            _ => return Err("not list".into()),
        };

        outer_list
            .elements
            .iter()
            .map(|e| {
                let m = match e {
                    Term::Map(m) => &m.map,
                    _ => return Err("not map".into()),
                };

                // get error field
                let error = match m.get(&Term::Atom(eetf::Atom::from("error"))) {
                    Some(Term::Atom(a)) => a.name.as_str().to_string(),
                    _ => return Err("no error field".into()),
                };

                // get logs field (list of binaries)
                let logs = match m.get(&Term::Atom(eetf::Atom::from("logs"))) {
                    Some(Term::List(log_list)) => log_list
                        .elements
                        .iter()
                        .filter_map(|log_term| {
                            log_term.get_binary().map(|bytes| String::from_utf8_lossy(&bytes).to_string())
                        })
                        .collect(),
                    _ => vec![],
                };

                Ok((error, logs))
            })
            .collect()
    }

    fn decode_muts(bin: &[u8]) -> Result<Vec<kv::Mutation>, Box<dyn std::error::Error>> {
        use crate::utils::misc::TermExt;
        let term = Term::decode(bin)?;
        let list = match &term {
            Term::List(l) => l,
            _ => return Err("not list".into()),
        };
        list.elements
            .iter()
            .map(|e| {
                let m = match e {
                    Term::Map(m) => &m.map,
                    _ => return Err("not map".into()),
                };
                let op = match m.get(&Term::Atom(eetf::Atom::from("op"))) {
                    Some(Term::Atom(a)) => a,
                    _ => return Err("no op".into()),
                };
                let key =
                    m.get(&Term::Atom(eetf::Atom::from("key"))).and_then(|t| t.get_binary()).ok_or("no key")?.to_vec();

                let (op, val) = match op.name.as_str() {
                    "put" => {
                        let v = m
                            .get(&Term::Atom(eetf::Atom::from("value")))
                            .and_then(|t| t.get_binary())
                            .ok_or("no val")?
                            .to_vec();
                        (kv::Op::Put, Some(v))
                    }
                    "delete" => (kv::Op::Delete, None),
                    "set_bit" => {
                        let bit = m
                            .get(&Term::Atom(eetf::Atom::from("value")))
                            .and_then(|t| if let Term::FixInteger(i) = t { Some(i.value) } else { None })
                            .ok_or("no bit")? as u32;
                        let size = m
                            .get(&Term::Atom(eetf::Atom::from("bloomsize")))
                            .and_then(|t| if let Term::FixInteger(i) = t { Some(i.value) } else { None })
                            .ok_or("no size")? as u32;
                        (kv::Op::SetBit { bit_idx: bit, bloom_size: size }, None)
                    }
                    "clear_bit" => {
                        let bit = m
                            .get(&Term::Atom(eetf::Atom::from("value")))
                            .and_then(|t| if let Term::FixInteger(i) = t { Some(i.value) } else { None })
                            .ok_or("no bit")? as u32;
                        (kv::Op::ClearBit { bit_idx: bit }, None)
                    }
                    _ => return Err("unknown op".into()),
                };
                Ok(kv::Mutation { op, key, value: val })
            })
            .collect()
    }

    fn copy_dir(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
        std::fs::create_dir_all(&dst)?;
        for e in std::fs::read_dir(src)? {
            let e = e?;
            if e.file_type()?.is_dir() {
                copy_dir(e.path(), dst.as_ref().join(e.file_name()))?;
            } else {
                std::fs::copy(e.path(), dst.as_ref().join(e.file_name()))?;
            }
        }
        Ok(())
    }

    fn create_test_config() -> crate::config::Config {
        let sk = crate::config::gen_sk();
        let pk = crate::config::get_pk(&sk);
        let pop = crate::utils::bls12_381::sign(&sk, &pk, crate::consensus::agg_sig::DST_POP)
            .map(|sig| sig.to_vec())
            .unwrap_or_else(|_| vec![0u8; 96]);
        crate::config::Config {
            work_folder: "/tmp/test".to_string(),
            version: crate::config::VERSION,
            offline: false,
            http_ipv4: std::net::Ipv4Addr::LOCALHOST,
            http_port: 80,
            udp_ipv4: std::net::Ipv4Addr::LOCALHOST,
            udp_port: 36969,
            public_ipv4: None,
            seed_ips: vec![],
            seed_anrs: vec![],
            other_nodes: vec![],
            trust_factor: 0.8,
            max_peers: 300,
            trainer_sk: sk,
            trainer_pk: pk,
            trainer_pk_b58: "test".to_string(),
            trainer_pop: pop,
            archival_node: false,
            autoupdate: false,
            computor_type: None,
            snapshot_height: 0,
            anr: None,
            anr_name: None,
            anr_desc: None,
        }
    }
}
