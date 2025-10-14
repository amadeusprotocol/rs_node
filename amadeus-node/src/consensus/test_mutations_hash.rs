use crate::config::Config;
/// Isolated test for mutations hash comparison against Elixir reference implementation
///
/// This test:
/// 1. Copies database from assets/rocksdb/28812308 to /tmp/isolated_contractstate_test
/// 2. Applies entry from assets/rocksdb/entry28812309
/// 3. Compares mutations hash with consensus from assets/rocksdb/consensus28812309
/// 4. Applies reverse mutations to rollback
/// 5. Re-applies entry to verify rollback worked correctly
///
/// Run: `cargo test test_mutations_hash_with_rollback -- --nocapture`
use crate::consensus::consensus::{Consensus, apply_entry};
use crate::consensus::doms::entry::Entry;
use crate::consensus::fabric::Fabric;
use crate::consensus::kv::revert;
use crate::utils::rocksdb::RocksDb;

// Source database (state at height 28812308 - before entry)
// Note: Paths are relative to workspace root (one level up from crate)
const SOURCE_DB_PATH: &str = "../assets/rocksdb/28812308";

// Temporary database path for testing
const DB_PATH: &str = "/tmp/isolated_contractstate_test";

// Paths to test data files (raw ETF-encoded data, no protocol envelope)
const ENTRY_DATA_PATH: &str = "../assets/rocksdb/entry28812309";
const CONSENSUS_DATA_PATH: &str = "../assets/rocksdb/consensus28812309";

/// Helper to recursively copy a directory
fn copy_dir_recursive(src: impl AsRef<std::path::Path>, dst: impl AsRef<std::path::Path>) -> std::io::Result<()> {
    let src = src.as_ref();
    let dst = dst.as_ref();

    // Remove destination if it exists
    if dst.exists() {
        std::fs::remove_dir_all(dst)?;
    }

    std::fs::create_dir_all(dst)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if ty.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_mutations_hash_with_rollback() -> Result<(), Box<dyn std::error::Error>> {
    copy_dir_recursive(SOURCE_DB_PATH, DB_PATH)?;

    // Load test data
    let entry_28812308_data = std::fs::read("../assets/rocksdb/entry28812308")?;
    let entry_28812309_data = std::fs::read(ENTRY_DATA_PATH)?;
    let consensus_data = std::fs::read(CONSENSUS_DATA_PATH)?;

    // 1. Verify entries 28812308 and 28812309 (hashes and links)
    let entry_28812308 = Entry::unpack(&entry_28812308_data).unwrap();
    let expected_hash: [u8; 32] = hex::decode("57c76ddbb68795ea8581108002837033739bdfddcb57dd6062f5871a316ee9f6").unwrap().try_into().unwrap();
    assert_eq!(entry_28812308.hash, expected_hash);

    let entry_28812309 = Entry::unpack(&entry_28812309_data).unwrap();
    assert_eq!(entry_28812309.header.prev_hash, expected_hash);

    // 2. Apply entry 28812309 and get mutations hash
    let db = RocksDb::open(DB_PATH.to_string()).await?;
    let fabric = Fabric::with_db(db);
    let config = create_test_config();

    fabric.db().put("sysconf", b"temporal_height", &((entry_28812309.header.height - 1) as u64).to_be_bytes())?;

    let trainers_key = format!("bic:epoch:trainers:height:{:012}", entry_28812309.header.height);
    if fabric.get_contractstate(trainers_key.as_bytes())?.is_none() {
        let trainers_term = eetf::Term::from(eetf::List {
            elements: vec![eetf::Term::from(eetf::Binary { bytes: config.trainer_pk.to_vec() })],
        });
        let mut trainers_encoded = Vec::new();
        trainers_term.encode(&mut trainers_encoded)?;
        fabric.put_contractstate(trainers_key.as_bytes(), &trainers_encoded)?;
    }

    let result1 = apply_entry(&fabric, &config, &entry_28812309)?;
    assert_eq!(result1.error, "ok");
    let hash1 = result1.mutations_hash;
    let muts1 = result1.muts.clone();

    // Get reverse mutations from database (apply_entry stores them there)
    let muts_rev_bin = fabric.get_muts_rev(&entry_28812309.hash)?.unwrap();
    let muts_rev = crate::consensus::kv::mutations_from_etf(&muts_rev_bin)?;
    println!("First apply: {} mutations, {} reverse", muts1.len(), muts_rev.len());

    // 3. Rollback using reverse mutations
    revert(fabric.db(), &muts_rev);
    crate::consensus::kv::reset();
    fabric.db().put("sysconf", b"temporal_height", &((entry_28812309.header.height - 1) as u64).to_be_bytes())?;

    // Reset trainers if needed (same as initial setup)
    let trainers_key = format!("bic:epoch:trainers:height:{:012}", entry_28812309.header.height);
    if fabric.get_contractstate(trainers_key.as_bytes())?.is_none() {
        let trainers_term = eetf::Term::from(eetf::List {
            elements: vec![eetf::Term::from(eetf::Binary { bytes: config.trainer_pk.to_vec() })],
        });
        let mut trainers_encoded = Vec::new();
        trainers_term.encode(&mut trainers_encoded)?;
        fabric.put_contractstate(trainers_key.as_bytes(), &trainers_encoded)?;
    }

    // 4. Re-apply entry to verify repeatability
    let result2 = apply_entry(&fabric, &config, &entry_28812309)?;
    assert_eq!(result2.error, "ok");
    let hash2 = result2.mutations_hash;
    let muts2 = result2.muts.clone();
    println!("Second apply: {} mutations", muts2.len());

    if hash1 != hash2 {
        println!("Mutations differ:");
        for (i, (m1, m2)) in muts1.iter().zip(muts2.iter()).enumerate() {
            if m1 != m2 {
                println!("Mutation {} differs:", i);
                println!("  First:  op={:?} key={}", m1.op, m1.key);
                println!("  Second: op={:?} key={}", m2.op, m2.key);
            }
        }
        if muts1.len() != muts2.len() {
            println!("Length differs: {} vs {}", muts1.len(), muts2.len());
        }
    }
    assert_eq!(hash1, hash2, "mutations hash must be repeatable");

    // 5. Verify entry hash and mutations hash match consensus
    let consensus = Consensus::from_etf_bin(&consensus_data).unwrap();
    assert_eq!(consensus.entry_hash, entry_28812309.hash);

    if hash2 != consensus.mutations_hash {
        println!("Mutations hash mismatch!");
        println!("Got:      {}", bs58::encode(&hash2).into_string());
        println!("Expected: {}", bs58::encode(&consensus.mutations_hash).into_string());
        debug_mutations_encoding(&result2.muts);
        panic!("Mutations hash mismatch");
    }

    Ok(())
}

/// Helper to create a minimal test config
fn create_test_config() -> Config {
    use std::net::Ipv4Addr;

    // Generate a valid BLS12-381 keypair for testing
    let trainer_sk = crate::config::gen_sk();
    let trainer_pk = crate::config::get_pk(&trainer_sk);
    let trainer_pop = crate::utils::bls12_381::sign(&trainer_sk, &trainer_pk, crate::consensus::DST_POP)
        .map(|sig| sig.to_vec())
        .unwrap_or_else(|_| vec![0u8; 96]);

    Config {
        work_folder: "/tmp/test_config".to_string(),
        version: crate::config::VERSION,
        offline: false,
        http_ipv4: Ipv4Addr::new(127, 0, 0, 1),
        http_port: 80,
        udp_ipv4: Ipv4Addr::new(127, 0, 0, 1),
        udp_port: 36969,
        public_ipv4: Some("127.0.0.1".to_string()),
        seed_ips: vec![],
        seed_anrs: vec![],
        other_nodes: vec![],
        trust_factor: 0.8,
        max_peers: 300,
        trainer_sk,
        trainer_pk,
        trainer_pk_b58: "test_pk".to_string(),
        trainer_pop,
        archival_node: false,
        autoupdate: false,
        computor_type: None,
        snapshot_height: 0,
        anr: None,
        anr_name: None,
        anr_desc: None,
    }
}

/// Debug helper to inspect how mutations are encoded to ETF
fn debug_mutations_encoding(muts: &[crate::consensus::kv::Mutation]) {
    use crate::utils::safe_etf::encode_safe_deterministic;
    use eetf::{Atom, Binary, FixInteger, List, Map, Term};
    use std::collections::HashMap;

    println!("\n=== ETF Encoding Debug ===");

    let mut etf_muts = Vec::new();
    for (i, m) in muts.iter().enumerate() {
        let mut map = HashMap::new();

        // Add op key
        let op_atom = match &m.op {
            crate::consensus::kv::Op::Put => Atom::from("put"),
            crate::consensus::kv::Op::Delete => Atom::from("delete"),
            crate::consensus::kv::Op::SetBit { .. } => Atom::from("set_bit"),
            crate::consensus::kv::Op::ClearBit { .. } => Atom::from("clear_bit"),
        };
        map.insert(Term::Atom(Atom::from("op")), Term::Atom(op_atom));

        // Add key
        map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: m.key.as_bytes().to_vec() }));

        // Add value field based on op type
        match (&m.op, &m.value) {
            (crate::consensus::kv::Op::Put, Some(v)) => {
                map.insert(Term::Atom(Atom::from("value")), Term::Binary(Binary { bytes: v.clone() }));
            }
            (crate::consensus::kv::Op::SetBit { bit_idx, bloom_size }, _) => {
                map.insert(Term::Atom(Atom::from("value")), Term::FixInteger(FixInteger { value: *bit_idx as i32 }));
                map.insert(
                    Term::Atom(Atom::from("bloomsize")),
                    Term::FixInteger(FixInteger { value: *bloom_size as i32 }),
                );
            }
            (crate::consensus::kv::Op::ClearBit { bit_idx }, _) => {
                map.insert(Term::Atom(Atom::from("value")), Term::FixInteger(FixInteger { value: *bit_idx as i32 }));
            }
            _ => {}
        }

        println!("Mutation {}: {:?}", i + 1, map);
        etf_muts.push(Term::Map(Map { map }));
    }

    // Create list term
    let list_term = Term::List(List { elements: etf_muts });

    // Encode
    let encoded = encode_safe_deterministic(&list_term);

    println!("\nETF encoded bytes ({} total):", encoded.len());
    println!("{:02x?}", encoded);

    // Hash
    let h = blake3::hash(&encoded);
    println!("\nBlake3 hash: {}", bs58::encode(h.as_bytes()).into_string());
}

/// Verify chain consistency between entry 28812308 and 28812309
#[tokio::test]
#[ignore]
async fn verify_entry_chain_consistency() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Verifying Entry Chain Consistency ===\n");

    // Read entry 28812308
    let entry_28812308_data =
        std::fs::read("../assets/rocksdb/entry28812308").map_err(|e| format!("Failed to read entry28812308: {}", e))?;
    let entry_28812308 = Entry::unpack(&entry_28812308_data)?;

    // Read entry 28812309
    let entry_28812309_data =
        std::fs::read("../assets/rocksdb/entry28812309").map_err(|e| format!("Failed to read entry28812309: {}", e))?;
    let entry_28812309 = Entry::unpack(&entry_28812309_data)?;

    println!("Entry 28812308:");
    println!("  Hash:   {}", bs58::encode(&entry_28812308.hash).into_string());
    println!("  Height: {}", entry_28812308.header.height);
    println!("  Slot:   {}", entry_28812308.header.slot);
    println!("  TXs:    {}", entry_28812308.txs.len());

    println!("\nEntry 28812309:");
    println!("  Hash:      {}", bs58::encode(&entry_28812309.hash).into_string());
    println!("  Height:    {}", entry_28812309.header.height);
    println!("  Slot:      {}", entry_28812309.header.slot);
    println!("  Prev Hash: {}", bs58::encode(&entry_28812309.header.prev_hash).into_string());
    println!("  TXs:       {}", entry_28812309.txs.len());

    // Verify chain consistency
    println!("\n=== Chain Consistency Checks ===");

    // Check 1: Entry 28812309 prev_hash should match entry 28812308 hash
    if entry_28812309.header.prev_hash == entry_28812308.hash {
        println!("✓ Entry 28812309 prev_hash matches entry 28812308 hash");
    } else {
        println!("✗ Entry 28812309 prev_hash does NOT match entry 28812308 hash");
        println!("  Expected: {}", bs58::encode(&entry_28812308.hash).into_string());
        println!("  Got:      {}", bs58::encode(&entry_28812309.header.prev_hash).into_string());
        return Err("Chain consistency check failed: prev_hash mismatch".into());
    }

    // Check 2: Heights should be sequential
    if entry_28812309.header.height == entry_28812308.header.height + 1 {
        println!("✓ Heights are sequential: {} -> {}", entry_28812308.header.height, entry_28812309.header.height);
    } else {
        println!("✗ Heights are NOT sequential");
        return Err("Chain consistency check failed: heights not sequential".into());
    }

    // Check 3: Slots should be sequential
    if entry_28812309.header.slot == entry_28812308.header.slot + 1 {
        println!("✓ Slots are sequential: {} -> {}", entry_28812308.header.slot, entry_28812309.header.slot);
    } else {
        println!("✗ Slots are NOT sequential");
        return Err("Chain consistency check failed: slots not sequential".into());
    }

    // Check 4: prev_slot should match
    if entry_28812309.header.prev_slot as u32 == entry_28812308.header.slot {
        println!("✓ Entry 28812309 prev_slot matches entry 28812308 slot");
    } else {
        println!("✗ Entry 28812309 prev_slot does NOT match entry 28812308 slot");
        return Err("Chain consistency check failed: prev_slot mismatch".into());
    }

    println!("\n=== SUCCESS ===");
    println!("✓ All chain consistency checks passed");
    println!("✓ Entry 28812308 correctly precedes entry 28812309");

    Ok(())
}

/// Helper test to manually run a specific entry on a specific state
/// Call this from Rust code or test framework with actual data
#[allow(dead_code)]
pub async fn test_entry_execution(
    db_path: &str,
    entry_bytes: &[u8],
    expected_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = RocksDb::open(db_path.to_string()).await?;
    let fabric = Fabric::with_db(db);
    let entry = Entry::unpack(entry_bytes)?;
    let config = create_test_config();

    let result = apply_entry(&fabric, &config, &entry)?;

    if result.error != "ok" {
        return Err(format!("Entry execution failed: {}", result.error).into());
    }

    let rust_hash_str = bs58::encode(&result.mutations_hash).into_string();

    println!("Rust mutations hash: {}", rust_hash_str);
    println!("Expected hash:       {}", expected_hash);

    if rust_hash_str == expected_hash {
        println!("✓ Hashes match!");
        Ok(())
    } else {
        println!("✗ Hashes do not match!");
        debug_mutations_encoding(&result.muts);
        Err("Hash mismatch".into())
    }
}
