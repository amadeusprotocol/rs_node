/// Test for mutations hash comparison for entry 34076357
///
/// This test applies entry 34076357 and verifies:
/// 1. The generated mutations match Elixir's expected mutations
/// 2. The mutations hash matches Elixir's consensus hash: DEYRMxK3rCgVvwFagmpJQecbreiLUeYjRxrVfs6yKiJ5
///
/// CRITICAL FINDING from Elixir node analysis:
/// The mutations_hash is computed from `logs ++ mutations`, NOT just mutations alone!
/// - logs = [%{error: :ok}] from transaction execution results
/// - mutations = state changes from contract execution
/// - combined_hash = blake3(etf_encode(logs ++ mutations))
///
/// IMPORTANT: This test requires the database snapshot at `assets/rocksdb/34076356` to match
/// the exact state of the Elixir node at height 34076356. The current snapshot appears to have
/// different state (e.g., different solution counts, bloom filter states, and balances), causing
/// the mutations to differ from the Elixir reference output.
///
/// Run: `cargo test test_applying_entry_34076357 -- --nocapture`
use crate::config::Config;
use crate::consensus::consensus::apply_entry;
use crate::consensus::doms::entry::Entry;
use crate::consensus::fabric::Fabric;
use crate::consensus::kv::{Mutation, Op};
use crate::utils::rocksdb::RocksDb;
use std::path::Path;

// Database path for testing (state at height 34076356 - before entry)
const DB_PATH: &str = "../assets/rocksdb/34076356";

// Expected Elixir mutations hash for entry 34076357
const EXPECTED_MUTATIONS_HASH: &str = "DEYRMxK3rCgVvwFagmpJQecbreiLUeYjRxrVfs6yKiJ5";

// Entry hash for 34076357
const ENTRY_HASH: &str = "2gTAqZxP2wB2jsoRUVyof8hZdDdFDf7uxYQXQhgVeTsk";

/// Get expected mutations from Elixir output
/// These mutations are what Elixir generates when applying entry 34076357
fn get_expected_mutations() -> Vec<Mutation> {
    // From Elixir iex output (height 34076357):
    // Mutation 1: put bic:base:nonce:<pubkey_bytes> = "1760291515110255478"
    // Mutation 2: put bic:coin:balance:<pubkey_bytes>:AMA = "87359172968597"
    // Mutation 3: put bic:coin:balance:<pubkey2_bytes>:AMA = "593747048871833"
    // Mutation 4: put bic:coin:balance:<zero_bytes>:AMA = "190024695000000"
    // Mutation 5: set_bit bic:epoch:solbloom:236 bit_idx=37899 bloomsize=65536
    // Mutation 6: put bic:epoch:solutions_count:<pubkey_bytes> = "29414"

    // Note: The keys contain raw binary pubkey bytes (48 bytes), not base58
    // The first pubkey from Elixir: [169, 116, 253, 131, 99, 226, 213, 36, ...]
    let pubkey1: Vec<u8> = vec![
        169, 116, 253, 131, 99, 226, 213, 36, 230, 131, 228, 47, 119, 228, 241, 167, 115, 48, 182, 254, 25, 82, 102,
        105, 157, 188, 251, 89, 12, 23, 165, 163, 53, 14, 68, 199, 199, 31, 162, 150, 137, 160, 19, 9, 212, 227, 136,
        137,
    ];

    // Second pubkey from Mutation 3: [149, 123, 95, 108, 38, 249, 41, 49, ...]
    let pubkey2: Vec<u8> = vec![
        149, 123, 95, 108, 38, 249, 41, 49, 137, 178, 203, 51, 87, 217, 50, 136, 157, 192, 35, 227, 54, 165, 52, 12,
        72, 196, 214, 121, 105, 87, 38, 112, 157, 156, 100, 11, 195, 11, 29, 113, 70, 228, 232, 18, 31, 162, 54, 229,
    ];

    // Zero pubkey from Mutation 4 (burn address): all zeros (48 bytes)
    let zero_pubkey: Vec<u8> = vec![0u8; 48];

    // Build keys with raw binary pubkeys (NOT base58!)
    let mut key1 = b"bic:base:nonce:".to_vec();
    key1.extend_from_slice(&pubkey1);

    let mut key2 = b"bic:coin:balance:".to_vec();
    key2.extend_from_slice(&pubkey1);
    key2.extend_from_slice(b":AMA");

    let mut key3 = b"bic:coin:balance:".to_vec();
    key3.extend_from_slice(&pubkey2);
    key3.extend_from_slice(b":AMA");

    let mut key4 = b"bic:coin:balance:".to_vec();
    key4.extend_from_slice(&zero_pubkey);
    key4.extend_from_slice(b":AMA");

    let key5 = "bic:epoch:solbloom:236".to_string();

    let mut key6 = b"bic:epoch:solutions_count:".to_vec();
    key6.extend_from_slice(&pubkey1);

    vec![
        Mutation { op: Op::Put, key: key1, value: Some(b"1760291515110255478".to_vec()) },
        Mutation { op: Op::Put, key: key2, value: Some(b"87359172968597".to_vec()) },
        Mutation { op: Op::Put, key: key3, value: Some(b"593747048871833".to_vec()) },
        Mutation { op: Op::Put, key: key4, value: Some(b"190024695000000".to_vec()) },
        Mutation { op: Op::SetBit { bit_idx: 37899, bloom_size: 65536 }, key: key5.as_bytes().to_vec(), value: None },
        Mutation { op: Op::Put, key: key6, value: Some(b"29414".to_vec()) },
    ]
}

/// Get expected reverse mutations from Elixir output
/// These mutations represent the OLD state before applying entry 34076357
fn get_expected_reverse_mutations() -> Vec<Mutation> {
    // From Elixir iex output (reverse mutations - state at height 34076356):
    // Reverse mutation 1: put bic:base:nonce:<pubkey_bytes> = "1760291514077609349" (old nonce)
    // Reverse mutation 2: put bic:coin:balance:<pubkey_bytes>:AMA = "87359192968597" (old balance)
    // Reverse mutation 3: put bic:coin:balance:<pubkey2_bytes>:AMA = "593747038871833" (old balance)
    // Reverse mutation 4: put bic:coin:balance:<zero_bytes>:AMA = "190024685000000" (old balance)
    // Reverse mutation 5: clear_bit bic:epoch:solbloom:236 bit_idx=37899 (reverse of set_bit)
    // Reverse mutation 6: put bic:epoch:solutions_count:<pubkey_bytes> = "29413" (old count)

    let pubkey1: Vec<u8> = vec![
        169, 116, 253, 131, 99, 226, 213, 36, 230, 131, 228, 47, 119, 228, 241, 167, 115, 48, 182, 254, 25, 82, 102,
        105, 157, 188, 251, 89, 12, 23, 165, 163, 53, 14, 68, 199, 199, 31, 162, 150, 137, 160, 19, 9, 212, 227, 136,
        137,
    ];

    let pubkey2: Vec<u8> = vec![
        149, 123, 95, 108, 38, 249, 41, 49, 137, 178, 203, 51, 87, 217, 50, 136, 157, 192, 35, 227, 54, 165, 52, 12,
        72, 196, 214, 121, 105, 87, 38, 112, 157, 156, 100, 11, 195, 11, 29, 113, 70, 228, 232, 18, 31, 162, 54, 229,
    ];

    let zero_pubkey: Vec<u8> = vec![0u8; 48];

    // Build keys with raw binary pubkeys
    let mut key1 = b"bic:base:nonce:".to_vec();
    key1.extend_from_slice(&pubkey1);

    let mut key2 = b"bic:coin:balance:".to_vec();
    key2.extend_from_slice(&pubkey1);
    key2.extend_from_slice(b":AMA");

    let mut key3 = b"bic:coin:balance:".to_vec();
    key3.extend_from_slice(&pubkey2);
    key3.extend_from_slice(b":AMA");

    let mut key4 = b"bic:coin:balance:".to_vec();
    key4.extend_from_slice(&zero_pubkey);
    key4.extend_from_slice(b":AMA");

    let key5 = "bic:epoch:solbloom:236".to_string();

    let mut key6 = b"bic:epoch:solutions_count:".to_vec();
    key6.extend_from_slice(&pubkey1);

    vec![
        Mutation { op: Op::Put, key: key1, value: Some(b"1760291514077609349".to_vec()) },
        Mutation { op: Op::Put, key: key2, value: Some(b"87359192968597".to_vec()) },
        Mutation { op: Op::Put, key: key3, value: Some(b"593747038871833".to_vec()) },
        Mutation { op: Op::Put, key: key4, value: Some(b"190024685000000".to_vec()) },
        Mutation { op: Op::ClearBit { bit_idx: 37899 }, key: key5.as_bytes().to_vec(), value: None },
        Mutation { op: Op::Put, key: key6, value: Some(b"29413".to_vec()) },
    ]
}

#[tokio::test]
async fn test_applying_entry_34076357() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Testing Entry 34076357 Application ===\n");

    // Check if source database exists
    if !Path::new(DB_PATH).exists() {
        println!("⚠ Database not found at: {}", DB_PATH);
        println!("  Skipping test...");
        return Ok(());
    }

    // Create temporary database copy
    let temp_db_path = format!("/tmp/test_34076357_{}", std::process::id());
    println!("Creating temporary database at: {}", temp_db_path);

    // Remove if exists
    if Path::new(&temp_db_path).exists() {
        std::fs::remove_dir_all(&temp_db_path)?;
    }

    // Copy database recursively to temp_db_path/db (RocksDb::open appends "/db" to the base path)
    let db_target_path = format!("{}/db", temp_db_path);
    copy_dir_all(DB_PATH, &db_target_path)?;
    println!("✓ Database copied to temporary location: {}", db_target_path);

    // Hardcoded entry 34076357
    use crate::consensus::doms::entry::EntryHeader;

    // Helper to convert Vec<u8> to fixed array
    fn to_array_32(v: Vec<u8>) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        Ok(v.try_into().map_err(|_| "wrong size")?)
    }
    fn to_array_48(v: Vec<u8>) -> Result<[u8; 48], Box<dyn std::error::Error>> {
        Ok(v.try_into().map_err(|_| "wrong size")?)
    }
    fn to_array_96(v: Vec<u8>) -> Result<[u8; 96], Box<dyn std::error::Error>> {
        Ok(v.try_into().map_err(|_| "wrong size")?)
    }

    let entry = Entry {
        hash: to_array_32(bs58::decode("2gTAqZxP2wB2jsoRUVyof8hZdDdFDf7uxYQXQhgVeTsk").into_vec()?)?,
        header: EntryHeader {
            slot: 34076357,
            dr: to_array_32(bs58::decode("Hj8RLwKEsGdEiXU6GTYcAyhKyUwfZLwsxToFYhNKgAqm").into_vec()?)?,
            height: 34076357,
            prev_hash: to_array_32(bs58::decode("67hzgMLoxWMwy81wYq6v57mMVDnCMu6ayDmJnCUrTRba").into_vec()?)?,
            prev_slot: 34076356,
            signer: to_array_48(bs58::decode("6V345vMryLBt31kvTPxSKPwDTegCU3fWe6PQjKqopmoDcb76cMLY7kw8kar8fcs4se").into_vec()?)?,
            txs_hash: to_array_32(bs58::decode("7cZyH7DUySXnWhJE3VsDPbtrhh8hr4z7byECVCGCbT8f").into_vec()?)?,
            vr: to_array_96(bs58::decode("qiioVcERd9csipMca7j4c1inpXS2aY7HpaB7mXoS9s7o83bDH2cXrs1qGEUHms4QSQVxNBnc2ssNT3cnrrd8pQNpkJMvDDEhZaaRs5tCExTJnQnWSEVy5ZqgkgnXN21DEqc").into_vec()?)?,
        },
        signature: to_array_96(bs58::decode("sTEtJzKWLTWCUwP9vr8vHRuEFjaw2pQkp69smFLNjzWdaTzC6ikra74MrVZRTbV9yikuur38CXksoLfqucigiyoTfJXcZeeCYdWo77Cva7qh1iAfzmXjDmNuYiDMA3Vi12Z").into_vec()?)?,
        mask: None,
        txs: vec![bs58::decode("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").into_vec()?],
    };

    println!("\nEntry loaded:");
    println!("  Hash:   {}", bs58::encode(&entry.hash).into_string());
    println!("  Height: {}", entry.header.height);
    println!("  Slot:   {}", entry.header.slot);
    println!("  TXs:    {}", entry.txs.len());

    // Verify entry hash
    let expected_entry_hash = bs58::decode(ENTRY_HASH).into_vec()?;
    assert_eq!(entry.hash.as_slice(), expected_entry_hash.as_slice(), "Entry hash mismatch");
    println!("✓ Entry hash verified");

    // Open temporary database
    let db = RocksDb::open(temp_db_path.clone()).await?;
    let fabric = Fabric::with_db(db.clone());
    let config = create_test_config();

    // Set up chain state for height 34076356
    db.put("sysconf", b"temporal_height", &(34076356u64).to_be_bytes())?;

    // Set up trainers for height 34076357
    let trainers_key = format!("bic:epoch:trainers:height:{:012}", 34076357).into_bytes();
    if fabric.db().get("contractstate", &trainers_key)?.is_none() {
        let trainers_term = eetf::Term::from(eetf::List {
            elements: vec![eetf::Term::from(eetf::Binary { bytes: config.trainer_pk.to_vec() })],
        });
        let mut trainers_encoded = Vec::new();
        trainers_term.encode(&mut trainers_encoded)?;
        fabric.db().put("contractstate", &trainers_key, &trainers_encoded)?;
    }

    // NOTE: The test database at assets/rocksdb/34076356 should already contain the correct
    // initial state matching Elixir at height 34076356, including bloom page 0 with bit 0 set.
    // If the test fails with 7 mutations instead of 6, it means bloom page 0 bit 0 is missing.

    println!("\n=== Applying Entry ===");
    let _attestation = apply_entry(&fabric, &config, &entry)?;
    println!("✓ Entry applied successfully");

    // Retrieve mutations from fabric storage
    let result_muts =
        crate::consensus::consensus::chain_muts(&fabric, &entry.hash).ok_or("No mutations found in database")?;

    // Get expected forward mutations
    let expected_muts = get_expected_mutations();
    println!("\n=== Forward Mutations Comparison ===");
    println!("Rust generated {} mutations", result_muts.len());
    println!("Elixir expected {} mutations", expected_muts.len());

    // Get expected reverse mutations
    let expected_muts_rev = get_expected_reverse_mutations();

    // Read reverse mutations from database (stored by apply_entry)
    let muts_rev = crate::consensus::consensus::chain_muts_rev(&fabric, &entry.hash);

    println!("\n=== Reverse Mutations Comparison ===");
    if let Some(ref rust_muts_rev) = muts_rev {
        println!("Rust generated {} reverse mutations", rust_muts_rev.len());
        println!("Elixir expected {} reverse mutations", expected_muts_rev.len());

        // Compare reverse mutations count
        if rust_muts_rev.len() != expected_muts_rev.len() {
            println!("✗ Reverse mutation count mismatch!");
            println!("\nRust reverse mutations:");
            for (i, m) in rust_muts_rev.iter().enumerate() {
                println!("  {}: {:?} key={:?}", i + 1, m.op, String::from_utf8_lossy(&m.key));
                if let Some(v) = &m.value {
                    println!("      value={:?}", String::from_utf8_lossy(v));
                }
            }
            println!("\nExpected reverse mutations:");
            for (i, m) in expected_muts_rev.iter().enumerate() {
                println!("  {}: {:?} key={:?}", i + 1, m.op, String::from_utf8_lossy(&m.key));
                if let Some(v) = &m.value {
                    println!("      value={:?}", String::from_utf8_lossy(v));
                }
            }
        } else {
            // Compare each reverse mutation
            let mut all_match = true;
            for (i, (rust_mut, expected_mut)) in rust_muts_rev.iter().zip(expected_muts_rev.iter()).enumerate() {
                if rust_mut.key != expected_mut.key
                    || rust_mut.op != expected_mut.op
                    || rust_mut.value != expected_mut.value
                {
                    all_match = false;
                    println!("✗ Reverse mutation {} mismatch:", i + 1);
                    println!(
                        "  Rust:     op={:?}, key={:?}, value={:?}",
                        rust_mut.op,
                        String::from_utf8_lossy(&rust_mut.key),
                        rust_mut.value.as_ref().map(|v| String::from_utf8_lossy(v))
                    );
                    println!(
                        "  Expected: op={:?}, key={:?}, value={:?}",
                        expected_mut.op,
                        String::from_utf8_lossy(&expected_mut.key),
                        expected_mut.value.as_ref().map(|v| String::from_utf8_lossy(v))
                    );
                }
            }
            if all_match {
                println!("✓ All reverse mutations match Elixir!");
            }
        }
    } else {
        println!("✗ No reverse mutations found in database!");
    }

    // Compare mutations count
    if result_muts.len() != expected_muts.len() {
        println!("✗ Mutation count mismatch: got {}, expected {}", result_muts.len(), expected_muts.len());
        println!("\nRust mutations:");
        for (i, m) in result_muts.iter().enumerate() {
            println!("  {}: {:?} key={:?}", i + 1, m.op, String::from_utf8_lossy(&m.key));
            if let Some(v) = &m.value {
                println!("      value={:?}", String::from_utf8_lossy(v));
            }
        }
        println!("\nExpected mutations:");
        for (i, m) in expected_muts.iter().enumerate() {
            println!("  {}: {:?} key={:?}", i + 1, m.op, String::from_utf8_lossy(&m.key));
            if let Some(v) = &m.value {
                println!("      value={:?}", String::from_utf8_lossy(v));
            }
        }
    }

    // Get mutations hash from our stored attestation
    println!("\n=== Mutations Hash Comparison ===");
    let my_att =
        crate::consensus::consensus::my_attestation_by_entryhash(&db, &entry.hash).ok_or("No attestation found")?;
    let rust_hash = bs58::encode(&my_att.mutations_hash).into_string();

    println!("Rust hash:     {}", rust_hash);
    println!("Expected hash: {}", EXPECTED_MUTATIONS_HASH);
    assert_eq!(rust_hash, EXPECTED_MUTATIONS_HASH, "Mutations hash mismatch");

    // Cleanup temporary database
    println!("\nCleaning up temporary database...");
    std::fs::remove_dir_all(&temp_db_path).ok();

    if rust_hash == EXPECTED_MUTATIONS_HASH {
        println!("✓ Mutations hash matches!");
        Ok(())
    } else {
        println!("✗ Mutations hash mismatch!");
        debug_mutations_encoding(&result_muts);
        Err("Mutations hash mismatch".into())
    }
}

/// Helper function to recursively copy a directory
fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> std::io::Result<()> {
    std::fs::create_dir_all(&dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

/// Helper to create a minimal test config
fn create_test_config() -> Config {
    use std::net::Ipv4Addr;

    // Generate a valid BLS12-381 keypair for testing
    let trainer_sk = crate::config::gen_sk();
    let trainer_pk = crate::config::get_pk(&trainer_sk);
    let trainer_pop = crate::utils::bls12_381::sign(&trainer_sk, &trainer_pk, crate::consensus::agg_sig::DST_POP)
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

/// Test that verifies chain rewind and re-apply produces identical mutations
///
/// NOTE: This test requires a complete database with all column families (tx, entry, etc.)
/// The current test database at assets/rocksdb/34076356 may be missing some column families
/// needed for the rewind operation.
#[tokio::test]
#[ignore]
async fn test_entry_34076357_rewind_and_reapply() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Testing Entry 34076357 Apply -> Rewind -> Re-apply ===\n");

    // Check if source database exists
    if !Path::new(DB_PATH).exists() {
        println!("⚠ Database not found at: {}", DB_PATH);
        println!("  Skipping test...");
        return Ok(());
    }

    // Create temporary database copy
    let temp_db_path = format!("/tmp/test_rewind_34076357_{}", std::process::id());
    println!("Creating temporary database at: {}", temp_db_path);

    // Remove if exists
    if Path::new(&temp_db_path).exists() {
        std::fs::remove_dir_all(&temp_db_path)?;
    }

    // Copy database recursively
    let db_target_path = format!("{}/db", temp_db_path);
    copy_dir_all(DB_PATH, &db_target_path)?;
    println!("✓ Database copied to temporary location");

    // Load entry
    use crate::consensus::doms::entry::EntryHeader;
    fn to_array_32(v: Vec<u8>) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        Ok(v.try_into().map_err(|_| "wrong size")?)
    }
    fn to_array_48(v: Vec<u8>) -> Result<[u8; 48], Box<dyn std::error::Error>> {
        Ok(v.try_into().map_err(|_| "wrong size")?)
    }
    fn to_array_96(v: Vec<u8>) -> Result<[u8; 96], Box<dyn std::error::Error>> {
        Ok(v.try_into().map_err(|_| "wrong size")?)
    }

    let entry = Entry {
        hash: to_array_32(bs58::decode("2gTAqZxP2wB2jsoRUVyof8hZdDdFDf7uxYQXQhgVeTsk").into_vec()?)?,
        header: EntryHeader {
            slot: 34076357,
            dr: to_array_32(bs58::decode("Hj8RLwKEsGdEiXU6GTYcAyhKyUwfZLwsxToFYhNKgAqm").into_vec()?)?,
            height: 34076357,
            prev_hash: to_array_32(bs58::decode("67hzgMLoxWMwy81wYq6v57mMVDnCMu6ayDmJnCUrTRba").into_vec()?)?,
            prev_slot: 34076356,
            signer: to_array_48(bs58::decode("6V345vMryLBt31kvTPxSKPwDTegCU3fWe6PQjKqopmoDcb76cMLY7kw8kar8fcs4se").into_vec()?)?,
            txs_hash: to_array_32(bs58::decode("7cZyH7DUySXnWhJE3VsDPbtrhh8hr4z7byECVCGCbT8f").into_vec()?)?,
            vr: to_array_96(bs58::decode("qiioVcERd9csipMca7j4c1inpXS2aY7HpaB7mXoS9s7o83bDH2cXrs1qGEUHms4QSQVxNBnc2ssNT3cnrrd8pQNpkJMvDDEhZaaRs5tCExTJnQnWSEVy5ZqgkgnXN21DEqc").into_vec()?)?,
        },
        signature: to_array_96(bs58::decode("sTEtJzKWLTWCUwP9vr8vHRuEFjaw2pQkp69smFLNjzWdaTzC6ikra74MrVZRTbV9yikuur38CXksoLfqucigiyoTfJXcZeeCYdWo77Cva7qh1iAfzmXjDmNuYiDMA3Vi12Z").into_vec()?)?,
        mask: None,
        txs: vec![bs58::decode("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").into_vec()?],
    };

    // Open database
    let db = RocksDb::open(temp_db_path.clone()).await?;
    let fabric = Fabric::with_db(db.clone());
    let config = create_test_config();

    // Set up chain state
    db.put("sysconf", b"temporal_height", &(34076356u64).to_be_bytes())?;

    // Set up trainers
    let trainers_key = format!("bic:epoch:trainers:height:{:012}", 34076357).into_bytes();
    if fabric.db().get("contractstate", &trainers_key)?.is_none() {
        let trainers_term = eetf::Term::from(eetf::List {
            elements: vec![eetf::Term::from(eetf::Binary { bytes: config.trainer_pk.to_vec() })],
        });
        let mut trainers_encoded = Vec::new();
        trainers_term.encode(&mut trainers_encoded)?;
        fabric.db().put("contractstate", &trainers_key, &trainers_encoded)?;
    }

    // NOTE: The test database at assets/rocksdb/34076356 should already contain the correct
    // initial state matching Elixir at height 34076356, including bloom page 0 with bit 0 set.
    // If the test fails, it means the database state doesn't match Elixir's state at this height.

    // Define key variables needed for verification later in the test.
    let pubkey1: [u8; 48] = [
        169, 116, 253, 131, 99, 226, 213, 36, 230, 131, 228, 47, 119, 228, 241, 167, 115, 48, 182, 254, 25, 82, 102,
        105, 157, 188, 251, 89, 12, 23, 165, 163, 53, 14, 68, 199, 199, 31, 162, 150, 137, 160, 19, 9, 212, 227, 136,
        137,
    ];
    let nonce_key = crate::utils::misc::bcat(&[b"bic:base:nonce:", &pubkey1]);
    let balance_key1 = crate::utils::misc::bcat(&[b"bic:coin:balance:", &pubkey1, b":AMA"]);

    // === FIRST APPLICATION ===
    println!("\n=== STEP 1: First Application ===");
    let _attestation1 = apply_entry(&fabric, &config, &entry)?;
    println!("✓ First application successful");

    let result1_muts = crate::consensus::consensus::chain_muts(&fabric, &entry.hash)
        .ok_or("No mutations found after first application")?;
    let my_att1 = crate::consensus::consensus::my_attestation_by_entryhash(&db, &entry.hash)
        .ok_or("No attestation found after first application")?;
    println!("  Forward mutations: {}", result1_muts.len());
    println!("  Mutations hash: {}", bs58::encode(&my_att1.mutations_hash).into_string());

    // Get reverse mutations from database
    let reverse_muts1 = crate::consensus::consensus::chain_muts_rev(&fabric, &entry.hash)
        .ok_or("No reverse mutations found after first application")?;
    println!("  Reverse mutations: {}", reverse_muts1.len());

    // Verify state after first application
    let balance_after_first =
        fabric.db().get("contractstate", &balance_key1)?.ok_or("Balance not found after first application")?;
    let balance_after_first_str = String::from_utf8_lossy(&balance_after_first);
    println!("  Balance after: {}", balance_after_first_str);
    assert_eq!(balance_after_first_str, "87359172968597", "Balance mismatch after first application");

    // === REWIND ===
    println!("\n=== STEP 2: Rewind ===");
    let rewound = crate::consensus::consensus::chain_rewind(&db, &entry.hash)?;
    assert!(rewound, "Rewind failed");
    println!("✓ Rewind successful");

    // Verify state restored after rewind
    let balance_after_rewind = fabric.db().get("contractstate", &balance_key1)?.ok_or("Balance not found after rewind")?;
    let balance_after_rewind_str = String::from_utf8_lossy(&balance_after_rewind);
    println!("  Balance after rewind: {}", balance_after_rewind_str);
    assert_eq!(balance_after_rewind_str, "87359192968597", "Balance not restored after rewind");

    let nonce_after_rewind = fabric.db().get("contractstate", &nonce_key)?.ok_or("Nonce not found after rewind")?;
    let nonce_after_rewind_str = String::from_utf8_lossy(&nonce_after_rewind);
    println!("  Nonce after rewind: {}", nonce_after_rewind_str);
    assert_eq!(nonce_after_rewind_str, "1760291514077609349", "Nonce not restored after rewind");

    // === SECOND APPLICATION ===
    println!("\n=== STEP 3: Second Application ===");
    let _attestation2 = apply_entry(&fabric, &config, &entry)?;
    println!("✓ Second application successful");

    let result2_muts = crate::consensus::consensus::chain_muts(&fabric, &entry.hash)
        .ok_or("No mutations found after second application")?;
    let my_att2 = crate::consensus::consensus::my_attestation_by_entryhash(&db, &entry.hash)
        .ok_or("No attestation found after second application")?;
    println!("  Forward mutations: {}", result2_muts.len());
    println!("  Mutations hash: {}", bs58::encode(&my_att2.mutations_hash).into_string());

    // Get reverse mutations from second application
    let reverse_muts2 = crate::consensus::consensus::chain_muts_rev(&fabric, &entry.hash)
        .ok_or("No reverse mutations found after second application")?;
    println!("  Reverse mutations: {}", reverse_muts2.len());

    // === COMPARISON ===
    println!("\n=== STEP 4: Comparison ===");

    // Compare forward mutations counts
    assert_eq!(
        result1_muts.len(),
        result2_muts.len(),
        "Forward mutation counts differ: {} vs {}",
        result1_muts.len(),
        result2_muts.len()
    );
    println!("✓ Forward mutation counts match: {}", result1_muts.len());

    // Compare reverse mutations counts
    assert_eq!(
        reverse_muts1.len(),
        reverse_muts2.len(),
        "Reverse mutation counts differ: {} vs {}",
        reverse_muts1.len(),
        reverse_muts2.len()
    );
    println!("✓ Reverse mutation counts match: {}", reverse_muts1.len());

    // Compare each forward mutation
    let mut forward_mismatches = 0;
    for (i, (m1, m2)) in result1_muts.iter().zip(result2_muts.iter()).enumerate() {
        if m1.key != m2.key || m1.op != m2.op || m1.value != m2.value {
            forward_mismatches += 1;
            println!("✗ Forward mutation {} differs:", i + 1);
            println!(
                "  First:  op={:?}, key={:?}, value={:?}",
                m1.op,
                String::from_utf8_lossy(&m1.key),
                m1.value.as_ref().map(|v| String::from_utf8_lossy(v))
            );
            println!(
                "  Second: op={:?}, key={:?}, value={:?}",
                m2.op,
                String::from_utf8_lossy(&m2.key),
                m2.value.as_ref().map(|v| String::from_utf8_lossy(v))
            );
        }
    }
    assert_eq!(forward_mismatches, 0, "Forward mutations differ");
    println!("✓ All forward mutations identical");

    // Compare each reverse mutation
    let mut reverse_mismatches = 0;
    for (i, (m1, m2)) in reverse_muts1.iter().zip(reverse_muts2.iter()).enumerate() {
        if m1.key != m2.key || m1.op != m2.op || m1.value != m2.value {
            reverse_mismatches += 1;
            println!("✗ Reverse mutation {} differs:", i + 1);
            println!(
                "  First:  op={:?}, key={:?}, value={:?}",
                m1.op,
                String::from_utf8_lossy(&m1.key),
                m1.value.as_ref().map(|v| String::from_utf8_lossy(v))
            );
            println!(
                "  Second: op={:?}, key={:?}, value={:?}",
                m2.op,
                String::from_utf8_lossy(&m2.key),
                m2.value.as_ref().map(|v| String::from_utf8_lossy(v))
            );
        }
    }
    assert_eq!(reverse_mismatches, 0, "Reverse mutations differ");
    println!("✓ All reverse mutations identical");

    // Compare mutations hashes
    assert_eq!(my_att1.mutations_hash, my_att2.mutations_hash, "Mutations hashes differ");
    println!("✓ Mutations hashes match");

    // Cleanup
    println!("\n✓ Test complete - Rewind and re-apply produce identical results!");
    std::fs::remove_dir_all(&temp_db_path).ok();

    Ok(())
}

/// Test to check bloom page 0 state in the local test database
#[tokio::test]
#[ignore]
async fn check_local_bloom_page_0() -> Result<(), Box<dyn std::error::Error>> {
    let db = RocksDb::open("../assets/rocksdb/34076356".to_string()).await?;
    let fabric = Fabric::with_db(db);

    let page0 = fabric.db().get("contractstate", b"bic:epoch:solbloom:0")?;

    match page0 {
        Some(data) => {
            println!("Bloom page 0 exists: {} bytes", data.len());
            println!("First 16 bytes (hex): {:02x?}", &data[..data.len().min(16)]);

            // Check bit 0
            if data.len() > 0 {
                let byte0 = data[0];
                let bit0_set = (byte0 & 0x01) != 0;
                println!("Bit 0 is: {}", if bit0_set { "SET" } else { "NOT SET" });
            }
        }
        None => {
            println!("Bloom page 0 does NOT exist");
        }
    }

    Ok(())
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
        map.insert(Term::Atom(Atom::from("key")), Term::Binary(Binary { bytes: m.key.clone() }));

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

        println!("Mutation {}: op={:?} key_len={}", i + 1, m.op, m.key.len());
        etf_muts.push(Term::Map(Map { map }));
    }

    // Create list term
    let list_term = Term::List(List { elements: etf_muts });

    // Encode
    let encoded = encode_safe_deterministic(&list_term);

    println!("\nETF encoded bytes ({} total):", encoded.len());
    println!("First 100 bytes: {:02x?}", &encoded[..encoded.len().min(100)]);

    // Hash
    let h = blake3::hash(&encoded);
    println!("\nBlake3 hash: {}", bs58::encode(h.as_bytes()).into_string());
}
