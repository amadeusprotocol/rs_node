# Test Data Assets

This directory contains binary test data used by the mutations hash test.

## Files

### entry28812309 (50,381 bytes)
- Raw ETF-encoded Entry from Elixir (no protocol envelope)
- Entry hash: `H4kp4aD3MZc9a6iX6vSJPj6JhpHvzUcvxB8MHQogZ5A9`
- Entry height: 28812309
- Entry slot: 28812309
- Contains 31 transactions

### consensus28812309 (217 bytes)
- ETF-encoded Consensus from Elixir
- Contains:
  - `entry_hash` - Hash of the entry this consensus is for
  - `mutations_hash` - Expected mutations hash from Elixir execution (93 mutations)
  - `aggsig` - Aggregate BLS signature (96 bytes)

**Note**: This consensus data was generated **before** Rust implemented transaction execution (commit 86e987e, Oct 13 2025). The current Rust implementation produces 97 mutations (4 extra for solution tracking), so the hash will NOT match until updated test data is generated.

## Usage

These files are loaded by the test in:
`amadeus-node/src/consensus/test_mutations_hash.rs`

The test:
1. Loads both files
2. Decodes the entry and consensus
3. Verifies consensus is for the correct entry
4. Executes the entry
5. Compares Rust's mutations hash against Elixir's mutations hash

## Updating Test Data

To test with a different entry:

### 1. From Elixir, export entry (raw, no protocol envelope):
```elixir
# Export the raw entry binary (already packed)
{:ok, entry_packed} = Entry.pack(entry)
File.write!("entry_new", entry_packed)
```

### 2. From Elixir, export consensus:
```elixir
# Get consensus for this entry (from my_attestation or consensus_by_entryhash)
{:ok, consensus_bin} = :rocksdb.get(db, "consensus_by_entryhash", entry_hash)
File.write!("consensus_new", consensus_bin)
```

### 3. Replace files:
```bash
cp entry_new assets/rocksdb/entryXXXXX
cp consensus_new assets/rocksdb/consensusXXXXX
```

### 4. Update test constants in test file:
```rust
const ENTRY_DATA_PATH: &str = "assets/rocksdb/entryXXXXX";
const CONSENSUS_DATA_PATH: &str = "assets/rocksdb/consensusXXXXX";
```

## File Format

Both files are raw ETF (Erlang Term Format) binary data:
- **Entry**: Raw packed entry binary (no protocol envelope wrapper)
- **Consensus**: Map with keys `entry_hash`, `mutations_hash`, `aggsig`

The test uses `Entry::unpack()` and `Consensus::from_etf_bin()` to decode them.
