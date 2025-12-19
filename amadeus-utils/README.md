# amadeus-utils

[![Crates.io](https://img.shields.io/crates/v/amadeus-utils.svg)](https://crates.io/crates/amadeus-utils)
[![Documentation](https://docs.rs/amadeus-utils/badge.svg)](https://docs.rs/amadeus-utils)

Cryptography, serialization, and database utilities for the Amadeus blockchain.

## Installation

```toml
[dependencies]
amadeus-utils = "1.3"
```

## Features

- **BLS12-381** - BLS signatures and public key operations
- **Blake3** - Fast cryptographic hashing with optional parallelization
- **Reed-Solomon** - Erasure coding for data sharding
- **vecpak** - Efficient binary serialization (serde-compatible)
- **safe_etf** - Deterministic Erlang Term Format encoding
- **RocksDB** - Transactional key-value database wrapper

## Quick Example

```rust
use amadeus_utils::bls12_381;

// Generate keypair and sign
let sk = bls12_381::generate_sk();
let pk = bls12_381::get_public_key(&sk)?;
let sig = bls12_381::sign(&sk, b"message", b"DOMAIN")?;

// Verify
bls12_381::verify(&pk, &sig, b"message", b"DOMAIN")?;
```

```rust
use amadeus_utils::blake3;

let hash = blake3::hash(b"data"); // [u8; 32]
```

```rust
use amadeus_utils::rocksdb::{RocksDb, Options};

let mut opts = Options::default();
opts.create_if_missing(true);

let db = RocksDb::open("path/to/db", opts, vec![])?;
let txn = db.transaction();
txn.put(b"key", b"value")?;
txn.commit()?;
```

## Feature Flags

- `rayon` - Enable parallel Blake3 hashing
- `system-metrics` - System resource monitoring

## Documentation

For detailed API documentation, see [docs.rs/amadeus-utils](https://docs.rs/amadeus-utils).

## License

Apache-2.0
