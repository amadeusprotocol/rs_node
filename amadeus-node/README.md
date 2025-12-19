# amadeus-node

[![Crates.io](https://img.shields.io/crates/v/amadeus-node.svg)](https://crates.io/crates/amadeus-node)
[![Documentation](https://docs.rs/amadeus-node/badge.svg)](https://docs.rs/amadeus-node)

Core library for the Amadeus blockchain node with networking, consensus, and storage.

## Installation

```toml
[dependencies]
amadeus-node = "1.3"
```

## Features

- **Networking** - UDP P2P protocol with encryption and compression
- **Consensus** - BFT consensus with dual chains (rooted and temporal)
- **Storage** - RocksDB-backed persistent chain storage
- **Transaction Pool** - Mempool and nonce tracking
- **Peer Management** - ANR (Amadeus Network Records) and handshakes

## Quick Example

```rust
use amadeus_node::{Config, Context};

// Load configuration
let config = Config::from_fs(None, None).await?;

// Create network context
let ctx = Context::with_config_and_socket(config, socket).await?;

// Handle incoming message
let protocol_msg = ctx.parse_udp(&buf, src_ip).await;
let instructions = ctx.handle(protocol_msg?, src_ip).await?;

for instruction in instructions {
    ctx.execute(instruction).await?;
}
```

```rust
use amadeus_node::consensus::doms::tx;

// Build transaction
let tx_packed = tx::build(
    &config,
    b"Coin",
    "transfer",
    &[recipient, amount, symbol],
    None,
    None,
    None,
);
```

## Module Structure

- `config` - Node configuration and identity
- `context` - Runtime state container
- `consensus::fabric` - Chain storage (RocksDB)
- `consensus::doms` - Domain types (Entry, Tx, Attestation)
- `node::protocol` - Network message handling
- `node::peers` - Peer connection management
- `node::txpool` - Transaction pool
- `metrics` - Performance telemetry

## Feature Flags

- `system-metrics` - Enable CPU/memory monitoring (default)

## Documentation

For detailed API documentation, see [docs.rs/amadeus-node](https://docs.rs/amadeus-node).

## License

Apache-2.0
