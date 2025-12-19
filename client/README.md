# Amadeus Client

Full node implementation for the Amadeus blockchain network.

## Overview

This crate provides the `amadeusd` binary - a complete blockchain node that
participates in consensus, validates transactions, maintains chain state, and
serves the web dashboard.

## Installation

Build from source:

```bash
git clone https://github.com/amadeusprotocol/rs_node
cd rs_node
cargo build --release --bin amadeusd
```

Binary location: `target/release/amadeusd`

## Running the Node

Start a full node:

```bash
cargo node
```

Or with custom configuration:

```bash
UDP_ADDR=0.0.0.0:36969 HTTP_PORT=3000 cargo node
```

## Environment Variables

- `UDP_ADDR` - P2P network address (default: `127.0.0.1:36969`)
- `HTTP_PORT` - Web dashboard and API port (default: `3000`)
- `UDP_DUMP` - File path to record network traffic for debugging
- `UDP_REPLAY` - File path to replay recorded network traffic
- `RUST_LOG` - Logging level (`debug`, `info`, `warn`, `error`)

## Features

### Consensus Participation

- Validates and propagates entries and transactions
- Maintains rooted and temporal chains with BFT consensus
- Processes attestations from validators
- Syncs with peer nodes via catchup protocol

### State Management

- Persistent RocksDB storage at `~/.amadeusd-rs/fabric/db`
- Transaction pool and mempool management
- Entry and transaction indexing
- Contract state storage

### Networking

- UDP-based peer-to-peer protocol
- Encrypted and compressed messaging (AES-256-GCM + zstd)
- Reed-Solomon erasure coding for large messages
- Automatic peer discovery and handshake

### Web Dashboard

Access at `http://localhost:3000`:

- Chain explorer and block viewer
- Transaction history and status
- Peer network visualization
- Contract deployment and interaction
- Wallet management

### REST API

Programmatic access at `http://localhost:3000/api`:

- `/api/chain/*` - Chain queries (entries, transactions, state)
- `/api/tx/submit` - Submit signed transactions
- `/api/contract/*` - Contract deployment and calls
- `/api/peer/*` - Peer network information
- `/api/wallet/*` - Wallet operations
- `/api/epoch/*` - Epoch and validator data
- `/api/metrics` - Prometheus metrics
- `/api/health` - Health check endpoint

OpenAPI spec: `http://localhost:3000/api/openapi.yaml`

## Configuration Files

Node configuration stored in: `~/.amadeusd-rs/`

- `config.json` - Node settings and validator identity
- `node.sk` - Secret key for node identity (if validator)
- `fabric/db/` - RocksDB chain database

## CLI Tool

For wallet management and transaction submission, use the separate CLI tool:

```bash
cargo install amadeus-cli
ama --help
```

See [amadeus-cli](https://crates.io/crates/amadeus-cli) for details.

## Debugging

### Network Traffic Recording

```bash
UDP_DUMP=traffic.bin cargo node
```

### Replay Recorded Traffic

```bash
UDP_REPLAY=traffic.bin cargo node
```

### Enable Debug Logs

```bash
RUST_LOG=debug cargo node
```

## License

Apache-2.0
