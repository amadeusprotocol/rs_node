# Amadeus Blockchain Node (Rust)

Rust implementation of the Amadeus blockchain node.
Check the original node implementation in
elixir [here](https://github.com/amadeus-robot/node.git).

## Project Structure

- [amadeus-utils](./amadeus-utils/) - Cryptography, serialization, compression,
  and database utilities
- [amadeus-runtime](./amadeus-runtime/) - WASM execution engine, built-in
  contracts (BIC), and state management
- [amadeus-node](./amadeus-node/) - Core node implementation: networking,
  consensus, and runtime
- [amadeus-cli](./amadeus-cli/) - Command-line wallet and transaction tool (
  `ama`)
- [amadeusd](./amadeusd/) - Full node binary (`amadeusd`)
- [http](./http/) - Web dashboard and REST API

## Quick Start

```bash
# Build all crates
cargo build --workspace

# Run tests
cargo test-all

# Start the node
cargo node
```

Detailed documentation:

- Node operation: [amadeusd/README.md](./amadeusd/README.md)
- CLI usage: [amadeus-cli/README.md](./amadeus-cli/README.md)
- Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md)

## Using as a Dependency

Add to your `Cargo.toml`:

```toml
[dependencies]
amadeus-node = { git = "https://github.com/amadeusprotocol/rs_node", branch = "main" }
```

## Development

Check [.cargo/config.toml](./.cargo/config.toml) for available command aliases:

- `cargo node` - Run the full node
- `cargo test-all` - Run all workspace tests
- `cargo lint` - Run clippy lints

## License

Apache-2.0
