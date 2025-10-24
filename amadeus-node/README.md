# Amadeus Node Library

Core library for the Amadeus blockchain node, containing networking protocol, consensus logic, and the Context runtime container.

## Features

- Network protocol implementation with Protocol trait
- Peer management and handshake tracking
- ANR (Amadeus Network Record) handling
- Transaction pool management
- Consensus logic and chain fabric
- BIC (Blockchain-in-a-coin) modules
- WebAssembly runtime and contract execution
- Configuration management
- Performance metrics collection

## Testing

To test the application of entries and generation of mutations, run:

```bash
cargo test -p amadeus-node test_apply_entry_34076357 -- --nocapture
cargo test -p amadeus-node test_apply_entry_34076383 -- --nocapture
cargo test -p amadeus-node test_apply_entry_34076433 -- --nocapture
```

## Note on Fabric Compatibility

The Fabric (RocksDB) uses ETF (Erlang Term Format) for most data serialization to maintain compatibility with Elixir nodes,
with bincode used only for specific internal fields like epoch numbers. Snapshots from https://snapshots.amadeus.bot/
should be compatible with this implementation.
