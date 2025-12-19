# amadeus-runtime

[![Crates.io](https://img.shields.io/crates/v/amadeus-runtime.svg)](https://crates.io/crates/amadeus-runtime)
[![Documentation](https://docs.rs/amadeus-runtime/badge.svg)](https://docs.rs/amadeus-runtime)

WebAssembly execution runtime and built-in contracts for the Amadeus blockchain.

## Installation

```toml
[dependencies]
amadeus-runtime = "1.3"
```

## Features

- **WASM Execution** - Gas-metered WebAssembly runtime (wasmi-based)
- **Built-in Contracts** - Core system contracts (Coin, Epoch, Contract, Sol, Lockup)
- **State Management** - Key-value store with atomic mutations
- **Contract Validation** - WASM bytecode validation before deployment

## Quick Example

```rust
use amadeus_runtime::consensus::bic::coin;
use amadeus_runtime::consensus::consensus_kv;

// Check token balance
let balance = coin::balance(&env, recipient_pk, b"AMA")?;

// State operations
consensus_kv::kv_put(&mut env, b"balance", b"1000")?;
let value = consensus_kv::kv_get(&env, b"balance")?;
```

```rust
use amadeus_runtime::consensus::bic::contract;

// Validate WASM before deployment
let wasm_bytes = std::fs::read("contract.wasm")?;
contract::validate(&wasm_bytes)?;
```

## Module Structure

- `consensus::bic` - Built-in contracts (coin, epoch, contract, sol, lockup)
- `consensus::consensus_apply` - Transaction execution and ApplyEnv
- `consensus::consensus_kv` - State store operations
- `consensus::consensus_muts` - Mutation types
- `consensus::wasm` - WebAssembly runtime

## Documentation

For detailed API documentation, see [docs.rs/amadeus-runtime](https://docs.rs/amadeus-runtime).

## License

Apache-2.0
