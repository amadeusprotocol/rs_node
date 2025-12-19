# amadeus-cli

[![Crates.io](https://img.shields.io/crates/v/amadeus-cli.svg)](https://crates.io/crates/amadeus-cli)
[![Downloads](https://img.shields.io/crates/d/amadeus-cli)](https://crates.io/crates/amadeus-cli)

Command-line interface for interacting with the Amadeus blockchain.

## Installation

```bash
cargo install amadeus-cli
```

Or from source:

```bash
git clone https://github.com/amadeusprotocol/rs_node
cd rs_node
cargo install --path amadeus-cli
```

## Usage

### Generate Wallet

```bash
ama gen-sk wallet.sk
ama get-pk --sk wallet.sk
```

### Send Transaction

```bash
# Transfer tokens
ama tx --sk wallet.sk Coin transfer '[{"b58": "RECIPIENT_PK"}, "100000000000", "AMA"]' \
  --url https://testnet-rpc.ama.one

# Call contract
ama tx --sk wallet.sk Contract test "[]" --url https://testnet-rpc.ama.one
```

### Deploy Contract

```bash
ama deploy-tx --sk wallet.sk contract.wasm --url https://testnet-rpc.ama.one
```

## Argument Format

Arguments are passed as JSON arrays:

- **String** → UTF-8 bytes (`"hello"`)
- **Number** → String bytes (`100` → `"100"`)
- **`{"b58": "..."}`** → Base58-decoded bytes (for addresses)
- **`{"hex": "..."}`** → Hex-decoded bytes
- **`{"utf8": "..."}`** → Explicit UTF-8 bytes

## Environment Variables

- `AMADEUS_URL` - Default node URL (overridden by `--url`)

## Built-in Contracts

- **Coin** - `transfer`, `create_and_mint`, `mint`, `pause`
- **Contract** - `deploy`
- **Epoch** - `submit_sol`, `set_emission_address`, `slash_trainer`

## License

Apache-2.0
