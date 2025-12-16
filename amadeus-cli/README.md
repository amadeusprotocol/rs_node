# Amadeus CLI

Command-line interface for interacting with the Amadeus blockchain.

## Installation

Install from crates.io:

```bash
cargo install amadeus-cli
```

Or build from source:

```bash
git clone https://github.com/valentynfaychuk/rs_node
cd rs_node
cargo install --path amadeus-cli
```

## Usage

The CLI provides commands for wallet management, transaction building, and
contract deployment.

### Generate a Wallet

```bash
ama gen-sk wallet.sk
```

### Get Public Key

```bash
ama get-pk --sk wallet.sk
```

### Send a Transaction

```bash
# Call a contract function
ama tx --sk wallet.sk Contract test "[]" --url https://testnet-rpc.ama.one

# Transfer tokens
ama tx --sk wallet.sk Coin transfer '[{"b58": "RECIPIENT_PK"}, "100000000000", "AMA"]' --url https://testnet-rpc.ama.one
```

### Deploy a Contract

```bash
ama deploy-tx --sk wallet.sk contract.wasm --url https://testnet-rpc.ama.one
```

## Argument Format

Arguments are passed as a JSON array where each element can be:

- **String** → UTF-8 bytes (e.g., `"hello"`)
- **Number** → String bytes (e.g., `100` becomes `"100"`)
- **`{"b58": "..."}`** → Base58-decoded bytes (for addresses)
- **`{"hex": "..."}`** → Hex-decoded bytes (with or without 0x)
- **`{"utf8": "..."}`** → Explicit UTF-8 bytes

## Environment Variables

- `AMADEUS_URL` - Default node URL (e.g., `https://testnet-rpc.ama.one`)

## Built-in Contracts

- **Coin** - `transfer`, `create_and_mint`, `mint`, `pause`
- **Contract** - `deploy`
- **Epoch** - `submit_sol`, `set_emission_address`, `slash_trainer`

## License

Apache-2.0
