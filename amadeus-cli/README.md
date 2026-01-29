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

### Create Transaction (Offline)

```bash
# Print Base58 transaction to stdout
ama tx --sk wallet.sk Coin transfer '[{"b58": "RECIPIENT_PK"}, "100000000000", "AMA"]'

# Save as JSON file for later submission
ama tx --sk wallet.sk Coin transfer '[{"b58": "RECIPIENT_PK"}, "100000000000", "AMA"]' \
  --save-json tx.json

# Submit saved transaction
curl -H "Content-Type: text/plain" \
  --data "$(jq -r .tx_base58 tx.json)" \
  https://testnet-rpc.ama.one/api/tx/submit
```

### Send Transaction (Online)

```bash
# Send to testnet
ama tx --sk wallet.sk Coin transfer '[{"b58": "RECIPIENT_PK"}, "100000000000", "AMA"]' \
  --send testnet

# Send to mainnet
ama tx --sk wallet.sk Coin transfer '[{"b58": "RECIPIENT_PK"}, "100000000000", "AMA"]' \
  --send mainnet

# Send to custom node
ama tx --sk wallet.sk Coin transfer '[{"b58": "RECIPIENT_PK"}, "100000000000", "AMA"]' \
  --send http://localhost:3000

# Call contract
ama tx --sk wallet.sk Contract test "[]" --send testnet
```

### Deploy Contract

```bash
# Send to testnet
ama deploy-tx --sk wallet.sk contract.wasm --send testnet

# Save offline for later submission
ama deploy-tx --sk wallet.sk contract.wasm --save-json deploy.json
```

## Argument Format

Arguments are passed as JSON arrays:

- **String** → UTF-8 bytes (`"hello"`)
- **Number** → String bytes (`100` → `"100"`)
- **`{"b58": "..."}`** → Base58-decoded bytes (for addresses)
- **`{"hex": "..."}`** → Hex-decoded bytes
- **`{"utf8": "..."}`** → Explicit UTF-8 bytes

## Network Endpoints

- **Testnet**: `https://testnet-rpc.ama.one` (use `--send testnet`)
- **Mainnet**: `https://mainnet-rpc.ama.one` (use `--send mainnet`)

## Built-in Contracts

- **Coin** - `transfer`, `create_and_mint`, `mint`, `pause`
- **Contract** - `deploy`
- **Epoch** - `submit_sol`, `set_emission_address`, `slash_trainer`

## License

Apache-2.0
