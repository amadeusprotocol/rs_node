# Amadeus Client

Client binaries for the Amadeus blockchain.

## CLI

Command-line tool for transactions and contract deployment.

### Quick Start

```bash
cargo cli gen-sk wallet.sk                # Generate wallet
cargo cli get-pk --sk wallet.sk           # Get public key
export AMADEUS_URL=http://testnet.ama.one # Set default node
```

### Transferring Tokens

```bash
# Transfer 99 AMA (amount in flat units: 99 * 10^9)
cargo cli tx --sk wallet.sk --url http://testnet.ama.one \
  Coin transfer '[{"b58": "7VZBw2Jf6csTtjb7jNL3QrwYa3vboWF7CdNw4ro1RNAhYfySj8Ze1Uyte81Bw3WCwP"}, "99000000000", "AMA"]'

# tx_hash: BKx2kchRPDUSQv2k2zNhwRbcaQdg7QJZDgY56qSM6bKv

# Verify on chain
curl http://testnet.ama.one/api/chain/tx/BKx2kchRPDUSQv2k2zNhwRbcaQdg7QJZDgY56qSM6bKv
```

### Deploying Smart Contracts

```bash
# Deploy contract
cargo cli deploy-tx --sk wallet.sk contract.wasm --url http://testnet.ama.one

# Contract address = your public key
MY_PK=$(cargo cli get-pk --sk wallet.sk)

# Call your contract
cargo cli tx --sk wallet.sk $MY_PK my_function '["arg1", 42]' --url http://testnet.ama.one
```

### Argument Format

JSON array where each element is:
- `"string"` - UTF-8 bytes
- `123` - Number as string bytes
- `{"b58": "..."}` - Base58-decoded bytes (addresses)
- `{"hex": "..."}` - Hex-decoded bytes

```bash
'[]'                                    # Empty
'["hello", 42]'                         # String and number
'[{"b58": "7VZBw2..."}, "100", "AMA"]'  # Address, amount, symbol
```

### Built-in Contracts

| Contract | Functions |
|----------|-----------|
| Coin | transfer, create_and_mint, mint, pause |
| Contract | deploy |
| Epoch | submit_sol, set_emission_address, slash_trainer |

### Environment Variables

- `AMADEUS_URL` - Default node URL

Run `cargo cli --help` for full documentation.

## Node

Full Amadeus node that syncs and gossips with the network.

```bash
cargo node
```
