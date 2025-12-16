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

### Using CLI to test Smart Contracts

You can find and build example wasm files that are used below in the
`contract_samples` of the [amadeus node](https://github.com/amadeusprotocol/node).


```bash
cargo cli gen-sk wallet.sk
cargo cli get-pk --sk wallet.sk

# Claim testnet AMA to the pk at https://mcp.ama.one/testnet-faucet

cargo cli gen-sk counter.sk
export COUNTER_PK=$(cargo cli get-pk --sk counter.sk)
cargo cli tx --sk wallet.sk --url http://testnet.ama.one Coin transfer '[{"b58": "'$COUNTER_PK'"}, "2000000000", "AMA"]'
cargo cli deploy-tx --sk counter.sk counter.wasm --url http://testnet.ama.one
cargo cli tx --sk counter.sk --url http://testnet.ama.one $COUNTER_PK init '[]'
curl "http://testnet.ama.one/api/contract/view/$COUNTER_PK/get"
cargo cli tx --sk wallet.sk --url http://testnet.ama.one $COUNTER_PK increment '["5"]'
curl "http://testnet.ama.one/api/contract/view/$COUNTER_PK/get"

cargo cli gen-sk deposit.sk
export DEPOSIT_PK=$(cargo cli get-pk --sk deposit.sk)
cargo cli tx --sk wallet.sk Coin transfer '[{"b58": "'$DEPOSIT_PK'"}, "2000000000", "AMA"]' --url http://testnet.ama.one
cargo cli deploy-tx --sk deposit.sk deposit.wasm --url http://testnet.ama.one
cargo cli tx --sk wallet.sk $DEPOSIT_PK balance '["AMA"]' --url http://testnet.ama.one
cargo cli tx --sk wallet.sk $DEPOSIT_PK deposit '[]' AMA 1500000000 --url http://testnet.ama.one
cargo cli tx --sk wallet.sk $DEPOSIT_PK balance '["AMA"]' --url http://testnet.ama.one

cargo cli gen-sk coin.sk
export COIN_PK=$(cargo cli get-pk --sk coin.sk)
cargo cli tx --sk wallet.sk Coin transfer '[{"b58": "'$COIN_PK'"}, "2000000000", "AMA"]' --url http://testnet.ama.one
cargo cli deploy-tx --sk coin.sk coin.wasm --url http://testnet.ama.one
cargo cli tx --sk wallet.sk $COIN_PK deposit '[]' AMA 1500000000 --url http://testnet.ama.one
cargo cli tx --sk wallet.sk $COIN_PK withdraw '["AMA", "500000000"]' --url http://testnet.ama.one
cargo cli tx --sk wallet.sk $COIN_PK withdraw '["AMA", "1000000000"]' --url http://testnet.ama.one

cargo cli gen-sk nft.sk
export NFT_PK=$(cargo cli get-pk --sk nft.sk)
cargo cli tx --sk wallet.sk Coin transfer '[{"b58": "'$NFT_PK'"}, "2000000000", "AMA"]' --url http://testnet.ama.one
cargo cli deploy-tx --sk nft.sk nft.wasm --url http://testnet.ama.one
cargo cli tx --sk wallet.sk $NFT_PK init '[]' --url http://testnet.ama.one
cargo cli tx --sk wallet.sk $NFT_PK claim '[]' --url http://testnet.ama.one
cargo cli tx --sk wallet.sk $NFT_PK view_nft '["AGENTIC", "1"]' --url http://testnet.ama.one
cargo cli tx --sk wallet.sk $NFT_PK claim '[]' --url http://testnet.ama.one
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

| Contract | Functions                                       |
|----------|-------------------------------------------------|
| Coin     | transfer, create_and_mint, mint, pause          |
| Contract | deploy                                          |
| Epoch    | submit_sol, set_emission_address, slash_trainer |

### Environment Variables

- `AMADEUS_URL` - Default node URL

Run `cargo cli --help` for full documentation.

## Node

Full Amadeus node that syncs and gossips with the network.

```bash
cargo node
```
