# Amadeus Client Library

Client binaries for the Amadeus blockchain.

## CLI

Transaction building and submission via HTTP API.

```bash
cargo cli gen-sk sk.local                     # Generate secret key
cargo cli get-pk --sk sk.local                # Get public key
cargo cli tx --sk sk.local Contract test "[]" # Build transaction
cargo cli tx --sk sk.local Contract test "[]" --url http://localhost  # Send
cargo cli contract-tx --sk sk.local app.wasm  # Deploy contract
```

## Node

Full Amadeus node that syncs and gossips with the network.

```bash
cargo node
```