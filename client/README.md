# Amadeus Client Library

This crate contains client binaries for interacting with the Amadeus blockchain.

## CLI

The CLI is a client that can deploy contracts and send transactions via HTTP.
After v1.1.7, all nodes use symmetric encryption and require a handshake and ANR (public IP),
so transactions must be sent through the HTTP API that every node exposes.

The CLI supports transaction building and sending with the `--url` parameter.

## Node

The Node is a full Amadeus node that connects to the network, gossips and syncs
the chain.