# Amadeus use cases

This crate shows different use cases for the Amadeus core library. It is 
called client because it is technically as client of ama_core library.

## CLI

The CLI is a client that can deploy a contract or send transactions. The 
initial version was abusing the property of the legacy MessageV2 to gossip 
transactions directly to nodes, but after v1.1.7 all nodes are using symmetric
encryption and require a handshake and ANR, i.e. the public IP.

Because of this, the only way to send transaction is through the HTTP API that
every node exposes. The CLI will undergo changes to support this.

## Node

The Node is a full Amadeus node that connects to the network, gossips and syncs
the chain.