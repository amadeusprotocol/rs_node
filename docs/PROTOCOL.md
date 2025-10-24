# Amadeus Node Protocol Specification

## Overview
This document describes the peer-to-peer messaging protocol implemented by types conforming to the `Protocol` trait in `amadeus-node/src/node/protocol.rs`. Messages are encoded as Erlang maps, compressed and optionally encrypted before transmission. Each frame begins with the ASCII prefix `AMA` followed by a three-byte semantic version.

## Handshake
Peers establish connectivity with a simple handshake:

- `ping` – announces the sender's temporal and rooted chain tips along with a millisecond timestamp.
- `pong` – echoes the timestamp from the corresponding `ping`.
- `who_are_you` – queries peer identity when no context is available.

## Core Message Types
The protocol supports a variety of operations for gossip and synchronization:

| Operation | Purpose |
|-----------|---------|
| `txpool(txs_packed)` | Broadcasts packed transactions.
| `peers(ips)` | Shares known peer IP addresses.
| `sol(sol)` | Propagates proof-of-work solutions.
| `entry(map)` | Delivers a chain entry; may include optional attestation and consensus payloads.
| `attestation_bulk(attestations_packed)` | Sends multiple attestations.
| `consensus_bulk(consensuses_packed)` | Sends multiple consensus records.
| `catchup_entry(heights)` | Requests entries at specific heights for synchronization.
| `catchup_tri(heights)`/`catchup_bi(heights)` | Requests triangular or binary interval data to accelerate sync.
| `catchup_attestation(hashes)` | Requests attestations by hash.
| `special_business(business)` and `special_business_reply(business)` | Exchange application-specific payloads.
| `solicit_entry(hash)`/`solicit_entry2()` | Solicits missing entries.

## Framing, Compression and Encryption
Payloads are serialized with `:erlang.term_to_binary/2` and deflate compression. Frames are then prepared as follows:

1. **Unsigned Frames** – For gossip without a shared key, the node signs the compressed payload with BLS and embeds its public key and signature in the frame. Large payloads are Reed–Solomon shard-split to keep individual UDP packets under ~1.3 KB.
2. **Encrypted Frames** – When a shared key is available, the payload is encrypted using AES‑256‑GCM. The key is derived from the shared key, the current nanosecond timestamp and a random IV. Payloads exceeding ~1.3 KB are similarly sharded.

Each frame includes:

- `"AMA"` prefix and semantic version.
- Sender public key.
- Optional signature (for unsigned frames).
- Shard index and total count (for sharded payloads).
- Nanosecond timestamp and original size.
- Compressed (and optionally encrypted) payload.

## Legacy Envelope
Older nodes may use a simpler `pack_message`/`unpack_message` flow where the payload is compressed, signed and wrapped in a fixed-key AES‑256‑GCM envelope.
