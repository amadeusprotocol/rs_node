# Amadeus Node Protocol Specification

## Overview

Messages use vecpak encoding, compressed with zstd and encrypted with
AES-256-GCM before transmission. Each frame begins with `AMA` followed by a
three-byte semantic version.

## Message Types

- `ping`/`ping_reply` – handshake with chain tips and timestamp
- `event_tip` – announces temporal and rooted chain state
- `event_tx` – broadcasts transactions
- `sol` – propagates proof-of-work solutions
- `entry` – delivers chain entry
- `event_attestation` – sends attestations
- `catchup`/`catchup_reply` – requests/provides entries at specific heights
- `get_peer_anrs`/`get_peer_anrs_reply` – exchanges peer identity info
- `new_phone_who_dis`/`new_phone_who_dis_reply` – queries peer identity
- `special_business`/`special_business_reply` – application-specific payloads

## Frame Format

Encrypted frames include:

- `AMA` prefix (3 bytes)
- Semantic version (3 bytes)
- Reserved byte (1 byte)
- Sender public key (48 bytes)
- Shard index and total (4 bytes)
- Nanosecond timestamp (8 bytes)
- Original payload size (4 bytes)
- Encrypted payload (nonce + tag + ciphertext)

Large payloads (>1.3 KB) use Reed-Solomon sharding.
