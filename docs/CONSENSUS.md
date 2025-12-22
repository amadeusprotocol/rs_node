# Amadeus Consensus Specification

## Overview

This document describes consensus rules and data structures in the Amadeus
network.

## Epoch

An epoch is 100,000 entries (blocks). Emission starts at 1,000,000 AMA and
decreases by 0.0333% each epoch. Logic changes occur at epoch boundaries.

## Contractstate

The contractstate is a key-value store holding chain state, stored in RocksDB (
Fabric). It updates with each applied entry.

## Entries

Entries (blocks) contain parent hash, height, slot number, and transactions.
Transactions generate mutations (applied) and reverse mutations (rewound).

The chain has two parts:

- **Rooted**: Immutable chain with BFT consensus (≥67%)
- **Temporal**: Mutable continuation maintained individually by nodes, rewound
  if conflicting with rooted

## Transactions

Transactions modify the contractstate:

- Contract alterations: modify smart contract data
- Contract deployments: upload WASM bytecode
- Solutions, trainer elections, and slashing are also transactions

## Solutions

Solutions are proof-of-work submissions. Structure:

- **Preamble (240 bytes)**: epoch, segment_vr_hash, trainer_pk, pop,
  computor_pk, nonce
- **Tensor_c (1024 bytes)**: Result of matrix multiplication (16×16 matrix)

The preamble generates two matrices via Blake3 XOF (16×50,240 and 50,240×16),
multiplied to produce tensor_c. The nonce is selected until tensor_c hash meets
difficulty (leading zero bytes). Validation uses Freivalds algorithm.

**Computors**: Anyone can create solutions. If trainer_pk ≠ computor_pk, trainer
pays computor 100 AMA.

## Trainers

Trainers are validators with at least one solution. The top 99 trainers by
solution count are selected each epoch. Trainers earn transaction fees from
their entries and can be slashed.

Each trainer has a slot number determining entry creation responsibility. If
offline, another trainer creates the entry with majority signatures (≥67%). The
backup trainer rotates deterministically every minute.