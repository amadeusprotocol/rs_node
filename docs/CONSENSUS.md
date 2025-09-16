# Amadeus consensus specification

## Overview

This document describes the consensus rules and data structures used in the
Amadeus network.

## Epoch

The epoch is a period of 100,000 entries (blocks). The epoch is maintained
inside of the contractstate (see next), and is incremented every height %
100,000 == 0. Changes in logic usually happen at the edge between epochs.
Notable epochs:

- Pre-103: Base emission only (1,000,000 AMA decreasing by 33.3% each epoch)
- 103-281: Base emission + 200,000 AMA fixed bonus
- 282-419: Base emission + 100,000 AMA fixed bonus
- 295+: New epoch transition logic (but still old emission until 420)
- 420+:
  - New power-law emission model
  - Automatic difficulty adjustment based on solution count
  - Community fund allocation system
  - Enhanced validator selection with early adopter protections


## Contractstate

The contractstate is a key-value store that holds the state of the chain. It is
the main source of truth for the current state of the blockchain. The
contractstate is updated every time a new block is applied. The contractstate
is stored in a dedicated column family in the RocksDB database, aka Fabric.
The special genesis entry is applied to form the initial contractstate to
kickstart the blockchain.

## Entries

Entries are blocks in the Amadeus blockchain. Every entry has the parent hash,
height and slot number. The height indicates the position of the entry from the
bottom, while the slot number indicates which trainer is responsible for this
entry. Entries contain transactions that modify the contractstate. Each
transaction is transformed into a mutation and a reverse mutation. The mutations
are applied to the contractstate when entries are applied, and the reverse
mutations are applied when entries are rewound.

The chain of entries forms a continuous immutable ledger that has a short mutable
continuation at the top, as follows:

- rooted part: the immutable chain that appends entries upon reaching consensus
  (BFT >=67%)
- temporal part: located on top of the rooted part, this is the region of the
  chain that each node maintains individually. It applies entries periodically
  with a best effort principle, and can be rewound only if the rooted part
  advances with an entry that conflicts with the temporal part.

### Structure

The temporal part can easily get thousands of entries ahead of the rooted part,
and is rewound often. In the temporal part, forks often exist and some entries
can be submitted in parallel, so it makes sense to group data into 3 realms and
store them separately, while individually optimizing the storage for each:

- immutable entries, consensus attestations and transactions (can be downloaded
  from other nodes on a need to know basis in runtime or stored per epoch and
  downloaded on demand by independent auditors for retrospective verification)
- contractstate that includes, trainers, solutions, and other mutable data (must
  be snapshotted and stored often, because it is the main source of truth and
  also to accelerate the bootstrap of new nodes)
- realtime networking data or cheap to rebuild data, like peers, indices, etc.
  (can be easily rebuilt from scratch when starting a node from the
  contractstate, seed config, handshakes etc.)

> Note: target is to have the temporal part no longer than 1 entry, but longer
> temporal chains can exist in the current implementation, thus to avoid the
> avalanche, after the temporal part exceeds 1000 entries, entries are starting
> to get processed in batches.

## Transactions

Transactions are the operations that modify the contractstate. There are two
types of transactions:

- contract alteration transactions: modify smart contract data in the
  contractstate
- contract deployment transactions: upload wasm bytecode and modify the
  contractstate

> It is important to note that submitting solutions (PoW), electing and slashing
> trainers are also transactions that are applied to contractstate.

## Solutions

Solutions are proof-of-work submissions that allow trainers to earn the
privilege to create new entries. The input data to mine a solution is called a
preamble:

- **Preamble (240 bytes)**: epoch, segment_vr_hash, trainer_pk, pop,
  computor_pk, nonce

The preamble is then turned into two large matrices via Blake3 XOF (16×50,240
and 50,240×16), which are later multiplied (~12.8M operations) to get a
tensor_c:

- **Tensor_c (1024 bytes)**: 16×16 matrix result from multiplication

The nonce is then randomly selected until the hash of the tensor_c is below
the target (difficulty), i.e. has a number of 0s:

- Epoch 0: 1 leading zero byte (probability 1/256)
- Epoch 1-243: 2 leading zero bytes (probability 1/65,536)
- Epoch 244+: 3 leading zero bytes (probability 1/16,777,216)

The way the work to mine a solution is done also evolves over time:

- Epoch 0: 256-byte solution, simpler validation
- Epoch 1-155: 320-byte solution, basic Freivalds
- Epoch 156-259: 1264-byte solution with Blake3.freivalds()
- Epoch 260-281: 1264-byte solution with Blake3.freivalds_e260()
- Epoch 282+: Same as 260+ but with segment_vr_hash verification

Solutions are fairly easy to validate. To do this, the validator needs to get 2
large matrices from the preamble using Blake3 XOF, and then use the Freivalds
algorithm to verify the multiplication result.

### Computors

Anyone can create a solution. If a solution is attributed to a `trainer_pk !=
computor_pk`, a payment of 100 AMA (native Amadeus currency) is sent from the
trainer to the computor, regardless of the difficulty. Whoever creates a
solution is called a computor. Often computors are the trainers themselves
(`trainer_pk = computor_pk`), because they are incentivized to have as many
solutions as possible and increase their chances of getting a slot in the next
epoch, creating entries and earning transaction fees.

## Trainers

Anyone who has at least one solution attributed to their pk (sol.trainer_pk) is
considered a trainer. Trainers are validators in the Amadeus ecosystem. The
list of trainers is maintained by the contractstate and is updated every epoch
by choosing the first 99 trainers with the most solutions. A trainer can be
slashed by creating the corresponding transaction.

Trainers earn primarily from transaction fees in their entries. Before epoch
282, trainers also received 1 AMA per entry.

To simplify the architecture, each node keeps an index of active trainers,
called trainers_per_height. A new height with the updated list is added every
time the list of trainers changes, due to epoch reselection or slashing:

- 1000000: [pk1, pk2, pk3, ...]
- 1023320: [pk2, pk3, pk4, ...]
- 2000000: [pk3, pk4, pk5, ...]

Each trainer has a slot number, so when the next entry with a slot number can
be created, the trainer with the index `id = slot %
trainers_for_height[height].len()` is responsible for its creation. If the
trainer is not online, the entry can then be created by another trainer and
must be collectively signed by a majority (>=67%). The trainer responsible for
entry creation in this case is determined by a deterministic function `id =
mins_since_unix_epoch % trainers_for_height[height].len()`. This way, the
trainer who will initiate a collective entry is well-defined and updates every
minute.

### Special Business

This specific type of activity is reserved for trainers who are initiating
slashing.