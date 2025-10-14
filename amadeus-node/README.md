# Amadeus Core Library

The core library to be used by projects in the Amadeus ecosystem.

## Fabric

The Fabric (rocksdb) is not compatible with the Elixir nodes, because
they are using ETF serialization, while this library uses bincode. This
means that https://snapshots.amadeus.bot/000028812306.zip cannot be used
to initialize the database.

## Apply entry

To test the application of the entry, generation of mutations, run the
following command:

```bash
cargo test -p amadeus-node test_mutations_hash_with_rollback -- --ignored --nocapture
```
