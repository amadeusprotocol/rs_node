# Amadeus Core Library

The core library to be used by projects in the Amadeus ecosystem.

## Fabric

The Fabric (rocksdb) is not compatible with the Elixir nodes, because
they are using ETF serialization, while this library uses bincode. This
means that https://snapshots.amadeus.bot/000028812306.zip cannot be used
to initialize the database.
