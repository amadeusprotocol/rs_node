# Rust rewrite of the Amadeus Node

This initiative aims to create a Rust implementation of
the [Amadeus Node](https://github.com/amadeus-robot/node.git).

- [core (ama_core)](./core/README.md): Core library, needed by every project in
  Amadeus ecosystem
- [client](./client/README.md): The library with examples of using the core
  library (cli, node, etc.)
- [http](./http/README.md): Web dashboard of the Amadeus Node, by default runs
  on port 3000

## Prerequisites

### Amadeus Elixir Node (Optional)

You need to have rust environment and a running node somewhere to connect to.
It is best to run the offline node on the same machine (it requires a lot of
storage).
To setup the machine, refer the Dockerfile
from https://github.com/amadeus-robot/node.git

```bash
mix deps.get
WORKFOLDER="$HOME/.cache/testamadeusd" OFFLINE=1 iex -S mix
```

### RocksDB toolbox (Optional)

To install rocksdb tools follow:

```bash
git clone https://github.com/facebook/rocksdb.git && cd rocksdb && make ldb && make sst_dump
brew install rocksdb # or on MacOS (this will install `rocksdb_ldb` and `rocksdb_sst_dump`)
```

## Testing

Check `.cargo/config.toml` for command aliases. Environment variables reflect
the original Elixir node settings:

- `UDP_ADDR` - address of the peer, default `127.0.0.1:36969`
- `UDP_DUMP` - file to dump the UDP traffic to
- `UDP_REPLAY` - file to replay the UDP traffic from
- `HTTP_PORT` - port to use for the web UI

### Unittests

You need to run `scripts/compile-contracts.sh` script before running
tests because wasm tests rely on contract wasm files. Tests are work
in progress and some of the KV unittests are flaky. Don't freak out
if they fail sometimes, just re-run them.

```bash
cargo install wasm-tools
./scripts/compile-contracts.sh

# The test-all is also an alias
cargo test-all
```

### CLI

CLI is a client that can deploy contracts and send transactions via HTTP.

```bash
# Generate a new secret key
cargo cli gen-sk sk.local

# Get public key from secret key file
cargo cli get-pk --sk sk.local

# Build a transaction (prints base58-encoded tx, doesn't send)
cargo cli tx --sk sk.local Contract test "[]"

# Build and send a transaction via HTTP
cargo cli tx --sk sk.local Contract test "[]" --url http://localhost

# Deploy a contract (prints base58-encoded tx)
cargo cli contract-tx --sk sk.local contracts/simple_counter.wasm

# Deploy a contract and send via HTTP to a specific node
cargo cli contract-tx --sk sk.local contracts/simple_counter.wasm --url http://72.9.144.110
```

### Node debugging

The node can be debugged using tokio-console (`cargo install tokio-console`)
and logs that are printed to the output. Alternatively you can use gdb/lldb
and leaks/heap.

> Expect memory footprint in the debugging mode to be higher and grow

```bash
cargo node
# for tokio console debugging
RUSTFLAGS="--cfg tokio_unstable" RUST_LOG=debug cargo node --features debugging
tokio-console # in another terminal
# for memory leaks analysis
leaks -nocontext $(pgrep -f "target/debug/node")
# for network analysis
sudo tcpdump -i any -nnvv -e 'udp and port 36969'
```

### Node simulation (NATIVE)

The client library has the implementation of a traffic capturing
and replay natively through rust, the size of the capture is a bit
smaller than pcap capture 8.3M vs 8.7M, and the **format is custom
binary and can't be reliably dumped/parsed/rewritten elsewhere**.

```bash
# Record traffic to log.local when running a node
# This command is not transparent and will require the UDP socket,
# beware when running it alongside another running amadeus node
UDP_DUMP=log.local cargo node
```

The `log.local` file has the binary capture of the traffic. If you
run the above command second time, the new capture will get appended.

```bash
# Replay the captured traffic
UDP_REPLAY=log.local cargo node
```

### Node simulation (PCAP)

Before running the simulation, run `scripts/rewrite-pcaps.sh en0`
to rewrite the pcap files to match your LAN, this is needed to fix
the replay addressing, feel free to choose any interface.

```bash
cargo node
# best to run the replay in another terminal
tcpreplay -i en0 --pps 1000 pcaps/test.pcap.local
```

Optionally you can watch the replay as it happens:

```bash
tcpdump -i en0 -n -vv udp dst port 36969 # to watch replay in real time
```

#### Recording capture

```bash
# This command is transparent to the node but could impact the performance,
# so feel free to run it alongside the node, but with caution
tcpdump -i any udp dst port 36969 -w test.pcap -c 10000
```

#### Troubleshooting replay

Replaying `pcaps/test.pcap.local` sends exactly 10000 packets, if you
see that not all packets from the capture reach the light client, it
could be because the kernel buffers are too small to handle the replay
at a given rate, you need to increase the kernel buffers for UDP
traffic or decrease the `--pps` value.

```bash
# The packets are often getting lost because they overflow the kernel buffers
# So it is suggested to increase the kernel buffers before replaying
sudo sysctl -w kern.ipc.maxsockbuf=8388608        # raises per-socket max
sudo sysctl -w net.inet.udp.recvspace=2097152     # default UDP recv buffer (per-socket)
sysctl kern.ipc.maxsockbuf net.inet.udp.recvspace # check the values
```

If you see that no packets can reach the light client, the reason could
be that your IP address changed (e.g. after restart), simply rerun:

```bash
rm pcaps/*.local && ./scripts/rewrite-pcaps.sh en0
```

## Debugging the RocksDB

If installed on MacOS using brew, the commands are `rocksdb_ldb` and
`rocksdb_sst_dump`,
if manually - then the commands are `ldb` and `sst_dump` respectively.

```bash
rocksdb_ldb --db=.config/amadeusd/fabric/db list_column_families
rocksdb_ldb --db=.config/amadeusd/fabric/db --column_family=sysconf scan
rocksdb_ldb --db=.config/amadeusd/fabric/db --column_family=entry_by_height scan
rocksdb_ldb --db=.config/amadeusd/fabric/db --column_family=sysconf get rooted_tip
```

## Debugging on Elixir Node

```elixir
NodePeers.all() |> Enum.filter(fn peer -> peer.ip == "167.99.137.218" end) |> Enum.map(& &1.ip)
API.Peer.all_for_web()
```

## Performance considerations

> Profiling of the node shows the biggest bottleneck as the
> `get_shared_secret` function that takes >82% of the CPU time.
> From it about 60% is BLS Scalar and 35% is parse public key.

Another direction of improvement is to avoid using synchronisation, like
mutexes, and instead to use channels for communication between the threads.

## Adding core library to other project

```bash
cargo add ama_core --git https://github.com/valentynfaychuk/rs_node --package ama_core --branch main
# Or add following to Cargo.toml
# [dependencies]
# ama_core = { package = "ama_core", git = "https://github.com/valentynfaychuk/rs_node", branch = "main" }
```

### Versioning (you need to install `cargo install cargo-release`)

The workspace uses semver (`major.minor.patch`).
Major - when you make a breaking change.
Minor - when you add a new feature.
Patch - when you fix a bug.

```bash
cargo release patch --workspace
cargo release minor --workspace
cargo release major --workspace
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.
