# Amadeus Client

Full node implementation for the Amadeus blockchain network.

## Overview

This crate provides the `amadeusd` binary - a complete blockchain node that
participates in consensus, validates transactions, maintains chain state, and
serves the web dashboard.

## Installation

Build from source:

```bash
git clone https://github.com/amadeusprotocol/rs_node
cd rs_node
cargo build --release --bin amadeusd
```

Binary location: `target/release/amadeusd`

## Running the Node

Start a full node:

```bash
cargo node
```

Or with custom configuration:

```bash
UDP_ADDR=0.0.0.0:36969 HTTP_PORT=3000 cargo node
```

## Environment Variables

- `UDP_ADDR` - P2P network address (default: `127.0.0.1:36969`)
- `HTTP_PORT` - Web dashboard and API port (default: `3000`)
- `UDP_DUMP` - File path to record network traffic for debugging
- `UDP_REPLAY` - File path to replay recorded network traffic
- `RUST_LOG` - Logging level (`debug`, `info`, `warn`, `error`)

## Features

### Consensus Participation

- Validates and propagates entries and transactions
- Maintains rooted and temporal chains with BFT consensus
- Processes attestations from validators
- Syncs with peer nodes via catchup protocol

### State Management

- Persistent RocksDB storage at `~/.amadeusd-rs/fabric/db`
- Transaction pool and mempool management
- Entry and transaction indexing
- Contract state storage

### Networking

- UDP-based peer-to-peer protocol
- Encrypted and compressed messaging (AES-256-GCM + zstd)
- Reed-Solomon erasure coding for large messages
- Automatic peer discovery and handshake

### Web Dashboard

Access at `http://localhost:3000`:

- Chain explorer and block viewer
- Transaction history and status
- Peer network visualization
- Contract deployment and interaction
- Wallet management

### REST API

Programmatic access at `http://localhost:3000/api`:

- `/api/chain/*` - Chain queries (entries, transactions, state)
- `/api/tx/submit` - Submit signed transactions
- `/api/contract/*` - Contract deployment and calls
- `/api/peer/*` - Peer network information
- `/api/wallet/*` - Wallet operations
- `/api/epoch/*` - Epoch and validator data
- `/api/metrics` - Prometheus metrics
- `/api/health` - Health check endpoint

OpenAPI spec: `http://localhost:3000/api/openapi.yaml`

## Configuration Files

Node configuration stored in: `~/.amadeusd-rs/`

- `config.json` - Node settings and validator identity
- `node.sk` - Secret key for node identity (if validator)
- `fabric/db/` - RocksDB chain database

## CLI Tool

For wallet management and transaction submission, use the separate CLI tool:

```bash
cargo install amadeus-cli
ama --help
```

See [amadeus-cli](https://crates.io/crates/amadeus-cli) for details.

## Testing

Check `.cargo/config.toml` for command aliases. Environment variables reflect
the original Elixir node settings:

- `UDP_ADDR` - address of the peer, default `127.0.0.1:36969`
- `UDP_DUMP` - file to dump the UDP traffic to
- `UDP_REPLAY` - file to replay the UDP traffic from
- `HTTP_PORT` - port to use for the web UI

### Unit Tests

Run the full test suite:

```bash
cargo test-all
```

Note: Some KV tests may be flaky. If they fail, re-run them.

## Debugging

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

### Network Traffic Recording

```bash
UDP_DUMP=traffic.bin cargo node
```

### Replay Recorded Traffic

```bash
UDP_REPLAY=traffic.bin cargo node
```

### Enable Debug Logs

```bash
RUST_LOG=debug cargo node
```

## Node Simulation (NATIVE)

The amadeusd library has the implementation of a traffic capturing
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

## Node Simulation (PCAP)

Before running the simulation, run `scripts/rewrite-pcaps.sh en0`
to rewrite the pcap files to match your LAN, this is needed to fix
the replay addressing, feel free to choose any interface.

```bash
cargo node
# best to run the replay in another terminal
tcpreplay -i en0 --pps 1000 assets/pcaps/test.pcap.local
```

Optionally you can watch the replay as it happens:

```bash
tcpdump -i en0 -n -vv udp dst port 36969 # to watch replay in real time
```

### Recording Capture

```bash
# This command is transparent to the node but could impact the performance,
# so feel free to run it alongside the node, but with caution
tcpdump -i any udp dst port 36969 -w test.pcap -c 10000
```

### Troubleshooting Replay

Replaying `assets/pcaps/test.pcap.local` sends exactly 10000 packets, if you
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
rm assets/pcaps/*.local && ./scripts/rewrite-pcaps.sh en0
```

## Debugging RocksDB

If installed on MacOS using brew, the commands are `rocksdb_ldb` and
`rocksdb_sst_dump`,
if manually - then the commands are `ldb` and `sst_dump` respectively.

```bash
rocksdb_ldb --db=.amadeusd-rs/fabric/db list_column_families
rocksdb_ldb --db=.amadeusd-rs/fabric/db --column_family=sysconf scan
rocksdb_ldb --db=.amadeusd-rs/fabric/db --column_family=entry_by_height scan
rocksdb_ldb --db=.amadeusd-rs/fabric/db --column_family=sysconf get rooted_tip
```

## Debugging on Elixir Node

```bash
cd ex
make depend && make
./build.sh
mix deps.get
WORKFOLDER="$HOME/.cache/testamadeusd" OFFLINE=1 iex -S mix
```

```elixir
NodePeers.all() |> Enum.filter(fn peer -> peer.ip == "167.99.137.218" end) |> Enum.map(& &1.ip)
API.Peer.all_for_web()
```

## Performance Considerations

> Profiling of the node shows the biggest bottleneck as the
> `get_shared_secret` function that takes >82% of the CPU time.
> From it about 60% is BLS Scalar and 35% is parse public key.

Another direction of improvement is to avoid using synchronisation, like
mutexes, and instead to use channels for communication between the threads.

## License

Apache-2.0
