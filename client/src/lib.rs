mod dump_replay;

use ama_core::config::Config;
use ama_core::node::ReedSolomonReassembler;
use ama_core::node::protocol::TxPool;
use ama_core::socket::UdpSocketExt;
pub use dump_replay::UdpSocketWrapper;
use std::net::SocketAddr;
use std::panic;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// Initializes tracing, panic hook and tokio-tracing if enabled
pub fn init_tracing() {
    let reg =
        tracing_subscriber::registry().with(fmt::layer().with_target(true).with_filter(EnvFilter::from_default_env()));

    // tokio-console requires tracing log level, so we surgically add
    // "RUST_LOG=tokio=trace" here to avoid spam in the log mainstream
    #[cfg(feature = "tokio-tracing")]
    let reg = reg.with(console_subscriber::spawn().with_filter(EnvFilter::new("tokio=trace")));

    reg.init();

    // reports to stderr without requiring tracing macros on panic
    let default = panic::take_hook();
    panic::set_hook(Box::new(move |pi| {
        eprintln!("panic: {}", pi);
        default(pi);
    }));
}

pub fn get_peer_addr() -> SocketAddr {
    std::env::var("UDP_ADDR").unwrap_or("127.0.0.1:36969".into()).parse().expect("valid UDP_ADDR")
}

pub fn get_http_port() -> u16 {
    std::env::var("HTTP_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(3000)
}

/// Send transaction to network via UDP
pub async fn send_transaction(config: &Config, tx_packed: Vec<u8>) -> anyhow::Result<()> {
    let payload = TxPool { valid_txs: vec![tx_packed] }.to_etf_bin()?;
    let shards = ReedSolomonReassembler::build_shards(config, payload)?;
    let node_addr = get_peer_addr();

    let socket = UdpSocketWrapper::bind("0.0.0.0:0").await?; // any available port
    for shard in shards.iter() {
        socket.send_to(shard, node_addr).await?;
    }

    Ok(println!("sent tx to {node_addr} ({} shards)", shards.len()))
}
