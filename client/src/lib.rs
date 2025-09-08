mod dump_replay;

pub use dump_replay::UdpSocketWrapper;
use std::net::Ipv4Addr;
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

pub fn get_peer_addr() -> Ipv4Addr {
    std::env::var("UDP_ADDR").ok().and_then(|s| s.parse().ok()).unwrap_or_else(|| "127.0.0.1".parse().unwrap())
}

pub fn get_http_port() -> u16 {
    std::env::var("HTTP_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(3000)
}
