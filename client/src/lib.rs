use jemallocator::Jemalloc;
use std::net::Ipv4Addr;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod dump_replay;

pub use dump_replay::UdpSocketWrapper;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

/// Initializes tracing, panic hook, tokio-tracing and memory stats if enabled
pub fn init_tracing() {
    let reg =
        tracing_subscriber::registry().with(fmt::layer().with_target(true).with_filter(EnvFilter::from_default_env()));

    // tokio-console requires tracing log level, so we surgically add
    // "RUST_LOG=tokio=trace" here to avoid spam in the log mainstream
    #[cfg(feature = "debugging")]
    let reg = reg.with(console_subscriber::spawn().with_filter(EnvFilter::new("tokio=trace")));

    reg.init();

    #[cfg(feature = "debugging")]
    std::thread::spawn(memory_stats_task);

    // reports to stderr without requiring tracing macros on panic
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |pi| {
        eprintln!("panic: {}", pi);
        default(pi);
    }));
}

#[cfg(feature = "debugging")]
#[tracing::instrument(name = "memory_stats", skip_all)]
fn memory_stats_task() {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(10));

        let _ = jemalloc_ctl::epoch::advance();
        let alloc = jemalloc_ctl::stats::allocated::read().unwrap_or_default();
        let active = jemalloc_ctl::stats::active::read().unwrap_or_default();
        let rss = jemalloc_ctl::stats::resident::read().unwrap_or_default();
        let frag = active.saturating_sub(alloc);
        let retained = rss.saturating_sub(active);
        tracing::info!("heap: alloc={alloc} active={active} frag={frag} | rss: resident={rss} retained={retained}");
    }
}

pub fn get_peer_addr() -> Ipv4Addr {
    std::env::var("UDP_ADDR").ok().and_then(|s| s.parse().ok()).unwrap_or_else(|| "127.0.0.1".parse().unwrap())
}

pub fn get_http_port() -> u16 {
    std::env::var("HTTP_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(3000)
}
