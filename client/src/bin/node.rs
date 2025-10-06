use amadeus_node::consensus::doms::entry::Entry;
use amadeus_node::node::protocol::Instruction;
use amadeus_node::{Config, Context};
use client::{UdpSocketWrapper, get_http_port, init_tracing};
use http::serve as http_serve;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tracing::{Instrument, debug, error, info, instrument, warn};

fn main() -> anyhow::Result<()> {
    init_tracing();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(16)
        .worker_threads(4)
        .thread_name("ama-node")
        .enable_all()
        .build()?;

    rt.block_on(node_main())
}

#[instrument(name = "node_main", skip_all)]
async fn node_main() -> anyhow::Result<()> {
    let config = Config::from_fs(None, None).await?;
    info!("working inside {}", config.get_root());
    info!("public address {}", config.get_public_ipv4());
    info!("public bs58key {}", bs58::encode(config.get_pk()).into_string());

    let addr = format!("0.0.0.0:{}", config.get_udp_port());
    let udp_socket = Arc::new(UdpSocketWrapper::bind(&addr).await?);
    let ctx = Context::with_config_and_socket(config, udp_socket).await?;

    // UDP amadeus node
    let ctx_local = ctx.clone();
    let udp = tokio::spawn(
        async move {
            info!("udp server listening on {addr}");
            if let Err(e) = recv_loop(ctx_local).await {
                error!("udp node error: {e}");
            }
        }
        .instrument(tracing::Span::current()),
    );

    let addr = format!("0.0.0.0:{}", get_http_port());
    let socket = TcpListener::bind(&addr).await.expect("bind http");

    // HTTP dashboard server
    let ctx_local = ctx.clone();
    let http = tokio::spawn(
        async move {
            info!("http server listening on {addr}");
            if let Err(e) = http_serve(socket, ctx_local).await {
                eprintln!("http server error: {e}");
            }
        }
        .instrument(tracing::Span::current()),
    );

    tokio::try_join!(udp, http)?;

    Ok(())
}

async fn recv_loop(ctx: Arc<Context>) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 65_535];

    loop {
        match timeout(Duration::from_secs(10), ctx.recv_from(&mut buf)).await {
            Ok(Ok((len, SocketAddr::V4(src)))) => {
                let ip = src.ip().to_owned();
                tokio::spawn(handle_packet(ctx.clone(), buf[..len].to_vec(), ip));
            }
            Ok(Ok((_, src))) => warn!("addr {src} not supported"),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => debug!("no messages, idling.."),
        }
    }
}

async fn handle_packet(ctx: Arc<Context>, buf: Vec<u8>, ip: Ipv4Addr) -> anyhow::Result<()> {
    ctx.inc_tasks();
    let res = handle_packet_inner(ctx.clone(), buf, ip).await;
    ctx.dec_tasks();
    res
}

async fn handle_packet_inner(ctx: Arc<Context>, buf: Vec<u8>, ip: Ipv4Addr) -> anyhow::Result<()> {
    let message = match ctx.parse_udp(&buf, ip).await {
        Some(p) => p,
        None => return Ok(()), // no message to process
    };

    if matches!(message.typename(), Entry::TYPENAME) {
        // example how to steer the core library
        debug!("received entry from {ip}");
    }

    let instructions = match ctx.handle(message, ip).await {
        Ok(i) => i,
        Err(_) => return Ok(()), // ignore malformed messages
    };

    for instr in instructions {
        if let Instruction::Noop { ref why } = instr {
            // another example how to steer the core library
            debug!("noop instruction: {why}");
        }

        ctx.execute(instr).await?;
    }

    Ok(())
}
