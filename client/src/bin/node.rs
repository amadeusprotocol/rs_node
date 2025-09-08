use ama_core::node::protocol::{Instruction, TxPool};
use ama_core::{Config, Context};
use client::{UdpSocketWrapper, get_http_port, init_tracing};
use http::serve as http_serve;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::spawn;
use tokio::time::timeout;
use tracing::{debug, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = Config::from_fs(None, None).await?;
    info!("working inside {}", config.get_root());
    info!("public address {}", config.get_public_ipv4());
    info!("public bs58key {}", bs58::encode(config.get_pk()).into_string());

    let addr = format!("0.0.0.0:{}", config.get_udp_port());
    let udp_socket = Arc::new(UdpSocketWrapper::bind(&addr).await?);
    let ctx = Arc::new(Context::with_config_and_socket(config, udp_socket).await?);

    // UDP amadeus node
    let ctx_local = ctx.clone();
    let udp = spawn(async move {
        info!("udp server listening on {addr}");
        if let Err(e) = recv_loop(ctx_local).await {
            eprintln!("udp node error: {e}");
        }
    });

    let addr = format!("0.0.0.0:{}", get_http_port());
    let socket = TcpListener::bind(&addr).await.expect("bind http");

    // HTTP dashboard server
    let ctx_local = ctx.clone();
    let http = spawn(async move {
        info!("http server listening on {addr}");
        if let Err(e) = http_serve(socket, ctx_local).await {
            eprintln!("http server error: {e}");
        }
    });

    tokio::try_join!(udp, http)?;
    Ok(())
}

async fn recv_loop(ctx: Arc<Context>) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 65_535];

    loop {
        match timeout(Duration::from_secs(10), ctx.recv_from(&mut buf)).await {
            Ok(Ok((len, SocketAddr::V4(src)))) => {
                let ip = src.ip().to_owned();

                let message = match ctx.parse_udp(&buf[..len], ip).await {
                    Some(p) => p,
                    None => continue, // no message to process
                };

                if message.typename() == TxPool::TYPENAME {
                    // example how to steer the core library
                    debug!("received txpool from {src}");
                }

                let instruction = match ctx.handle(message, ip).await {
                    Ok(i) => i,
                    Err(_) => continue,
                };

                if let Instruction::Noop { ref why } = instruction {
                    // another example how to steer the core library
                    debug!("noop instruction: {why}");
                }

                // TODO: refactor to instruction.execute(&ctx).await?;
                ctx.execute(instruction).await?;
            }
            Ok(Ok((_, src))) => warn!("addr {src} not supported"),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => debug!("no messages, idling.."),
        }
    }
}
