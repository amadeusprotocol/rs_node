use ama_core::Context;
use ama_core::config::Config;
use ama_core::node::protocol::{Instruction, TxPool};
use client::{UdpSocketWrapper, get_http_port, init_tracing};
use http::serve;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::spawn;
use tokio::time::timeout;
use tracing::{debug, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = Config::from_fs(None, None).await?;
    info!("working inside {}", config.get_root());
    info!("public address {}", config.get_public_ipv4());
    info!("public key {}", bs58::encode(config.get_pk()).into_string());

    let udp_socket = Arc::new(UdpSocketWrapper::bind("0.0.0.0:36969").await?);
    let ctx = Arc::new(Context::with_config_and_socket(config, udp_socket).await?);

    // UDP amadeus node
    let ctx_udp = ctx.clone();
    let udp = spawn(async move {
        if let Err(e) = recv_loop(ctx_udp).await {
            eprintln!("udp loop error: {e}");
        }
    });

    // HTTP dashboard server
    let ctx_http = ctx.clone();
    let http = spawn(async move {
        let port = get_http_port();
        let socket = TcpListener::bind(&format!("0.0.0.0:{port}")).await.expect("bind http");

        if let Err(e) = serve(socket, ctx_http).await {
            eprintln!("http server error: {e}");
        }
    });

    // Wait for either task to finish (or join both if you prefer)
    tokio::try_join!(udp, http)?;
    Ok(())
}

async fn recv_loop(ctx: Arc<Context>) -> anyhow::Result<()> {
    info!("udp server listening on 0.0.0.0:36969");
    let mut buf = vec![0u8; 65_535];

    loop {
        match timeout(Duration::from_secs(10), ctx.recv_from(&mut buf)).await {
            Err(_) => {} // timeout
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok((len, src))) => {
                let message = match ctx.parse_udp(&buf[..len], src).await {
                    Some(p) => p,
                    None => continue, // no message to process
                };

                if message.typename() == TxPool::TYPENAME {
                    // example how to steer the core library
                    debug!("received ping from {src}");
                }

                let instruction = match ctx.handle(message, src).await {
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
        }
    }
}
