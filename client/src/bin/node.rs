use ama_core::node::protocol::Instruction;
use ama_core::socket::UdpSocketExt;
use ama_core::{Context, read_udp_packet};
use client::{UdpSocketWrapper, get_http_port, init_tracing};
use http::serve;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::spawn;
use tokio::time::timeout;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let udp_socket = Arc::new(UdpSocketWrapper::bind("0.0.0.0:36969").await.expect("bind udp"));

    let config = ama_core::config::Config::from_fs(None, None).await?;
    info!("working inside {}", config.get_root());
    let ctx = Arc::new(Context::with_config_and_socket(config, udp_socket.clone()).await?);

    // UDP amadeus node
    let ctx_udp = ctx.clone();
    let socket_clone = udp_socket.clone();
    let udp = spawn(async move {
        if let Err(e) = recv_loop(socket_clone, ctx_udp).await {
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

async fn recv_loop(socket: Arc<UdpSocketWrapper>, ctx: Arc<Context>) -> anyhow::Result<()> {
    info!(
        "udp server listening on {}",
        socket.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| "unknown".into())
    );

    let mut buf = vec![0u8; 65_535];
    let timeout_secs = Duration::from_secs(10);

    loop {
        match timeout(timeout_secs, socket.recv_from_with_metrics(&mut buf, ctx.get_metrics())).await {
            Err(_) => {} // timeout
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok((len, src))) => match read_udp_packet(&ctx, src, &buf[..len]).await {
                Some(proto) => {
                    if let Ok(instruction) = proto.handle_with_metrics(&ctx, src).await {
                        handle_instruction(&ctx, instruction, src).await?;
                    }
                }
                None => {} // still waiting for more shards
            },
        }
    }
}

async fn handle_instruction(_ctx: &Context, instruction: Instruction, src: SocketAddr) -> anyhow::Result<()> {
    match instruction {
        Instruction::ReplyPong { ts_m: _ } => {
            // handle pong reply if needed
        }

        Instruction::SpecialBusiness { business } => {
            // handle special business messages
            println!("received special business from {:?}, data len: {}", src, business.len());
        }

        Instruction::SpecialBusinessReply { business } => {
            // handle special business reply messages
            println!("received special business reply from {:?}, data len: {}", src, business.len());
        }

        Instruction::Noop => {
            // Most protocol messages now handle their state internally and return Noop
            // This is the expected case for NewPhoneWhoDis, What, and other protocol messages
        }

        _ => {
            // Handle any other instructions that still need processing
            // Most have been moved to protocol handle_inner implementations
        }
    }

    Ok(())
}
