use ama_core::consensus::DST_ANR_CHALLENGE;
use ama_core::node::anr;
use ama_core::node::protocol::{Instruction, What};
use ama_core::utils::bls12_381 as bls;
use ama_core::{Context, read_udp_packet};
use client::{DumpReplaySocket, get_http_port, init_tracing};
use http::serve;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::spawn;
use tokio::time::timeout;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let ctx = Arc::new(Context::new().await?);

    // HTTP dashboard server
    let ctx_http = ctx.clone();
    let http = spawn(async move {
        let port = get_http_port();
        let socket = TcpListener::bind(&format!("0.0.0.0:{port}")).await.expect("bind http");

        println!("http listening on {port}");
        if let Err(e) = serve(socket, ctx_http).await {
            eprintln!("http server error: {e}");
        }
    });

    // UDP amadeus node
    let ctx_udp = ctx.clone();
    let udp = spawn(async move {
        let socket = UdpSocket::bind("0.0.0.0:36969").await.expect("bind udp");

        println!("udp listening on 36969"); // port must always be 36969
        if let Err(e) = recv_loop(socket, ctx_udp).await {
            eprintln!("udp loop error: {e}");
        }
    });

    // Wait for either task to finish (or join both if you prefer)
    tokio::try_join!(http, udp)?;
    Ok(())
}

async fn recv_loop(socket: UdpSocket, ctx: Arc<Context>) -> anyhow::Result<()> {
    info!(
        "udp server listening on {}",
        socket.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| "unknown".into())
    );

    let mut buf = vec![0u8; 65_535];
    let timeout_secs = Duration::from_secs(10);

    loop {
        match timeout(timeout_secs, socket.dump_replay_recv_from(&mut buf)).await {
            Err(_) => {} // timeout
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok((len, src))) => match read_udp_packet(&ctx, src, &buf[..len]).await {
                Some(proto) => {
                    if let Ok(instruction) = proto.handle(&ctx, src).await {
                        handle_instruction(&ctx, instruction, src).await?;
                    }
                }
                None => {} // still waiting for more shards
            },
        }
    }
}

async fn handle_instruction(ctx: &Context, instruction: Instruction, src: SocketAddr) -> anyhow::Result<()> {
    use tokio::net::UdpSocket;

    match instruction {
        Instruction::ReplyWhatChallenge { anr, challenge } => {
            // received NewPhoneWhoDis, reply with What message containing challenge signature
            println!("received new_phone_who_dis from {:?}, challenge {}, replying with what", src, challenge);

            // Get our own ANR to include in the What response
            let my_ip = ctx
                .get_config()
                .public_ipv4
                .as_ref()
                .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
                .unwrap_or_else(|| std::net::Ipv4Addr::new(127, 0, 0, 1));

            let my_anr = anr::ANR::build(
                &ctx.get_config().trainer_sk,
                &ctx.get_config().trainer_pk,
                &ctx.get_config().trainer_pop,
                my_ip,
                ctx.get_config().get_ver(),
            )
            .map_err(|e| anyhow::anyhow!("failed to build ANR: {}", e))?;

            // sign the challenge: signature = BLS(sender_pk || challenge) with OUR private key
            let mut challenge_msg = anr.pk.clone();
            challenge_msg.extend_from_slice(&challenge.to_be_bytes());

            let signature = bls::sign(&ctx.get_config().trainer_sk, &challenge_msg, DST_ANR_CHALLENGE)
                .map_err(|e| anyhow::anyhow!("failed to sign challenge: {}", e))?;

            // create What response with OUR ANR
            let what_msg = What::new(my_anr, challenge, signature.to_vec())
                .map_err(|e| anyhow::anyhow!("failed to create What message: {}", e))?;

            // serialize and send
            let payload =
                what_msg.to_etf_bin().map_err(|e| anyhow::anyhow!("failed to serialize What message: {}", e))?;

            let shards = ama_core::node::ReedSolomonReassembler::build_shards(ctx.get_config(), payload)
                .map_err(|e| anyhow::anyhow!("failed to build shards: {}", e))?;

            let sock =
                UdpSocket::bind("0.0.0.0:0").await.map_err(|e| anyhow::anyhow!("failed to bind socket: {}", e))?;

            for shard in shards {
                sock.send_to(&shard, src).await.map_err(|e| anyhow::anyhow!("failed to send shard: {}", e))?;
            }

            // insert the sender's ANR into our store
            anr::insert(anr.clone()).await?;
            
            // update peer information with ANR data (version and public key)
            if let std::net::IpAddr::V4(sender_ip) = src.ip() {
                let _ = ctx.update_peer_from_anr(sender_ip, &anr.pk, &anr.version).await;
                let _ = ctx.set_peer_handshake_status(sender_ip, ama_core::node::peers::HandshakeStatus::SentWhat).await;
            }
        }

        Instruction::ReceivedWhatResponse { responder_anr, challenge, their_signature } => {
            // received What response to our new_phone_who_dis
            println!("received what response from {:?}, verifying signature", src);

            // verify the signature: they signed (our_pk || challenge) with their private key
            let mut challenge_msg = ctx.get_config().trainer_pk.to_vec();
            challenge_msg.extend_from_slice(&challenge.to_be_bytes());

            // verify using the responder's public key from their ANR
            if let Err(e) = bls::verify(&responder_anr.pk, &their_signature, &challenge_msg, DST_ANR_CHALLENGE) {
                println!("signature verification failed: {}", e);
                return Ok(());
            }

            println!("handshake completed with {:?}, pk: {}", src, bs58::encode(&responder_anr.pk).into_string());

            // insert the responder's ANR and mark as handshaked
            anr::insert(responder_anr.clone()).await?;
            anr::set_handshaked(&responder_anr.pk).await?;
            
            // update peer information with ANR data (version and public key)
            if let std::net::IpAddr::V4(responder_ip) = src.ip() {
                let _ = ctx.update_peer_from_anr(responder_ip, &responder_anr.pk, &responder_anr.version).await;
            }
            
            // update peer's handshaked status in NodePeers to received_what (handshake completed)
            ctx.set_peer_handshaked(&responder_anr.pk).await?;
            ctx.set_peer_handshake_status_by_pk(&responder_anr.pk, ama_core::node::peers::HandshakeStatus::ReceivedWhat).await?;

            println!("peer {} is now handshaked", bs58::encode(&responder_anr.pk).into_string());
        }

        Instruction::HandshakeComplete { anr } => {
            // This instruction is no longer used in the new flow
            // Keep for backward compatibility
            println!("handshake completed with {:?}, pk: {}", src, bs58::encode(&anr.pk).into_string());
            anr::insert(anr.clone()).await?;
            anr::set_handshaked(&anr.pk).await?;
            
            // update peer's handshaked status in NodePeers (backward compatibility case)
            ctx.set_peer_handshaked(&anr.pk).await?;
            ctx.set_peer_handshake_status_by_pk(&anr.pk, ama_core::node::peers::HandshakeStatus::ReceivedWhat).await?;
        }

        Instruction::ReplyPong { ts_m: _ } => {
            // handle pong reply (existing functionality)
        }

        _ => {
            // handle other instructions (existing functionality)
        }
    }

    Ok(())
}
