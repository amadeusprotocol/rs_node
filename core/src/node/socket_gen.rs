use crate::consensus::DST_NODE;
use crate::node::anr;
use crate::node::msg_v2::MessageV2;
use crate::node::peers::Peer;
use crate::node::protocol;
use crate::node::state::NodeState;
use crate::utils::blake3;
use crate::utils::bls12_381;
use crate::utils::misc::TermExt;
use eetf::Term;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::Duration;
use tokio::net::UdpSocket as TokioUdpSocket;
use tracing::{debug, error, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Socket error: {0}")]
    SocketError(String),
    #[error("Message parsing error: {0}")]
    MessageParsingError(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Signature verification failed")]
    InvalidSignature,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct SocketGenConfig {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub name: String,
    pub buffer_size: usize,
    pub send_buffer: usize,
    pub recv_buffer: usize,
}

impl Default for SocketGenConfig {
    fn default() -> Self {
        Self {
            ip: Ipv4Addr::new(127, 0, 0, 1),
            port: 36969,
            name: "NodeGenSocketGen".to_string(),
            buffer_size: 65536,
            send_buffer: 33554432, // 32MB
            recv_buffer: 33554432, // 32MB
        }
    }
}

#[derive(Debug)]
pub struct NodeGenSocketGen {
    config: SocketGenConfig,
    socket: Arc<TokioUdpSocket>,
    node_state: Arc<RwLock<NodeState>>,
    peers: Arc<RwLock<HashMap<Vec<u8>, Peer>>>,
}

impl NodeGenSocketGen {
    pub async fn new(config: SocketGenConfig) -> Result<Self, Error> {
        let addr = SocketAddr::new(config.ip.into(), config.port);
        let socket = TokioUdpSocket::bind(addr).await?;

        // check and warn about buffer sizes
        Self::check_buffer_sizes(&socket).await?;

        info!("UDP socket listening on {}:{} with buffer size {}KB", config.ip, config.port, config.buffer_size / 1024);

        Ok(Self {
            config,
            socket: Arc::new(socket),
            node_state: Arc::new(RwLock::new(NodeState::init())),
            peers: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    async fn check_buffer_sizes(_socket: &TokioUdpSocket) -> Result<(), Error> {
        // Note: Tokio UdpSocket doesn't expose buffer size methods
        // This is a simplified implementation - in production you might want to
        // check system buffer sizes through other means
        warn!("Buffer size checking not implemented for Tokio UdpSocket");
        Ok(())
    }

    pub async fn run(&self) -> Result<(), Error> {
        let socket = Arc::clone(&self.socket);
        let node_state = Arc::clone(&self.node_state);
        let peers = Arc::clone(&self.peers);

        let mut buf = vec![0u8; self.config.buffer_size];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let data = buf[..len].to_vec();
                    let ip = match addr.ip() {
                        std::net::IpAddr::V4(ipv4) => ipv4,
                        _ => {
                            warn!("Received message from non-IPv4 address: {}", addr);
                            continue;
                        }
                    };

                    // spawn task to handle message
                    let node_state_clone = Arc::clone(&node_state);
                    let peers_clone = Arc::clone(&peers);
                    let socket_clone = Arc::clone(&socket);

                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_udp_message(data, ip, node_state_clone, peers_clone, socket_clone).await
                        {
                            debug!("Error handling UDP message: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error receiving UDP message: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    async fn handle_udp_message(
        data: Vec<u8>,
        peer_ip: Ipv4Addr,
        _node_state: Arc<RwLock<NodeState>>,
        _peers: Arc<RwLock<HashMap<Vec<u8>, Peer>>>,
        _socket: Arc<TokioUdpSocket>,
    ) -> Result<(), Error> {
        match MessageV2::try_from(data.as_slice()) {
            Ok(msg_v2) => {
                let _peer_ip_str = peer_ip.to_string();

                // handle single shard signed message
                if msg_v2.shard_total == 2 {
                    // single shard (total * 2)
                    // verify signature
                    let signing_data = [&msg_v2.pk[..], &msg_v2.payload[..]].concat();
                    let hash = blake3::hash(&signing_data);

                    if bls12_381::verify(&msg_v2.pk, &msg_v2.signature, &hash, DST_NODE).is_err() {
                        return Err(Error::InvalidSignature);
                    }

                    let _has_permission = anr::handshaked_and_valid_ip4(&msg_v2.pk, &peer_ip).await.unwrap_or(false);

                    // decompress and parse payload
                    if let Ok(decompressed) = miniz_oxide::inflate::decompress_to_vec(&msg_v2.payload) {
                        if let Ok(term) = Term::decode(&decompressed[..]) {
                            if let Some(_map) = term.get_term_map() {
                                // handle the protocol message using protocol module
                                if let Ok(proto) = protocol::from_etf_bin(&msg_v2.payload) {
                                    debug!("Received {} from {}", proto.typename(), peer_ip);
                                    // TODO: Handle protocol message
                                }
                            }
                        }
                    }
                } else {
                    // multi-shard message - handle reassembly
                    let has_permission = anr::handshaked_and_valid_ip4(&msg_v2.pk, &peer_ip).await.unwrap_or(false);

                    if has_permission {
                        debug!(
                            "Received shard {}/{} from {}",
                            msg_v2.shard_index + 1,
                            msg_v2.shard_total / 2, // divide by 2 as per protocol
                            peer_ip
                        );
                        // TODO: implement reassembly logic
                    }
                }
            }
            Err(e) => {
                debug!("Failed to parse MessageV2: {}", e);
            }
        }

        Ok(())
    }

    async fn send_response(socket: Arc<TokioUdpSocket>, peer_ip: Ipv4Addr, response: Vec<u8>) -> Result<(), Error> {
        let addr = SocketAddr::new(peer_ip.into(), 36969);
        socket.send_to(&response, addr).await?;
        Ok(())
    }

    pub async fn send_to_some(&self, peer_ips: Vec<String>, msg_compressed: Vec<u8>) -> Result<(), Error> {
        for ip_str in peer_ips {
            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                // initial bootstrap messages are sent unencrypted to the fixed node port (36969)
                // TODO: implement encrypt_message_v2 when shared_secret is established
                let addr = SocketAddr::new(ip.into(), 36969);
                self.socket.send_to(&msg_compressed, addr).await?;
            }
        }
        Ok(())
    }

    // TODO: implement AES decryption when needed
}
