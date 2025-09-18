use crate::config::Config;
use crate::node::anr::Anr;
use crate::node::anr_manager::AnrManager;
use crate::node::msg_encrypted::EncryptedMessage;
use crate::node::protocol::Protocol;
use crate::socket::UdpSocketExt;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use std::io::prelude::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::debug;

// Helper function for zlib compression to match Elixir reference
fn compress_with_zlib(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

/// Options for broadcasting messages
#[derive(Debug, Clone)]
pub struct BroadcastOptions {
    /// Maximum number of validators to send to
    pub validators: usize,
    /// Maximum number of regular peers to send to
    pub peers: usize,
    /// Include self in broadcast
    pub include_self: bool,
}

impl Default for BroadcastOptions {
    fn default() -> Self {
        Self { validators: 1000, peers: 10, include_self: false }
    }
}

/// Broadcast manager for sending messages to network peers
pub struct BroadcastManager {
    config: Arc<Config>,
    anr_manager: Arc<AnrManager>,
    socket: Arc<dyn UdpSocketExt>,
}

impl BroadcastManager {
    pub fn new(config: Arc<Config>, anr_manager: Arc<AnrManager>, socket: Arc<dyn UdpSocketExt>) -> Self {
        Self { config, anr_manager, socket }
    }

    /// Broadcast a protocol message to network peers
    pub async fn broadcast<P: Protocol>(&self, msg: &P, opts: BroadcastOptions) -> Result<usize, BroadcastError> {
        // Get handshaked validators and peers
        let (validators, peers) = self.anr_manager.get_handshaked_and_online().await;

        // Build recipient list
        let mut recipients = Vec::new();

        // Add self if requested
        if opts.include_self {
            if let Ok(my_anr) = self.anr_manager.get_or_build_my_anr().await {
                recipients.push(my_anr);
            }
        }

        // Add validators (up to limit)
        recipients.extend(validators.into_iter().take(opts.validators));

        // Add peers (up to limit)
        recipients.extend(peers.into_iter().take(opts.peers));

        debug!(
            "Broadcasting to {} recipients (validators: {}, peers: {})",
            recipients.len(),
            opts.validators.min(recipients.len()),
            opts.peers.min(recipients.len().saturating_sub(opts.validators))
        );

        // Send to all recipients
        let mut sent = 0;
        for anr in recipients {
            if let Err(e) = self.send_to_anr(msg, &anr).await {
                debug!("Failed to send to {}: {}", anr.ip4, e);
            } else {
                sent += 1;
            }
        }

        Ok(sent)
    }

    /// Send a message to a specific ANR
    async fn send_to_anr<P: Protocol>(&self, msg: &P, anr: &Anr) -> Result<(), BroadcastError> {
        // Get ETF binary of the message
        let payload = msg.to_etf_bin().map_err(|e| BroadcastError::Serialization(e.to_string()))?;

        // Compress the payload using zlib to match Elixir reference
        let compressed = compress_with_zlib(&payload).map_err(|e| BroadcastError::Compression(e.to_string()))?;

        // Get shared secret for encryption
        let shared_secret =
            self.anr_manager.get_shared_secret(&anr.pk).await.map_err(|e| BroadcastError::Encryption(e.to_string()))?;

        // Get version from config
        let version = self.config.version;

        // Encrypt the message
        let messages = EncryptedMessage::encrypt(&self.config.get_pk(), &shared_secret, &compressed, version)
            .map_err(|e| BroadcastError::Encryption(e.to_string()))?;

        // Send all message shards
        let dst = SocketAddr::new(std::net::IpAddr::V4(anr.ip4), self.config.udp_port);
        for msg in messages {
            let packet = msg.to_bytes();
            self.socket.send_to(&packet, dst).await.map_err(|e| BroadcastError::Network(e.to_string()))?;
        }

        Ok(())
    }

    /// Broadcast to check unverified ANRs
    pub async fn broadcast_check_unverified_anr(&self) -> Result<(), BroadcastError> {
        let my_pk = self.config.get_pk();
        let unverified = self.anr_manager.get_random_unverified(3).await;

        debug!("Checking {} unverified ANRs", unverified.len());

        for anr in unverified {
            if anr.pk == my_pk {
                continue;
            }

            // Send handshake request (new_phone_who_dis)
            // This would be implemented as a protocol message
            debug!("Sending handshake request to {}", anr.ip4);
        }

        Ok(())
    }

    /// Request peer ANRs from verified peers
    pub async fn broadcast_request_peer_anrs(&self) -> Result<(), BroadcastError> {
        let my_pk = self.config.get_pk();
        let peers = self.anr_manager.get_random_verified(3).await;

        debug!("Requesting ANRs from {} peers", peers.len());

        for anr in peers {
            if anr.pk == my_pk {
                continue;
            }

            // Send ANR request
            // This would be implemented as a protocol message
            debug!("Requesting ANRs from {}", anr.ip4);
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BroadcastError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Compression error: {0}")]
    Compression(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Network error: {0}")]
    Network(String),
}
