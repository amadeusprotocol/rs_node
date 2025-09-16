use crate::Context;
use crate::config::Config;
use crate::node::anr_manager::AnrManager;
use crate::node::msg_encrypted::EncryptedMessage;
use crate::node::protocol::Instruction;
use crate::utils::misc::get_unix_nanos_now;
use miniz_oxide::inflate::decompress_to_vec;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn, info};
use eetf::Term;

/// Handles incoming UDP packets and message reassembly
pub struct PacketHandler {
    config: Arc<Config>,
    anr_manager: Arc<AnrManager>,
    reassembly_buffers: Arc<RwLock<HashMap<ReassemblyKey, ReassemblyBuffer>>>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReassemblyKey {
    pk: Vec<u8>,
    ts_nano: u64,
    shard_total: u16,
}

struct ReassemblyBuffer {
    shards: HashMap<u16, Vec<u8>>,
    original_size: u32,
    version: (u8, u8, u8),
    created_at: u64,
}

impl PacketHandler {
    pub fn new(config: Arc<Config>, anr_manager: Arc<AnrManager>) -> Self {
        Self {
            config,
            anr_manager,
            reassembly_buffers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Process incoming UDP packet
    pub async fn process_packet(
        &self,
        data: &[u8],
        peer_ip: Ipv4Addr,
        ctx: &Context,
    ) -> Result<Vec<Instruction>, PacketError> {
        // Try to parse as encrypted message
        let msg = EncryptedMessage::try_from(data)
            .map_err(|e| PacketError::ParseError(e.to_string()))?;

        // Check if message is to self
        if msg.pk == self.config.get_pk() {
            return Err(PacketError::MessageToSelf);
        }

        // Check version requirement (minimum 1.1.7)
        if msg.version.0 < 1 ||
           (msg.version.0 == 1 && msg.version.1 < 1) ||
           (msg.version.0 == 1 && msg.version.1 == 1 && msg.version.2 < 7) {
            return Err(PacketError::VersionTooOld(format!(
                "{}.{}.{}", msg.version.0, msg.version.1, msg.version.2
            )));
        }

        // Check if we have ANR for this peer
        let has_anr = self.anr_manager.get(&msg.pk).await.is_some();
        if !has_anr {
            // Request ANR from peer
            debug!("No ANR for peer {}, requesting handshake", hex::encode(&msg.pk[0..4]));
            // TODO: Send new_phone_who_dis message
            return Ok(vec![]);
        }

        // Check if handshaked and valid IP
        if !self.anr_manager.handshaked_and_valid_ip4(&msg.pk, peer_ip).await {
            debug!("Peer not handshaked or invalid IP: {}", peer_ip);
            return Ok(vec![]);
        }

        // Update last message time
        self.anr_manager.set_last_message(&msg.pk).await;

        // Handle based on shard count
        if msg.shard_total == 1 {
            // Single message, decrypt and process immediately
            self.process_single_message(msg, peer_ip, ctx).await
        } else {
            // Multi-shard message, add to reassembly buffer
            self.process_shard(msg, peer_ip, ctx).await
        }
    }

    /// Process a single (non-sharded) encrypted message
    async fn process_single_message(
        &self,
        msg: EncryptedMessage,
        peer_ip: Ipv4Addr,
        ctx: &Context,
    ) -> Result<Vec<Instruction>, PacketError> {
        // Get shared secret
        let shared_secret = self.anr_manager.get_shared_secret(&msg.pk).await
            .map_err(|e| PacketError::DecryptionError(e.to_string()))?;

        // Decrypt payload
        let decrypted = msg.decrypt(&shared_secret)
            .map_err(|e| PacketError::DecryptionError(e.to_string()))?;

        // Decompress
        let decompressed = decompress_to_vec(&decrypted)
            .map_err(|e| PacketError::DecompressionError(e.to_string()))?;

        // Parse ETF term
        let term = Term::decode(decompressed.as_slice())
            .map_err(|e| PacketError::EtfError(e.to_string()))?;

        // Process the protocol message
        self.process_protocol_message(term, peer_ip, ctx).await
    }

    /// Process a message shard
    async fn process_shard(
        &self,
        msg: EncryptedMessage,
        peer_ip: Ipv4Addr,
        ctx: &Context,
    ) -> Result<Vec<Instruction>, PacketError> {
        let key = ReassemblyKey {
            pk: msg.pk.to_vec(),
            ts_nano: msg.ts_nano,
            shard_total: msg.shard_total,
        };

        let data_shards_needed = (msg.shard_total / 2) as usize;

        // Add shard to buffer
        let mut buffers = self.reassembly_buffers.write().await;

        let buffer = buffers.entry(key.clone()).or_insert_with(|| {
            ReassemblyBuffer {
                shards: HashMap::new(),
                original_size: msg.original_size,
                version: msg.version,
                created_at: get_unix_nanos_now() as u64,
            }
        });

        // Get shared secret for decryption
        let shared_secret = self.anr_manager.get_shared_secret(&msg.pk).await
            .map_err(|e| PacketError::DecryptionError(e.to_string()))?;

        // Decrypt shard
        let decrypted_shard = msg.decrypt(&shared_secret)
            .map_err(|e| PacketError::DecryptionError(e.to_string()))?;

        buffer.shards.insert(msg.shard_index, decrypted_shard);

        // Check if we have enough shards
        if buffer.shards.len() >= data_shards_needed {
            // Reconstruct message using Reed-Solomon
            let mut shards_vec: Vec<(usize, Vec<u8>)> = buffer.shards
                .iter()
                .map(|(idx, data)| (*idx as usize, data.clone()))
                .collect();
            shards_vec.sort_by_key(|s| s.0);

            // For now, just concatenate the shards in order
            // TODO: Implement proper Reed-Solomon decoding
            let mut reconstructed = Vec::with_capacity(buffer.original_size as usize);
            for (_, shard_data) in shards_vec.iter() {
                reconstructed.extend_from_slice(shard_data);
            }
            reconstructed.truncate(buffer.original_size as usize);

            // Remove from buffer to prevent reprocessing
            buffers.remove(&key);

            // Decompress
            let decompressed = decompress_to_vec(&reconstructed)
                .map_err(|e| PacketError::DecompressionError(e.to_string()))?;

            // Parse ETF term
            let term = Term::decode(decompressed.as_slice())
                .map_err(|e| PacketError::EtfError(e.to_string()))?;

            // Process the protocol message
            self.process_protocol_message(term, peer_ip, ctx).await
        } else {
            debug!(
                "Buffering shard {}/{} for message from {}",
                buffer.shards.len(),
                data_shards_needed,
                hex::encode(&msg.pk[0..4])
            );
            Ok(vec![])
        }
    }

    /// Process a decoded protocol message
    async fn process_protocol_message(
        &self,
        _term: Term,
        peer_ip: Ipv4Addr,
        _ctx: &Context,
    ) -> Result<Vec<Instruction>, PacketError> {
        // Parse the protocol message from ETF term
        // This would dispatch to the appropriate protocol handler
        // based on the message type (op field)

        // For now, return empty instructions
        // TODO: Implement protocol message dispatching

        info!("Received protocol message from {}", peer_ip);
        Ok(vec![])
    }

    /// Clean up stale reassembly buffers
    pub async fn cleanup_stale_buffers(&self, max_age_secs: u64) {
        let now = get_unix_nanos_now() as u64;
        let threshold = now - (max_age_secs * 1_000_000_000);

        let mut buffers = self.reassembly_buffers.write().await;
        let before = buffers.len();

        buffers.retain(|_, buffer| buffer.created_at > threshold);

        let removed = before - buffers.len();
        if removed > 0 {
            debug!("Cleaned up {} stale reassembly buffers", removed);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Message to self")]
    MessageToSelf,
    #[error("Version too old: {0}")]
    VersionTooOld(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    #[error("Decompression error: {0}")]
    DecompressionError(String),
    #[error("ETF decode error: {0}")]
    EtfError(String),
    #[error("Reed-Solomon error: {0}")]
    ReedSolomonError(String),
}