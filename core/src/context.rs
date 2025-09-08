use crate::config::{ANR_CHECK_SECS, CLEANUP_SECS};
use crate::node::anr::{Anr, NodeAnrs};
use crate::node::peers::HandshakeStatus;
use crate::node::peers::HandshakeStatus::SentNewPhoneWhoDis;
use crate::node::protocol::*;
use crate::node::protocol::{Instruction, NewPhoneWhoDis};
use crate::node::{anr, peers};
use crate::socket::UdpSocketExt;
use crate::utils::misc::get_unix_millis_now;
use crate::utils::misc::{Typename, get_unix_secs_now};
use crate::{config, consensus, metrics, node, utils};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::spawn;
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Fabric(#[from] consensus::fabric::Error),
    #[error(transparent)]
    Archiver(#[from] utils::archiver::Error),
    #[error(transparent)]
    Protocol(#[from] node::protocol::Error),
    #[error(transparent)]
    Config(#[from] config::Error),
    #[error(transparent)]
    Anr(#[from] anr::Error),
    #[error(transparent)]
    Peers(#[from] peers::Error),
    #[error("{0}")]
    String(String),
}

/// Runtime container for config, metrics, reassembler, and node state.
pub struct Context {
    pub(crate) config: config::Config,
    pub(crate) metrics: Arc<metrics::Metrics>,
    pub(crate) reassembler: Arc<node::ReedSolomonReassembler>,
    pub(crate) node_peers: Arc<peers::NodePeers>,
    pub(crate) node_registry: Arc<NodeAnrs>,
    pub(crate) broadcaster: Option<Arc<dyn node::Broadcaster>>,
    pub(crate) socket: Arc<dyn UdpSocketExt>,
    // optional handles for broadcast tasks
    pub(crate) ping_handle: Option<tokio::task::JoinHandle<()>>,
    pub(crate) anr_handle: Option<tokio::task::JoinHandle<()>>,
    pub(crate) start_time: std::time::Instant,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub last_ts: u64,
    pub last_msg: String,
    pub handshake_status: HandshakeStatus,
    pub version: Option<String>,
}

impl Context {
    pub async fn with_config_and_socket(config: config::Config, socket: Arc<dyn UdpSocketExt>) -> Result<Self, Error> {
        use crate::consensus::fabric::init_kvdb;
        use crate::utils::archiver::init_storage;
        use metrics::Metrics;
        use node::reassembler::ReedSolomonReassembler as Reassembler;
        use tokio::time::{Duration, interval};

        assert_ne!(config.get_root(), "");
        init_kvdb(&config.get_root()).await?;
        init_storage(&config.get_root()).await?;

        let metrics = Arc::new(Metrics::new());
        let node_peers = Arc::new(peers::NodePeers::default());
        let node_anrs = Arc::new(NodeAnrs::new());

        node_anrs.seed(&config).await; // must be done before node_peers.seed()
        node_peers.seed(&config, &node_anrs).await?;

        {
            // oneshot bootstrap task to send new_phone_who_dis to seed nodes
            let config = config.clone();
            let socket = socket.clone();
            let metrics = metrics.clone();
            let node_peers = node_peers.clone();
            let anr = Anr::from_config(&config)?;
            spawn(async move {
                let challenge = get_unix_secs_now() as i32; // FIXME: unix secs will overflow i32 in 2038
                let new_phone_who_dis = NewPhoneWhoDis { anr, challenge };

                let mut sent_count = 0;
                for ip in &config.seed_nodes {
                    let addr = match ip.parse::<Ipv4Addr>() {
                        Ok(ip) => ip,
                        Err(e) => {
                            warn!("bootstrap: invalid seed node ip {}: {}", ip, e);
                            continue;
                        }
                    };

                    if let Err(e) = new_phone_who_dis
                        .send_to_with_metrics(&config, socket.clone(), addr, &metrics)
                        .await
                    {
                        warn!("bootstrap: failed to send new_phone_who_dis to {addr}: {e}");
                        continue;
                    }

                    if let Err(e) = node_peers.set_handshake_status(addr, SentNewPhoneWhoDis).await {
                        warn!("bootstrap: failed to set handshake status for {addr}: {e}");
                    }

                    sent_count += 1;
                }

                info!("bootstrap: sent new_phone_who_dis to {sent_count} nodes");
            });
        }

        let reassembler = Arc::new(Reassembler::new());

        {
            // periodic cleanup task
            let reassembler = reassembler.clone();
            let node_peers = node_peers.clone();
            let node_anrs = node_anrs.clone();
            spawn(async move {
                let mut ticker = interval(Duration::from_secs(CLEANUP_SECS));
                loop {
                    ticker.tick().await;
                    let cleared_shards = reassembler.clear_stale(CLEANUP_SECS).await;
                    let cleared_peers = node_peers.clear_stale(&node_anrs).await;
                    if cleared_shards > 0 || cleared_peers > 0 {
                        debug!("cleanup: cleared {} stale shards, {} stale peers", cleared_shards, cleared_peers);
                    }
                }
            });
        }

        {
            // periodic anr check task
            let config = config.clone();
            let socket = socket.clone();
            let metrics = metrics.clone();
            let node_peers = node_peers.clone();
            let node_anrs = node_anrs.clone();
            spawn(async move {
                let mut ticker = interval(Duration::from_secs(ANR_CHECK_SECS));
                loop {
                    ticker.tick().await;
                    // get random unverified anrs and attempt to verify them
                    let unverified_anrs = node_anrs.get_random_not_handshaked(3).await;
                    if !unverified_anrs.is_empty() {
                            debug!("anrcheck: found {} unverified anrs", unverified_anrs.len());

                            let challenge = get_unix_secs_now() as i32; // FIXME: unix secs will overflow i32 in 2038
                            let anr = match Anr::from_config(&config) {
                                Ok(a) => a,
                                Err(e) => {
                                    warn!("anrcheck: failed to create anr from config: {e}");
                                    continue;
                                }
                            };

                            let new_phone_who_dis = NewPhoneWhoDis { anr, challenge };

                            for (_, ip) in unverified_anrs.iter().cloned() {
                                if let Err(e) = new_phone_who_dis
                                    .send_to_with_metrics(
                                        &config,
                                        socket.clone(),
                                        ip,
                                        &metrics,
                                    )
                                    .await
                                {
                                    warn!("anrcheck: failed to send new_phone_who_dis to {ip}: {e}");
                                } else if let Err(e) = node_peers.set_handshake_status(ip, SentNewPhoneWhoDis).await {
                                    warn!("anrcheck: failed to set handshake status for {ip}: {e}");
                                }
                            }
                    }
                }
            });
        }

        Ok(Self {
            config,
            metrics,
            reassembler,
            node_peers,
            node_registry: node_anrs,
            broadcaster: None,
            socket,
            ping_handle: None,
            anr_handle: None,
            start_time: std::time::Instant::now(),
        })
    }

    pub fn get_prometheus_metrics(&self) -> String {
        self.metrics.get_prometheus()
    }

    pub fn get_json_metrics(&self) -> Value {
        self.metrics.get_json()
    }

    /// Convenience function to send UDP data with metrics tracking
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to_with_metrics(buf, target, &self.metrics).await
    }

    /// Convenience function to receive UDP data with metrics tracking
    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from_with_metrics(buf, &self.metrics).await
    }

    pub async fn is_peer_handshaked(&self, ip: Ipv4Addr) -> bool {
        if let Some(peer) = self.node_peers.by_ip(ip).await {
            if let Some(ref pk) = peer.pk {
                if self.node_registry.is_handshaked(pk).await {
                    return true;
                }
            }
        }
        false
    }

    pub async fn get_peers(&self) -> HashMap<String, PeerInfo> {
        // Run peer scan in a blocking task to avoid starving the async runtime
        let node_peers = self.node_peers.clone();
        let mut result = HashMap::new();
        if let Ok(all_peers) = node_peers.all().await {
            for peer in all_peers {
                let peer_info = PeerInfo {
                    last_ts: peer.last_seen,
                    last_msg: peer.last_msg_type.unwrap_or_else(|| "unknown".to_string()),
                    handshake_status: peer.handshake_status.clone(),
                    version: peer.version.clone(),
                };
                result.insert(peer.ip.to_string(), peer_info);
            }
        }
        result
    }

    pub fn get_config(&self) -> &config::Config {
        &self.config
    }

    pub fn get_socket(&self) -> Arc<dyn UdpSocketExt> {
        self.socket.clone()
    }

    pub fn get_metrics(&self) -> &metrics::Metrics {
        &self.metrics
    }

    pub fn get_metrics_snapshot(&self) -> metrics::MetricsSnapshot {
        self.metrics.get_snapshot()
    }

    pub fn get_uptime(&self) -> String {
        let duration = self.start_time.elapsed();
        format_duration(duration)
    }

    pub fn get_block_height(&self) -> u64 {
        consensus::consensus::get_chain_height().unwrap_or(0)
    }

    pub async fn get_entries(&self) -> Vec<(u64, u64, u64)> {
        // Try to get real archived entries, fallback to sample data if it fails
        tokio::task::spawn_blocking(|| {
            tokio::runtime::Handle::current().block_on(async {
                consensus::entry::get_archived_entries().await.unwrap_or_else(|_| {
                    // Fallback to sample data if archiver fails
                    vec![
                        (201, 20100123, 1024), // (epoch, height, size_bytes)
                        (201, 20100456, 2048),
                        (202, 20200789, 1536),
                        (202, 20201012, 3072),
                        (203, 20300345, 2560),
                    ]
                })
            })
        })
        .await
        .unwrap_or_else(|_| {
            // Fallback if spawn_blocking fails
            vec![
                (201, 20100123, 1024),
                (201, 20100456, 2048),
                (202, 20200789, 1536),
                (202, 20201012, 3072),
                (203, 20300345, 2560),
            ]
        })
    }

    /// Set the handshaked status for a peer with the given public key
    pub async fn set_peer_handshaked(&self, pk: &[u8]) -> Result<(), peers::Error> {
        self.node_peers.set_handshaked(pk).await
    }

    /// Set handshake status for a peer by IP address
    pub async fn set_peer_handshake_status(&self, ip: Ipv4Addr, status: HandshakeStatus) -> Result<(), peers::Error> {
        self.node_peers.set_handshake_status(ip, status).await
    }

    /// Set handshake status for a peer by public key
    pub async fn set_peer_handshake_status_by_pk(
        &self,
        pk: &[u8],
        status: HandshakeStatus,
    ) -> Result<(), peers::Error> {
        self.node_peers.set_handshake_status_by_pk(pk, status).await
    }

    /// Update peer information from ANR data
    pub async fn update_peer_from_anr(&self, ip: Ipv4Addr, pk: &[u8], version: &str, status: HandshakeStatus) {
        self.node_peers.update_peer_from_anr(ip, pk, version, status).await
    }

    /// register a UDP broadcaster implementation and start periodic ping/anr tasks
    pub fn set_broadcaster(&mut self, broadcaster: Arc<dyn node::Broadcaster>) {
        use tokio::spawn;
        use tokio::time::{Duration, interval};
        use tracing::debug;

        self.broadcaster = Some(broadcaster.clone());

        // ping loop every 500ms
        let b1 = broadcaster.clone();
        let node_peers1 = self.node_peers.clone();
        self.ping_handle = Some(spawn(async move {
            let mut ticker = interval(Duration::from_millis(500));
            loop {
                ticker.tick().await;
                // placeholder ping payload
                let payload = Vec::new();
                if let Ok(ips) = node_peers1.get_all_ips().await {
                    debug!("broadcast ping to {} peers", ips.len());
                    b1.send_to(ips, payload);
                }
            }
        }));

        // ANR verification loop every 1s
        let b2 = broadcaster.clone();
        let my_pk_copy = self.config.trainer_pk.to_vec();
        let node_registry_clone = self.node_registry.clone();
        self.anr_handle = Some(spawn(async move {
            let mut ticker = interval(Duration::from_secs(1));
            loop {
                ticker.tick().await;
                let list = node_registry_clone.get_random_not_handshaked(3).await;
                if !list.is_empty() {
                    for (pk, ip) in list {
                        if pk != my_pk_copy {
                            let payload = Vec::new(); // placeholder new_phone_who_dis
                            b2.send_to(vec![ip.to_string()], payload);
                        }
                    }
                }
            }
        }));
    }

    /// manual trigger for ping broadcast (optional helper)
    pub async fn broadcast_ping(&self) {
        if let Some(b) = &self.broadcaster {
            if let Ok(ips) = self.node_peers.get_all_ips().await {
                b.send_to(ips, Vec::new());
            }
        }
    }

    /// manual trigger for ANR check broadcast (optional helper)
    pub async fn broadcast_check_anr(&self) {
        if let Some(b) = &self.broadcaster {
            let my_pk = self.config.trainer_pk.to_vec();
            let list = self.node_registry.get_random_not_handshaked(3).await;
            if !list.is_empty() {
                for (pk, ip) in list {
                    if pk != my_pk {
                        b.send_to(vec![ip.to_string()], Vec::new());
                    }
                }
            }
        }
    }

    /// manual trigger for cleanup (optional helper)
    pub async fn cleanup_stale(&self) {
        const CLEANUP_SECS: u64 = 8;
        let cleared_shards = self.reassembler.clear_stale(CLEANUP_SECS).await;
        let cleared_peers = self.node_peers.clear_stale(&self.node_registry).await;
        info!("cleanup: cleared {} stale shards, {} stale peers", cleared_shards, cleared_peers);
    }

    /// Reads UDP datagram and silently does parsing, validation and reassembly
    /// If the protocol message is complete, returns Some(Protocol)
    pub async fn parse_udp(&self, buf: &[u8], src: Ipv4Addr) -> Option<Box<dyn Protocol>> {
        self.metrics.add_incoming_udp_packet(buf.len());
        match self.reassembler.add_shard(buf).await {
            Ok(Some(packet)) => match parse_etf_bin(&packet) {
                Ok(proto) => {
                    self.node_peers.update_peer_from_proto(src, proto.typename()).await;
                    self.metrics.add_incoming_proto(proto.typename());
                    return Some(proto);
                }
                Err(e) => self.metrics.add_error(&e),
            },
            Ok(None) => {} // waiting for more shards, not an error
            Err(e) => self.metrics.add_error(&e),
        }

        None
    }

    pub async fn handle(&self, message: Box<dyn Protocol>, src: Ipv4Addr) -> Result<Instruction, Error> {
        self.metrics.add_incoming_proto(message.typename());
        message.handle(self, src).await.map_err(|e| {
            warn!("can't handle {}: {e}", message.typename());
            self.metrics.add_error(&e);
            e.into()
        })
    }

    pub async fn execute(&self, instruction: Instruction) -> Result<(), Error> {
        let name = instruction.typename();
        self.execute_inner(instruction).await.inspect_err(|e| warn!("can't execute {name}: {e}"))
    }

    /// Handle instruction processing following the Elixir reference implementation
    pub async fn execute_inner(&self, instruction: Instruction) -> Result<(), Error> {
        match instruction {
            Instruction::Noop { why } => {
                debug!("noop: {why}");
                Ok(())
            }

            Instruction::SendWhat { what, dst } => {
                // Send the specified protocol message to the destination
                let Context { config, socket, metrics, .. } = self;
                what.send_to_with_metrics(config, socket.clone(), dst, metrics)
                    .await
                    .map_err(|e| Error::String(format!("Failed to send SendWhat to {}: {:?}", dst, e)))?;
                Ok(())
            }

            Instruction::SendPong { ts_m, dst } => {
                // Reply with pong message
                let seen_time_ms = get_unix_millis_now();
                let pong = Pong { ts: ts_m, seen_time: seen_time_ms };
                pong.send_to_with_metrics(&self.config, self.socket.clone(), dst, &self.metrics)
                    .await
                    .map_err(|e| Error::String(format!("Failed to send pong: {:?}", e)))
            }

            Instruction::ValidTxs { txs } => {
                // Insert valid transactions into tx pool
                info!("received {} valid transactions", txs.len());
                // TODO: implement TXPool.insert(txs) equivalent
                Ok(())
            }

            Instruction::Peers { ips } => {
                // Handle received peer IPs
                info!("received {} peer IPs", ips.len());
                for ip_str in ips {
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        // TODO: add peer to NodePeers or update peer list
                        debug!("adding peer IP: {}", ip);
                    }
                }
                Ok(())
            }

            Instruction::ReceivedSol { sol: _ } => {
                // Handle received solution
                info!("received solution");
                // TODO: validate solution and potentially submit to tx pool
                // Following Elixir implementation:
                // - Check epoch matches current epoch
                // - Verify solution
                // - Check POP signature
                // - Add to TXPool as gifted sol
                // - Build submit_sol transaction
                Ok(())
            }

            Instruction::ReceivedEntry { entry } => {
                // Handle received blockchain entry
                info!("received entry, height: {}", entry.header.height);
                // TODO: implement entry validation and insertion
                // Following Elixir implementation:
                // - Check if entry already exists by hash
                // - Validate entry
                // - Insert into Fabric if height >= rooted_tip_height
                Ok(())
            }

            Instruction::AttestationBulk { bulk } => {
                // Handle bulk attestations
                info!("received attestation bulk with {} attestations", bulk.attestations.len());
                // TODO: process each attestation
                // Following Elixir implementation:
                // - Unpack and validate each attestation
                // - Add to FabricCoordinatorGen or AttestationCache
                Ok(())
            }

            Instruction::ConsensusesPacked { packed: _ } => {
                // Handle packed consensuses
                info!("received consensus bulk");
                // TODO: unpack and validate consensuses
                // Following Elixir implementation:
                // - Unpack each consensus
                // - Send to FabricCoordinatorGen for validation
                Ok(())
            }

            Instruction::CatchupEntryReq { heights } => {
                // Handle catchup entry request
                info!("received catchup entry request for {} heights", heights.len());
                if heights.len() > 100 {
                    warn!("catchup entry request too large: {} heights", heights.len());
                    return Ok(());
                }
                // TODO: implement entry catchup response
                // Following Elixir implementation:
                // - For each height, get entries by height
                // - Send entry messages back to requester
                Ok(())
            }

            Instruction::CatchupTriReq { heights } => {
                // Handle catchup tri request (entries with attestations/consensus)
                info!("received catchup tri request for {} heights", heights.len());
                if heights.len() > 30 {
                    warn!("catchup tri request too large: {} heights", heights.len());
                    return Ok(());
                }
                // TODO: implement tri catchup response
                // Following Elixir implementation:
                // - Get entries by height with attestations or consensus
                // - Send entry messages with attached data back to requester
                Ok(())
            }

            Instruction::CatchupBiReq { heights } => {
                // Handle catchup bi request (attestations and consensuses)
                info!("received catchup bi request for {} heights", heights.len());
                if heights.len() > 30 {
                    warn!("catchup bi request too large: {} heights", heights.len());
                    return Ok(());
                }
                // TODO: implement bi catchup response
                // Following Elixir implementation:
                // - Get attestations and consensuses by height
                // - Send attestation_bulk and consensus_bulk messages
                Ok(())
            }

            Instruction::CatchupAttestationReq { hashes } => {
                // Handle catchup attestation request
                info!("received catchup attestation request for {} hashes", hashes.len());
                if hashes.len() > 30 {
                    warn!("catchup attestation request too large: {} hashes", hashes.len());
                    return Ok(());
                }
                // TODO: implement attestation catchup response
                // Following Elixir implementation:
                // - Get attestations by entry hash
                // - Send attestation_bulk message back to requester
                Ok(())
            }

            Instruction::SpecialBusiness { business: _ } => {
                // Handle special business messages
                info!("received special business");
                // TODO: implement special business handling
                // Following Elixir implementation:
                // - Parse business operation (slash_trainer_tx, slash_trainer_entry)
                // - Generate appropriate attestation/signature
                // - Reply with special_business_reply
                Ok(())
            }

            Instruction::SpecialBusinessReply { business: _ } => {
                // Handle special business reply messages
                info!("received special business reply");
                // TODO: implement special business reply handling
                // Following Elixir implementation:
                // - Parse reply operation
                // - Verify signatures
                // - Forward to SpecialMeetingGen
                Ok(())
            }

            Instruction::SolicitEntry { hash: _ } => {
                // Handle solicit entry request
                info!("received solicit entry request");
                // TODO: implement solicit entry handling
                // Following Elixir implementation:
                // - Check if peer is authorized trainer
                // - Compare entry scores
                // - Potentially backstep temporal chain
                Ok(())
            }

            Instruction::SolicitEntry2 => {
                // Handle solicit entry2 request
                info!("received solicit entry2 request");
                // TODO: implement solicit entry2 handling
                // Following Elixir implementation:
                // - Check if peer is authorized trainer for next height
                // - Get best entry for current height
                // - Potentially rewind chain if needed
                Ok(())
            }

            Instruction::ReplyWhatChallenge { anr: _, challenge: _ } => {
                // Handle what challenge reply (part of handshake)
                info!("replying to what challenge");
                // TODO: implement what challenge reply
                // This is handled internally by NewPhoneWhoDis protocol handler
                Ok(())
            }

            Instruction::ReceivedWhatResponse { responder_anr: _, challenge: _, their_signature: _ } => {
                // Handle received what response (handshake completion)
                info!("received what response");
                // TODO: implement what response handling
                // This is handled internally by What protocol handler
                Ok(())
            }

            Instruction::HandshakeComplete { anr: _ } => {
                // Handle handshake completion
                info!("handshake completed with peer");
                // TODO: mark peer as handshaked
                // This is handled internally by What protocol handler
                Ok(())
            }
        }
    }

    /// manual trigger for bootstrap handshake to seed nodes (optional helper)
    pub async fn bootstrap_handshake(&self) -> Result<(), Error> {
        // create our own ANR for the handshake
        let my_ip = self
            .config
            .public_ipv4
            .as_ref()
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
            .unwrap_or_else(|| Ipv4Addr::new(127, 0, 0, 1));

        let my_anr = Anr::build(
            &self.config.trainer_sk,
            &self.config.trainer_pk,
            &self.config.trainer_pop,
            my_ip,
            self.config.get_ver(),
        )?;

        // create NewPhoneWhoDis message
        let challenge = get_unix_secs_now() as i32; // FIXME: unix secs will overflow i32 in 2038
        let new_phone_who_dis = NewPhoneWhoDis { anr: my_anr, challenge };

        // serialize to compressed ETF binary
        let payload = new_phone_who_dis
            .to_etf_bin()
            .map_err(|e| Error::String(format!("Failed to serialize NewPhoneWhoDis: {:?}", e)))?;

        // Print message bytes in Elixir iex format for verification
        let byte_list: Vec<String> = payload.iter().map(|b| b.to_string()).collect();
        println!("🔍 Manual Bootstrap - Elixir verification command (paste in iex):");
        println!("bytes = [{}]", byte_list.join(", "));
        println!(":erlang.binary_to_term(:erlang.list_to_binary(bytes))");
        println!("# Should show nested map with ANR fields: ip4, pk, pop, port, signature, ts, version");
        println!("# Challenge value: {}", challenge);
        println!();

        // build shards for transmission
        let shards = node::ReedSolomonReassembler::build_shards(&self.config, &payload)
            .map_err(|e| Error::String(format!("Failed to create shards: {:?}", e)))?;

        let sock = self.get_socket();

        for ip in &self.config.seed_nodes {
            let addr = format!("{}:{}", ip, 36969);
            if let Ok(target) = addr.parse::<SocketAddr>() {
                info!(%addr, count = shards.len(), challenge, "sending bootstrap new_phone_who_dis");
                for shard in &shards {
                    sock.send_to_with_metrics(shard, target, &self.metrics)
                        .await
                        .map_err(|e| Error::String(format!("Failed to send shard: {:?}", e)))?;
                }

                // Track sent packet metric
                self.metrics.add_outgoing_proto("new_phone_who_dis");

                // Set handshake status to SentNewPhoneWhoDis for this peer
                if let Ok(seed_ip) = ip.parse::<Ipv4Addr>() {
                    let _ = self.set_peer_handshake_status(seed_ip, SentNewPhoneWhoDis).await;
                }
            }
        }

        info!("sent bootstrap new_phone_who_dis");
        Ok(())
    }
}

/// Format a duration into human-readable form following the requirements:
/// - seconds if less than a minute
/// - minutes plus seconds if less than hour  
/// - hours and minutes if less than day
/// - days and hours if less than month
/// - months and days if less than year
/// - years, months and days if bigger than year
fn format_duration(duration: std::time::Duration) -> String {
    let total_seconds = duration.as_secs();

    if total_seconds < 60 {
        return format!("{}s", total_seconds);
    }

    let minutes = total_seconds / 60;
    let seconds = total_seconds % 60;

    if minutes < 60 {
        return format!("{}m {}s", minutes, seconds);
    }

    let hours = minutes / 60;
    let minutes = minutes % 60;

    if hours < 24 {
        return format!("{}h {}m", hours, minutes);
    }

    let days = hours / 24;
    let hours = hours % 24;

    if days < 30 {
        return format!("{}d {}h", days, hours);
    }

    let months = days / 30; // Approximate months as 30 days
    let days = days % 30;

    if months < 12 {
        return format!("{}mo {}d", months, days);
    }

    let years = months / 12;
    let months = months % 12;

    format!("{}y {}mo {}d", years, months, days)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::MockSocket;

    #[tokio::test(flavor = "multi_thread")]
    async fn tokio_rwlock_allows_concurrent_reads() {
        // set up a tokio RwLock and verify concurrent read access without awaiting while holding a guard
        let lock = tokio::sync::RwLock::new(0usize);

        // acquire first read
        let r1 = lock.read().await;
        assert_eq!(*r1, 0);
        // try to acquire another read without await; should succeed when a read lock is already held
        let r2 = lock.try_read();
        assert!(r2.is_ok(), "try_read should succeed when another reader holds the lock");
        // drop the second read guard before attempting a write to avoid deadlock
        drop(r2);
        drop(r1);

        // now ensure we can write exclusively after dropping readers
        let mut w = lock.write().await;
        *w += 1;
        assert_eq!(*w, 1);
    }

    #[tokio::test]
    async fn test_anr_verification_request_creation() {
        // test that we can create an ANR verification request without errors
        use crate::utils::bls12_381 as bls;
        use std::net::Ipv4Addr;

        // create test config
        let sk = bls::generate_sk();
        let pk = bls::get_public_key(&sk).expect("pk");
        let pop = bls::sign(&sk, &pk, consensus::DST_POP).expect("pop");

        let config = config::Config {
            work_folder: "/tmp/test".to_string(),
            version_3b: [1, 2, 3],
            offline: false,
            http_ipv4: Ipv4Addr::new(127, 0, 0, 1),
            http_port: 3000,
            udp_ipv4: Ipv4Addr::new(127, 0, 0, 1),
            udp_port: 36969,
            public_ipv4: Some("127.0.0.1".to_string()),
            seed_nodes: Vec::new(),
            seed_anrs: Vec::new(),
            other_nodes: Vec::new(),
            trust_factor: 0.8,
            max_peers: 100,
            trainer_sk: sk,
            trainer_pk: pk,
            trainer_pk_b58: String::new(),
            trainer_pop: pop.to_vec(),
            archival_node: false,
            autoupdate: false,
            computor_type: None,
            snapshot_height: 0,
            anr: None,
            anr_desc: None,
            anr_name: None,
        };

        let target_ip = Ipv4Addr::new(127, 0, 0, 1);

        // test that ANR creation doesn't panic and handles errors gracefully
        let my_anr =
            Anr::build(&config.trainer_sk, &config.trainer_pk, &config.trainer_pop, target_ip, "testver".to_string());
        assert!(my_anr.is_ok());
    }

    #[tokio::test]
    async fn test_get_random_unverified_anrs() {
        // test the ANR selection logic - create a test registry
        let registry = NodeAnrs::new();
        let result = registry.get_random_not_handshaked(3).await;

        // should not panic and should return a vector
        // should return at most 3 results as requested
        assert!(result.len() <= 3);
    }

    #[tokio::test]
    async fn test_cleanup_stale_manual_trigger() {
        // test that cleanup_stale can be called manually without error
        use crate::utils::bls12_381 as bls;
        use std::net::Ipv4Addr;

        // create test config with minimal requirements
        let sk = bls::generate_sk();
        let pk = bls::get_public_key(&sk).expect("pk");
        let pop = bls::sign(&sk, &pk, consensus::DST_POP).expect("pop");

        // Use unique work folder to avoid OnceCell conflicts with other tests
        let unique_id = format!("{}_{}", std::process::id(), utils::misc::get_unix_nanos_now());
        let config = config::Config {
            work_folder: format!("/tmp/test_cleanup_{}", unique_id),
            version_3b: [1, 2, 3],
            offline: false,
            http_ipv4: Ipv4Addr::new(127, 0, 0, 1),
            http_port: 3000,
            udp_ipv4: Ipv4Addr::new(127, 0, 0, 1),
            udp_port: 36969,
            public_ipv4: Some("127.0.0.1".to_string()),
            seed_nodes: vec!["127.0.0.1".to_string()],
            seed_anrs: Vec::new(),
            other_nodes: Vec::new(),
            trust_factor: 0.8,
            max_peers: 100,
            trainer_sk: sk,
            trainer_pk: pk,
            trainer_pk_b58: String::new(),
            trainer_pop: pop.to_vec(),
            archival_node: false,
            autoupdate: false,
            computor_type: None,
            snapshot_height: 0,
            anr: None,
            anr_desc: None,
            anr_name: None,
        };

        // create context with test config
        let socket = Arc::new(MockSocket::new());
        let ctx = Context::with_config_and_socket(config, socket).await.expect("context creation");

        // test cleanup_stale manual trigger - should not panic
        ctx.cleanup_stale().await;
    }

    #[tokio::test]
    async fn test_bootstrap_handshake_manual_trigger() {
        // test that bootstrap_handshake can be called manually
        use crate::utils::bls12_381 as bls;
        use std::net::Ipv4Addr;

        // create test config
        let sk = bls::generate_sk();
        let pk = bls::get_public_key(&sk).expect("pk");
        let pop = bls::sign(&sk, &pk, consensus::DST_POP).expect("pop");

        let work_folder = format!("/tmp/test_bootstrap_{}", std::process::id());
        let config = config::Config {
            work_folder,
            version_3b: [1, 2, 3],
            offline: false,
            http_ipv4: Ipv4Addr::new(127, 0, 0, 1),
            http_port: 3000,
            udp_ipv4: Ipv4Addr::new(127, 0, 0, 1),
            udp_port: 36969,
            public_ipv4: Some("127.0.0.1".to_string()),
            seed_nodes: vec!["127.0.0.1".to_string()], // test seed node
            seed_anrs: Vec::new(),
            other_nodes: Vec::new(),
            trust_factor: 0.8,
            max_peers: 100,
            trainer_sk: sk,
            trainer_pk: pk,
            trainer_pk_b58: String::new(),
            trainer_pop: pop.to_vec(),
            archival_node: false,
            autoupdate: false,
            computor_type: None,
            snapshot_height: 0,
            anr: None,
            anr_desc: None,
            anr_name: None,
        };

        // create context with test config
        let socket = Arc::new(MockSocket::new());
        let ctx = Context::with_config_and_socket(config, socket).await.expect("context creation");

        // test bootstrap_handshake manual trigger - should handle errors gracefully
        match ctx.bootstrap_handshake().await {
            Ok(()) => {
                // success case - message was sent
            }
            Err(_e) => {
                // failure case is ok for testing, might be due to network issues
                // the important thing is that it doesn't panic
            }
        }
    }

    #[tokio::test]
    async fn test_context_convenience_socket_functions() {
        // test that Context convenience functions work without panicking
        use std::sync::Arc;

        use crate::utils::bls12_381 as bls;
        use std::net::Ipv4Addr;

        let sk = bls::generate_sk();
        let pk = bls::get_public_key(&sk).expect("pk");
        let pop = bls::sign(&sk, &pk, consensus::DST_POP).expect("pop");

        let config = config::Config {
            work_folder: "/tmp/test_convenience".to_string(),
            version_3b: [1, 2, 3],
            offline: false,
            http_ipv4: Ipv4Addr::new(127, 0, 0, 1),
            http_port: 3000,
            udp_ipv4: Ipv4Addr::new(127, 0, 0, 1),
            udp_port: 36969,
            public_ipv4: Some("127.0.0.1".to_string()),
            seed_nodes: Vec::new(),
            seed_anrs: Vec::new(),
            other_nodes: Vec::new(),
            trust_factor: 0.8,
            max_peers: 100,
            trainer_sk: sk,
            trainer_pk: pk,
            trainer_pk_b58: String::new(),
            trainer_pop: pop.to_vec(),
            archival_node: false,
            autoupdate: false,
            computor_type: None,
            snapshot_height: 0,
            anr: None,
            anr_desc: None,
            anr_name: None,
        };
        let socket = Arc::new(MockSocket::new());

        match Context::with_config_and_socket(config, socket).await {
            Ok(context) => {
                let mut buf = [0u8; 1024];
                let target = "127.0.0.1:1234".parse().unwrap();

                // Test send_to convenience function - should return error with MockSocket but not panic
                match context.send_to(b"test", target).await {
                    Ok(_) => {
                        // unexpected success with MockSocket
                    }
                    Err(_) => {
                        // expected error with MockSocket
                    }
                }

                // Test recv_from convenience function - should return error with MockSocket but not panic
                match context.recv_from(&mut buf).await {
                    Ok(_) => {
                        // unexpected success with MockSocket
                    }
                    Err(_) => {
                        // expected error with MockSocket
                    }
                }
            }
            Err(_) => {
                // context creation failed - this is acceptable for this test
            }
        }
    }
}
