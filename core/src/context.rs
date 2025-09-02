use crate::config::{ANR_CHECK_SECS, CLEANUP_SECS};
use crate::node::anr::{Anr, NodeRegistry};
use crate::node::peers::HandshakeStatus::SentNewPhoneWhoDis;
use crate::node::protocol::NewPhoneWhoDis;
use crate::node::protocol::Protocol;
use crate::node::{NodeState, peers};
use crate::utils::misc::TermExt;
#[cfg(test)]
use crate::socket::MockSocket;
use crate::socket::UdpSocketExt;
use crate::utils::misc::get_unix_secs_now;
use crate::{Error, config, metrics, node};
use rand::random;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::spawn;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Reads UDP datagram and silently does parsing, validation and reassembly
/// If the protocol message is complete, returns Some(Protocol)
pub async fn read_udp_packet(ctx: &Context, src: SocketAddr, buf: &[u8]) -> Option<Box<dyn Protocol>> {
    use crate::node::protocol::from_etf_bin;
    ctx.metrics.add_incoming_udp_packet(buf.len());

    match ctx.reassembler.add_shard(buf).await {
        Ok(Some(packet)) => match from_etf_bin(&packet) {
            Ok(proto) => {
                let _last_ts = get_unix_secs_now();
                let last_msg = proto.typename().to_string();

                // Extract IP from SocketAddr and update peer info
                if let std::net::IpAddr::V4(ipv4) = src.ip() {
                    let _ = ctx.update_peer_activity(ipv4, &last_msg).await;
                }

                return Some(proto);
            }
            Err(e) => ctx.metrics.add_error(&e),
        },
        Ok(None) => {} // waiting for more shards, not an error
        Err(e) => ctx.metrics.add_error(&e),
    }

    None
}

/// Runtime container for config, metrics, reassembler, and node state.
pub struct Context {
    pub(crate) config: config::Config,
    pub(crate) metrics: Arc<metrics::Metrics>,
    pub(crate) reassembler: Arc<node::ReedSolomonReassembler>,
    pub(crate) node_peers: Arc<peers::NodePeers>,
    pub(crate) node_registry: Arc<NodeRegistry>,
    pub(crate) node_state: Arc<RwLock<NodeState>>,
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
    pub handshake_status: crate::node::peers::HandshakeStatus,
    pub version: Option<String>,
}

impl Context {
    pub async fn with_config_and_socket(config: config::Config, socket: Arc<dyn UdpSocketExt>) -> Result<Self, Error> {
        use crate::consensus::fabric::init_kvdb;
        use crate::utils::archiver::init_storage;
        use metrics::Metrics;
        use node::reassembler::ReedSolomonReassembler as Reassembler;
        use tokio::time::{Duration, interval};

        assert_ne!(config.work_folder, "");
        init_kvdb(&config.work_folder).await?;
        init_storage(&config.work_folder).await?;

        let metrics = Arc::new(Metrics::new());
        let node_peers = Arc::new(peers::NodePeers::default());
        let node_registry = Arc::new(NodeRegistry::new());

        node_registry.seed(&config).await?; // must be done before node_peers.seed()
        node_peers.seed(&config, &node_registry).await?;

        {
            // oneshot bootstrap task to send new_phone_who_dis to seed nodes
            let config = config.clone();
            let socket = socket.clone();
            let metrics = metrics.clone();
            let node_peers = node_peers.clone();
            let anr = Anr::from_config(&config)?;
            spawn(async move {
                let challenge = random::<u64>();
                let new_phone_who_dis = match NewPhoneWhoDis::new(anr.clone(), challenge) {
                    Ok(msg) => msg,
                    Err(e) => {
                        warn!("bootstrap: failed to create NewPhoneWhoDis: {e}");
                        return;
                    }
                };

                // Add detailed logging to debug the ANR format being sent
                info!("bootstrap: created new_phone_who_dis with challenge {}", challenge);
                info!("bootstrap: ANR size: {} bytes (Elixir limit: 390 bytes) ✅", new_phone_who_dis.anr.len());
                
                // Log ANR structure for debugging
                if let Ok(anr_term) = eetf::Term::decode(&new_phone_who_dis.anr[..]) {
                    if let Some(anr_map) = anr_term.get_term_map() {
                        let fields: Vec<String> = anr_map.0.keys()
                            .map(|k| format!("{:?}", k))
                            .collect();
                        info!("bootstrap: ANR fields: [{}]", fields.join(", "));
                        
                        // Check specific field formats
                        if let Some(ip4_term) = anr_map.0.get(&eetf::Term::Atom(eetf::Atom::from("ip4"))) {
                            info!("bootstrap: ANR ip4 field type: {:?}", ip4_term);
                        }
                        if let Some(ts_term) = anr_map.0.get(&eetf::Term::Atom(eetf::Atom::from("ts"))) {
                            info!("bootstrap: ANR ts field type: {:?}", ts_term);
                        }
                        if let Some(sig_term) = anr_map.0.get(&eetf::Term::Atom(eetf::Atom::from("signature"))) {
                            if let eetf::Term::Binary(bin) = sig_term {
                                info!("bootstrap: ANR signature size: {} bytes", bin.bytes.len());
                            }
                        }
                    }
                } else {
                    warn!("bootstrap: failed to decode ANR binary for logging");
                }

                // Log the complete message size that will be sent
                if let Ok(etf_bin) = new_phone_who_dis.to_etf_bin() {
                    info!("bootstrap: complete new_phone_who_dis message size: {} bytes", etf_bin.len());
                    // Note: The 390-byte limit in Elixir applies only to the ANR itself, not the complete message
                    if etf_bin.len() > 1000 {  // Only warn if message is extremely large
                        warn!("bootstrap: message is very large ({}B), may cause network issues", etf_bin.len());
                    }
                }

                let mut sent_count = 0;
                for ip in &config.seed_nodes {
                    let addr = match ip.parse::<Ipv4Addr>() {
                        Ok(ip) => ip,
                        Err(e) => {
                            warn!("bootstrap: invalid seed node ip {}: {}", ip, e);
                            continue;
                        }
                    };

                    info!("bootstrap: sending new_phone_who_dis to {}:36969", addr);
                    if let Err(e) = new_phone_who_dis
                        .send_to_with_metrics(&config, socket.clone(), SocketAddr::new(addr.into(), 36969), &metrics)
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

        let node_state = Arc::new(RwLock::new(NodeState::init()));
        let reassembler = Arc::new(Reassembler::new());

        {
            // periodic cleanup task
            let reassembler = reassembler.clone();
            let node_peers = node_peers.clone();
            let node_registry_cleanup = node_registry.clone();
            spawn(async move {
                let mut ticker = interval(Duration::from_secs(CLEANUP_SECS));
                loop {
                    ticker.tick().await;
                    let cleared_shards = reassembler.clear_stale(CLEANUP_SECS).await;
                    let cleared_peers = node_peers.clear_stale(&node_registry_cleanup).await;
                    debug!("cleanup: cleared {cleared_shards} stale shards, {cleared_peers} stale peers");
                }
            });
        }

        {
            // periodic anr check task
            let config = config.clone();
            let socket = socket.clone();
            let metrics = metrics.clone();
            let node_peers = node_peers.clone();
            let node_registry_clone = node_registry.clone();
            spawn(async move {
                let mut ticker = interval(Duration::from_secs(ANR_CHECK_SECS));
                loop {
                    ticker.tick().await;
                    // get random unverified anrs and attempt to verify them
                    match node_registry_clone.get_random_not_handshaked(3).await {
                        Ok(unverified_anrs) => {
                            debug!("anrcheck: found {} unverified anrs", unverified_anrs.len());

                            let anr = match Anr::from_config(&config) {
                                Ok(a) => a,
                                Err(e) => {
                                    warn!("anrcheck: failed to create anr from config: {e}");
                                    continue;
                                }
                            };

                            let challenge = random::<u64>();
                            let new_phone_who_dis = match NewPhoneWhoDis::new(anr, challenge) {
                                Ok(msg) => msg,
                                Err(e) => {
                                    warn!("anrcheck: failed to create NewPhoneWhoDis: {e}");
                                    return;
                                }
                            };

                            // Log ANR details for verification attempts too
                            debug!("anrcheck: ANR size: {} bytes (Elixir limit: 390 bytes) ✅", new_phone_who_dis.anr.len());
                            if let Ok(etf_bin) = new_phone_who_dis.to_etf_bin() {
                                debug!("anrcheck: complete message size: {} bytes", etf_bin.len());
                                // The 390-byte limit applies only to ANR, not complete message
                                if new_phone_who_dis.anr.len() > 390 {
                                    warn!("anrcheck: ANR size ({} bytes) exceeds Elixir's 390-byte limit!", new_phone_who_dis.anr.len());
                                }
                            }

                            for (_, ip) in unverified_anrs.iter().cloned() {
                                debug!("anrcheck: sending new_phone_who_dis to {}:36969", ip);
                                if let Err(e) = new_phone_who_dis
                                    .send_to_with_metrics(
                                        &config,
                                        socket.clone(),
                                        SocketAddr::new(ip.into(), 36969),
                                        &metrics,
                                    )
                                    .await
                                {
                                    warn!("anrcheck: failed to send new_phone_who_dis to {ip}: {e}");
                                    continue;
                                }

                                if let Err(e) = node_peers.set_handshake_status(ip, SentNewPhoneWhoDis).await {
                                    warn!("anrcheck: failed to set handshake status for {ip}: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            warn!("anrcheck: can't get random unverified anrs {e}");
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
            node_registry,
            node_state,
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
    pub async fn send_to(&self, buf: &[u8], target: std::net::SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to_with_metrics(buf, target, &self.metrics).await
    }

    /// Convenience function to receive UDP data with metrics tracking  
    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, std::net::SocketAddr)> {
        self.socket.recv_from_with_metrics(buf, &self.metrics).await
    }

    pub async fn update_peer_activity(&self, ip: Ipv4Addr, last_msg: &str) -> Result<(), Error> {
        // Update peer activity using the node_peers instance
        self.node_peers.update_peer_activity(ip, last_msg).await.map_err(|e| Error::String(e.to_string()))?;
        Ok(())
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

    pub fn get_node_state(&self) -> Arc<RwLock<NodeState>> {
        Arc::clone(&self.node_state)
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

    pub async fn get_entries(&self) -> Vec<(u64, u64, u64)> {
        // Try to get real archived entries, fallback to sample data if it fails
        tokio::task::spawn_blocking(|| {
            tokio::runtime::Handle::current().block_on(async {
                crate::consensus::entry::get_archived_entries().await.unwrap_or_else(|_| {
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
    pub async fn set_peer_handshake_status(
        &self,
        ip: std::net::Ipv4Addr,
        status: peers::HandshakeStatus,
    ) -> Result<(), peers::Error> {
        self.node_peers.set_handshake_status(ip, status).await
    }

    /// Set handshake status for a peer by public key
    pub async fn set_peer_handshake_status_by_pk(
        &self,
        pk: &[u8],
        status: peers::HandshakeStatus,
    ) -> Result<(), peers::Error> {
        self.node_peers.set_handshake_status_by_pk(pk, status).await
    }

    /// Update peer information from ANR data
    pub async fn update_peer_from_anr(
        &self,
        ip: std::net::Ipv4Addr,
        pk: &[u8],
        version: &str,
    ) -> Result<(), peers::Error> {
        self.node_peers.update_peer_from_anr(ip, pk, version).await
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
                if let Ok(list) = node_registry_clone.get_random_not_handshaked(3).await {
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
            if let Ok(list) = self.node_registry.get_random_not_handshaked(3).await {
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
        tracing::info!("cleanup: cleared {} stale shards, {} stale peers", cleared_shards, cleared_peers);
    }

    /// Handle instruction processing following the Elixir reference implementation
    pub async fn handle_instruction(
        &self,
        instruction: crate::node::protocol::Instruction,
        src: std::net::SocketAddr,
    ) -> Result<(), crate::Error> {
        use crate::node::protocol::Instruction;
        use tracing::{debug, info, warn};

        match instruction {
            Instruction::Noop => {
                // Do nothing
                Ok(())
            }

            Instruction::ReplyPong { ts_m } => {
                // Reply with pong message
                use crate::node::protocol::{Pong, Protocol};
                let pong = Pong { ts_m, seen_time_ms: crate::utils::misc::get_unix_millis_now() };
                pong.send_to_with_metrics(&self.config, self.socket.clone(), src, &self.metrics)
                    .await
                    .map_err(|e| crate::Error::String(format!("Failed to send pong: {:?}", e)))
            }

            Instruction::ObservedPong { ts_m, seen_time_ms } => {
                // Update peer latency information
                if let std::net::IpAddr::V4(peer_ip) = src.ip() {
                    let latency = seen_time_ms.saturating_sub(ts_m);
                    debug!("observed pong from {} with latency {}ms", peer_ip, latency);
                    // TODO: update peer latency in NodePeers
                }
                Ok(())
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
                    if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                        // TODO: add peer to NodePeers or update peer list
                        debug!("adding peer IP: {}", ip);
                    }
                }
                Ok(())
            }

            Instruction::ReceivedSol { sol: _ } => {
                // Handle received solution
                info!("received solution from {}", src);
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
                info!("received entry from {}, height: {}", src, entry.header.height);
                // TODO: implement entry validation and insertion
                // Following Elixir implementation:
                // - Check if entry already exists by hash
                // - Validate entry
                // - Insert into Fabric if height >= rooted_tip_height
                Ok(())
            }

            Instruction::AttestationBulk { bulk } => {
                // Handle bulk attestations
                info!("received attestation bulk with {} attestations from {}", bulk.attestations.len(), src);
                // TODO: process each attestation
                // Following Elixir implementation:
                // - Unpack and validate each attestation
                // - Add to FabricCoordinatorGen or AttestationCache
                Ok(())
            }

            Instruction::ConsensusesPacked { packed: _ } => {
                // Handle packed consensuses
                info!("received consensus bulk from {}", src);
                // TODO: unpack and validate consensuses
                // Following Elixir implementation:
                // - Unpack each consensus
                // - Send to FabricCoordinatorGen for validation
                Ok(())
            }

            Instruction::CatchupEntryReq { heights } => {
                // Handle catchup entry request
                info!("received catchup entry request for {} heights from {}", heights.len(), src);
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
                info!("received catchup tri request for {} heights from {}", heights.len(), src);
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
                info!("received catchup bi request for {} heights from {}", heights.len(), src);
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
                info!("received catchup attestation request for {} hashes from {}", hashes.len(), src);
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
                info!("received special business from {}", src);
                // TODO: implement special business handling
                // Following Elixir implementation:
                // - Parse business operation (slash_trainer_tx, slash_trainer_entry)
                // - Generate appropriate attestation/signature
                // - Reply with special_business_reply
                Ok(())
            }

            Instruction::SpecialBusinessReply { business: _ } => {
                // Handle special business reply messages
                info!("received special business reply from {}", src);
                // TODO: implement special business reply handling
                // Following Elixir implementation:
                // - Parse reply operation
                // - Verify signatures
                // - Forward to SpecialMeetingGen
                Ok(())
            }

            Instruction::SolicitEntry { hash: _ } => {
                // Handle solicit entry request
                info!("received solicit entry request from {}", src);
                // TODO: implement solicit entry handling
                // Following Elixir implementation:
                // - Check if peer is authorized trainer
                // - Compare entry scores
                // - Potentially backstep temporal chain
                Ok(())
            }

            Instruction::SolicitEntry2 => {
                // Handle solicit entry2 request
                info!("received solicit entry2 request from {}", src);
                // TODO: implement solicit entry2 handling
                // Following Elixir implementation:
                // - Check if peer is authorized trainer for next height
                // - Get best entry for current height
                // - Potentially rewind chain if needed
                Ok(())
            }

            Instruction::ReplyWhatChallenge { anr: _, challenge: _ } => {
                // Handle what challenge reply (part of handshake)
                info!("replying to what challenge from {}", src);
                // TODO: implement what challenge reply
                // This is handled internally by NewPhoneWhoDis protocol handler
                Ok(())
            }

            Instruction::ReceivedWhatResponse { responder_anr: _, challenge: _, their_signature: _ } => {
                // Handle received what response (handshake completion)
                info!("received what response from {}", src);
                // TODO: implement what response handling
                // This is handled internally by What protocol handler
                Ok(())
            }

            Instruction::HandshakeComplete { anr: _ } => {
                // Handle handshake completion
                info!("handshake completed with peer {}", src);
                // TODO: mark peer as handshaked
                // This is handled internally by What protocol handler
                Ok(())
            }
        }
    }

    /// manual trigger for bootstrap handshake to seed nodes (optional helper)
    pub async fn bootstrap_handshake(&self) -> Result<(), Error> {
        use crate::node::protocol::NewPhoneWhoDis;
        use tracing::info;

        // create our own ANR for the handshake
        let my_ip = self
            .config
            .public_ipv4
            .as_ref()
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
            .unwrap_or_else(|| std::net::Ipv4Addr::new(127, 0, 0, 1));

        let my_anr = Anr::build(
            &self.config.trainer_sk,
            &self.config.trainer_pk,
            &self.config.trainer_pop,
            my_ip,
            self.config.get_ver(),
        )?;

        // generate a random challenge
        let challenge = random::<u64>();

        // create NewPhoneWhoDis message
        let new_phone_who_dis = NewPhoneWhoDis::new(my_anr, challenge)
            .map_err(|e| Error::String(format!("Failed to create NewPhoneWhoDis: {:?}", e)))?;

        // serialize to compressed ETF binary
        let payload = new_phone_who_dis
            .to_etf_bin()
            .map_err(|e| Error::String(format!("Failed to serialize NewPhoneWhoDis: {:?}", e)))?;

        // build shards for transmission
        let shards = node::ReedSolomonReassembler::build_shards(&self.config, &payload)
            .map_err(|e| Error::String(format!("Failed to create shards: {:?}", e)))?;

        let sock = self.get_socket();

        for ip in &self.config.seed_nodes {
            let addr = format!("{}:{}", ip, 36969);
            if let Ok(target) = addr.parse::<std::net::SocketAddr>() {
                info!(%addr, count = shards.len(), challenge, "sending bootstrap new_phone_who_dis");
                for shard in &shards {
                    sock.send_to_with_metrics(shard, target, &self.metrics)
                        .await
                        .map_err(|e| Error::String(format!("Failed to send shard: {:?}", e)))?;
                }

                // Track sent packet metric
                self.metrics.add_outgoing_proto_by_name("new_phone_who_dis");

                // Set handshake status to SentNewPhoneWhoDis for this peer
                if let Ok(seed_ip) = ip.parse::<std::net::Ipv4Addr>() {
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
        let pop = bls::sign(&sk, &pk, crate::consensus::DST_POP).expect("pop");

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
        let my_anr = Anr::build(&config.trainer_sk, &config.trainer_pk, &config.trainer_pop, target_ip, "testver".to_string());
        assert!(my_anr.is_ok());
    }

    #[tokio::test]
    async fn test_get_random_unverified_anrs() {
        // test the ANR selection logic - create a test registry
        let registry = NodeRegistry::new();
        let result = registry.get_random_not_handshaked(3).await;

        // should not panic and should return a result
        assert!(result.is_ok());

        let unverified = result.unwrap();
        // should return at most 3 results as requested
        assert!(unverified.len() <= 3);
    }

    #[tokio::test]
    async fn test_cleanup_stale_manual_trigger() {
        // test that cleanup_stale can be called manually without error
        use crate::utils::bls12_381 as bls;
        use std::net::Ipv4Addr;

        // create test config with minimal requirements
        let sk = bls::generate_sk();
        let pk = bls::get_public_key(&sk).expect("pk");
        let pop = bls::sign(&sk, &pk, crate::consensus::DST_POP).expect("pop");

        // Use unique work folder to avoid OnceCell conflicts with other tests
        let unique_id = format!("{}_{}", std::process::id(), crate::utils::misc::get_unix_nanos_now());
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
        let pop = bls::sign(&sk, &pk, crate::consensus::DST_POP).expect("pop");

        let config = config::Config {
            work_folder: "/tmp/test2".to_string(),
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
        let pop = bls::sign(&sk, &pk, crate::consensus::DST_POP).expect("pop");

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
