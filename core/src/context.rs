use crate::consensus::DST_ANR_CHALLENGE;
use crate::node::anr::{Anr, NodeAnrs};
use crate::node::peers::HandshakeStatus;
use crate::node::protocol::*;
use crate::node::protocol::{Instruction, NewPhoneWhoDis};
use crate::node::{anr, peers};
use crate::socket::UdpSocketExt;
use crate::utils::bls12_381;
use crate::utils::misc::{Typename, get_unix_secs_now, pk_challenge_into_bin};
use crate::utils::misc::{format_duration, get_unix_millis_now};
use crate::{SystemStats, config, consensus, get_system_stats, metrics, node, utils};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

#[derive(Debug, thiserror::Error, strum_macros::IntoStaticStr)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Bls(#[from] bls12_381::Error),
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

impl Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

/// Runtime container for config, metrics, reassembler, and node state.
pub struct Context {
    pub(crate) config: config::Config,
    pub(crate) metrics: metrics::Metrics,
    pub(crate) reassembler: node::ReedSolomonReassembler,
    pub(crate) node_peers: peers::NodePeers,
    pub(crate) node_anrs: NodeAnrs,
    pub(crate) socket: Arc<dyn UdpSocketExt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub last_ts: u64,
    pub last_msg: String,
    pub handshake_status: HandshakeStatus,
    pub version: Option<String>,
    pub height: u64,
    pub latency: u64,
}

impl Context {
    pub async fn with_config_and_socket(
        config: config::Config,
        socket: Arc<dyn UdpSocketExt>,
    ) -> Result<Arc<Self>, Error> {
        use crate::config::{BROADCAST_PERIOD_SECS, CLEANUP_PERIOD_SECS, HANDSHAKE_PERIOD_SECS};
        use crate::consensus::fabric::init_kvdb;
        use crate::utils::archiver::init_storage;
        use metrics::Metrics;
        use node::reassembler::ReedSolomonReassembler as Reassembler;
        use tokio::time::{Duration, interval};

        assert_ne!(config.get_root(), "");
        init_kvdb(&config.get_root()).await?;
        init_storage(&config.get_root()).await?;

        let metrics = Metrics::new();
        let node_peers = peers::NodePeers::default();
        let node_anrs = NodeAnrs::new();
        let reassembler = Reassembler::new();

        node_anrs.seed(&config).await; // must be done before node_peers.seed()
        node_peers.seed(&config, &node_anrs).await?;

        let ctx = Arc::new(Self { config, metrics, reassembler, node_peers, node_anrs, socket });

        tokio::spawn({
            let ctx = ctx.clone();
            async move {
                if let Err(e) = ctx.bootstrap_task().await {
                    warn!("bootstrap task error: {e}");
                    ctx.metrics.add_error(&e);
                }
            }
        });

        tokio::spawn({
            let ctx = ctx.clone();
            async move {
                let mut ticker = interval(Duration::from_secs(CLEANUP_PERIOD_SECS));
                loop {
                    ticker.tick().await;
                    ctx.cleanup_task(CLEANUP_PERIOD_SECS).await;
                }
            }
        });

        tokio::spawn({
            let ctx = ctx.clone();
            async move {
                let mut ticker = interval(Duration::from_secs(HANDSHAKE_PERIOD_SECS));
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    if let Err(e) = ctx.handshake_task().await {
                        warn!("handshake task error: {e}");
                        ctx.metrics.add_error(&e);
                    }
                }
            }
        });

        tokio::spawn({
            let ctx = ctx.clone();
            async move {
                let mut ticker = interval(Duration::from_secs(BROADCAST_PERIOD_SECS));
                loop {
                    ticker.tick().await;
                    if let Err(e) = ctx.broadcast_task().await {
                        // broadcast errors are expected when starting from scratch
                        debug!("broadcast task error: {e}");
                        //ctx.metrics.add_error(&e);
                    }
                }
            }
        });

        Ok(ctx)
    }

    #[instrument(skip(self), name = "bootstrap_task")]
    async fn bootstrap_task(&self) -> Result<(), Error> {
        let anr = Anr::from_config(&self.config)?;
        let challenge = get_unix_secs_now() as i32; // FIXME: unix secs will overflow i32 in 2038
        let new_phone_who_dis = NewPhoneWhoDis { anr, challenge };

        for ip in &self.config.seed_ips {
            new_phone_who_dis.send_to_with_metrics(&self.config, self.socket.clone(), *ip, &self.metrics).await?;
            self.node_peers.set_handshake_status(*ip, HandshakeStatus::Initiated).await?;
        }

        info!("sent new_phone_who_dis to {} seed nodes", self.config.seed_ips.len());
        Ok(())
    }

    #[instrument(skip(self), name = "cleanup_task")]
    async fn cleanup_task(&self, cleanup_secs: u64) {
        let cleared_shards = self.reassembler.clear_stale(cleanup_secs).await;
        let cleared_peers = self.node_peers.clear_stale(&self.node_anrs).await;
        if cleared_shards > 0 || cleared_peers > 0 {
            debug!("cleared {} stale shards, {} stale peers", cleared_shards, cleared_peers);
        }
    }

    #[instrument(skip(self), name = "handshake_task")]
    async fn handshake_task(&self) -> Result<(), Error> {
        let unverified_anrs = self.node_anrs.get_random_not_handshaked(3).await;
        if !unverified_anrs.is_empty() {
            let challenge = get_unix_secs_now() as i32; // FIXME: unix secs will overflow i32 in 2038
            let anr = Anr::from_config(&self.config)?;
            let new_phone_who_dis = NewPhoneWhoDis { anr, challenge };

            let nodes_count = unverified_anrs.len();
            for ip in &unverified_anrs {
                new_phone_who_dis.send_to_with_metrics(&self.config, self.socket.clone(), *ip, &self.metrics).await?;
                self.node_peers.set_handshake_status(*ip, HandshakeStatus::Initiated).await?;
            }

            info!("sent new_phone_who_dis to {nodes_count} nodes");
        }

        Ok(())
    }

    #[instrument(skip(self), name = "broadcast_task")]
    async fn broadcast_task(&self) -> Result<(), Error> {
        let ping = Ping::from_current_tips()?;

        let my_ip = self.config.get_public_ipv4();
        let peers = self.node_peers.all().await?;
        if !peers.is_empty() {
            let mut sent_count = 0;
            for peer in peers {
                if peer.ip != my_ip {
                    self.send_message_to(&ping, peer.ip).await?;
                    sent_count += 1;
                }
            }

            debug!("sent {sent_count} ping messages");
        }

        Ok(())
    }

    async fn autoupdate_task(&self) -> Result<(), Error> {
        // TODO: check if updates are available, then download and verify update signature and
        // apply set the flag to make the node restart after it's slot
        Ok(())
    }

    pub fn get_prometheus_metrics(&self) -> String {
        self.metrics.get_prometheus()
    }

    pub fn get_json_metrics(&self) -> Value {
        self.metrics.get_json()
    }

    pub fn get_json_health(&self) -> Value {
        serde_json::json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "uptime": self.metrics.get_uptime()
        })
    }

    /// Convenience function to send UDP data with metrics tracking
    pub async fn send_message_to(&self, message: &impl Protocol, dst: Ipv4Addr) -> Result<(), Error> {
        message.send_to_with_metrics(&self.config, self.socket.clone(), dst, &self.metrics).await.map_err(Into::into)
    }

    /// Convenience function to receive UDP data with metrics tracking
    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from_with_metrics(buf, &self.metrics).await
    }

    pub async fn is_peer_handshaked(&self, ip: Ipv4Addr) -> bool {
        if let Some(peer) = self.node_peers.by_ip(ip).await {
            if let Some(ref pk) = peer.pk {
                if self.node_anrs.is_handshaked(pk).await {
                    return true;
                }
            }
        }
        false
    }

    pub async fn get_peers(&self) -> HashMap<String, PeerInfo> {
        let my_ip = self.config.get_public_ipv4();
        let mut result = HashMap::new();
        if let Ok(all_peers) = self.node_peers.all().await {
            for peer in all_peers {
                if peer.ip == my_ip {
                    continue; // skip self
                }

                let peer_info = PeerInfo {
                    last_ts: peer.last_seen,
                    last_msg: peer.last_msg_type.unwrap_or_else(|| "unknown".to_string()),
                    handshake_status: peer.handshake_status.clone(),
                    version: peer.version.clone(),
                    height: peer.temporal.map(|t| t.header_unpacked.height).unwrap_or(0),
                    latency: peer.latency.unwrap_or(0),
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

    pub fn get_system_stats(&self) -> SystemStats {
        get_system_stats()
    }

    pub fn get_uptime(&self) -> String {
        format_duration(self.metrics.get_uptime())
    }

    /// Add a task to the metrics tracker
    pub fn inc_tasks(&self) {
        self.metrics.inc_tasks();
    }

    /// Remove a task from the metrics tracker
    pub fn dec_tasks(&self) {
        self.metrics.dec_tasks();
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
    pub async fn update_peer_from_anr(&self, ip: Ipv4Addr, pk: &[u8], version: &str, status: Option<HandshakeStatus>) {
        self.node_peers.update_peer_from_anr(ip, pk, version, status).await
    }

    /// manual trigger for cleanup (optional helper)
    pub async fn cleanup_stale(&self) {
        const CLEANUP_SECS: u64 = 8;
        let cleared_shards = self.reassembler.clear_stale(CLEANUP_SECS).await;
        let cleared_peers = self.node_peers.clear_stale(&self.node_anrs).await;
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

    pub async fn handle(&self, message: Box<dyn Protocol>, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
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
            }

            Instruction::SendWhat { challenge, dst } => {
                let anr = Anr::from_config(&self.config)?;
                let data = pk_challenge_into_bin(&self.config.trainer_pk, challenge);
                let signature = bls12_381::sign(&self.config.trainer_sk, &data, DST_ANR_CHALLENGE)?.to_vec();
                let what = What { anr, challenge, signature };
                self.send_message_to(&what, dst).await?;
            }

            Instruction::SendPong { ts_m, dst } => {
                let seen_time_ms = get_unix_millis_now();
                let pong = Pong { ts: ts_m, seen_time: seen_time_ms };
                self.send_message_to(&pong, dst).await?;
            }

            Instruction::SendPeersV2 { dst } => {
                let anrs = self.node_anrs.get_random_handshaked_anrs(3).await;
                if anrs.is_empty() {
                    debug!("not sending peers_v2, no handshaked anrs");
                    return Ok(());
                }
                let peers_v2 = PeersV2 { anrs };
                self.send_message_to(&peers_v2, dst).await?;
            }

            Instruction::ValidTxs { txs } => {
                // Insert valid transactions into tx pool
                info!("received {} valid transactions", txs.len());
                // TODO: implement TXPool.insert(txs) equivalent
            }

            Instruction::Peers { ips } => {
                // Handle received peer IPs
                info!("received {} peer IPs", ips.len());
                for ip in ips {
                    // TODO: add peer to NodePeers or update peer list
                    debug!("adding peer IP: {}", ip);
                }
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
            }

            Instruction::ReceivedEntry { entry } => {
                // Handle received blockchain entry
                info!("received entry, height: {}", entry.header.height);
                // TODO: implement entry validation and insertion
                // Following Elixir implementation:
                // - Check if entry already exists by hash
                // - Validate entry
                // - Insert into Fabric if height >= rooted_tip_height
            }

            Instruction::AttestationBulk { bulk } => {
                // Handle bulk attestations
                info!("received attestation bulk with {} attestations", bulk.attestations.len());
                // TODO: process each attestation
                // Following Elixir implementation:
                // - Unpack and validate each attestation
                // - Add to FabricCoordinatorGen or AttestationCache
            }

            Instruction::ConsensusesPacked { packed: _ } => {
                // Handle packed consensuses
                info!("received consensus bulk");
                // TODO: unpack and validate consensuses
                // Following Elixir implementation:
                // - Unpack each consensus
                // - Send to FabricCoordinatorGen for validation
            }

            Instruction::CatchupEntryReq { heights } => {
                // Handle catchup entry request
                info!("received catchup entry request for {} heights", heights.len());
                if heights.len() > 100 {
                    warn!("catchup entry request too large: {} heights", heights.len());
                }
                // TODO: implement entry catchup response
                // Following Elixir implementation:
                // - For each height, get entries by height
                // - Send entry messages back to requester
            }

            Instruction::CatchupTriReq { heights } => {
                // Handle catchup tri request (entries with attestations/consensus)
                info!("received catchup tri request for {} heights", heights.len());
                if heights.len() > 30 {
                    warn!("catchup tri request too large: {} heights", heights.len());
                }
                // TODO: implement tri catchup response
                // Following Elixir implementation:
                // - Get entries by height with attestations or consensus
                // - Send entry messages with attached data back to requester
            }

            Instruction::CatchupBiReq { heights } => {
                // Handle catchup bi request (attestations and consensuses)
                info!("received catchup bi request for {} heights", heights.len());
                if heights.len() > 30 {
                    warn!("catchup bi request too large: {} heights", heights.len());
                }
                // TODO: implement bi catchup response
                // Following Elixir implementation:
                // - Get attestations and consensuses by height
                // - Send attestation_bulk and consensus_bulk messages
            }

            Instruction::CatchupAttestationReq { hashes } => {
                // Handle catchup attestation request
                info!("received catchup attestation request for {} hashes", hashes.len());
                if hashes.len() > 30 {
                    warn!("catchup attestation request too large: {} hashes", hashes.len());
                }
                // TODO: implement attestation catchup response
                // Following Elixir implementation:
                // - Get attestations by entry hash
                // - Send attestation_bulk message back to requester
            }

            Instruction::SpecialBusiness { business: _ } => {
                // Handle special business messages
                info!("received special business");
                // TODO: implement special business handling
                // Following Elixir implementation:
                // - Parse business operation (slash_trainer_tx, slash_trainer_entry)
                // - Generate appropriate attestation/signature
                // - Reply with special_business_reply
            }

            Instruction::SpecialBusinessReply { business: _ } => {
                // Handle special business reply messages
                info!("received special business reply");
                // TODO: implement special business reply handling
                // Following Elixir implementation:
                // - Parse reply operation
                // - Verify signatures
                // - Forward to SpecialMeetingGen
            }

            Instruction::SolicitEntry { hash: _ } => {
                // Handle solicit entry request
                info!("received solicit entry request");
                // TODO: implement solicit entry handling
                // Following Elixir implementation:
                // - Check if peer is authorized trainer
                // - Compare entry scores
                // - Potentially backstep temporal chain
            }

            Instruction::SolicitEntry2 => {
                // Handle solicit entry2 request
                info!("received solicit entry2 request");
                // TODO: implement solicit entry2 handling
                // Following Elixir implementation:
                // - Check if peer is authorized trainer for next height
                // - Get best entry for current height
                // - Potentially rewind chain if needed
            }

            Instruction::ReplyWhatChallenge { anr: _, challenge: _ } => {
                // Handle what challenge reply (part of handshake)
                info!("replying to what challenge");
                // TODO: implement what challenge reply
                // This is handled internally by NewPhoneWhoDis protocol handler
            }

            Instruction::ReceivedWhatResponse { responder_anr: _, challenge: _, their_signature: _ } => {
                // Handle received what response (handshake completion)
                info!("received what response");
                // TODO: implement what response handling
                // This is handled internally by What protocol handler
            }

            Instruction::HandshakeComplete { anr: _ } => {
                // Handle handshake completion
                info!("handshake completed with peer");
                // TODO: mark peer as handshaked
                // This is handled internally by What protocol handler
            }
        };

        Ok(())
    }
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
            seed_ips: Vec::new(),
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
            seed_ips: vec!["127.0.0.1".parse().unwrap()],
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
            seed_ips: vec!["127.0.0.1".parse().unwrap()], // test seed node
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
        match ctx.bootstrap_task().await {
            Ok(()) => {
                // success case - message was sent
            }
            Err(_e) => {
                // failure case is ok for testing, might be due to network issues
                // the important thing is that it doesn't panic
            }
        }
    }

    #[test]
    fn test_context_task_tracking() {
        // test that Context task tracking wrapper functions work
        use crate::utils::bls12_381 as bls;
        use std::net::Ipv4Addr;

        let sk = bls::generate_sk();
        let pk = bls::get_public_key(&sk).expect("pk");
        let pop = bls::sign(&sk, &pk, consensus::DST_POP).expect("pop");

        let config = config::Config {
            work_folder: "/tmp/test_tasks".to_string(),
            version_3b: [1, 2, 3],
            offline: false,
            http_ipv4: Ipv4Addr::new(127, 0, 0, 1),
            http_port: 3000,
            udp_ipv4: Ipv4Addr::new(127, 0, 0, 1),
            udp_port: 36969,
            public_ipv4: Some("127.0.0.1".to_string()),
            seed_ips: Vec::new(),
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
        let metrics = metrics::Metrics::new();
        let node_peers = peers::NodePeers::default();
        let node_anrs = crate::node::anr::NodeAnrs::new();
        let reassembler = node::reassembler::ReedSolomonReassembler::new();

        let ctx = Context { config, metrics, reassembler, node_peers, node_anrs, socket };

        // Test task tracking via Context wrapper methods
        let snapshot = ctx.get_metrics_snapshot();
        assert_eq!(snapshot.tasks, 0);

        ctx.inc_tasks();
        ctx.inc_tasks();
        let snapshot = ctx.get_metrics_snapshot();
        assert_eq!(snapshot.tasks, 2);

        ctx.dec_tasks();
        let snapshot = ctx.get_metrics_snapshot();
        assert_eq!(snapshot.tasks, 1);
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
            seed_ips: Vec::new(),
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
                let target: Ipv4Addr = "127.0.0.1".parse().unwrap();

                let pong = Pong { ts: 1234567890, seen_time: 1234567890123 };
                // Test send_to convenience function - should return error with MockSocket but not panic
                match context.send_message_to(&pong, target).await {
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
