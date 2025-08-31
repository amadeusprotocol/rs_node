use crate::node::protocol::Protocol;
use crate::node::{NodeState, anr, peers};
use crate::utils::misc::get_unix_secs_now;
use crate::{Error, config, metrics, node};
use rand::random;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Reads UDP datagram and silently does parsing, validation and reassembly
/// If the protocol message is complete, returns Some(Protocol)
pub async fn read_udp_packet(ctx: &Context, src: SocketAddr, buf: &[u8]) -> Option<Box<dyn Protocol>> {
    use crate::node::protocol::from_etf_bin;
    ctx.metrics.add_v2_udp_packet(buf.len());

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
    pub(crate) metrics: metrics::Metrics,
    pub(crate) reassembler: Arc<node::ReedSolomonReassembler>,
    pub(crate) node_peers: Arc<peers::NodePeers>,
    node_state: Arc<RwLock<NodeState>>,
    broadcaster: Option<Arc<dyn node::Broadcaster>>,
    // optional handles for broadcast tasks
    pub ping_handle: Option<tokio::task::JoinHandle<()>>,
    pub anr_handle: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub last_ts: u64,
    pub last_msg: String,
    pub handshake_status: crate::node::peers::HandshakeStatus,
    pub version: Option<String>,
}

impl Context {
    pub async fn new() -> Result<Self, Error> {
        let config = config::Config::from_fs(None, None).await?;
        Self::with_config(config).await
    }

    pub async fn with_config(config: config::Config) -> Result<Self, Error> {
        use crate::consensus::fabric::init_kvdb;
        use crate::utils::archiver::init_storage;
        use metrics::Metrics;
        use node::reassembler::ReedSolomonReassembler as Reassembler;
        use tokio::time::{Duration, interval};

        assert_ne!(config.work_folder, "");
        init_kvdb(&config.work_folder).await?;
        init_storage(&config.work_folder).await?;

        let my_ip = config
            .public_ipv4
            .as_ref()
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
            .unwrap_or_else(|| Ipv4Addr::new(127, 0, 0, 1));

        // convert seed anrs from config to ANR structs
        let seed_anrs: Vec<anr::ANR> = config
            .seed_anrs
            .iter()
            .filter_map(|seed| {
                seed.ip4.parse::<Ipv4Addr>().ok().map(|ip| anr::ANR {
                    ip4: ip,
                    pk: seed.pk.clone(),
                    pop: vec![0u8; 96], // seed anrs don't include pop in config
                    port: seed.port,
                    signature: seed.signature.clone(),
                    ts: seed.ts,
                    version: seed.version.clone(),
                    handshaked: false,
                    hasChainPop: false,
                    error: None,
                    error_tries: 0,
                    next_check: seed.ts + 3,
                })
            })
            .collect();

        let my_sk = config.trainer_sk;
        let my_pk = config.trainer_pk;
        let my_pop = config.trainer_pop.clone();

        anr::seed(seed_anrs, &my_sk, &my_pk, &my_pop, config.get_ver(), Some(my_ip)).await?;

        // create node peers instance
        let node_peers = Arc::new(peers::NodePeers::default());
        node_peers.seed(my_ip).await?;

        // send initial bootstrap handshake to seed nodes (new_phone_who_dis)
        {
            let boot_cfg = config.clone();
            let seed_ips = config.seed_nodes.clone();
            tokio::spawn(async move {
                use crate::node::protocol::NewPhoneWhoDis;
                use tokio::net::UdpSocket;
                use tracing::info;

                // create our own ANR for the handshake
                let my_ip = boot_cfg
                    .public_ipv4
                    .as_ref()
                    .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
                    .unwrap_or_else(|| std::net::Ipv4Addr::new(127, 0, 0, 1));

                let my_anr = match anr::ANR::build(
                    &boot_cfg.trainer_sk,
                    &boot_cfg.trainer_pk,
                    &boot_cfg.trainer_pop,
                    my_ip,
                    boot_cfg.get_ver(),
                ) {
                    Ok(anr) => anr,
                    Err(_) => return,
                };

                // generate a random challenge
                let challenge = random::<u64>();

                // create NewPhoneWhoDis message
                let new_phone_who_dis = match NewPhoneWhoDis::new(my_anr, challenge) {
                    Ok(msg) => msg,
                    Err(_) => return,
                };

                // serialize to compressed ETF binary
                let payload = match new_phone_who_dis.to_etf_bin() {
                    Ok(p) => p,
                    Err(_) => return,
                };

                // build shards for transmission
                if let Ok(shards) = node::ReedSolomonReassembler::build_shards(&boot_cfg, payload) {
                    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
                        for ip in seed_ips {
                            let addr = format!("{}:{}", ip, 36969);
                            if let Ok(target) = addr.parse::<std::net::SocketAddr>() {
                                info!(%addr, count = shards.len(), challenge, "sending bootstrap new_phone_who_dis");
                                for shard in &shards {
                                    let _ = sock.send_to(shard, target).await;
                                }
                            }
                        }
                    }
                }
                info!("sent bootstrap new_phone_who_dis, exiting bootstrap task");
            });
        }

        let node_state = Arc::new(RwLock::new(NodeState::init()));
        let reassembler = Arc::new(Reassembler::new());

        const CLEANUP_SECS: u64 = 8;
        let reassembler_local = reassembler.clone();
        let node_peers_local = node_peers.clone();
        tokio::spawn(async move {
            use tracing::info;
            let mut ticker = interval(Duration::from_secs(CLEANUP_SECS));
            loop {
                ticker.tick().await;
                let cleared_shards = reassembler_local.clear_stale(CLEANUP_SECS).await;
                let cleared_peers = node_peers_local.clear_stale().await;
                info!("cleanup: cleared {} stale shards, {} stale peers", cleared_shards, cleared_peers);
            }
        });

        // periodic ANR verification task - runs every 1 second
        const ANR_CHECK_SECS: u64 = 1;
        let config_local = config.clone();
        tokio::spawn(async move {
            use tracing::debug;
            let mut ticker = interval(Duration::from_secs(ANR_CHECK_SECS));
            loop {
                ticker.tick().await;
                
                // get random unverified ANRs and attempt to verify them
                match anr::get_random_unverified(3).await {
                    Ok(unverified_anrs) => {
                        if !unverified_anrs.is_empty() {
                            debug!("ANR check: found {} unverified ANRs", unverified_anrs.len());
                            
                            for (pk, ip4) in unverified_anrs {
                                // skip our own public key
                                if pk == config_local.trainer_pk {
                                    continue;
                                }
                                
                                // send NewPhoneWhoDis message to this IP to verify ANR
                                if let Err(e) = send_anr_verification_request(&config_local, ip4).await {
                                    debug!("Failed to send ANR verification request to {}: {}", ip4, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to get random unverified ANRs: {}", e);
                    }
                }
            }
        });

        let metrics = Metrics::new();
        Ok(Self {
            config,
            metrics,
            reassembler,
            node_peers,
            node_state,
            broadcaster: None,
            ping_handle: None,
            anr_handle: None,
        })
    }

    pub fn get_prometheus_metrics(&self) -> String {
        self.metrics.get_prometheus()
    }

    pub fn get_json_metrics(&self) -> Value {
        self.metrics.get_json()
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

    pub async fn get_entries(&self) -> Vec<String> {
        vec![]
    }

    /// Set the handshaked status for a peer with the given public key
    pub async fn set_peer_handshaked(&self, pk: &[u8]) -> Result<(), peers::Error> {
        self.node_peers.set_handshaked(pk).await
    }

    /// Set handshake status for a peer by IP address
    pub async fn set_peer_handshake_status(&self, ip: std::net::Ipv4Addr, status: peers::HandshakeStatus) -> Result<(), peers::Error> {
        self.node_peers.set_handshake_status(ip, status).await
    }

    /// Set handshake status for a peer by public key
    pub async fn set_peer_handshake_status_by_pk(&self, pk: &[u8], status: peers::HandshakeStatus) -> Result<(), peers::Error> {
        self.node_peers.set_handshake_status_by_pk(pk, status).await
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
        self.anr_handle = Some(spawn(async move {
            let mut ticker = interval(Duration::from_secs(1));
            loop {
                ticker.tick().await;
                if let Ok(list) = anr::get_random_unverified(3).await {
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
            if let Ok(list) = anr::get_random_unverified(3).await {
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
        let cleared_peers = self.node_peers.clear_stale().await;
        tracing::info!("cleanup: cleared {} stale shards, {} stale peers", cleared_shards, cleared_peers);
    }

    /// manual trigger for bootstrap handshake to seed nodes (optional helper)
    pub async fn bootstrap_handshake(&self) -> Result<(), Error> {
        use crate::node::protocol::NewPhoneWhoDis;
        use tokio::net::UdpSocket;
        use tracing::info;

        // create our own ANR for the handshake
        let my_ip = self.config
            .public_ipv4
            .as_ref()
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
            .unwrap_or_else(|| std::net::Ipv4Addr::new(127, 0, 0, 1));

        let my_anr = anr::ANR::build(
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
        let payload = new_phone_who_dis.to_etf_bin()
            .map_err(|e| Error::String(format!("Failed to serialize NewPhoneWhoDis: {:?}", e)))?;

        // build shards for transmission
        let shards = node::ReedSolomonReassembler::build_shards(&self.config, payload)
            .map_err(|e| Error::String(format!("Failed to create shards: {:?}", e)))?;

        let sock = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| Error::String(format!("Failed to bind UDP socket: {:?}", e)))?;

        for ip in &self.config.seed_nodes {
            let addr = format!("{}:{}", ip, 36969);
            if let Ok(target) = addr.parse::<std::net::SocketAddr>() {
                info!(%addr, count = shards.len(), challenge, "sending bootstrap new_phone_who_dis");
                for shard in &shards {
                    sock.send_to(shard, target).await
                        .map_err(|e| Error::String(format!("Failed to send shard: {:?}", e)))?;
                }
            }
        }
        
        info!("sent bootstrap new_phone_who_dis");
        Ok(())
    }
}

/// Send ANR verification request via NewPhoneWhoDis message
async fn send_anr_verification_request(config: &config::Config, target_ip: Ipv4Addr) -> Result<(), Error> {
    use crate::node::protocol::NewPhoneWhoDis;
    use tokio::net::UdpSocket;
    
    // create our own ANR for the verification request
    let my_ip = config
        .public_ipv4
        .as_ref()
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .unwrap_or_else(|| Ipv4Addr::new(127, 0, 0, 1));

    let my_anr = anr::ANR::build(
        &config.trainer_sk,
        &config.trainer_pk,
        &config.trainer_pop,
        my_ip,
        config.get_ver(),
    )?;

    // generate a random challenge for this verification
    let challenge = random::<u64>();

    // create NewPhoneWhoDis message
    let new_phone_who_dis = NewPhoneWhoDis::new(my_anr, challenge)
        .map_err(|e| Error::String(format!("Failed to create NewPhoneWhoDis: {:?}", e)))?;
    
    // serialize to ETF binary
    let payload = new_phone_who_dis.to_etf_bin()
        .map_err(|e| Error::String(format!("Failed to serialize NewPhoneWhoDis: {:?}", e)))?;
    
    // create shards for transmission
    let shards = crate::node::ReedSolomonReassembler::build_shards(config, payload)
        .map_err(|e| Error::String(format!("Failed to create shards: {:?}", e)))?;
    
    // send shards via UDP
    let socket = UdpSocket::bind("0.0.0.0:0").await
        .map_err(|e| Error::String(format!("Failed to bind UDP socket: {:?}", e)))?;
    let target = SocketAddr::new(std::net::IpAddr::V4(target_ip), 36969);
    
    for shard in shards {
        socket.send_to(&shard, target).await
            .map_err(|e| Error::String(format!("Failed to send shard: {:?}", e)))?;
    }
    
    Ok(())
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
        let pop = bls::sign(&sk, &pk, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_").expect("pop");
        
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
        
        // test that the function doesn't panic and handles errors gracefully
        match send_anr_verification_request(&config, target_ip).await {
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
    async fn test_get_random_unverified_anrs() {
        // test the ANR selection logic
        let result = anr::get_random_unverified(3).await;
        
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
        let pop = bls::sign(&sk, &pk, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_").expect("pop");
        
        let config = config::Config {
            work_folder: "/tmp/test".to_string(),
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
        let ctx = Context::with_config(config).await.expect("context creation");
        
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
        let pop = bls::sign(&sk, &pk, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_").expect("pop");
        
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
        let ctx = Context::with_config(config).await.expect("context creation");
        
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
}
