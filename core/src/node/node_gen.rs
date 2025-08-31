use crate::node::{
    anr, peers,
    socket_gen::{NodeGenSocketGen, SocketGenConfig},
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Socket error: {0}")]
    SocketError(String),
    #[error("ANR error: {0}")]
    AnrError(#[from] anr::Error),
    #[error("Peers error: {0}")]
    PeersError(#[from] peers::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Main node generator managing node state and broadcasting
pub struct NodeGen {
    ip: Ipv4Addr,
    port: u16,
    socket_gens: Vec<Arc<NodeGenSocketGen>>,
    node_peers: Arc<peers::NodePeers>,
}

impl NodeGen {
    pub async fn new(ip: Ipv4Addr, port: u16, node_peers: Arc<peers::NodePeers>) -> Result<Self, Error> {
        // create multiple socket generators (8 as in Elixir)
        let mut socket_gens = Vec::new();
        for i in 0..8 {
            let config = SocketGenConfig {
                ip,
                port: port + i as u16, // slightly different ports for each socket gen
                name: format!("NodeGenSocketGen{}", i),
                ..Default::default()
            };

            let socket_gen = NodeGenSocketGen::new(config).await.map_err(|e| Error::SocketError(e.to_string()))?;
            socket_gens.push(Arc::new(socket_gen));
        }

        Ok(Self { ip, port, socket_gens, node_peers })
    }

    pub async fn start(&self) -> Result<(), Error> {
        info!("Starting NodeGen on {}:{}", self.ip, self.port);

        // start all socket generators
        for socket_gen in &self.socket_gens {
            let socket_gen_clone = Arc::clone(socket_gen);
            tokio::spawn(async move {
                if let Err(e) = socket_gen_clone.run().await {
                    warn!("Socket generator error: {}", e);
                }
            });
        }

        Ok(())
    }

    /// Get socket generator by index
    pub fn get_socket_gen(&self) -> Arc<NodeGenSocketGen> {
        let idx = rand::random::<usize>() % self.socket_gens.len();
        Arc::clone(&self.socket_gens[idx])
    }

    /// Get reassembly generator index for a given pk and timestamp
    pub fn get_reassembly_gen_index(pk: &[u8], ts_nano: u64) -> u32 {
        let mut hasher = DefaultHasher::new();
        pk.hash(&mut hasher);
        ts_nano.hash(&mut hasher);
        (hasher.finish() % 32) as u32
    }

    pub async fn broadcast_ping(&self) -> Result<(), Error> {
        debug!("Broadcasting ping to all peers");

        // TODO: create ping message using protocol module
        let msg_compressed = vec![]; // placeholder

        let all_ips = self.node_peers.get_all_ips().await?;
        let socket_gen = self.get_socket_gen();

        socket_gen.send_to_some(all_ips, msg_compressed).await.map_err(|e| Error::SocketError(e.to_string()))?;

        Ok(())
    }

    pub async fn broadcast_check_anr(&self, config: &crate::config::Config) -> Result<(), Error> {
        debug!("Broadcasting ANR checks");

        // use provided trainer pk
        let my_pk = config.trainer_pk.to_vec();

        let random_unverified = anr::get_random_unverified(3).await?;

        for (pk, ip) in random_unverified {
            if pk != my_pk {
                debug!("ANR request to {}", ip);

                // create our own ANR for the verification request
                let my_anr = anr::ANR::build(
                    &config.trainer_sk,
                    &config.trainer_pk,
                    &config.trainer_pop,
                    self.ip,
                    config.get_ver(),
                )
                .map_err(|e| Error::AnrError(e))?;

                // generate a random challenge for this verification
                let challenge =
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()
                        as u64;

                // create new_phone_who_dis message using protocol module
                let new_phone_who_dis = crate::node::protocol::NewPhoneWhoDis::new(my_anr, challenge)
                    .map_err(|e| Error::SocketError(format!("Failed to create NewPhoneWhoDis: {:?}", e)))?;

                // serialize to ETF binary
                let payload = new_phone_who_dis
                    .to_etf_bin()
                    .map_err(|e| Error::SocketError(format!("Failed to serialize NewPhoneWhoDis: {:?}", e)))?;

                // create shards for transmission (large messages need sharding)
                let shards = crate::node::ReedSolomonReassembler::build_shards(config, payload)
                    .map_err(|e| Error::SocketError(format!("Failed to create shards: {:?}", e)))?;

                // send each shard individually to the target IP
                for shard in shards {
                    let socket_gen = self.get_socket_gen();
                    socket_gen
                        .send_to_some(vec![ip.to_string()], shard)
                        .await
                        .map_err(|e| Error::SocketError(e.to_string()))?;
                }
            }
        }

        Ok(())
    }

    pub async fn broadcast(
        &self,
        msg_type: BroadcastType,
        who: PeerSelector,
        _args: Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        debug!("Broadcasting {:?} to {:?}", msg_type, who);

        // TODO: create message using protocol module based on msg_type
        let msg_compressed = vec![]; // placeholder

        let ips = match who {
            PeerSelector::All => self.node_peers.get_all_ips().await?,
            PeerSelector::ByWho(_who_type) => {
                // TODO: convert who_type string to appropriate Who enum variant
                // For now, just return all IPs
                self.node_peers.get_all_ips().await?
            }
        };

        let socket_gen = self.get_socket_gen();
        socket_gen.send_to_some(ips, msg_compressed).await.map_err(|e| Error::SocketError(e.to_string()))?;

        Ok(())
    }
    //
    // async fn tick(&self) -> Result<(), Error> {
    //     debug!("Node tick - clearing stale peers");
    //     let cleared_count = self.node_peers.clear_stale_inner().await?;
    //     debug!("cleared {} stale peers", cleared_count);
    //     Ok(())
    // }
}

#[derive(Debug, Clone)]
pub enum BroadcastType {
    TxPool,
    Entry,
    AttestationBulk,
    Sol,
    SpecialBusiness,
}

#[derive(Debug, Clone)]
pub enum PeerSelector {
    All,
    ByWho(String),
}

impl crate::node::Broadcaster for NodeGen {
    fn send_to(&self, ips: Vec<String>, payload: Vec<u8>) {
        let socket_gen = self.get_socket_gen();
        tokio::spawn(async move {
            // ignore result per fire-and-forget semantics
            let _ = socket_gen.send_to_some(ips, payload).await;
        });
    }
}
