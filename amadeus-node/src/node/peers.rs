use crate::config::Config;
use crate::consensus::doms::EntrySummary;
use crate::node::anr;
use crate::node::protocol::{EventTip, PingReply};
use crate::utils::misc::{Typename, get_unix_millis_now};
use crate::{Context, Ver};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::spawn_blocking;
use tracing::{info, warn};

/// Represents the different stages of the handshake process
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeStatus {
    /// No handshake initiated
    None,
    /// Sent new_phone_who_dis message, waiting for what response
    Initiated,
    /// Sent/received what message response (handshake done for us)
    Completed,
}

#[derive(Debug)]
struct ConcurrentMap<K, V> {
    inner: RwLock<HashMap<K, V>>,
}

impl<K: Eq + Hash + Clone, V: Clone> ConcurrentMap<K, V> {
    fn new() -> Self {
        Self { inner: RwLock::new(HashMap::new()) }
    }
    async fn len(&self) -> usize {
        self.inner.read().await.len()
    }
    async fn insert(&self, key: K, value: V) -> Result<(), ()> {
        let mut map = self.inner.write().await;
        if map.contains_key(&key) {
            Err(())
        } else {
            map.insert(key, value);
            Ok(())
        }
    }
    async fn remove(&self, key: &K) -> Option<V> {
        self.inner.write().await.remove(key)
    }
    async fn read<R>(&self, key: &K, f: impl FnOnce(&K, &V) -> R) -> Option<R> {
        let v = {
            let map = self.inner.read().await;
            map.get(key).cloned()
        };
        v.as_ref().map(|vv| f(key, vv))
    }
    async fn scan(&self, mut f: impl FnMut(&K, &V)) {
        let snapshot: Vec<(K, V)> = {
            let map = self.inner.read().await;
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        for (k, v) in snapshot.iter() {
            f(k, v);
        }
    }
    async fn update<R>(&self, key: &K, mut f: impl FnMut(&K, &mut V) -> R) -> Option<R> {
        let mut map = self.inner.write().await;
        if let Some(v) = map.get_mut(key) { Some(f(key, v)) } else { None }
    }
}

#[derive(Debug, thiserror::Error, strum_macros::IntoStaticStr)]
pub enum Error {
    #[error("ANR error: {0}")]
    AnrError(#[from] anr::Error),
    #[error("Consensus error: {0}")]
    ConsensusError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
}

impl crate::utils::misc::Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub ip: Ipv4Addr,
    #[serde_as(as = "Option<[_; 48]>")]
    pub pk: Option<[u8; 48]>,
    pub version: Option<Ver>,
    pub latency: Option<u64>,
    pub last_msg: u64,
    pub last_ping: Option<u64>,
    pub last_pong: Option<u64>,
    pub shared_secret: Option<Vec<u8>>,
    pub temporal: Option<TipInfo>,
    pub rooted: Option<TipInfo>,
    pub last_seen_ms: u64,
    pub last_msg_type: Option<String>,
    pub handshake_status: HandshakeStatus,
}

impl Peer {
    /// Check if the handshake is completed (either we sent what or received what)
    pub fn is_handshaked(&self) -> bool {
        self.handshake_status == HandshakeStatus::Completed
    }

    /// Check if a peer is online
    pub fn is_online(&self) -> bool {
        // Peer is online if last ping was within 6 seconds (6000 ms)
        // Use saturating_sub to prevent overflow if last_ping > ts_m
        get_unix_millis_now().saturating_sub(self.last_ping.unwrap_or_default()) <= 6_000
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct TipInfo {
    pub height: u64,
    pub prev_hash: [u8; 32],
}

impl From<EntrySummary> for TipInfo {
    fn from(summary: EntrySummary) -> Self {
        Self { height: summary.header.height, prev_hash: summary.header.prev_hash }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderInfo {
    pub height: u64,
    pub prev_hash: [u8; 32],
}

/// NodePeers structure managing the peer database
#[derive(Debug, Clone)]
pub struct NodePeers {
    peers: Arc<ConcurrentMap<Ipv4Addr, Peer>>,
    max_peers: usize,
}

impl NodePeers {
    /// Create a new NodePeers instance
    pub fn new(max_peers: usize) -> Self {
        Self { peers: Arc::new(ConcurrentMap::new()), max_peers }
    }

    /// Create with default max_peers of 100
    pub fn default() -> Self {
        Self::new(100)
    }

    pub async fn clear_stale(&self, fabric: &crate::consensus::fabric::Fabric, node_registry: &anr::NodeAnrs) -> usize {
        self.clear_stale_inner(fabric, node_registry)
            .await
            .inspect_err(|e| warn!("peer cleanup error: {}", e))
            .unwrap_or(0)
    }

    /// Clear stale peers and add missing validators/handshaked nodes
    pub async fn clear_stale_inner(
        &self,
        fabric: &crate::consensus::fabric::Fabric,
        node_registry: &anr::NodeAnrs,
    ) -> Result<usize, Error> {
        let ts_m = get_unix_millis_now();
        let height = fabric.get_temporal_height_or_0();
        let validators = fabric.trainers_for_height(height + 1).unwrap_or_default();
        let validators_vec: Vec<Vec<u8>> = validators.iter().map(|pk| pk.to_vec()).collect();

        let validator_anr_ips = node_registry.by_pks_ip(&validators_vec).await;
        let validators_map: std::collections::HashSet<&[u8; 48]> = validators.iter().collect();

        let handshaked_ips = node_registry.get_all_handshaked_ip4().await;

        let mut cur_ips = Vec::new();
        let mut cur_val_ips = Vec::new();

        // Clean stale peers and collect current IPs
        let mut to_remove = Vec::new();
        self.peers
            .scan(|ip, peer| {
                // Remove peers that haven't sent messages in 60 seconds (60*1000 ms)
                if ts_m > (peer.last_msg + 60_000) {
                    to_remove.push(*ip);
                    return;
                }

                if let Some(ref pk) = peer.pk {
                    if validators_map.contains(pk) {
                        cur_val_ips.push(*ip);
                    } else {
                        cur_ips.push(*ip);
                    }
                } else {
                    cur_ips.push(*ip);
                }
            })
            .await;

        // Remove stale peers after scanning
        let cleared_count = to_remove.len();
        for ip in to_remove {
            let _ = self.peers.remove(&ip).await;
        }

        // Find missing validators and handshaked peers
        let missing_vals: Vec<_> = validator_anr_ips.iter().filter(|ip| !cur_val_ips.contains(ip)).cloned().collect();

        let missing_ips: Vec<_> = handshaked_ips.into_iter().filter(|ip| !cur_ips.contains(ip)).collect();

        // Get max_peers config
        let add_size = self
            .max_peers
            .saturating_sub(self.size().await)
            .saturating_sub(cur_val_ips.len())
            .saturating_sub(missing_vals.len());

        let missing_ips = spawn_blocking(move || {
            // Shuffle and take limited missing IPs
            let mut missing_ips = missing_ips;
            use rand::seq::SliceRandom;
            let mut rng = rand::rng();
            missing_ips.shuffle(&mut rng);
            missing_ips.truncate(add_size);
            missing_ips
        })
        .await
        .unwrap_or_default();

        // Add missing validators and peers with proper handshake status from ANR
        for ip in missing_vals.iter().chain(missing_ips.iter()) {
            // Find the ANR for this IP to get handshake status
            let mut handshake_status = HandshakeStatus::None;
            let anrs = node_registry.get_all().await;

            for anr in anrs {
                if anr.ip4 == *ip {
                    handshake_status = if anr.handshaked { HandshakeStatus::Completed } else { HandshakeStatus::None };
                    break;
                }
            }

            let _ = self
                .insert_new_peer(Peer {
                    ip: *ip,
                    pk: None,
                    version: None,
                    latency: None,
                    last_msg: ts_m,
                    last_ping: None,
                    last_pong: None,
                    shared_secret: None,
                    temporal: None,
                    rooted: None,
                    last_seen_ms: ts_m,
                    last_msg_type: None,
                    handshake_status,
                })
                .await;
        }

        Ok(cleared_count)
    }

    /// Insert a new peer if it doesn't already exist
    pub async fn insert_new_peer(&self, mut peer: Peer) -> bool {
        if peer.last_msg == 0 {
            peer.last_msg = get_unix_millis_now();
        }

        self.peers.insert(peer.ip, peer).await.is_ok()
    }

    /// Seed initial peers with validators
    pub async fn seed(
        &self,
        fabric: &crate::consensus::fabric::Fabric,
        config: &Config,
        node_anrs: &anr::NodeAnrs,
    ) -> Result<(), Error> {
        let height = fabric.get_temporal_height_or_0();
        let validators = fabric.trainers_for_height(height + 1).unwrap_or_default();
        let validators: Vec<Vec<u8>> = validators.iter().map(|pk| pk.to_vec()).collect();

        let validator_ips: Vec<_> =
            node_anrs.by_pks_ip(&validators).await.into_iter().filter(|ip| *ip != config.get_public_ipv4()).collect();

        let ts_m = get_unix_millis_now();
        for ip in validator_ips {
            let _ = self.insert_new_peer(Peer {
                ip,
                pk: None,
                version: None,
                latency: None,
                last_msg: ts_m,
                last_ping: None,
                last_pong: None,
                shared_secret: None,
                temporal: None,
                rooted: None,
                last_seen_ms: ts_m,
                last_msg_type: None,
                handshake_status: HandshakeStatus::None,
            });
        }

        Ok(())
    }

    /// Get number of peers
    pub async fn size(&self) -> usize {
        self.peers.len().await
    }

    /// Get random online peers
    pub async fn random(&self, no: usize) -> Result<Vec<Peer>, Error> {
        let online_peers = self.get_online().await?;
        if online_peers.is_empty() {
            return Ok(vec![]);
        }

        use rand::seq::SliceRandom;
        let mut rng = rand::rng();
        let mut peers = online_peers;
        peers.shuffle(&mut rng);
        peers.truncate(no);

        Ok(peers)
    }

    /// Get all peers
    pub async fn get_all(&self) -> Result<Vec<Peer>, Error> {
        let mut peers = Vec::new();
        self.peers
            .scan(|_, peer| {
                peers.push(peer.clone());
            })
            .await;
        Ok(peers)
    }

    /// Get all online peers
    pub async fn get_online(&self) -> Result<Vec<Peer>, Error> {
        let mut online_peers = Vec::new();

        self.peers
            .scan(|_, peer| {
                if peer.is_online() {
                    online_peers.push(peer.clone());
                }
            })
            .await;

        Ok(online_peers)
    }

    /// Get summary of online peers
    pub async fn get_online_ip_l_th_rh(&self) -> Result<Vec<(Ipv4Addr, Option<u64>, Option<u64>, Option<u64>)>, Error> {
        let online_peers = self.get_online().await?;
        let mut summary = Vec::new();

        for peer in online_peers {
            let temporal_height = peer.temporal.as_ref().map(|t| t.height);
            let rooted_height = peer.rooted.as_ref().map(|r| r.height);

            summary.push((peer.ip, peer.latency, temporal_height, rooted_height));
        }

        Ok(summary)
    }

    /// Get shared secret for a peer by public key
    pub async fn get_shared_secret(&self, pk: &[u8]) -> Result<Vec<u8>, Error> {
        if pk.is_empty() {
            return Ok(vec![]);
        }

        let mut found_secret = None;
        self.peers
            .scan(|_, peer| {
                if let Some(ref peer_pk) = peer.pk {
                    if peer_pk == pk {
                        found_secret = peer.shared_secret.clone();
                    }
                }
            })
            .await;

        // Return found secret or empty vector
        Ok(found_secret.unwrap_or_default())
    }

    /// Get peer by IP address
    pub async fn by_ip(&self, ip: Ipv4Addr) -> Option<Peer> {
        self.peers.read(&ip, |_, peer| peer.clone()).await
    }

    /// Get peers by multiple public keys
    pub async fn by_pks(&self, pks: &[Vec<u8>]) -> Result<Vec<Peer>, Error> {
        let mut peers = Vec::new();

        self.peers
            .scan(|_, peer| {
                if let Some(ref peer_pk) = peer.pk {
                    // Compare peer_pk (which is [u8; 48]) with pks (which are Vec<u8>)
                    if pks.iter().any(|pk| pk.as_slice() == peer_pk.as_slice()) {
                        peers.push(peer.clone());
                    }
                }
            })
            .await;

        Ok(peers)
    }

    /// Get peers for a specific height (trainers)
    pub async fn for_height(&self, fabric: &crate::consensus::fabric::Fabric, height: u64) -> Result<Vec<Peer>, Error> {
        let trainers = fabric.trainers_for_height(height).unwrap_or_default();
        let trainers_set: std::collections::HashSet<&[u8; 48]> = trainers.iter().collect();
        let mut peers = Vec::new();

        self.peers
            .scan(|_, peer| {
                if let Some(ref pk) = peer.pk {
                    if trainers_set.contains(pk) {
                        peers.push(peer.clone());
                    }
                }
            })
            .await;

        Ok(peers)
    }

    /// Get peer IPs by who specification
    pub async fn by_who(&self, fabric: &crate::consensus::fabric::Fabric, who: Who) -> Result<Vec<Ipv4Addr>, Error> {
        match who {
            Who::Some(peer_ips) => Ok(peer_ips),
            Who::Trainers => {
                let height = fabric.get_temporal_height_or_0();
                let trainer_peers = self.for_height(fabric, height + 1).await?;
                let mut ips: Vec<_> = trainer_peers.iter().map(|p| p.ip).collect();

                if ips.is_empty() {
                    return Ok(vec![]);
                }

                use rand::seq::SliceRandom;
                let mut rng = rand::rng();
                ips.shuffle(&mut rng);
                Ok(ips)
            }
            Who::NotTrainers(cnt) => {
                let height = fabric.get_temporal_height_or_0();
                let trainer_peers = self.for_height(fabric, height + 1).await?;
                let trainer_ips: std::collections::HashSet<_> = trainer_peers.iter().map(|p| p.ip).collect();

                let all_peers = self.get_all().await?;
                let not_trainer_ips: Vec<_> =
                    all_peers.iter().map(|p| p.ip).filter(|ip| !trainer_ips.contains(ip)).collect();

                if not_trainer_ips.is_empty() {
                    return Ok(vec![]);
                }

                use rand::seq::SliceRandom;
                let mut rng = rand::rng();
                let mut ips = not_trainer_ips;
                ips.shuffle(&mut rng);
                ips.truncate(cnt);
                Ok(ips)
            }
            Who::Random(no) => {
                let random_peers = self.random(no).await?;
                Ok(random_peers.iter().map(|p| p.ip).collect())
            }
        }
    }

    // fn apply_latency_filters(
    //     mut filtered: Vec<(Ipv4Addr, Option<u64>, Option<u32>, Option<u32>)>,
    //     filter: HeightFilter,
    // ) -> Result<Vec<(Ipv4Addr, Option<u64>, Option<u32>, Option<u32>)>, Error> {
    //     let take = filter.take.unwrap_or(3);
    //
    //     // Apply latency2 filter first
    //     if let Some(latency2) = filter.latency2 {
    //         let new_filtered: Vec<_> =
    //             filtered.iter().filter(|(_, lat, _, _)| lat.unwrap_or(u64::MAX) <= latency2).cloned().collect();
    //
    //         if new_filtered.len() >= take {
    //             let mut new_filter = filter;
    //             new_filter.latency2 = None;
    //             return Self::apply_latency_filters(new_filtered, new_filter);
    //         }
    //         // Continue with current filtered list
    //     }
    //
    //     // Apply latency1 filter
    //     if let Some(latency1) = filter.latency1 {
    //         let new_filtered: Vec<_> =
    //             filtered.iter().filter(|(_, lat, _, _)| lat.unwrap_or(u64::MAX) <= latency1).cloned().collect();
    //
    //         if new_filtered.len() >= take {
    //             let mut new_filter = filter;
    //             new_filter.latency1 = None;
    //             return Self::apply_latency_filters(new_filtered, new_filter);
    //         }
    //         // Continue with current filtered list
    //     }
    //
    //     // Apply main latency filter
    //     if let Some(latency) = filter.latency {
    //         let new_filtered: Vec<_> =
    //             filtered.iter().filter(|(_, lat, _, _)| lat.unwrap_or(u64::MAX) <= latency).cloned().collect();
    //
    //         if new_filtered.len() >= take {
    //             filtered = new_filtered;
    //         }
    //         // Continue with filtered list (either new or original)
    //     }
    //
    //     // Truncate to requested size
    //     filtered.truncate(take);
    //     Ok(filtered)
    // }

    pub async fn update_peer_ping_timestamp(&self, ip: Ipv4Addr, ts_m: u64) {
        // Update using ConcurrentMap's update method
        self.peers
            .update(&ip, |_key, peer| {
                peer.last_ping = Some(ts_m);
            })
            .await;
    }

    pub async fn update_peer_from_tip(&self, _ctx: &Context, ip: Ipv4Addr, tip: &EventTip) {
        let current_time_ms = get_unix_millis_now();
        let temporal: TipInfo = tip.temporal.clone().into();
        let rooted: TipInfo = tip.rooted.clone().into();

        let updated = self
            .peers
            .update(&ip, |_key, peer| {
                peer.last_seen_ms = current_time_ms;
                peer.last_msg = current_time_ms;
                peer.last_msg_type = Some(tip.typename().to_string());
                peer.temporal = Some(temporal.clone());
                peer.rooted = Some(rooted.clone());
            })
            .await
            .is_some();

        if !updated {
            let new_peer = Peer {
                ip,
                pk: None, // Will be set during handshake
                version: None,
                latency: None,
                last_msg: current_time_ms,
                last_seen_ms: current_time_ms,
                last_ping: None,
                last_pong: None,
                shared_secret: None,
                temporal: Some(temporal),
                rooted: Some(rooted),
                last_msg_type: Some(tip.typename().to_string()),
                handshake_status: HandshakeStatus::None,
            };
            self.insert_new_peer(new_peer).await;
        }
    }

    pub async fn update_peer_from_pong(&self, ip: Ipv4Addr, pong: &PingReply) {
        let current_time_ms = get_unix_millis_now();
        let latency = current_time_ms.saturating_sub(pong.ts_m);

        let updated = self
            .peers
            .update(&ip, |_key, peer| {
                peer.latency = Some(latency);
                peer.last_pong = Some(current_time_ms);
                peer.last_seen_ms = current_time_ms;
                peer.last_msg = current_time_ms;
                peer.last_msg_type = Some("pong".to_string());
            })
            .await
            .is_some();

        if !updated {
            // Create new peer if it doesn't exist
            let new_peer = Peer {
                ip,
                pk: None,
                version: None,
                latency: Some(latency),
                last_msg: current_time_ms,
                last_ping: None,
                last_pong: Some(current_time_ms),
                shared_secret: None,
                temporal: None,
                rooted: None,
                last_seen_ms: current_time_ms,
                last_msg_type: Some("pong".to_string()),
                handshake_status: HandshakeStatus::None,
            };
            self.insert_new_peer(new_peer).await;
        }
    }

    /// Update peer activity and last message type
    pub async fn update_peer_from_proto(&self, ip: Ipv4Addr, last_msg_type: &str) {
        let current_time_ms = get_unix_millis_now();

        let updated = self
            .peers
            .update(&ip, |_key, peer| {
                peer.last_seen_ms = current_time_ms;
                peer.last_msg = current_time_ms;
                peer.last_msg_type = Some(last_msg_type.to_string());
            })
            .await
            .is_some();

        if !updated {
            // Create new peer if it doesn't exist
            let new_peer = Peer {
                ip,
                pk: None,
                version: None,
                latency: None,
                last_msg: current_time_ms,
                last_ping: None,
                last_pong: None,
                shared_secret: None,
                temporal: None,
                rooted: None,
                last_seen_ms: current_time_ms,
                last_msg_type: Some(last_msg_type.to_string()),
                handshake_status: HandshakeStatus::None,
            };
            self.insert_new_peer(new_peer).await;
        }
    }

    /// Set handshake status for a specific IP
    pub async fn set_handshake_status(&self, ip: Ipv4Addr, status: HandshakeStatus) -> Result<(), Error> {
        self.peers
            .update(&ip, |_key, peer| {
                peer.handshake_status = status.clone();
            })
            .await;
        Ok(())
    }

    /// Update peer with version and public key information from ANR
    pub async fn update_peer_from_anr(
        &self,
        ip: Ipv4Addr,
        pk: &[u8; 48],
        version: &Ver,
        status: Option<HandshakeStatus>,
    ) {
        let current_time_ms = get_unix_millis_now();

        let updated = self
            .peers
            .update(&ip, |_key, peer| {
                peer.pk = Some(*pk);
                peer.version = Some(*version);
                peer.last_seen_ms = current_time_ms;
                if let Some(status) = &status {
                    peer.handshake_status = status.clone();
                }
            })
            .await
            .is_some();

        // Create new peer if it doesn't exist
        if !updated {
            let peer = Peer {
                ip,
                pk: Some(*pk),
                version: Some(*version),
                latency: None,
                last_msg: current_time_ms,
                last_ping: None,
                last_pong: None,
                shared_secret: None,
                temporal: None,
                rooted: None,
                last_seen_ms: current_time_ms,
                last_msg_type: None,
                handshake_status: status.unwrap_or(HandshakeStatus::None),
            };
            let _ = self.peers.insert(ip, peer).await;
        }
    }

    /// Returns temporal, rooted and bft heights across peers
    pub async fn get_heights(&self, trainer_pks: &[[u8; 48]]) -> Result<(u64, u64, u64), Error> {
        let mut online_trainers = Vec::new();
        let mut online_nontrainers = Vec::new();

        let now_ms = get_unix_millis_now();
        self.peers
            .scan(|_, peer| {
                if let Some(pk) = peer.pk
                    && peer.last_seen_ms > now_ms - 30_000
                {
                    if trainer_pks.contains(&pk) {
                        online_trainers.push(peer.clone());
                    } else {
                        online_nontrainers.push(peer.clone());
                    }
                }
            })
            .await;

        let mut highest_temporal = 0;
        let mut highest_rooted = 0;
        for peer in online_nontrainers.iter() {
            if let Some(temporal_height) = peer.temporal.map(|t| t.height)
                && let Some(rooted_height) = peer.rooted.map(|t| t.height)
            {
                if temporal_height > highest_temporal {
                    highest_temporal = temporal_height;
                }
                if rooted_height > highest_rooted {
                    highest_rooted = rooted_height;
                }
            }
        }

        let mut trainers_per_height = BTreeMap::new();
        for peer in online_trainers.iter() {
            if let Some(temporal_height) = peer.temporal.map(|t| t.height)
                && let Some(rooted_height) = peer.rooted.map(|t| t.height)
            {
                if temporal_height > highest_temporal {
                    highest_temporal = temporal_height;
                }
                if rooted_height > highest_rooted {
                    highest_rooted = rooted_height;
                }
                *trainers_per_height.entry(rooted_height).or_insert(0) += 1;
            }
        }

        let mut remaining_to_bft = (online_trainers.len() * 2) / 3;
        for (height, trainers) in trainers_per_height.into_iter() {
            remaining_to_bft = remaining_to_bft.saturating_sub(trainers);
            if remaining_to_bft == 0 {
                info!(
                    "Temporal: {} Rooted: {} BFT: {} (2/3 from {} online trainers of {} total)",
                    highest_temporal,
                    highest_rooted,
                    height,
                    online_trainers.len(),
                    trainer_pks.len()
                );
                return Ok((highest_temporal, highest_rooted, height));
            }
        }

        Ok((highest_temporal, highest_rooted, 0))
    }

    pub async fn get_trainer_ips_above_rooted(
        &self,
        height: u64,
        trainer_pks: &[[u8; 48]],
    ) -> Result<Vec<Ipv4Addr>, Error> {
        let online_trainers_above_temporal: Vec<Ipv4Addr> = self
            .get_online_trainers(trainer_pks)
            .await?
            .into_iter()
            .filter_map(|peer| {
                peer.rooted.as_ref().and_then(|rooted| if rooted.height >= height { Some(peer.ip) } else { None })
            })
            .collect();

        Ok(online_trainers_above_temporal)
    }

    pub async fn get_trainer_ips_above_temporal(
        &self,
        height: u64,
        trainer_pks: &[[u8; 48]],
    ) -> Result<Vec<Ipv4Addr>, Error> {
        let online_trainers_above_temporal: Vec<Ipv4Addr> = self
            .get_online_trainers(trainer_pks)
            .await?
            .into_iter()
            .filter_map(|peer| {
                peer.temporal.as_ref().and_then(|temporal| if temporal.height >= height { Some(peer.ip) } else { None })
            })
            .collect();

        Ok(online_trainers_above_temporal)
    }

    pub async fn get_online_trainers(&self, trainer_pks: &[[u8; 48]]) -> Result<Vec<Peer>, Error> {
        let online_trainers: Vec<Peer> = self
            .get_online()
            .await?
            .into_iter()
            .filter(|peer| peer.pk.as_ref().map_or(false, |pk| trainer_pks.contains(pk)))
            .collect();
        Ok(online_trainers)
    }

    /// Get peers summary with counts
    pub async fn get_peers_summary(&self, my_ip: Ipv4Addr, trainer_pks: &[[u8; 48]]) -> Result<PeersSummary, Error> {
        let all_peers = self.get_all().await?;
        let mut online = 0;
        let mut connecting = 0;
        let mut trainers = 0;
        let mut peers_map = HashMap::new();

        for peer in all_peers {
            if peer.ip == my_ip {
                continue;
            }

            match peer.handshake_status {
                HandshakeStatus::Completed => {
                    online += 1;
                    if peer.pk.as_ref().map_or(false, |pk| trainer_pks.contains(pk)) {
                        trainers += 1;
                    }
                }
                HandshakeStatus::Initiated => connecting += 1,
                _ => {}
            }

            let peer_info = PeerInfo {
                last_ts: peer.last_seen_ms,
                last_msg: peer.last_msg_type.unwrap_or_else(|| "unknown".to_string()),
                handshake_status: peer.handshake_status.clone(),
                version: peer.version,
                height: peer.temporal.map(|t| t.height).unwrap_or(0),
                temporal_height: peer.temporal.map(|t| t.height).unwrap_or(0),
                rooted_height: peer.rooted.map(|r| r.height).unwrap_or(0),
                latency: peer.latency.unwrap_or(0),
            };
            peers_map.insert(peer.ip.to_string(), peer_info);
        }

        Ok(PeersSummary { online, connecting, trainers, peers: peers_map })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub last_ts: u64,
    pub last_msg: String,
    pub handshake_status: HandshakeStatus,
    pub version: Option<Ver>,
    pub height: u64,
    pub temporal_height: u64,
    pub rooted_height: u64,
    pub latency: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeersSummary {
    pub online: usize,
    pub connecting: usize,
    pub trainers: usize,
    pub peers: HashMap<String, PeerInfo>,
}

#[derive(Debug)]
pub enum Who {
    Some(Vec<Ipv4Addr>),
    Trainers,
    NotTrainers(usize),
    Random(usize),
}

#[derive(Debug, Clone)]
pub struct HeightFilter {
    pub min_temporal: Option<u64>,
    pub min_rooted: Option<u64>,
    pub take: Option<usize>,
    pub sort: Option<String>,
    pub latency: Option<u64>,
    pub latency1: Option<u64>,
    pub latency2: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_peer_operations() {
        let node_peers = NodePeers::new(100);
        let ip = Ipv4Addr::new(127, 0, 0, 1);

        let ts_m = get_unix_millis_now();
        let mut test_pk = [0u8; 48];
        test_pk[0] = 1;
        test_pk[1] = 2;
        test_pk[2] = 3;

        let peer = Peer {
            ip,
            pk: Some(test_pk),
            version: Some(Ver::new(1, 0, 0)),
            latency: Some(100),
            last_msg: ts_m,
            last_ping: Some(ts_m),
            last_pong: None,
            shared_secret: None,
            temporal: None,
            rooted: None,
            last_seen_ms: ts_m,
            last_msg_type: Some("ping".to_string()),
            handshake_status: HandshakeStatus::None,
        };

        // Test insert
        assert!(node_peers.insert_new_peer(peer.clone()).await);

        // Test size
        assert_eq!(node_peers.size().await, 1);

        // Test by_ip
        let retrieved = node_peers.by_ip(ip).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().ip, ip);

        // Test peer was inserted correctly
        let retrieved = node_peers.by_ip(ip).await.unwrap();
        assert_eq!(retrieved.last_msg, ts_m);
    }
}
