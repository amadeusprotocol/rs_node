use crate::config::Config;
use crate::consensus;
use crate::node::anr;
use crate::utils::misc::get_unix_millis_now;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::spawn_blocking;
use tracing::warn;

/// Represents the different stages of the handshake process
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeStatus {
    /// No handshake initiated
    None,
    /// Sent new_phone_who_dis message, waiting for what response
    SentNewPhoneWhoDis,
    /// Sent what message response (handshake success from our side)
    SentWhat,
    /// Received what message response (handshake completed successfully)
    ReceivedWhat,
    /// Handshake failed (signature verification, timeout, etc.)
    Failed,
}

// minimal concurrent map wrapper to mimic scc::HashMap APIs used in this module
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub ip: Ipv4Addr,
    pub pk: Option<Vec<u8>>,
    pub version: Option<String>,
    pub latency: Option<u64>,
    pub last_msg: u64,
    pub last_ping: Option<u64>,
    pub last_pong: Option<u64>,
    pub shared_secret: Option<Vec<u8>>,
    pub temporal: Option<TemporalInfo>,
    pub rooted: Option<RootedInfo>,
    pub last_seen: u64,
    pub last_msg_type: Option<String>,
    pub handshake_status: HandshakeStatus,
}

impl Peer {
    /// Check if the handshake is completed (either we sent what or received what)
    pub fn is_handshaked(&self) -> bool {
        matches!(self.handshake_status, HandshakeStatus::SentWhat | HandshakeStatus::ReceivedWhat)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalInfo {
    pub header_unpacked: HeaderInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootedInfo {
    pub header_unpacked: HeaderInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderInfo {
    pub height: u64,
    pub prev_hash: Option<Vec<u8>>,
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

    pub async fn clear_stale(&self, node_registry: &anr::NodeAnrs) -> usize {
        self.clear_stale_inner(node_registry).await.inspect_err(|e| warn!("peer cleanup error: {}", e)).unwrap_or(0)
    }

    /// Clear stale peers and add missing validators/handshaked nodes
    pub async fn clear_stale_inner(&self, node_registry: &anr::NodeAnrs) -> Result<usize, Error> {
        let ts_m = get_unix_millis_now() as u64;

        // Get validators for current height + 1
        let height = consensus::chain_height();
        let validators = consensus::trainers_for_height(height + 1).unwrap_or_default();
        let validators: Vec<Vec<u8>> = validators.iter().map(|pk| pk.to_vec()).collect();

        let validator_anr_ips = node_registry.by_pks_ip(&validators).await?;
        let validators_map: std::collections::HashSet<Vec<u8>> = validators.into_iter().collect();

        let handshaked_ips = node_registry.handshaked_pk_ip4().await?;

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

        let missing_ips: Vec<_> = handshaked_ips.iter().map(|(_, ip)| *ip).filter(|ip| !cur_ips.contains(ip)).collect();

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
            let mut rng = rand::thread_rng();
            missing_ips.shuffle(&mut rng);
            missing_ips.truncate(add_size);
            missing_ips
        })
        .await
        .unwrap_or_default();

        // Add missing validators and peers
        for ip in missing_vals.iter().chain(missing_ips.iter()) {
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
                    last_seen: ts_m,
                    last_msg_type: None,
                    handshake_status: HandshakeStatus::None,
                })
                .await;
        }

        Ok(cleared_count)
    }

    /// Insert a new peer if it doesn't already exist
    pub async fn insert_new_peer(&self, mut peer: Peer) -> Result<bool, Error> {
        if peer.last_msg == 0 {
            peer.last_msg = get_unix_millis_now() as u64;
        }

        Ok(self.peers.insert(peer.ip, peer).await.is_ok())
    }

    /// Seed initial peers with validators
    pub async fn seed(&self, config: &Config, node_registry: &anr::NodeAnrs) -> Result<(), Error> {
        let height = consensus::chain_height();
        let validators = consensus::trainers_for_height(height + 1).unwrap_or_default();
        let validators: Vec<Vec<u8>> = validators.iter().map(|pk| pk.to_vec()).collect();

        let validator_ips: Vec<_> = node_registry
            .by_pks_ip(&validators)
            .await?
            .into_iter()
            .filter(|ip| *ip != config.get_public_ipv4())
            .collect();

        for ip in validator_ips {
            let _ = self.insert_new_peer(Peer {
                ip,
                pk: None,
                version: None,
                latency: None,
                last_msg: get_unix_millis_now() as u64,
                last_ping: None,
                last_pong: None,
                shared_secret: None,
                temporal: None,
                rooted: None,
                last_seen: get_unix_millis_now() as u64,
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
        let online_peers = self.online().await?;
        if online_peers.is_empty() {
            return Ok(vec![]);
        }

        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        let mut peers = online_peers;
        peers.shuffle(&mut rng);
        peers.truncate(no);

        Ok(peers)
    }

    /// Get all peers
    pub async fn all(&self) -> Result<Vec<Peer>, Error> {
        let mut peers = Vec::new();
        self.peers
            .scan(|_, peer| {
                peers.push(peer.clone());
            })
            .await;
        Ok(peers)
    }

    /// Get all online peers
    pub async fn online(&self) -> Result<Vec<Peer>, Error> {
        let mut online_peers = Vec::new();

        self.peers
            .scan(|_, peer| {
                if Self::is_online(peer, None) {
                    online_peers.push(peer.clone());
                }
            })
            .await;

        Ok(online_peers)
    }

    /// Check if a peer is online
    pub fn is_online(peer: &Peer, trainer_pk: Option<&[u8]>) -> bool {
        let ts_m = get_unix_millis_now() as u64;

        match (&peer.pk, peer.last_ping) {
            (None, _) => false,
            (Some(_), None) => false,
            (Some(pk), Some(last_ping)) => {
                // Check if this is our own trainer PK (always online)
                if let Some(my_trainer_pk) = trainer_pk {
                    if pk == my_trainer_pk {
                        return true;
                    }
                }

                // Peer is online if last ping was within 6 seconds (6000 ms)
                (ts_m - last_ping) <= 6_000
            }
        }
    }

    /// Get all trainer peers for given height
    pub async fn all_trainers(&self, height: Option<u64>) -> Result<Vec<Peer>, Error> {
        let height = height.unwrap_or_else(|| consensus::chain_height());
        let pks = consensus::trainers_for_height(height + 1).unwrap_or_default();
        let pks: Vec<Vec<u8>> = pks.iter().map(|pk| pk.to_vec()).collect();

        let mut trainers = Vec::new();
        for pk in pks {
            self.peers
                .scan(|_, peer| {
                    if let Some(ref peer_pk) = peer.pk {
                        if *peer_pk == pk {
                            trainers.push(peer.clone());
                        }
                    }
                })
                .await;
        }

        Ok(trainers)
    }

    /// Get summary of all peers
    pub async fn summary(&self) -> Result<Vec<(Ipv4Addr, Option<u64>, Option<u64>, Option<u64>)>, Error> {
        let mut summary = Vec::new();

        self.peers
            .scan(|_, peer| {
                let temporal_height = peer.temporal.as_ref().map(|t| t.header_unpacked.height);
                let rooted_height = peer.rooted.as_ref().map(|r| r.header_unpacked.height);

                summary.push((peer.ip, peer.latency, temporal_height, rooted_height));
            })
            .await;

        // Sort by IP
        summary.sort_by_key(|(ip, _, _, _)| ip.octets());

        Ok(summary)
    }

    /// Get summary of online peers only
    pub async fn summary_online(&self) -> Result<Vec<(Ipv4Addr, Option<u64>, Option<u64>, Option<u64>)>, Error> {
        let online_peers = self.online().await?;
        let mut summary = Vec::new();

        for peer in online_peers {
            let temporal_height = peer.temporal.as_ref().map(|t| t.header_unpacked.height);
            let rooted_height = peer.rooted.as_ref().map(|r| r.header_unpacked.height);

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

        if let Some(secret) = found_secret {
            return Ok(secret);
        }

        // TODO: Generate shared secret using BLS
        // For now, return empty vector as placeholder
        Ok(vec![])
    }

    /// Get peer by IP address
    pub async fn by_ip(&self, ip: Ipv4Addr) -> Result<Option<Peer>, Error> {
        Ok(self.peers.read(&ip, |_, peer| peer.clone()).await)
    }

    /// Get IP addresses for a given public key
    pub async fn ips_by_pk(&self, pk: &[u8]) -> Result<Vec<Ipv4Addr>, Error> {
        let mut ips = Vec::new();

        self.peers
            .scan(|ip, peer| {
                if let Some(ref peer_pk) = peer.pk {
                    if peer_pk == pk {
                        ips.push(*ip);
                    }
                }
            })
            .await;

        Ok(ips)
    }

    /// Get first peer by public key
    pub async fn by_pk(&self, pk: &[u8]) -> Result<Option<Peer>, Error> {
        let mut found_peer = None;

        self.peers
            .scan(|_, peer| {
                if let Some(ref peer_pk) = peer.pk {
                    if peer_pk == pk && found_peer.is_none() {
                        found_peer = Some(peer.clone());
                    }
                }
            })
            .await;

        Ok(found_peer)
    }

    /// Get peers by multiple public keys
    pub async fn by_pks(&self, pks: &[Vec<u8>]) -> Result<Vec<Peer>, Error> {
        let pks_set: std::collections::HashSet<_> = pks.iter().collect();
        let mut peers = Vec::new();

        self.peers
            .scan(|_, peer| {
                if let Some(ref peer_pk) = peer.pk {
                    if pks_set.contains(peer_pk) {
                        peers.push(peer.clone());
                    }
                }
            })
            .await;

        Ok(peers)
    }

    /// Get peers for a specific height (trainers)
    pub async fn for_height(&self, height: u64) -> Result<Vec<Peer>, Error> {
        let trainers = consensus::trainers_for_height(height).unwrap_or_default();
        let trainers: Vec<Vec<u8>> = trainers.iter().map(|pk| pk.to_vec()).collect();

        let trainers_set: std::collections::HashSet<_> = trainers.iter().collect();
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

    /// Get all peer IPs as strings
    pub async fn get_all_ips(&self) -> Result<Vec<String>, Error> {
        let mut ips = Vec::new();
        self.peers
            .scan(|_key, peer| {
                ips.push(peer.ip.to_string());
            })
            .await;
        Ok(ips)
    }

    /// Get peer IPs by who specification
    pub async fn by_who(&self, who: Who) -> Result<Vec<Ipv4Addr>, Error> {
        match who {
            Who::Some(peer_ips) => Ok(peer_ips),
            Who::Trainers => {
                let height = consensus::chain_height();
                let trainer_peers = self.for_height(height + 1).await?;
                let mut ips: Vec<_> = trainer_peers.iter().map(|p| p.ip).collect();

                if ips.is_empty() {
                    return Ok(vec![]);
                }

                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                ips.shuffle(&mut rng);
                Ok(ips)
            }
            Who::NotTrainers(cnt) => {
                let height = consensus::chain_height();
                let trainer_peers = self.for_height(height + 1).await?;
                let trainer_ips: std::collections::HashSet<_> = trainer_peers.iter().map(|p| p.ip).collect();

                let all_peers = self.all().await?;
                let not_trainer_ips: Vec<_> =
                    all_peers.iter().map(|p| p.ip).filter(|ip| !trainer_ips.contains(ip)).collect();

                if not_trainer_ips.is_empty() {
                    return Ok(vec![]);
                }

                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
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

    /// Get highest heights from online peers with filtering
    pub async fn highest_height(&self, filter: HeightFilter) -> Result<Vec<u64>, Error> {
        let summary = self.summary_online().await?;

        let min_temporal = filter.min_temporal.unwrap_or(0);
        let min_rooted = filter.min_rooted.unwrap_or(0);

        let mut filtered: Vec<_> = summary
            .into_iter()
            .filter(|(_, _, temp, rooted)| temp.unwrap_or(0) >= min_temporal && rooted.unwrap_or(0) >= min_rooted)
            .collect();

        // Sort by temporal or rooted height
        let sort_by_temporal = filter.sort.as_deref() != Some("rooted");

        filtered.sort_by(|(_, _, temp1, rooted1), (_, _, temp2, rooted2)| {
            let height1 = if sort_by_temporal { temp1.unwrap_or(0) } else { rooted1.unwrap_or(0) };
            let height2 = if sort_by_temporal { temp2.unwrap_or(0) } else { rooted2.unwrap_or(0) };
            height2.cmp(&height1) // descending order
        });

        // Apply latency filtering if specified
        filtered = Self::highest_height_filter(filtered, filter)?;

        let heights = filtered
            .into_iter()
            .map(|(_, _, temp, rooted)| if sort_by_temporal { temp.unwrap_or(0) } else { rooted.unwrap_or(0) })
            .collect();

        Ok(heights)
    }

    fn highest_height_filter(
        mut filtered: Vec<(Ipv4Addr, Option<u64>, Option<u64>, Option<u64>)>,
        filter: HeightFilter,
    ) -> Result<Vec<(Ipv4Addr, Option<u64>, Option<u64>, Option<u64>)>, Error> {
        let take = filter.take.unwrap_or(3);

        // Apply latency2 filter first
        if let Some(latency2) = filter.latency2 {
            let new_filtered: Vec<_> =
                filtered.iter().filter(|(_, lat, _, _)| lat.unwrap_or(u64::MAX) <= latency2).cloned().collect();

            if new_filtered.len() >= take {
                let mut new_filter = filter;
                new_filter.latency2 = None;
                return Self::highest_height_filter(new_filtered, new_filter);
            }
            // Continue with current filtered list
        }

        // Apply latency1 filter
        if let Some(latency1) = filter.latency1 {
            let new_filtered: Vec<_> =
                filtered.iter().filter(|(_, lat, _, _)| lat.unwrap_or(u64::MAX) <= latency1).cloned().collect();

            if new_filtered.len() >= take {
                let mut new_filter = filter;
                new_filter.latency1 = None;
                return Self::highest_height_filter(new_filtered, new_filter);
            }
            // Continue with current filtered list
        }

        // Apply main latency filter
        if let Some(latency) = filter.latency {
            let new_filtered: Vec<_> =
                filtered.iter().filter(|(_, lat, _, _)| lat.unwrap_or(u64::MAX) <= latency).cloned().collect();

            if new_filtered.len() >= take {
                filtered = new_filtered;
            }
            // Continue with filtered list (either new or original)
        }

        // Truncate to requested size
        filtered.truncate(take);
        Ok(filtered)
    }

    /// Update peer activity and last message type
    pub async fn update_peer_activity(&self, ip: Ipv4Addr, last_msg_type: &str) -> Result<(), Error> {
        let current_time = get_unix_millis_now() as u64;

        // Try to update existing peer first
        let updated = self
            .peers
            .update(&ip, |_key, peer| {
                peer.last_seen = current_time;
                peer.last_msg = current_time;
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
                last_msg: current_time,
                last_ping: None,
                last_pong: None,
                shared_secret: None,
                temporal: None,
                rooted: None,
                last_seen: current_time,
                last_msg_type: Some(last_msg_type.to_string()),
                handshake_status: HandshakeStatus::None,
            };
            self.insert_new_peer(new_peer).await?;
        }

        Ok(())
    }

    /// Set the handshaked status for a peer with the given public key
    pub async fn set_handshaked(&self, pk: &[u8]) -> Result<(), Error> {
        // Find and update the peer with matching public key
        let mut found = false;
        self.peers
            .scan(|_ip, peer| {
                if let Some(ref peer_pk) = peer.pk {
                    if peer_pk == pk {
                        found = true;
                    }
                }
            })
            .await;

        if found {
            // Update all peers with this public key
            let ips_to_update: Vec<Ipv4Addr> = {
                let mut ips = Vec::new();
                self.peers
                    .scan(|ip, peer| {
                        if let Some(ref peer_pk) = peer.pk {
                            if peer_pk == pk {
                                ips.push(*ip);
                            }
                        }
                    })
                    .await;
                ips
            };

            for ip in ips_to_update {
                self.peers
                    .update(&ip, |_key, peer| {
                        peer.handshake_status = HandshakeStatus::ReceivedWhat;
                    })
                    .await;
            }
        }

        Ok(())
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

    /// Set handshake status for peers with matching public key
    pub async fn set_handshake_status_by_pk(&self, pk: &[u8], status: HandshakeStatus) -> Result<(), Error> {
        let ips_to_update: Vec<Ipv4Addr> = {
            let mut ips = Vec::new();
            self.peers
                .scan(|ip, peer| {
                    if let Some(ref peer_pk) = peer.pk {
                        if peer_pk == pk {
                            ips.push(*ip);
                        }
                    }
                })
                .await;
            ips
        };

        for ip in ips_to_update {
            self.peers
                .update(&ip, |_key, peer| {
                    peer.handshake_status = status.clone();
                })
                .await;
        }

        Ok(())
    }

    /// Update peer with version and public key information from ANR
    pub async fn update_peer_from_anr(&self, ip: Ipv4Addr, pk: &[u8], version: &str) -> Result<(), Error> {
        let current_time = get_unix_millis_now() as u64;
        let updated = self
            .peers
            .update(&ip, |_key, peer| {
                peer.pk = Some(pk.to_vec());
                peer.version = Some(version.to_string());
                peer.last_seen = current_time;
            })
            .await
            .is_some();

        if !updated {
            // Create new peer if it doesn't exist
            let peer = Peer {
                ip,
                pk: Some(pk.to_vec()),
                version: Some(version.to_string()),
                latency: None,
                last_msg: current_time,
                last_ping: None,
                last_pong: None,
                shared_secret: None,
                temporal: None,
                rooted: None,
                last_seen: current_time,
                last_msg_type: None,
                handshake_status: HandshakeStatus::None,
            };
            let _ = self.peers.insert(ip, peer).await;
        }

        Ok(())
    }
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

        let peer = Peer {
            ip,
            pk: Some(vec![1, 2, 3]),
            version: Some("1.0.0".to_string()),
            latency: Some(100),
            last_msg: get_unix_millis_now() as u64,
            last_ping: Some(get_unix_millis_now() as u64),
            last_pong: None,
            shared_secret: None,
            temporal: None,
            rooted: None,
            last_seen: get_unix_millis_now() as u64,
            last_msg_type: Some("ping".to_string()),
            handshake_status: HandshakeStatus::None,
        };

        // Test insert
        assert!(node_peers.insert_new_peer(peer.clone()).await.unwrap());

        // Test size
        assert_eq!(node_peers.size().await, 1);

        // Test by_ip
        let retrieved = node_peers.by_ip(ip).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().ip, ip);

        // Test is_online
        let retrieved = node_peers.by_ip(ip).await.unwrap().unwrap();
        assert!(NodePeers::is_online(&retrieved, None));
    }
}
