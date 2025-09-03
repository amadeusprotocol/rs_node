// use crate::consensus::entry::Entry; // TODO: Remove when Entry handling is implemented
use crate::node::{
    anr::{self, NodeAnrs},
    peers,
};
use crate::utils::misc::get_unix_millis_now;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;

#[derive(Debug, thiserror::Error, strum_macros::IntoStaticStr)]
pub enum Error {
    #[error("ANR error: {0}")]
    AnrError(#[from] anr::Error),
    #[error("Peers error: {0}")]
    PeersError(#[from] peers::Error),
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    #[error("Invalid challenge")]
    InvalidChallenge,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid entry")]
    InvalidEntry,
    #[error("Permission denied")]
    PermissionDenied,
}

impl crate::utils::misc::Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub challenges: HashMap<Vec<u8>, u64>, // pk -> challenge
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub ip: Ipv4Addr,
    pub signer: Vec<u8>,
    pub version: String,
}

#[derive(Debug)]
pub enum StateMessage {
    NewPhoneWhoDis { anr: anr::Anr, challenge: u64 },
    What { anr: anr::Anr, challenge: u64, signature: Vec<u8> },
    Ping { temporal: Vec<u8>, rooted: Vec<u8>, ts_m: u128 },
    Pong { ts_m: u128 },
    TxPool { txs_packed: Vec<Vec<u8>> },
    PeersV2 { anrs: Vec<anr::Anr> },
    Sol { sol: Vec<u8> },
    Entry { entry_packed: Vec<u8>, consensus_packed: Option<Vec<u8>>, attestation_packed: Option<Vec<u8>> },
    AttestationBulk { attestations_packed: Vec<Vec<u8>> },
    ConsensusBulk { consensuses_packed: Vec<Vec<u8>> },
    CatchupEntry { heights: Vec<u64> },
    CatchupTri { heights: Vec<u64> },
    CatchupBi { heights: Vec<u64> },
    CatchupAttestation { hashes: Vec<Vec<u8>> },
    SpecialBusiness { business: SpecialBusiness },
    SpecialBusinessReply { business: SpecialBusinessReply },
    SolicitEntry { hash: Vec<u8> },
    SolicitEntry2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialBusiness {
    pub op: String,
    pub epoch: Option<u64>,
    pub malicious_pk: Option<Vec<u8>>,
    pub entry_packed: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialBusinessReply {
    pub op: String,
    pub epoch: Option<u64>,
    pub malicious_pk: Option<Vec<u8>>,
    pub entry_hash: Option<Vec<u8>>,
    pub pk: Vec<u8>,
    pub signature: Vec<u8>,
}

impl NodeState {
    pub fn init() -> Self {
        NodeState { challenges: HashMap::new() }
    }

    /// Handle incoming protocol messages
    pub async fn handle(
        &mut self,
        msg: StateMessage,
        peer: &PeerInfo,
        node_peers: &peers::NodePeers,
        node_registry: &NodeAnrs,
    ) -> Result<Option<Vec<u8>>, Error> {
        match msg {
            StateMessage::NewPhoneWhoDis { anr, challenge } => {
                self.handle_new_phone_who_dis(anr, challenge, peer, node_registry).await
            }
            StateMessage::What { anr, challenge, signature } => {
                self.handle_what(anr, challenge, signature, peer, node_registry).await
            }
            StateMessage::Ping { temporal, rooted, ts_m } => {
                self.handle_ping(temporal, rooted, ts_m, peer, node_peers, node_registry).await
            }
            StateMessage::Pong { ts_m } => self.handle_pong(ts_m, peer, node_peers).await,
            StateMessage::TxPool { txs_packed } => self.handle_txpool(txs_packed).await,
            StateMessage::PeersV2 { anrs } => self.handle_peers_v2(anrs, node_registry).await,
            StateMessage::Sol { sol } => self.handle_sol(sol, peer, node_registry).await,
            StateMessage::Entry { entry_packed, consensus_packed, attestation_packed } => {
                self.handle_entry(entry_packed, consensus_packed, attestation_packed).await
            }
            StateMessage::AttestationBulk { attestations_packed } => {
                self.handle_attestation_bulk(attestations_packed).await
            }
            StateMessage::ConsensusBulk { consensuses_packed } => self.handle_consensus_bulk(consensuses_packed).await,
            StateMessage::CatchupEntry { heights } => self.handle_catchup_entry(heights, peer).await,
            StateMessage::CatchupTri { heights } => self.handle_catchup_tri(heights, peer).await,
            StateMessage::CatchupBi { heights } => self.handle_catchup_bi(heights, peer).await,
            StateMessage::CatchupAttestation { hashes } => self.handle_catchup_attestation(hashes, peer).await,
            StateMessage::SpecialBusiness { business } => self.handle_special_business(business, peer).await,
            StateMessage::SpecialBusinessReply { business } => self.handle_special_business_reply(business).await,
            StateMessage::SolicitEntry { hash } => self.handle_solicit_entry(hash, peer).await,
            StateMessage::SolicitEntry2 => self.handle_solicit_entry2(peer).await,
        }
    }

    /// Handle new_phone_who_dis message
    async fn handle_new_phone_who_dis(
        &mut self,
        anr: anr::Anr,
        challenge: u64,
        peer: &PeerInfo,
        node_registry: &NodeAnrs,
    ) -> Result<Option<Vec<u8>>, Error> {
        // Verify ANR
        let verified_anr = anr::Anr::verify_and_unpack(anr)?;

        // Check if ANR IP matches peer IP
        if verified_anr.ip4 != peer.ip {
            return Err(Error::PermissionDenied);
        }

        // TODO: Get trainer keys from config
        let _trainer_sk = [0u8; 32]; // placeholder
        let trainer_pk = vec![0u8; 48]; // placeholder

        // Sign challenge
        // TODO: Implement BLS signing
        let _challenge_msg = [trainer_pk.clone(), challenge.to_le_bytes().to_vec()].concat();
        let _signature = [0u8; 96]; // placeholder signature

        // Store ANR
        node_registry.insert(verified_anr).await?;

        // Create what? message
        // TODO: Create proper protocol message
        let response = serde_json::to_vec(&challenge).map_err(|e| Error::ProtocolError(e.to_string()))?;
        Ok(Some(response))
    }

    /// Handle what? message
    async fn handle_what(
        &mut self,
        anr: anr::Anr,
        challenge: u64,
        signature: Vec<u8>,
        peer: &PeerInfo,
        node_registry: &NodeAnrs,
    ) -> Result<Option<Vec<u8>>, Error> {
        // Verify ANR
        let verified_anr = anr::Anr::verify_and_unpack(anr)?;

        // Check if ANR IP matches peer IP
        if verified_anr.ip4 != peer.ip {
            return Err(Error::PermissionDenied);
        }

        // Check challenge timing (within 6 seconds)
        let now = get_unix_millis_now() as u64 / 1000;
        let delta = if now > challenge { now - challenge } else { challenge - now };
        if delta > 6 {
            return Err(Error::InvalidChallenge);
        }

        // TODO: Verify BLS signature
        // For now, just verify signature is not empty
        if signature.is_empty() {
            return Err(Error::InvalidSignature);
        }

        // Store ANR and mark as handshaked
        let pk = verified_anr.pk.clone();
        node_registry.insert(verified_anr).await?;
        node_registry.set_handshaked(&pk).await?;

        Ok(None)
    }

    /// Handle ping message
    async fn handle_ping(
        &mut self,
        temporal: Vec<u8>,
        rooted: Vec<u8>,
        ts_m: u128,
        peer: &PeerInfo,
        node_peers: &peers::NodePeers,
        node_registry: &NodeAnrs,
    ) -> Result<Option<Vec<u8>>, Error> {
        // TODO: Unpack and validate entries
        // For now, just check that entries are not empty
        if temporal.is_empty() || rooted.is_empty() {
            return Err(Error::InvalidEntry);
        }

        // Check if peer has permission (is handshaked)
        let has_permission = node_registry.handshaked_and_valid_ip4(&peer.signer, &peer.ip).await?;

        if has_permission {
            // Send random verified ANRs to peer
            let anrs = node_registry.get_random_verified(3).await?;
            if !anrs.is_empty() {
                // TODO: Send peers_v2 message to peer
                tracing::debug!("Sending peers_v2 to {}", peer.ip);
            }
        }

        // Update peer information
        let mut peer_data = peers::Peer {
            ip: peer.ip,
            pk: Some(peer.signer.clone()),
            version: Some(peer.version.clone()),
            latency: None,
            last_msg: get_unix_millis_now() as u64,
            last_ping: Some(get_unix_millis_now() as u64),
            last_pong: None,
            shared_secret: None,
            temporal: None, // TODO: Parse temporal entry
            rooted: None,   // TODO: Parse rooted entry
            last_seen: get_unix_millis_now() as u64,
            last_msg_type: Some("pong".to_string()),
            handshake_status: crate::node::peers::HandshakeStatus::None, // Will be updated when handshake completes
        };

        // Get or generate shared secret
        if let Ok(secret) = node_peers.get_shared_secret(&peer.signer).await {
            if !secret.is_empty() {
                peer_data.shared_secret = Some(secret);
            } else {
                // TODO: Generate shared secret using BLS
                peer_data.shared_secret = Some(vec![0u8; 32]); // placeholder
            }
        }

        node_peers.insert_new_peer(peer_data).await?;

        // Send pong response
        let pong_data = ts_m.to_le_bytes().to_vec();
        Ok(Some(pong_data))
    }

    /// Handle pong message
    async fn handle_pong(
        &mut self,
        ts_m: u128,
        peer: &PeerInfo,
        node_peers: &peers::NodePeers,
    ) -> Result<Option<Vec<u8>>, Error> {
        let seen_time = get_unix_millis_now() as u64;
        let latency = seen_time - (ts_m as u64);

        // Update peer latency and last_pong
        if let Ok(Some(mut peer_data)) = node_peers.by_ip(peer.ip).await {
            peer_data.latency = Some(latency);
            peer_data.last_pong = Some(seen_time);
            peer_data.last_msg = get_unix_millis_now() as u64;
            peer_data.pk = Some(peer.signer.clone());

            node_peers.insert_new_peer(peer_data).await?;
        }

        Ok(None)
    }

    /// Handle txpool message
    async fn handle_txpool(&mut self, txs_packed: Vec<Vec<u8>>) -> Result<Option<Vec<u8>>, Error> {
        // TODO: Validate transactions and insert into pool
        tracing::debug!("Received {} transactions", txs_packed.len());

        // Placeholder validation - just check that transactions are not empty
        let valid_txs: Vec<_> = txs_packed.into_iter().filter(|tx| !tx.is_empty()).collect();

        tracing::debug!("Validated {} transactions", valid_txs.len());

        // TODO: Insert into transaction pool

        Ok(None)
    }

    /// Handle peers_v2 message
    async fn handle_peers_v2(
        &mut self,
        anrs: Vec<anr::Anr>,
        node_registry: &NodeAnrs,
    ) -> Result<Option<Vec<u8>>, Error> {
        // Verify and insert ANRs
        let mut valid_anrs = Vec::new();

        for anr in anrs {
            if let Ok(verified_anr) = anr::Anr::verify_and_unpack(anr) {
                valid_anrs.push(verified_anr);
            }
        }

        for anr in valid_anrs {
            node_registry.insert(anr).await?;
        }

        Ok(None)
    }

    /// Handle sol (solution) message
    async fn handle_sol(
        &mut self,
        sol: Vec<u8>,
        peer: &PeerInfo,
        _node_registry: &NodeAnrs,
    ) -> Result<Option<Vec<u8>>, Error> {
        // TODO: Implement solution validation and processing
        tracing::debug!("Received solution from {}", peer.ip);

        // Placeholder - just check that solution is not empty
        if sol.is_empty() {
            return Err(Error::ProtocolError("Empty solution".to_string()));
        }

        // TODO: Verify solution against current epoch
        // TODO: Verify proof of possession
        // TODO: Add to transaction pool if valid

        Ok(None)
    }

    /// Handle entry message
    async fn handle_entry(
        &mut self,
        entry_packed: Vec<u8>,
        consensus_packed: Option<Vec<u8>>,
        attestation_packed: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let seen_time = get_unix_millis_now() as u64;

        // TODO: Check if entry already exists by hash

        // TODO: Unpack and validate entry
        if entry_packed.is_empty() {
            return Err(Error::InvalidEntry);
        }

        // TODO: Insert entry into fabric if valid and height >= rooted tip
        tracing::debug!("Processing entry at time {}", seen_time);

        // Handle consensus data if present
        if let Some(consensus_data) = consensus_packed {
            if !consensus_data.is_empty() {
                tracing::debug!("Processing consensus data");
                // TODO: Validate and process consensus
            }
        }

        // Handle attestation data if present
        if let Some(attestation_data) = attestation_packed {
            if !attestation_data.is_empty() {
                tracing::debug!("Processing attestation data");
                // TODO: Validate and process attestation
            }
        }

        Ok(None)
    }

    /// Handle attestation_bulk message
    async fn handle_attestation_bulk(&mut self, attestations_packed: Vec<Vec<u8>>) -> Result<Option<Vec<u8>>, Error> {
        tracing::debug!("Processing {} attestations", attestations_packed.len());

        for attestation_data in attestations_packed {
            if !attestation_data.is_empty() {
                // TODO: Unpack and validate attestation
                // TODO: Add to fabric coordinator if valid
                tracing::debug!("Processing attestation");
            }
        }

        Ok(None)
    }

    /// Handle consensus_bulk message
    async fn handle_consensus_bulk(&mut self, consensuses_packed: Vec<Vec<u8>>) -> Result<Option<Vec<u8>>, Error> {
        tracing::debug!("Processing {} consensuses", consensuses_packed.len());

        for consensus_data in consensuses_packed {
            if !consensus_data.is_empty() {
                // TODO: Unpack consensus and validate
                // TODO: Send to fabric coordinator
                tracing::debug!("Processing consensus");
            }
        }

        Ok(None)
    }

    /// Handle catchup_entry message  
    async fn handle_catchup_entry(&mut self, heights: Vec<u64>, peer: &PeerInfo) -> Result<Option<Vec<u8>>, Error> {
        if heights.len() > 100 {
            return Err(Error::ProtocolError("Too many heights requested".to_string()));
        }

        tracing::debug!("Catchup entry request for {} heights from {}", heights.len(), peer.ip);

        // TODO: Get entries by height and send them back to peer
        for height in heights {
            tracing::debug!("Getting entries for height {}", height);
            // TODO: fabric::entries_by_height(height)
            // TODO: Send entry messages back to peer
        }

        Ok(None)
    }

    /// Handle catchup_tri message
    async fn handle_catchup_tri(&mut self, heights: Vec<u64>, peer: &PeerInfo) -> Result<Option<Vec<u8>>, Error> {
        if heights.len() > 30 {
            return Err(Error::ProtocolError("Too many heights requested".to_string()));
        }

        tracing::debug!("Catchup tri request for {} heights from {}", heights.len(), peer.ip);

        // TODO: Get entries with attestations/consensus by height
        for height in heights {
            tracing::debug!("Getting tri data for height {}", height);
            // TODO: fabric::get_entries_by_height_w_attestation_or_consensus(height)
            // TODO: Send entry messages with attestation/consensus data
        }

        Ok(None)
    }

    /// Handle catchup_bi message
    async fn handle_catchup_bi(&mut self, heights: Vec<u64>, peer: &PeerInfo) -> Result<Option<Vec<u8>>, Error> {
        if heights.len() > 30 {
            return Err(Error::ProtocolError("Too many heights requested".to_string()));
        }

        tracing::debug!("Catchup bi request for {} heights from {}", heights.len(), peer.ip);

        // TODO: Get attestations and consensuses by height
        let attestations_packed: Vec<u8> = Vec::new();
        let consensuses_packed: Vec<u8> = Vec::new();

        for height in heights {
            tracing::debug!("Getting bi data for height {}", height);
            // TODO: fabric::get_attestations_and_consensuses_by_height(height)
            // TODO: Pack attestations and consensuses
        }

        if !attestations_packed.is_empty() {
            tracing::debug!("Sending {} attestations", attestations_packed.len());
            // TODO: Send attestation_bulk message
        }

        if !consensuses_packed.is_empty() {
            tracing::debug!("Sending {} consensuses", consensuses_packed.len());
            // TODO: Send consensus_bulk message
        }

        Ok(None)
    }

    /// Handle catchup_attestation message
    async fn handle_catchup_attestation(
        &mut self,
        hashes: Vec<Vec<u8>>,
        peer: &PeerInfo,
    ) -> Result<Option<Vec<u8>>, Error> {
        if hashes.len() > 30 {
            return Err(Error::ProtocolError("Too many hashes requested".to_string()));
        }

        tracing::debug!("Catchup attestation request for {} hashes from {}", hashes.len(), peer.ip);

        let attestations_packed: Vec<u8> = Vec::new();

        for _hash in hashes {
            tracing::debug!("Getting attestation for hash");
            // TODO: fabric::my_attestation_by_entryhash(hash)
            // TODO: Pack attestation if found
        }

        if !attestations_packed.is_empty() {
            tracing::debug!("Sending {} attestations", attestations_packed.len());
            // TODO: Send attestation_bulk message
        }

        Ok(None)
    }

    /// Handle special_business message
    async fn handle_special_business(
        &mut self,
        business: SpecialBusiness,
        peer: &PeerInfo,
    ) -> Result<Option<Vec<u8>>, Error> {
        tracing::debug!("Special business request: {} from {}", business.op, peer.ip);

        match business.op.as_str() {
            "slash_trainer_tx" => {
                if let (Some(epoch), Some(malicious_pk)) = (business.epoch, business.malicious_pk) {
                    // TODO: SpecialMeetingAttestGen::maybe_attest("slash_trainer_tx", epoch, malicious_pk)
                    tracing::debug!("Slash trainer tx request for epoch {} pk {:?}", epoch, malicious_pk);

                    // TODO: Generate signature if we can attest
                    let signature = vec![0u8; 96]; // placeholder

                    if !signature.is_empty() {
                        // TODO: Get trainer PK from config
                        let trainer_pk = vec![0u8; 48]; // placeholder

                        let _reply = SpecialBusinessReply {
                            op: "slash_trainer_tx_reply".to_string(),
                            epoch: Some(epoch),
                            malicious_pk: Some(malicious_pk),
                            entry_hash: None,
                            pk: trainer_pk,
                            signature,
                        };

                        // TODO: Send special_business_reply message
                        tracing::debug!("Sending slash trainer tx reply");
                    }
                }
            }
            "slash_trainer_entry" => {
                if let Some(_entry_packed) = business.entry_packed {
                    // TODO: Unpack entry and get hash
                    // TODO: SpecialMeetingAttestGen::maybe_attest("slash_trainer_entry", entry_packed)
                    tracing::debug!("Slash trainer entry request");

                    let signature = vec![0u8; 96]; // placeholder

                    if !signature.is_empty() {
                        let trainer_pk = vec![0u8; 48]; // placeholder
                        let entry_hash = vec![0u8; 32]; // placeholder - get from unpacked entry

                        let _reply = SpecialBusinessReply {
                            op: "slash_trainer_entry_reply".to_string(),
                            epoch: None,
                            malicious_pk: None,
                            entry_hash: Some(entry_hash),
                            pk: trainer_pk,
                            signature,
                        };

                        // TODO: Send special_business_reply message
                        tracing::debug!("Sending slash trainer entry reply");
                    }
                }
            }
            _ => {
                tracing::warn!("Unknown special business operation: {}", business.op);
            }
        }

        Ok(None)
    }

    /// Handle special_business_reply message
    async fn handle_special_business_reply(
        &mut self,
        business: SpecialBusinessReply,
    ) -> Result<Option<Vec<u8>>, Error> {
        tracing::debug!("Special business reply: {}", business.op);

        match business.op.as_str() {
            "slash_trainer_tx_reply" => {
                if let (Some(epoch), Some(malicious_pk)) = (business.epoch, business.malicious_pk) {
                    // TODO: Verify signature
                    // TODO: Send to SpecialMeetingGen
                    tracing::debug!("Slash trainer tx reply for epoch {} pk {:?}", epoch, malicious_pk);
                }
            }
            "slash_trainer_entry_reply" => {
                if let Some(_entry_hash) = business.entry_hash {
                    // TODO: Verify signature against entry hash
                    // TODO: Send to SpecialMeetingGen
                    tracing::debug!("Slash trainer entry reply for hash");
                }
            }
            _ => {
                tracing::warn!("Unknown special business reply operation: {}", business.op);
            }
        }

        Ok(None)
    }

    /// Handle solicit_entry message
    async fn handle_solicit_entry(&mut self, _hash: Vec<u8>, peer: &PeerInfo) -> Result<Option<Vec<u8>>, Error> {
        tracing::debug!("Solicit entry request from {}", peer.ip);

        // TODO: Get entry by hash
        // TODO: Check if peer is trainer for entry height
        // TODO: Check entry conditions (height > rooted tip, multiple entries, etc.)
        // TODO: Call FabricSnapshot::backstep_temporal if conditions met

        Ok(None)
    }

    /// Handle solicit_entry2 message
    async fn handle_solicit_entry2(&mut self, peer: &PeerInfo) -> Result<Option<Vec<u8>>, Error> {
        tracing::debug!("Solicit entry2 request from {}", peer.ip);

        // TODO: Get current chain tip entry
        // TODO: Check if peer is trainer for current height + 1
        // TODO: Find best entry for height
        // TODO: Rewind chain if current hash != best entry hash

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_node_state_init() {
        let state = NodeState::init();
        assert!(state.challenges.is_empty());
    }

    #[tokio::test]
    async fn test_handle_txpool() {
        let mut state = NodeState::init();
        let _peer = PeerInfo { ip: Ipv4Addr::new(127, 0, 0, 1), signer: vec![1, 2, 3], version: "1.0.0".to_string() };

        let txs = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let result = state.handle_txpool(txs).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
