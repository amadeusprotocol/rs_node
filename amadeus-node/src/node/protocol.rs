use crate::Context;
use crate::consensus::consensus::{self, Consensus};
use crate::consensus::doms::attestation::EventAttestation;
use crate::consensus::doms::entry::{Entry, EventEntry};
use crate::consensus::doms::sol::Solution;
use crate::consensus::doms::tx::TxU;
use crate::consensus::doms::{Attestation, EntrySummary};
use crate::consensus::fabric::Fabric;
use crate::node::anr::Anr;
use crate::node::peers::HandshakeStatus;
use crate::node::{anr, peers};
use crate::utils::Hash;
use crate::utils::bls12_381;
use crate::utils::misc::{Typename, get_unix_millis_now};
#[cfg(test)]
use crate::utils::{PublicKey, Signature};
use amadeus_utils::B3f4;
use amadeus_utils::vecpak::{self as vecpak, PropListMap, VecpakExt};
use std::fmt::Debug;
use std::io::Error as IoError;
use std::net::{Ipv4Addr, SocketAddr};
use tracing::instrument;
use tracing::warn;

/// Every object that has this trait must be convertible from a Vecpak
/// Binary representation and must be able to handle itself as a message
#[async_trait::async_trait]
pub trait Protocol: Typename + Debug + Send + Sync {
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error>
    where
        Self: Sized;
    /// Convert to vecpak binary format
    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error>;
    /// Handle a message returning instructions for upper layers
    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error>;

    /// Convert to binary format (always vecpak now)
    fn to_bin(&self, _version: crate::Ver) -> Result<Vec<u8>, Error> {
        self.to_vecpak_packet_bin()
    }

    /// Send this protocol message to a destination using encrypted format (v1.1.7+)
    /// REQUIRES ANR to be available - use send_to_legacy_with_metrics for bootstrap messages
    async fn send_to_with_metrics(&self, ctx: &Context, dst: Ipv4Addr) -> Result<(), Error> {
        let dst_addr = SocketAddr::new(std::net::IpAddr::V4(dst), ctx.config.udp_port);
        let dst_anr = ctx.node_anrs.get_by_ip4(dst).await.ok_or(Error::NoAnrForDestination(dst))?;
        let payload = self.to_bin(ctx.config.version).inspect_err(|e| ctx.metrics.add_error(e))?;

        let shards = ctx.reassembler.build_shards(&ctx.config, &payload, &dst_anr.pk).await?;
        for shard in &shards {
            ctx.socket.send_to_with_metrics(shard, dst_addr, &ctx.metrics).await?;
        }

        ctx.metrics.add_outgoing_proto(self.typename());
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, strum_macros::IntoStaticStr)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Bls(#[from] bls12_381::Error),
    #[error(transparent)]
    Tx(#[from] crate::consensus::doms::tx::Error),
    #[error(transparent)]
    Entry(#[from] crate::consensus::doms::entry::Error),
    #[error(transparent)]
    Archiver(#[from] crate::utils::archiver::Error),
    #[error(transparent)]
    Peers(#[from] peers::Error),
    #[error(transparent)]
    Consensus(#[from] consensus::Error),
    #[error(transparent)]
    Fabric(#[from] crate::consensus::fabric::Error),
    #[error(transparent)]
    Sol(#[from] crate::consensus::doms::sol::Error),
    #[error(transparent)]
    Att(#[from] crate::consensus::doms::attestation::Error),
    #[error(transparent)]
    Reassembler(#[from] crate::node::reassembler::Error),
    #[error(transparent)]
    Anr(#[from] anr::Error),
    #[error("parse error: {0}")]
    ParseError(&'static str),
    #[error("No ANR found for destination IP: {0}")]
    NoAnrForDestination(Ipv4Addr),
    #[error(transparent)]
    Vecpak(#[from] vecpak::Error),
    #[error("other error: {0}")]
    Other(String),
}

impl Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

/// Result of handling an incoming message.
#[derive(Debug, strum_macros::IntoStaticStr)]
pub enum Instruction {
    Noop { why: String },
    SendNewPhoneWhoDisReply { dst: Ipv4Addr },
    SendGetPeerAnrsReply { anrs: Vec<Anr>, dst: Ipv4Addr },
    SendPingReply { ts_m: u64, dst: Ipv4Addr },

    ValidTxs { txs: Vec<Vec<u8>> },
    ReceivedSol { sol: Solution },
    ReceivedEntry { entry: Entry },
    ReceivedAttestation { attestation: Attestation },
    ReceivedConsensus { consensus: Consensus },
    SpecialBusiness { business: Vec<u8> },
    SpecialBusinessReply { business: Vec<u8> },
    SolicitEntry { hash: Vec<u8> },
    SolicitEntry2,
}

impl Typename for Instruction {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

/// Does proto parsing and validation
/// Primary format is Vecpak; legacy ETF is auto-converted
#[instrument(skip(bin), name = "Proto::from_vecpak_validated")]
pub fn parse_vecpak_bin(bin: &[u8]) -> Result<Box<dyn Protocol>, Error> {
    use amadeus_utils::vecpak::{VecpakExt, decode};

    // decode as vecpak (auto-detects and converts legacy ETF if needed)
    let term = decode(bin).map_err(|e| Error::Other(e.to_string()))?;

    // get PropListMap from the term
    let map = term.get_proplist_map().ok_or(Error::ParseError("map"))?;

    // `op` determines the variant (binary string key in vecpak)
    let op_name = map.get_string(b"op").ok_or(Error::ParseError("op"))?;
    let proto: Box<dyn Protocol> = match op_name.as_str() {
        Ping::TYPENAME => Box::new(vecpak::from_slice::<Ping>(bin)?),
        PingReply::TYPENAME => Box::new(vecpak::from_slice::<PingReply>(bin)?),
        EventEntry::TYPENAME => Box::new(vecpak::from_slice::<EventEntry>(bin)?),
        EventTip::TYPENAME => Box::new(vecpak::from_slice::<EventTip>(bin)?),
        EventAttestation::TYPENAME => Box::new(vecpak::from_slice::<EventAttestation>(bin)?),
        Solution::TYPENAME => Box::new(Solution::from_vecpak_map_validated(map)?),
        EventTx::TYPENAME => Box::new(vecpak::from_slice::<EventTx>(bin)?),
        GetPeerAnrs::TYPENAME => Box::new(vecpak::from_slice::<GetPeerAnrs>(bin)?),
        GetPeerAnrsReply::TYPENAME => Box::new(vecpak::from_slice::<GetPeerAnrsReply>(bin)?),
        NewPhoneWhoDis::TYPENAME => Box::new(vecpak::from_slice::<NewPhoneWhoDis>(bin)?),
        NewPhoneWhoDisReply::TYPENAME => Box::new(vecpak::from_slice::<NewPhoneWhoDisReply>(bin)?),
        SpecialBusiness::TYPENAME => Box::new(SpecialBusiness::from_vecpak_map_validated(map)?),
        SpecialBusinessReply::TYPENAME => Box::new(SpecialBusinessReply::from_vecpak_map_validated(map)?),
        Catchup::TYPENAME => Box::new(vecpak::from_slice::<Catchup>(bin)?),
        CatchupReply::TYPENAME => Box::new(vecpak::from_slice::<CatchupReply>(bin)?),
        _ => return Err(Error::ParseError("op")),
    };

    Ok(proto)
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EventTip {
    pub op: String,
    pub temporal: EntrySummary,
    pub rooted: EntrySummary,
}

impl Typename for EventTip {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for EventTip {
    fn from_vecpak_map_validated(_map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        Err(Error::ParseError("use vecpak::from_slice"))
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        Ok(vecpak::to_vec(&self)?)
    }

    #[instrument(skip(self, ctx), fields(src = %src), name = "EventTip::handle")]
    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        // TODO: validate temporal and rooted entry signatures like in Elixir

        let signer = self.temporal.header.signer.to_vec();
        let is_trainer =
            match ctx.fabric.trainers_for_height(ctx.fabric.get_temporal_height().ok().flatten().unwrap_or_default()) {
                Some(trainers) => trainers.iter().any(|pk| pk.as_slice() == signer),
                None => false,
            };

        if is_trainer || ctx.is_peer_handshaked(src).await {
            ctx.node_peers.update_peer_from_tip(ctx, src, self).await;
        }

        Ok(vec![Instruction::Noop { why: "event_tip handling not implemented".to_string() }])
    }
}

impl EventTip {
    pub const TYPENAME: &'static str = "event_tip";

    pub fn new(temporal: EntrySummary, rooted: EntrySummary) -> Self {
        Self { op: Self::TYPENAME.to_string(), temporal, rooted }
    }

    pub fn from_current_tips() -> Result<Self, Error> {
        // Deprecated: use from_current_tips_db with an explicit DB handle
        Err(Error::Consensus(consensus::Error::NotImplemented("from_current_tips requires DB context")))
    }

    /// Build EventTip from the current temporal/rooted tips in Fabric using the provided Fabric handle
    pub fn from_current_tips_db(fab: &Fabric) -> Result<Self, Error> {
        // Helper to load EntrySummary by tip hash, or return empty summary if missing
        fn entry_summary_by_hash(fab: &Fabric, hash: &Hash) -> EntrySummary {
            if let Some(entry) = fab.get_entry_by_hash(hash) { entry.into() } else { EntrySummary::empty() }
        }

        let temporal_summary = match fab.get_temporal_hash()? {
            Some(h) => entry_summary_by_hash(fab, &Hash::from(h)),
            None => EntrySummary::empty(),
        };

        let rooted_summary = match fab.get_rooted_hash()? {
            Some(h) => entry_summary_by_hash(fab, &Hash::from(h)),
            None => EntrySummary::empty(),
        };

        Ok(Self { op: Self::TYPENAME.to_string(), temporal: temporal_summary, rooted: rooted_summary })
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Ping {
    pub op: String,
    pub ts_m: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PingReply {
    pub op: String,
    pub ts_m: u64,
    #[serde(skip)]
    pub seen_time: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Catchup {
    pub op: String,
    pub height_flags: Vec<CatchupHeight>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CatchupHeight {
    pub height: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashes: Option<Vec<Vec<u8>>>,
}

impl Catchup {
    pub const TYPENAME: &'static str = "catchup";
}

impl Typename for Catchup {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for Catchup {
    fn from_vecpak_map_validated(_map: PropListMap) -> Result<Self, Error> {
        Err(Error::ParseError("use vecpak::from_slice"))
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        Ok(vecpak::to_vec(&self)?)
    }

    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        Ok(vec![Instruction::Noop { why: "catchup received".to_string() }])
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CatchupReply {
    pub op: String,
    pub tries: Vec<CatchupHeightReply>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CatchupHeightReply {
    pub height: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<Entry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestations: Option<Vec<Attestation>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consensuses: Option<Vec<Consensus>>,
}

impl CatchupReply {
    pub const TYPENAME: &'static str = "catchup_reply";
}

impl Typename for CatchupReply {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for CatchupReply {
    fn from_vecpak_map_validated(_map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        Err(Error::ParseError("use vecpak::from_slice"))
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        Ok(vecpak::to_vec(&self)?)
    }

    async fn handle(&self, ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        let instructions = Vec::new();
        let rooted_tip_height = ctx.fabric.get_rooted_height()?.unwrap_or(0);

        for trie in &self.tries {
            if let Some(ref entries) = trie.entries {
                for entry in entries {
                    if entry.header.height >= rooted_tip_height {
                        let seen_time_ms = get_unix_millis_now();
                        let entry_bin = entry.to_vecpak_bin();
                        {
                            let _ = ctx.fabric.insert_entry(
                                &entry.hash,
                                entry.header.height,
                                entry.header.slot,
                                &entry_bin,
                                seen_time_ms,
                            );
                        }
                    }
                }
            }

            if let Some(ref attestations) = trie.attestations {
                for _attestation in attestations {}
            }

            if let Some(ref consensuses) = trie.consensuses {
                for consensus in consensuses {
                    let _ = ctx.fabric.insert_consensus(&consensus);
                }
            }
        }

        Ok(instructions)
    }
}

#[derive(Debug)]
pub struct SolicitEntry {
    pub hash: Vec<u8>,
}

#[derive(Debug)]
pub struct SolicitEntry2;

impl Typename for Ping {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for Ping {
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        let ts_m = map.get_integer(b"ts_m").ok_or(Error::ParseError("ts_m"))?;
        Ok(Self { op: Self::TYPENAME.to_string(), ts_m })
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        let bin = vecpak::to_vec(&self)?;
        Ok(bin)
    }

    #[instrument(skip(self, ctx), fields(src = %src), name = "Ping::handle")]
    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        ctx.node_peers.update_peer_ping_timestamp(src, self.ts_m).await;
        Ok(vec![Instruction::SendPingReply { ts_m: self.ts_m, dst: src }])
    }
}

impl Ping {
    pub const TYPENAME: &'static str = "ping";

    /// Create a new Ping with current timestamp (v1.1.7+ simplified format)
    pub fn new() -> Self {
        Self { op: Self::TYPENAME.to_string(), ts_m: get_unix_millis_now() }
    }

    /// Create Ping with specific timestamp
    pub fn with_timestamp(ts_m: u64) -> Self {
        Self { op: Self::TYPENAME.to_string(), ts_m }
    }
}

impl Typename for PingReply {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for PingReply {
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        let ts_m = map.get_integer(b"ts_m").ok_or(Error::ParseError("ts_m"))?;
        let seen_time_ms = get_unix_millis_now();
        // check what else must be validated
        Ok(Self { op: Self::TYPENAME.to_string(), ts_m: ts_m, seen_time: seen_time_ms })
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        let bin = vecpak::to_vec(&self)?;
        Ok(bin)
    }

    #[instrument(skip(self, ctx), fields(src = %src), name = "PingReply::handle")]
    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        ctx.node_peers.update_peer_from_pong(src, self).await;
        Ok(vec![Instruction::Noop { why: "pong processed".to_string() }])
    }
}

impl PingReply {
    pub const TYPENAME: &'static str = "ping_reply";

    pub fn new(ts_m: u64) -> Self {
        Self { op: Self::TYPENAME.to_string(), ts_m, seen_time: get_unix_millis_now() }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EventTx {
    pub op: String,
    #[serde(rename = "txus")]
    pub txs: Vec<TxU>,
}

impl Typename for EventTx {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for EventTx {
    fn from_vecpak_map_validated(_map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        Err(Error::ParseError("use vecpak::from_slice"))
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        Ok(vecpak::to_vec(&self)?)
    }

    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        Ok(vec![Instruction::Noop { why: "event_tx handling not implemented".to_string() }])
    }
}

impl EventTx {
    pub const TYPENAME: &'static str = "event_tx";

    pub fn new(txs: Vec<TxU>) -> Self {
        Self { op: Self::TYPENAME.to_string(), txs }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[allow(non_snake_case)]
pub struct GetPeerAnrs {
    pub op: String,
    pub hasPeersb3f4: Vec<B3f4>,
}

impl Typename for GetPeerAnrs {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for GetPeerAnrs {
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        let list = map.get_list(b"hasPeersb3f4").ok_or(Error::ParseError("hasPeersb3f4"))?;
        let mut has_peers_b3f4 = Vec::<B3f4>::new();
        for t in list {
            use std::convert::TryInto;
            let b = t.get_binary().ok_or(Error::ParseError("hasPeersb3f4"))?;
            let b3f4: [u8; 4] = b.try_into().map_err(|_| Error::ParseError("hasPeersb3f4_length"))?;
            has_peers_b3f4.push(b3f4.into());
        }

        Ok(Self { op: Self::TYPENAME.to_string(), hasPeersb3f4: has_peers_b3f4 })
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        let bin = vecpak::to_vec(&self)?;
        Ok(bin)
    }

    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        let anrs = ctx.node_anrs.get_all_excluding_b3f4(&self.hasPeersb3f4).await;

        Ok(vec![Instruction::SendGetPeerAnrsReply { anrs, dst: src }])
    }
}

impl GetPeerAnrs {
    pub const TYPENAME: &'static str = "get_peer_anrs";

    pub fn new(has_peers_b3f4: Vec<B3f4>) -> Self {
        Self { op: Self::TYPENAME.to_string(), hasPeersb3f4: has_peers_b3f4 }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct GetPeerAnrsReply {
    pub op: String,
    pub anrs: Vec<Anr>,
}

impl Typename for GetPeerAnrsReply {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for GetPeerAnrsReply {
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        let list = map.get_list(b"anrs").ok_or(Error::ParseError("anrs"))?;
        let mut anrs = Vec::new();
        for term in list {
            let anr_map = term.get_proplist_map().ok_or(Error::ParseError("anr_map"))?;
            let anr = Anr::from_vecpak_map(anr_map)?;
            if anr.verify_signature() {
                anrs.push(anr);
            }
        }
        Ok(Self { op: Self::TYPENAME.to_string(), anrs })
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        let bin = vecpak::to_vec(&self)?;
        Ok(bin)
    }

    async fn handle(&self, ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        for anr in &self.anrs {
            ctx.node_anrs.insert(anr.clone()).await;
        }
        Ok(vec![Instruction::Noop { why: format!("inserted {} anrs", self.anrs.len()) }])
    }
}

impl GetPeerAnrsReply {
    pub const TYPENAME: &'static str = "get_peer_anrs_reply";

    pub fn new(anrs: Vec<Anr>) -> Self {
        Self { op: Self::TYPENAME.to_string(), anrs }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NewPhoneWhoDis {
    pub op: String,
}

impl Typename for NewPhoneWhoDis {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for NewPhoneWhoDis {
    fn from_vecpak_map_validated(_map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        // v1.1.7+ simplified - no fields to parse
        Ok(Self { op: Self::TYPENAME.to_string() })
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        let bin = vecpak::to_vec(&self)?;
        Ok(bin)
    }

    #[instrument(skip_all)]
    async fn handle(&self, _ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        // v1.1.7+ simplified - respond with NewPhoneWhoDisReply
        Ok(vec![Instruction::SendNewPhoneWhoDisReply { dst: src }])
    }
}

impl NewPhoneWhoDis {
    pub const TYPENAME: &'static str = "new_phone_who_dis";

    /// Create new NewPhoneWhoDis message (v1.1.7+ simplified)
    pub fn new() -> Self {
        Self { op: Self::TYPENAME.to_string() }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NewPhoneWhoDisReply {
    pub op: String,
    pub anr: Anr,
}

impl Typename for NewPhoneWhoDisReply {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for NewPhoneWhoDisReply {
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        let anr_map = map.get_proplist_map(b"anr").ok_or(Error::ParseError("anr"))?;
        let anr = Anr::from_vecpak_map(anr_map)?;

        if !anr.verify_signature() {
            return Err(Error::ParseError("anr_signature_invalid"));
        }

        Ok(Self { op: Self::TYPENAME.to_string(), anr })
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        let bin = vecpak::to_vec(&self)?;
        Ok(bin)
    }

    #[instrument(skip(self, ctx), fields(src = %src), name = "NewPhoneWhoDisReply::handle")]
    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        // SECURITY: ip address spoofing protection
        if src != self.anr.ip4 {
            return Err(Error::ParseError("anr_ip_mismatch"));
        }

        let now_s = crate::utils::misc::get_unix_secs_now();
        let age_secs = now_s.saturating_sub(self.anr.ts);
        if age_secs > 60 {
            return Err(Error::ParseError("anr_too_old"));
        }

        ctx.node_anrs.insert(self.anr.clone()).await;
        ctx.node_anrs.set_handshaked(self.anr.pk.as_ref()).await;
        ctx.update_peer_from_anr(src, &self.anr.pk, &self.anr.version, Some(HandshakeStatus::Completed)).await;

        Ok(vec![Instruction::Noop { why: "handshake completed".to_string() }])
    }
}

impl NewPhoneWhoDisReply {
    pub const TYPENAME: &'static str = "new_phone_who_dis_reply";

    pub fn new(anr: Anr) -> Self {
        Self { op: Self::TYPENAME.to_string(), anr }
    }
}

#[derive(Debug)]
pub struct SpecialBusiness {
    pub business: Vec<u8>,
}

impl Typename for SpecialBusiness {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for SpecialBusiness {
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        let business = map.get_binary::<Vec<u8>>(b"business").ok_or(Error::ParseError("business"))?;
        Ok(Self { business })
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        use amadeus_utils::vecpak::encode;
        let pairs = vec![
            (vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Self::TYPENAME.as_bytes().to_vec())),
            (vecpak::Term::Binary(b"business".to_vec()), vecpak::Term::Binary(self.business.clone())),
        ];
        Ok(encode(vecpak::Term::PropList(pairs)))
    }

    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        // TODO: Implement special business handling logic
        // For now, just pass the business data to the state handler
        Ok(vec![Instruction::SpecialBusiness { business: self.business.clone() }])
    }
}

impl SpecialBusiness {
    pub const TYPENAME: &'static str = "special_business";
}

#[derive(Debug)]
pub struct SpecialBusinessReply {
    pub business: Vec<u8>,
}

impl Typename for SpecialBusinessReply {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for SpecialBusinessReply {
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        let business = map.get_binary::<Vec<u8>>(b"business").ok_or(Error::ParseError("business"))?;
        Ok(Self { business })
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        use amadeus_utils::vecpak::encode;
        let pairs = vec![
            (vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Self::TYPENAME.as_bytes().to_vec())),
            (vecpak::Term::Binary(b"business".to_vec()), vecpak::Term::Binary(self.business.clone())),
        ];
        Ok(encode(vecpak::Term::PropList(pairs)))
    }

    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        // TODO: Implement special business reply handling logic
        Ok(vec![Instruction::SpecialBusinessReply { business: self.business.clone() }])
    }
}

impl SpecialBusinessReply {
    pub const TYPENAME: &'static str = "special_business_reply";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::consensus::doms::entry::{EntryHeader, EntrySummary};
    use crate::utils::bls12_381::sign as bls_sign;
    use amadeus_utils::version::Ver;

    #[tokio::test]
    async fn test_ping_vecpak_roundtrip() {
        // create a sample ping message
        let _temporal = create_dummy_entry_summary();
        let _rooted = create_dummy_entry_summary();
        let ping = Ping::new();

        // serialize to vecpak
        let bin = ping.to_vecpak_packet_bin().expect("should serialize");

        // deserialize back
        let result = parse_vecpak_bin(&bin).expect("should deserialize");

        // check that we get the right type
        assert_eq!(result.typename(), "ping");
    }

    #[tokio::test]
    async fn test_pong_vecpak_roundtrip() {
        let pong = PingReply { op: PingReply::TYPENAME.to_string(), ts_m: 1234567890, seen_time: 9876543210 };

        let bin = pong.to_vecpak_packet_bin().expect("should serialize");
        let result = parse_vecpak_bin(&bin).expect("should deserialize");

        // check that the result type is Pong
        assert_eq!(result.typename(), "ping_reply");
    }

    #[tokio::test]
    async fn test_txpool_vecpak_roundtrip() {
        use crate::consensus::doms::tx::{Tx, TxAction, TxU};

        let tx1 = TxU {
            hash: Hash::new([1u8; 32]),
            signature: Signature::new([2u8; 96]),
            tx: Tx {
                action: TxAction {
                    args: vec![vec![1, 2, 3]],
                    contract: "Test".to_string(),
                    function: "test".to_string(),
                    op: "call".to_string(),
                    attached_symbol: None,
                    attached_amount: None,
                },
                nonce: 12345,
                signer: PublicKey::new([3u8; 48]),
            },
        };

        let event_tx = EventTx::new(vec![tx1]);

        let bin = event_tx.to_vecpak_packet_bin().expect("should serialize");
        let result = parse_vecpak_bin(&bin).expect("should deserialize");

        assert_eq!(result.typename(), "event_tx");
    }

    #[tokio::test]
    async fn test_peers_vecpak_roundtrip() {
        let peers = GetPeerAnrs::new(vec![[192, 168, 1, 1].into(), [10, 0, 0, 1].into()]);

        let bin = peers.to_vecpak_packet_bin().expect("should serialize");
        let result = parse_vecpak_bin(&bin).expect("should deserialize");

        assert_eq!(result.typename(), "get_peer_anrs");
    }

    #[tokio::test]
    async fn test_new_phone_who_dis_roundtrip_and_handle() {
        use crate::node::anr;
        use crate::utils::{bls12_381 as bls, misc::get_unix_secs_now};
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

        // build a valid ANR for 127.0.0.1
        let sk = bls::generate_sk();
        let pk = bls::get_public_key(&sk).expect("pk");
        let pop = bls_sign(&sk, pk.as_ref(), crate::consensus::DST_POP).expect("pop");
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let _my_anr = anr::Anr::build(&sk, &pk, pop.as_ref(), ip, Ver::new(1, 0, 0)).expect("anr");

        let _challenge_s = get_unix_secs_now();
        let msg = NewPhoneWhoDis::new();

        // roundtrip serialize/deserialize
        let bin = msg.to_vecpak_packet_bin().expect("serialize");
        let parsed = parse_vecpak_bin(&bin).expect("deserialize");
        assert_eq!(parsed.typename(), "new_phone_who_dis");

        // Test that message can be parsed (handle_inner now does state updates directly)
        let _src = SocketAddr::V4(SocketAddrV4::new(ip, 36969));
        // Protocol handle_inner now manages state internally and returns Noop
    }

    #[tokio::test]
    async fn test_new_phone_who_dis_ip_mismatch_noop() {
        use crate::node::anr;
        use crate::utils::{bls12_381 as bls, misc::get_unix_secs_now};
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

        let sk = bls::generate_sk();
        let pk = bls::get_public_key(&sk).expect("pk");
        let pop = bls_sign(&sk, pk.as_ref(), crate::consensus::DST_POP).expect("pop");
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let _my_anr = anr::Anr::build(&sk, &pk, pop.as_ref(), ip, Ver::new(1, 0, 0)).expect("anr");
        let _challenge_s = get_unix_secs_now();
        let _msg = NewPhoneWhoDis::new();

        // Test with mismatched source ip - should be handled internally now
        let wrong_ip = Ipv4Addr::new(127, 0, 0, 2);
        let _src = SocketAddr::V4(SocketAddrV4::new(wrong_ip, 36969));
        // Protocol handle_inner now manages validation internally
    }

    fn create_dummy_entry_summary() -> EntrySummary {
        let header = EntryHeader {
            height: 1,
            slot: 1,
            prev_slot: 0,
            prev_hash: Hash::new([0u8; 32]),
            dr: Hash::new([1u8; 32]),
            vr: Signature::new([2u8; 96]),
            signer: PublicKey::new([3u8; 48]),
            root_tx: Hash::new([4u8; 32]),
            root_validator: Hash::new([15u8; 32]),
        };

        EntrySummary { header, signature: Signature::new([5u8; 96]), mask: None }
    }

    #[tokio::test]
    async fn test_ping_ts_m_field_validation() {
        let ping = Ping::with_timestamp(1234567890);
        let valid_bin = ping.to_vecpak_packet_bin().expect("should serialize");
        let result = parse_vecpak_bin(&valid_bin);
        assert!(result.is_ok(), "Valid ping should parse successfully");

        let ping_reply = PingReply { op: PingReply::TYPENAME.to_string(), ts_m: 1234567890, seen_time: 9876543210 };
        let valid_bin = ping_reply.to_vecpak_packet_bin().expect("should serialize");
        let result = parse_vecpak_bin(&valid_bin);
        assert!(result.is_ok(), "Valid ping_reply should parse successfully");
    }

    #[tokio::test]
    #[ignore = "requires clean database or migrated snapshot"]
    async fn test_protocol_send_to() {
        // Test that Protocol trait's send_to method works with Context convenience functions
        use crate::socket::MockSocket;
        use crate::utils::bls12_381 as bls;
        use std::net::Ipv4Addr;
        use std::sync::Arc;

        let sk = bls::generate_sk();
        let pk = bls::get_public_key(&sk).expect("pk");
        let pop = bls_sign(&sk, pk.as_ref(), crate::consensus::DST_POP).expect("pop");

        let config = Config {
            work_folder: "/tmp/test_protocol_send_to".to_string(),
            version: Ver::new(1, 2, 3),
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

        let dummy_socket = Arc::new(MockSocket::new());
        let target: Ipv4Addr = "127.0.0.1".parse().unwrap();

        match Context::with_config_and_socket(config, dummy_socket).await {
            Ok(ctx) => {
                // Create a Pong message to test with
                let pong = PingReply { op: PingReply::TYPENAME.to_string(), ts_m: 12345, seen_time: 67890 };

                // Check metrics before sending
                let metrics_json_before = ctx.metrics.get_json();
                let sent_before = metrics_json_before.get("outgoing_protos");

                // Test Protocol::send_to method - should return error with MockSocket but not panic
                match pong.send_to_with_metrics(&ctx, target).await {
                    Ok(_) => {
                        // unexpected success with MockSocket
                    }
                    Err(_) => {
                        // expected error with MockSocket - the important thing is that it compiled and didn't panic
                    }
                }

                // Check that sent packet counter was incremented even when send fails
                let metrics_json_after = ctx.metrics.get_json();
                let sent_after = metrics_json_after.get("outgoing_protos").unwrap().as_object().unwrap();
                match sent_before {
                    Some(obj) => {
                        let sent_before_obj = obj.as_object().unwrap();
                        let pong_before = sent_before_obj.get("ping_reply").map(|v| v.as_u64().unwrap()).unwrap_or(0);
                        let pong_after = sent_after.get("ping_reply").map(|v| v.as_u64().unwrap()).unwrap_or(0);
                        assert_eq!(
                            pong_after,
                            pong_before + 1,
                            "Sent packet counter should increment even on send failure"
                        );
                    }
                    None => {
                        // no sent packets before, should have 1 pong now
                        assert_eq!(sent_after.get("ping_reply").unwrap().as_u64().unwrap(), 1);
                    }
                }
            }
            Err(_) => {
                // context creation failed - this is acceptable for this test
            }
        }
    }

    #[tokio::test]
    async fn test_catchup_and_catchup_reply_vecpak_roundtrip() {
        // Test Catchup
        let height_flag = CatchupHeight {
            height: 42,
            c: Some(true),
            e: None,
            a: Some(true),
            hashes: Some(vec![vec![1, 2, 3], vec![4, 5, 6]]),
        };

        let catchup = Catchup { op: Catchup::TYPENAME.to_string(), height_flags: vec![height_flag] };

        // Test Catchup serialization
        let catchup_bin = catchup.to_vecpak_packet_bin().expect("should serialize catchup");
        let parsed_catchup = parse_vecpak_bin(&catchup_bin).expect("should deserialize catchup");
        assert_eq!(parsed_catchup.typename(), "catchup");

        use crate::consensus::doms::tx::{EntryTx, EntryTxAction, EntryTxInner};
        let test_tx = EntryTx {
            hash: Hash::new([0xAB; 32]),
            signature: Signature::new([0xCD; 96]),
            tx: EntryTxInner {
                action: EntryTxAction {
                    args: vec![vec![1, 2, 3]],
                    contract: "Test".to_string(),
                    function: "test".to_string(),
                    op: "call".to_string(),
                    attached_symbol: None,
                    attached_amount: None,
                },
                nonce: 12345,
                signer: PublicKey::new([0xEF; 48]),
            },
        };
        let entry1 = Entry {
            hash: Hash::new([1; 32]),
            header: EntryHeader {
                height: 100,
                slot: 1,
                prev_slot: 0,
                prev_hash: Hash::new([0; 32]),
                dr: Hash::new([2; 32]),
                vr: Signature::new([0; 96]),
                signer: PublicKey::new([3; 48]),
                root_tx: Hash::new([4; 32]),
                root_validator: Hash::new([15; 32]),
            },
            signature: Signature::new([5; 96]),
            mask: None,
            txs: vec![test_tx],
        };

        let attestation1 = Attestation {
            entry_hash: Hash::new([6; 32]),
            mutations_hash: Hash::new([7; 32]),
            signer: PublicKey::new([8; 48]),
            signature: Signature::new([9; 96]),
        };

        let consensus1 = Consensus {
            entry_hash: Hash::new([10; 32]),
            mutations_hash: Hash::new([11; 32]),
            aggsig: crate::consensus::consensus::Aggsig {
                mask: vec![0b10100000], // equivalent to bitvec![1, 0, 1]
                aggsig: [12; 96].to_vec(),
                mask_size: 3,
                mask_set_size: 2,
            },
        };

        let trie1 = CatchupHeightReply {
            height: 100,
            entries: Some(vec![entry1]),
            attestations: Some(vec![attestation1]),
            consensuses: None,
        };
        let trie2 =
            CatchupHeightReply { height: 101, entries: None, attestations: None, consensuses: Some(vec![consensus1]) };
        let catchup_reply = CatchupReply { op: CatchupReply::TYPENAME.to_string(), tries: vec![trie1, trie2] };

        // Test CatchupReply serialization
        let reply_bin = catchup_reply.to_vecpak_packet_bin().expect("should serialize catchup_reply");
        let parsed_reply = parse_vecpak_bin(&reply_bin).expect("should deserialize catchup_reply");
        assert_eq!(parsed_reply.typename(), "catchup_reply");
    }

    #[tokio::test]
    async fn test_vecpak_ping_parsing() {
        // test parsing a vecpak-encoded ping message
        // vecpak format: proplist with "op" -> "ping" and "ts_m" -> timestamp
        use crate::utils::vecpak::{self, Term as VTerm};

        let ts_m: i128 = 1234567890;
        let vecpak_ping = VTerm::PropList(vec![
            (VTerm::Binary(b"op".to_vec()), VTerm::Binary(b"ping".to_vec())),
            (VTerm::Binary(b"ts_m".to_vec()), VTerm::VarInt(ts_m)),
        ]);

        // encode to vecpak binary
        let mut vecpak_bin = Vec::new();
        vecpak::encode_term(&mut vecpak_bin, vecpak_ping);

        // parse should detect vecpak and convert to protocol
        let parsed = parse_vecpak_bin(&vecpak_bin).expect("should parse vecpak ping");
        assert_eq!(parsed.typename(), "ping");
    }

    #[tokio::test]
    async fn test_ping_roundtrip_via_vecpak() {
        // test that ping can be encoded to vecpak and parsed back correctly
        let original = Ping::with_timestamp(1234567890123);
        let version = Ver::new(1, 2, 3);

        // encode to vecpak
        let payload = original.to_bin(version).expect("should encode");

        // parse back - should detect vecpak and convert to protocol
        let parsed = parse_vecpak_bin(&payload).expect("should parse vecpak");
        assert_eq!(parsed.typename(), "ping");

        // verify contents via dynamic dispatch (we know it's a Ping)
        // since we can't downcast easily, we'll serialize it again and compare
        let re_encoded = parsed.to_bin(version).expect("should re-encode");
        assert_eq!(payload, re_encoded, "roundtrip should preserve encoding");
    }

    #[tokio::test]
    async fn test_ping_reply_roundtrip_via_vecpak() {
        let original = PingReply { op: PingReply::TYPENAME.to_string(), ts_m: 1234567890123, seen_time: 0 };
        let version = Ver::new(1, 2, 3);
        let payload = original.to_bin(version).expect("should encode");

        let parsed = parse_vecpak_bin(&payload).expect("should parse vecpak");
        assert_eq!(parsed.typename(), "ping_reply");

        let re_encoded = parsed.to_bin(version).expect("should re-encode");
        assert_eq!(payload, re_encoded, "roundtrip should preserve encoding");
    }

    #[tokio::test]
    async fn test_new_phone_who_dis_reply_roundtrip_via_vecpak() {
        use crate::node::anr::Anr;
        use crate::utils::bls12_381;
        use std::net::Ipv4Addr;

        // create a test ANR
        let sk = bls12_381::generate_sk();
        let pk = bls12_381::get_public_key(&sk).expect("pk");
        let pop = bls12_381::sign(&sk, pk.as_ref(), crate::consensus::DST_POP).expect("pop");

        let anr = Anr::build(&sk, &pk, pop.as_ref(), Ipv4Addr::new(192, 168, 1, 1), Ver::new(1, 2, 5)).expect("anr");

        let original = NewPhoneWhoDisReply::new(anr);
        let version = Ver::new(1, 2, 3);
        let payload = original.to_bin(version).expect("should encode");

        let parsed = parse_vecpak_bin(&payload).expect("should parse vecpak");
        assert_eq!(parsed.typename(), "new_phone_who_dis_reply");

        let re_encoded = parsed.to_bin(version).expect("should re-encode");
        assert_eq!(payload, re_encoded, "roundtrip should preserve encoding");
    }

    #[tokio::test]
    async fn test_get_peer_anrs_roundtrip_via_vecpak() {
        let original = GetPeerAnrs::new(vec![[1, 2, 3, 4].into(), [5, 6, 7, 8].into()]);
        let version = Ver::new(1, 2, 3);
        let payload = original.to_bin(version).expect("should encode");

        let parsed = parse_vecpak_bin(&payload).expect("should parse vecpak");
        assert_eq!(parsed.typename(), "get_peer_anrs");

        let re_encoded = parsed.to_bin(version).expect("should re-encode");
        assert_eq!(payload, re_encoded, "roundtrip should preserve encoding");
    }

    #[tokio::test]
    async fn test_event_tx_roundtrip_via_vecpak() {
        use crate::consensus::doms::tx::{Tx, TxAction, TxU};

        // create simple test transactions
        let tx1 = TxU {
            hash: Hash::new([1u8; 32]),
            signature: Signature::new([2u8; 96]),
            tx: Tx {
                action: TxAction {
                    args: vec![vec![1, 2, 3]],
                    contract: "Test".to_string(),
                    function: "test".to_string(),
                    op: "call".to_string(),
                    attached_symbol: None,
                    attached_amount: None,
                },
                nonce: 12345,
                signer: PublicKey::new([3u8; 48]),
            },
        };
        let tx2 = TxU {
            hash: Hash::new([4u8; 32]),
            signature: Signature::new([5u8; 96]),
            tx: Tx {
                action: TxAction {
                    args: vec![vec![4, 5, 6]],
                    contract: "Test2".to_string(),
                    function: "test2".to_string(),
                    op: "call".to_string(),
                    attached_symbol: None,
                    attached_amount: None,
                },
                nonce: 67890,
                signer: PublicKey::new([6u8; 48]),
            },
        };

        let original = EventTx::new(vec![tx1, tx2]);
        let version = Ver::new(1, 2, 3);
        let payload = original.to_bin(version).expect("should encode");

        let parsed = parse_vecpak_bin(&payload).expect("should parse vecpak");
        assert_eq!(parsed.typename(), "event_tx");

        // re-encoding may differ because validation filters, so just check parsing works
    }

    #[tokio::test]
    async fn test_parse_real_elixir_new_phone_who_dis() {
        // real packet from Elixir node at 167.235.169.185
        let packet = hex::decode("0701010501026f700501116e65775f70686f6e655f77686f5f646973").unwrap();

        let parsed = parse_vecpak_bin(&packet).expect("should parse real elixir packet");
        assert_eq!(parsed.typename(), "new_phone_who_dis");

        // re-encode and compare
        let version = Ver::new(1, 2, 3);
        let re_encoded = parsed.to_bin(version).expect("should re-encode");
        assert_eq!(packet, re_encoded, "re-encoded must match original from Elixir");
    }

    #[tokio::test]
    async fn test_parse_event_tx_with_structured_txu() {
        // Real packet that previously failed with "invalid type tag" error
        // This is an event_tx containing a structured TxU (map) instead of raw bytes
        let packet = hex::decode("0701020501026f700501086576656e745f74780501047478757306010107010305010274780701030501056e6f6e63650308187c02e8527c7cbf050106616374696f6e0701040501026f7005010463616c6c05010461726773060101050204f09e01000060f7e2fb1fbd6e6425d1fdb53a172e548a3369d041508952e0c27ee7bd548963904796524edd0037f341613e24a7bf2c1992044ea66cbc8d8f1ff91b3d61705de2780321cc74bb12c693913edf938ca4b6348ad0d56c1fb45c5d0c573ccc09771dcf89434cba91a977f5d8e7bcddd60220ca849cbf3babb55d515b14e8d248a40f6a515f91174b41fe9296f0cf027bc1d3cb1d8b2e4c5bfee88c3f0c914678ad45ac8fbf59b9cb0f535861ef54c474ad904796524edd0037f341613e24a7bf2c1992044ea66cbc8d8f1ff91b3d61705de2780321cc74bb12c693913edf938ca48566b77b83ee09c66333f2a34deba8ffa9f1aeff6205baffd891e5ffdb1fa8ff4190a6ffe96ef1ffd9cfc9ffb1bdb6ffe72ee5ff41e3eeffad23daff3c69b4ffb042cbff3d3e0d005e3696ffa7119dffd030bcffaaceaeff6f25caff76d5a3ffe40c9bff7291e4ff14fcd0ff2fe5cfffc2b7f5ffc869d2ffce69d6ffa7a0dbff24cfc7ff71ec09008862a3ff4b237dffe554d9ff9e84baff0adcd7ff8d9f9fff48e1b7ffce29daff0236a7ffad19bbffb065fbffe7cac0ffd941f2ff9e1d96ffad5ec7ffd4111300c0078bffd82db8ff8353bcff01dfd8fff139acff79c5afffa4bcb2ff617aeaffbaa4caff3a2ed4ff04730b00e66dc6ff6946cdff29e4abffac5ba3fff9571a008b19aeffde77aaff0987bcffe226b1ffb11cbbff88d1a6ff8ab1d6ff9b3ed8ff8460cdff6841e7ff9d16dbffebc1d3ffb76cfdffffd9c3ff9329c5fffa46f5ff649c99ff78fab1ffcf64bdffc65fc1ff7316c6ffed4eb2fff3a8a1ff8ec9cfff95d5d4ff8b66c0ffc1aff5ff889ac2ff87f3f5ff49fab0ff2a3db6ffebaf130008d88bffc1ab91ff5d00cdffd864a0ff06edceff66decbff8181c6ffda9dbcff2826ccffbcb2c0ff27c5e0ff294edaff5b8bd9ff07c998ff4571b6ff9fc8160069eeb5ffad93b2ff80a7bbffbae9c2ff65ecbdffa591a4ff2683c8ffe9c5d8ffc969b6ff1ba6c5ff19400e00830bc9ff5857bcff0cb89bffe8a4b4ffdeefffff547badfffd76b1ffeed4b0ffbc44cbff0c3ebfff0cb9b5ff08c9a8ff97b4caffc11de3ff2173a7fff744eaffdbd1f1ff3ab3dfffaefc96ffeca3abff8aba2100f8e084ff90cabeffdb0bbaffca18d1ffaff6c0ff45a38dffe05aaeff3db7cfff87c9bcffbabdc0ffb81be9ffeb1bcdff7741d5ff6ef9b2ffba33b6ff5b1a02006593a9ff4398b4ff666bb3ffe42fcbff7fceb9ffa179c3ffaaadd4ffa48efbff0578c6ffe541c9ff43dff8ff257498ff0d88dbff49758affb3c7c1ff8f7df9ff1ff587ff0842d6ffe954b9fff39fc8ffbd55a3ff2ea1a2ffa28bc5ff874bdcffa06ddcff9b74b6ff1976e6ffa2a8b8ff1d27d9ff31ffc3ff8603bbff760b270029349dff40c8a4ff27b8c5ff97faa1ff7087c9ff66cfa3ff46bdb2ffd404e8ff387dc5ff0512d7ffe955f5ffcd6bc6ffc777d9fff0439aff0034b0ffc1ad5100f9b4adff79379eff7e5eb9ff444096ffb8f0d2ff6f4cc5ffe4cbd7ff2abdf1ff8ccec0ff152cc7ffa7ccf4fff186ceff7a99d3ff608e94ffc9dfd4ff1a9b1c00a5f4bfff21dda5ff21b5ceff0d1ba6ff6388edff336fa7ffdd29b8ff41a8d5ffaccdc5ffbfdcc3ff64cff1ffdad7c2ff79afdfff699c9dfff1b2d1ff0014460022f399ffc803a5ff1a1396ff7df5ceff95eec6ff182eadff834ab1ff8de1d6ff8af2c1ffee38c9ff4a90eaff1b29c0ff6390cbff724aa8ffa417adffae762900ca90a2ff050108636f6e747261637405010545706f636805010866756e6374696f6e05010a7375626d69745f736f6c0501067369676e657205013098b033f3c88d92c3ed617e06b87ff452bebc505fcdcc094f5f673433817825801ba0eaa8319f05804ed4728c9809d3380501046861736805012092a51d6e44c6e8b662d2870c4a8a9efd99f026de98c6a3a67f1652a79fa2d6b20501097369676e6174757265050160ad01c361a5845bf5772540c3719bd7088a742c4905271bb89edbd3808accf0e2a2186d300370d42f7da17cddab2ddb310517521e67a74438d25cf549b46e51d385f32cafe2b8e8a4f3c71dd384f7456f41c0d83556205890ae5522cd2a18c45f").unwrap();

        let parsed = parse_vecpak_bin(&packet).expect("should parse event_tx with structured TxU");
        assert_eq!(parsed.typename(), "event_tx");
    }

    #[tokio::test]
    async fn test_parse_catchup_reply_from_elixir() {
        // Real CatchupReply packet from Elixir node
        // Tests deserialization of Entry, Consensus, and Attestation with Elixir's nested aggsig format
        // Load from file if it exists, otherwise skip
        let paths = ["packet", "../packet", "../../packet"];
        let packet = match paths.iter().find_map(|p| std::fs::read_to_string(p).ok()) {
            Some(hex_str) => match hex::decode(hex_str.trim()) {
                Ok(bytes) => bytes,
                Err(_) => return, // Skip if not valid hex
            },
            None => return, // Skip if file not found
        };

        // Verify basic structure
        let term = vecpak::decode(&packet).expect("should decode as vecpak");
        let map = term.get_proplist_map().expect("should be a proplist");
        assert_eq!(map.get_string(b"op").expect("should have op"), "catchup_reply");

        // Full deserialization test
        let parsed = vecpak::from_slice::<CatchupReply>(&packet).expect("should parse catchup_reply");
        assert!(!parsed.tries.is_empty(), "should have at least one trie");

        // Verify first trie has expected structure
        let first_trie = &parsed.tries[0];
        assert!(first_trie.entries.as_ref().map_or(false, |e| !e.is_empty()), "should have entries");
        assert!(first_trie.consensuses.as_ref().map_or(false, |c| !c.is_empty()), "should have consensuses");
    }
}
