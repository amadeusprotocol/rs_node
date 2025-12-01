use crate::Context;
use crate::consensus::consensus::{self, Consensus};
use crate::consensus::doms::attestation::EventAttestation;
use crate::consensus::doms::entry::{Entry, EventEntry};
use crate::consensus::doms::tx::TxU;
use crate::consensus::doms::{Attestation, EntrySummary};
use crate::consensus::fabric::Fabric;
use crate::node::anr::Anr;
use crate::node::peers::HandshakeStatus;
use crate::node::{anr, peers};
use crate::utils::Hash;
use crate::utils::bls12_381;
use crate::utils::misc::get_unix_millis_now;
#[cfg(test)]
use crate::utils::{PublicKey, Signature};
use amadeus_utils::B3f4;
use amadeus_utils::vecpak;
use ambassador::{Delegate, delegatable_trait};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::io::Error as IoError;
use std::net::{Ipv4Addr, SocketAddr};
use tracing::instrument;

#[derive(Delegate, Debug, Serialize, Deserialize)]
#[delegate(Handle)]
pub enum Protocol {
    Ping(Ping),
    PingReply(PingReply),
    EventEntry(EventEntry),
    EventTip(EventTip),
    EventAttestation(EventAttestation),
    EventTx(EventTx),
    GetPeerAnrs(GetPeerAnrs),
    GetPeerAnrsReply(GetPeerAnrsReply),
    NewPhoneWhoDis(NewPhoneWhoDis),
    NewPhoneWhoDisReply(NewPhoneWhoDisReply),
    Catchup(Catchup),
    CatchupReply(CatchupReply),
    SpecialBusiness(SpecialBusiness),
    SpecialBusinessReply(SpecialBusinessReply),
}

impl Typename for Protocol {
    fn typename(&self) -> &'static str {
        match self {
            Protocol::Ping(_) => Ping::TYPENAME,
            Protocol::PingReply(_) => PingReply::TYPENAME,
            Protocol::EventEntry(_) => EventEntry::TYPENAME,
            Protocol::EventTip(_) => EventTip::TYPENAME,
            Protocol::EventAttestation(_) => EventAttestation::TYPENAME,
            Protocol::EventTx(_) => EventTx::TYPENAME,
            Protocol::GetPeerAnrs(_) => GetPeerAnrs::TYPENAME,
            Protocol::GetPeerAnrsReply(_) => GetPeerAnrsReply::TYPENAME,
            Protocol::NewPhoneWhoDis(_) => NewPhoneWhoDis::TYPENAME,
            Protocol::NewPhoneWhoDisReply(_) => NewPhoneWhoDisReply::TYPENAME,
            Protocol::Catchup(_) => Catchup::TYPENAME,
            Protocol::CatchupReply(_) => CatchupReply::TYPENAME,
            Protocol::SpecialBusiness(_) => SpecialBusiness::TYPENAME,
            Protocol::SpecialBusinessReply(_) => SpecialBusinessReply::TYPENAME,
        }
    }
}

impl Protocol {
    /// Requires ANR to be available due to e2e encryption
    pub async fn send_to_with_metrics(&self, ctx: &Context, dst: Ipv4Addr) -> Result<(), Error> {
        let dst_addr = SocketAddr::new(std::net::IpAddr::V4(dst), ctx.config.udp_port);
        let dst_anr = ctx.anrs.get_by_ip4(dst).await.ok_or(Error::NoAnrForDestination(dst))?;

        let shards = ctx.reassembler.build_shards(&ctx.config, &vecpak::to_vec(&self)?, &dst_anr.pk).await?;
        for shard in &shards {
            ctx.socket.send_to_with_metrics(shard, dst_addr, &ctx.metrics).await?;
        }

        ctx.metrics.add_outgoing_proto(self.typename());
        Ok(())
    }
}

/// Trait for types that can provide their type name as a static string
#[delegatable_trait]
pub trait Typename {
    /// Get the type name for this instance
    /// For enums, this can return different names based on the variant
    fn typename(&self) -> &'static str;
}

/// Every object that has this trait must be convertible from a Vecpak
/// Binary representation and must be able to handle itself as a message
#[async_trait::async_trait]
#[delegatable_trait]
pub trait Handle: Typename + Debug + Send + Sync + Serialize {
    /// Handle a message returning instructions for upper layers
    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error>;
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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EventTip {
    pub temporal: EntrySummary,
    pub rooted: EntrySummary,
}

impl Typename for EventTip {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Handle for EventTip {
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
            ctx.peers.update_peer_from_tip(ctx, src, self).await;
        }

        Ok(vec![Instruction::Noop { why: "event_tip handling not implemented".to_string() }])
    }
}

impl EventTip {
    pub const TYPENAME: &'static str = "event_tip";

    pub fn new(temporal: EntrySummary, rooted: EntrySummary) -> Self {
        Self { temporal, rooted }
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

        Ok(Self { temporal: temporal_summary, rooted: rooted_summary })
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Ping {
    pub ts_m: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PingReply {
    pub ts_m: u64,
    #[serde(skip)]
    pub seen_time: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Catchup {
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
impl Handle for Catchup {
    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        Ok(vec![Instruction::Noop { why: "catchup received".to_string() }])
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CatchupReply {
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
impl Handle for CatchupReply {
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
impl Handle for Ping {
    #[instrument(skip(self, ctx), fields(src = %src), name = "Ping::handle")]
    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        ctx.peers.update_peer_ping_timestamp(src, self.ts_m).await;
        Ok(vec![Instruction::SendPingReply { ts_m: self.ts_m, dst: src }])
    }
}

impl Ping {
    pub const TYPENAME: &'static str = "ping";

    /// Create a new Ping with current timestamp (v1.1.7+ simplified format)
    pub fn new() -> Self {
        Self { ts_m: get_unix_millis_now() }
    }

    /// Create Ping with specific timestamp
    pub fn with_timestamp(ts_m: u64) -> Self {
        Self { ts_m }
    }
}

impl Typename for PingReply {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Handle for PingReply {
    #[instrument(skip(self, ctx), fields(src = %src), name = "PingReply::handle")]
    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        ctx.peers.update_peer_from_pong(src, self).await;
        Ok(vec![Instruction::Noop { why: "pong processed".to_string() }])
    }
}

impl PingReply {
    pub const TYPENAME: &'static str = "ping_reply";

    pub fn new(ts_m: u64) -> Self {
        Self { ts_m, seen_time: get_unix_millis_now() }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EventTx {
    #[serde(rename = "txus")]
    pub txs: Vec<TxU>,
}

impl Typename for EventTx {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Handle for EventTx {
    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        Ok(vec![Instruction::Noop { why: "event_tx handling not implemented".to_string() }])
    }
}

impl EventTx {
    pub const TYPENAME: &'static str = "event_tx";

    pub fn new(txs: Vec<TxU>) -> Self {
        Self { txs }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[allow(non_snake_case)]
pub struct GetPeerAnrs {
    pub hasPeersb3f4: Vec<B3f4>,
}

impl Typename for GetPeerAnrs {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Handle for GetPeerAnrs {
    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        let anrs = ctx.anrs.get_all_excluding_b3f4(&self.hasPeersb3f4).await;

        Ok(vec![Instruction::SendGetPeerAnrsReply { anrs, dst: src }])
    }
}

impl GetPeerAnrs {
    pub const TYPENAME: &'static str = "get_peer_anrs";

    pub fn new(has_peers_b3f4: Vec<B3f4>) -> Self {
        Self { hasPeersb3f4: has_peers_b3f4 }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct GetPeerAnrsReply {
    pub anrs: Vec<Anr>,
}

impl Typename for GetPeerAnrsReply {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Handle for GetPeerAnrsReply {
    async fn handle(&self, ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        for anr in &self.anrs {
            ctx.anrs.insert(anr.clone()).await;
        }
        Ok(vec![Instruction::Noop { why: format!("inserted {} anrs", self.anrs.len()) }])
    }
}

impl GetPeerAnrsReply {
    pub const TYPENAME: &'static str = "get_peer_anrs_reply";

    pub fn new(anrs: Vec<Anr>) -> Self {
        Self { anrs }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NewPhoneWhoDis {}

impl Typename for NewPhoneWhoDis {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Handle for NewPhoneWhoDis {
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
        Self {}
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct NewPhoneWhoDisReply {
    pub anr: Anr,
}

impl Typename for NewPhoneWhoDisReply {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Handle for NewPhoneWhoDisReply {
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

        ctx.anrs.insert(self.anr.clone()).await;
        ctx.anrs.set_handshaked(self.anr.pk.as_ref()).await;
        ctx.update_peer_from_anr(src, &self.anr.pk, &self.anr.version, Some(HandshakeStatus::Completed)).await;

        Ok(vec![Instruction::Noop { why: "handshake completed".to_string() }])
    }
}

impl NewPhoneWhoDisReply {
    pub const TYPENAME: &'static str = "new_phone_who_dis_reply";

    pub fn new(anr: Anr) -> Self {
        Self { anr }
    }
}

/// Application-specific payload for special business operations.
/// Used for operations like slash_trainer_tx, slash_trainer_entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SpecialBusiness {
    #[serde(with = "serde_bytes")]
    pub business: Vec<u8>,
}

impl SpecialBusiness {
    pub const TYPENAME: &'static str = "special_business";

    pub fn new(business: Vec<u8>) -> Self {
        Self { business }
    }
}

impl Typename for SpecialBusiness {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Handle for SpecialBusiness {
    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        Ok(vec![Instruction::SpecialBusiness { business: self.business.clone() }])
    }
}

/// Reply to a special business request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SpecialBusinessReply {
    #[serde(with = "serde_bytes")]
    pub business: Vec<u8>,
}

impl SpecialBusinessReply {
    pub const TYPENAME: &'static str = "special_business_reply";

    pub fn new(business: Vec<u8>) -> Self {
        Self { business }
    }
}

impl Typename for SpecialBusinessReply {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Handle for SpecialBusinessReply {
    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        Ok(vec![Instruction::SpecialBusinessReply { business: self.business.clone() }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::doms::entry::{Entry, EntryHeader, EntrySummary};
    use crate::consensus::doms::tx::{EntryTx, EntryTxAction, EntryTxInner, Tx, TxAction, TxU};
    use crate::node::anr::Anr;
    use crate::utils::bls12_381;
    use amadeus_utils::version::Ver;
    use std::net::Ipv4Addr;

    fn dummy_anr() -> Anr {
        let sk = bls12_381::generate_sk();
        let pk = bls12_381::get_public_key(&sk).unwrap();
        let pop = bls12_381::sign(&sk, pk.as_ref(), crate::consensus::DST_POP).unwrap();
        Anr::build(&sk, &pk, pop.as_ref(), Ipv4Addr::new(127, 0, 0, 1), Ver::new(1, 0, 0)).unwrap()
    }

    fn dummy_entry_summary() -> EntrySummary {
        EntrySummary {
            header: EntryHeader {
                height: 1,
                slot: 1,
                prev_slot: 0,
                prev_hash: Hash::new([0; 32]),
                dr: Hash::new([1; 32]),
                vr: Signature::new([2; 96]),
                signer: PublicKey::new([3; 48]),
                root_tx: Hash::new([4; 32]),
                root_validator: Hash::new([5; 32]),
            },
            signature: Signature::new([6; 96]),
            mask: None,
        }
    }

    fn dummy_entry() -> Entry {
        Entry {
            hash: Hash::new([10; 32]),
            header: EntryHeader {
                height: 1,
                slot: 1,
                prev_slot: 0,
                prev_hash: Hash::new([0; 32]),
                dr: Hash::new([1; 32]),
                vr: Signature::new([2; 96]),
                signer: PublicKey::new([3; 48]),
                root_tx: Hash::new([4; 32]),
                root_validator: Hash::new([5; 32]),
            },
            signature: Signature::new([6; 96]),
            mask: None,
            txs: vec![EntryTx {
                hash: Hash::new([20; 32]),
                signature: Signature::new([21; 96]),
                tx: EntryTxInner {
                    action: EntryTxAction {
                        args: vec![],
                        contract: "C".into(),
                        function: "f".into(),
                        op: "call".into(),
                        attached_symbol: None,
                        attached_amount: None,
                    },
                    nonce: 1,
                    signer: PublicKey::new([22; 48]),
                },
            }],
        }
    }

    fn dummy_txu() -> TxU {
        TxU {
            hash: Hash::new([30; 32]),
            signature: Signature::new([31; 96]),
            tx: Tx {
                action: TxAction {
                    args: vec![],
                    contract: "C".into(),
                    function: "f".into(),
                    op: "call".into(),
                    attached_symbol: None,
                    attached_amount: None,
                },
                nonce: 1,
                signer: PublicKey::new([32; 48]),
            },
        }
    }

    fn dummy_attestation() -> Attestation {
        Attestation {
            entry_hash: Hash::new([40; 32]),
            mutations_hash: Hash::new([41; 32]),
            signer: PublicKey::new([42; 48]),
            signature: Signature::new([43; 96]),
        }
    }

    fn roundtrip<T: serde::Serialize + for<'de> serde::Deserialize<'de>>(msg: &T) -> T {
        let bin = vecpak::to_vec(msg).expect("serialize");
        vecpak::from_slice(&bin).expect("deserialize")
    }

    #[test]
    fn ping_roundtrip() {
        let msg = Protocol::Ping(Ping::with_timestamp(123456));
        let rt = roundtrip(&msg);
        assert_eq!(rt.typename(), "ping");
    }

    #[test]
    fn ping_reply_roundtrip() {
        let msg = Protocol::PingReply(PingReply { ts_m: 123456, seen_time: 0 });
        let rt = roundtrip(&msg);
        assert_eq!(rt.typename(), "ping_reply");
    }

    #[test]
    fn event_entry_roundtrip() {
        let msg = Protocol::EventEntry(EventEntry { entry_packed: dummy_entry() });
        let rt = roundtrip(&msg);
        assert_eq!(rt.typename(), "event_entry");
    }

    #[test]
    fn event_tip_roundtrip() {
        let msg = Protocol::EventTip(EventTip::new(dummy_entry_summary(), dummy_entry_summary()));
        let rt = roundtrip(&msg);
        assert_eq!(rt.typename(), "event_tip");
    }

    #[test]
    fn event_attestation_roundtrip() {
        let msg = Protocol::EventAttestation(EventAttestation::new(vec![dummy_attestation()]));
        let rt = roundtrip(&msg);
        assert_eq!(rt.typename(), "event_attestation");
    }

    #[test]
    fn event_tx_roundtrip() {
        let msg = Protocol::EventTx(EventTx::new(vec![dummy_txu()]));
        let rt = roundtrip(&msg);
        assert_eq!(rt.typename(), "event_tx");
    }

    #[test]
    fn get_peer_anrs_roundtrip() {
        let msg = Protocol::GetPeerAnrs(GetPeerAnrs::new(vec![[1, 2, 3, 4].into()]));
        let rt = roundtrip(&msg);
        assert_eq!(rt.typename(), "get_peer_anrs");
    }

    #[test]
    fn get_peer_anrs_reply_roundtrip() {
        let msg = Protocol::GetPeerAnrsReply(GetPeerAnrsReply::new(vec![dummy_anr()]));
        let rt = roundtrip(&msg);
        assert_eq!(rt.typename(), "get_peer_anrs_reply");
    }

    #[test]
    fn new_phone_who_dis_roundtrip() {
        let msg = Protocol::NewPhoneWhoDis(NewPhoneWhoDis::new());
        let rt = roundtrip(&msg);
        assert_eq!(rt.typename(), "new_phone_who_dis");
    }

    #[test]
    fn new_phone_who_dis_reply_roundtrip() {
        let msg = Protocol::NewPhoneWhoDisReply(NewPhoneWhoDisReply::new(dummy_anr()));
        let rt = roundtrip(&msg);
        assert_eq!(rt.typename(), "new_phone_who_dis_reply");
    }

    #[test]
    fn special_business_roundtrip() {
        let msg = Protocol::SpecialBusiness(SpecialBusiness::new(vec![1, 2, 3, 4, 5]));
        let rt = roundtrip(&msg);
        assert_eq!(rt.typename(), "special_business");
        if let Protocol::SpecialBusiness(sb) = rt {
            assert_eq!(sb.business, vec![1, 2, 3, 4, 5]);
        }
    }

    #[test]
    fn special_business_reply_roundtrip() {
        let msg = Protocol::SpecialBusinessReply(SpecialBusinessReply::new(vec![6, 7, 8, 9]));
        let rt = roundtrip(&msg);
        assert_eq!(rt.typename(), "special_business_reply");
        if let Protocol::SpecialBusinessReply(sbr) = rt {
            assert_eq!(sbr.business, vec![6, 7, 8, 9]);
        }
    }

    #[test]
    fn parse_real_elixir_event_tx() {
        let packet = hex::decode("0701020501026f700501086576656e745f74780501047478757306010107010305010274780701030501056e6f6e63650308187c02e8527c7cbf050106616374696f6e0701040501026f7005010463616c6c05010461726773060101050204f09e01000060f7e2fb1fbd6e6425d1fdb53a172e548a3369d041508952e0c27ee7bd548963904796524edd0037f341613e24a7bf2c1992044ea66cbc8d8f1ff91b3d61705de2780321cc74bb12c693913edf938ca4b6348ad0d56c1fb45c5d0c573ccc09771dcf89434cba91a977f5d8e7bcddd60220ca849cbf3babb55d515b14e8d248a40f6a515f91174b41fe9296f0cf027bc1d3cb1d8b2e4c5bfee88c3f0c914678ad45ac8fbf59b9cb0f535861ef54c474ad904796524edd0037f341613e24a7bf2c1992044ea66cbc8d8f1ff91b3d61705de2780321cc74bb12c693913edf938ca48566b77b83ee09c66333f2a34deba8ffa9f1aeff6205baffd891e5ffdb1fa8ff4190a6ffe96ef1ffd9cfc9ffb1bdb6ffe72ee5ff41e3eeffad23daff3c69b4ffb042cbff3d3e0d005e3696ffa7119dffd030bcffaaceaeff6f25caff76d5a3ffe40c9bff7291e4ff14fcd0ff2fe5cfffc2b7f5ffc869d2ffce69d6ffa7a0dbff24cfc7ff71ec09008862a3ff4b237dffe554d9ff9e84baff0adcd7ff8d9f9fff48e1b7ffce29daff0236a7ffad19bbffb065fbffe7cac0ffd941f2ff9e1d96ffad5ec7ffd4111300c0078bffd82db8ff8353bcff01dfd8fff139acff79c5afffa4bcb2ff617aeaffbaa4caff3a2ed4ff04730b00e66dc6ff6946cdff29e4abffac5ba3fff9571a008b19aeffde77aaff0987bcffe226b1ffb11cbbff88d1a6ff8ab1d6ff9b3ed8ff8460cdff6841e7ff9d16dbffebc1d3ffb76cfdffffd9c3ff9329c5fffa46f5ff649c99ff78fab1ffcf64bdffc65fc1ff7316c6ffed4eb2fff3a8a1ff8ec9cfff95d5d4ff8b66c0ffc1aff5ff889ac2ff87f3f5ff49fab0ff2a3db6ffebaf130008d88bffc1ab91ff5d00cdffd864a0ff06edceff66decbff8181c6ffda9dbcff2826ccffbcb2c0ff27c5e0ff294edaff5b8bd9ff07c998ff4571b6ff9fc8160069eeb5ffad93b2ff80a7bbffbae9c2ff65ecbdffa591a4ff2683c8ffe9c5d8ffc969b6ff1ba6c5ff19400e00830bc9ff5857bcff0cb89bffe8a4b4ffdeefffff547badfffd76b1ffeed4b0ffbc44cbff0c3ebfff0cb9b5ff08c9a8ff97b4caffc11de3ff2173a7fff744eaffdbd1f1ff3ab3dfffaefc96ffeca3abff8aba2100f8e084ff90cabeffdb0bbaffca18d1ffaff6c0ff45a38dffe05aaeff3db7cfff87c9bcffbabdc0ffb81be9ffeb1bcdff7741d5ff6ef9b2ffba33b6ff5b1a02006593a9ff4398b4ff666bb3ffe42fcbff7fceb9ffa179c3ffaaadd4ffa48efbff0578c6ffe541c9ff43dff8ff257498ff0d88dbff49758affb3c7c1ff8f7df9ff1ff587ff0842d6ffe954b9fff39fc8ffbd55a3ff2ea1a2ffa28bc5ff874bdcffa06ddcff9b74b6ff1976e6ffa2a8b8ff1d27d9ff31ffc3ff8603bbff760b270029349dff40c8a4ff27b8c5ff97faa1ff7087c9ff66cfa3ff46bdb2ffd404e8ff387dc5ff0512d7ffe955f5ffcd6bc6ffc777d9fff0439aff0034b0ffc1ad5100f9b4adff79379eff7e5eb9ff444096ffb8f0d2ff6f4cc5ffe4cbd7ff2abdf1ff8ccec0ff152cc7ffa7ccf4fff186ceff7a99d3ff608e94ffc9dfd4ff1a9b1c00a5f4bfff21dda5ff21b5ceff0d1ba6ff6388edff336fa7ffdd29b8ff41a8d5ffaccdc5ffbfdcc3ff64cff1ffdad7c2ff79afdfff699c9dfff1b2d1ff0014460022f399ffc803a5ff1a1396ff7df5ceff95eec6ff182eadff834ab1ff8de1d6ff8af2c1ffee38c9ff4a90eaff1b29c0ff6390cbff724aa8ffa417adffae762900ca90a2ff050108636f6e747261637405010545706f636805010866756e6374696f6e05010a7375626d69745f736f6c0501067369676e657205013098b033f3c88d92c3ed617e06b87ff452bebc505fcdcc094f5f673433817825801ba0eaa8319f05804ed4728c9809d3380501046861736805012092a51d6e44c6e8b662d2870c4a8a9efd99f026de98c6a3a67f1652a79fa2d6b20501097369676e6174757265050160ad01c361a5845bf5772540c3719bd7088a742c4905271bb89edbd3808accf0e2a2186d300370d42f7da17cddab2ddb310517521e67a74438d25cf549b46e51d385f32cafe2b8e8a4f3c71dd384f7456f41c0d83556205890ae5522cd2a18c45f").unwrap();
        let parsed: Protocol = vecpak::from_slice(&packet).expect("should parse real elixir event_tx");
        assert_eq!(parsed.typename(), "event_tx");
        assert_eq!(packet, vecpak::to_vec(&parsed).expect("should encode real elixir event_tx"));
    }

    #[test]
    fn handshake_compatibility() {
        let p_hex = "0701010501026f700501116e65775f70686f6e655f77686f5f646973";
        let p_bytes = hex::decode(p_hex).expect("valid hex");
        let npwd: Protocol = amadeus_utils::vecpak::from_slice(&p_bytes).unwrap();
        let rt_bytes = amadeus_utils::vecpak::to_vec(&npwd).unwrap();
        assert_eq!(rt_bytes, p_bytes);

        let p_hex = "0701020501026f700501176e65775f70686f6e655f77686f5f6469735f7265706c79050103616e72070107050102706b050130a9e81ed8c8eaaebd8dd53a889d8c5a8612ab7330275a5d39043e95200e7c1b66f0dc00c5307e867a55a9ad9e7ae4b9f005010274730304692634f205010369703405010c37322e392e3134342e313130050103706f70050160b62a96d62af0d2d7006ab560c64bde562df13ae642380a31d935276412c59f9944dceaa4060903e4ead197e97ad1654910be87ac556a5063e1d68df542aab1a3f75df3eab891a7cab572ba7170716c5487183ef28ef89f7c7555be2bb1d41218050104706f72740302906905010776657273696f6e050105312e332e300501097369676e6174757265050160b62d43994fa7614138d205ecefeb1677d4998574aac1db8fdd5673de4e1d2ae8391c4cf703007ce37778e20624650143068c59596b5838536ecfd05a0d0805b0baa04dcae97caf9f199232fbfff462ebb35bfc653576af43007ba9666a2952a7";
        let p_bytes = hex::decode(p_hex).expect("valid hex");
        let npwdr: Protocol = amadeus_utils::vecpak::from_slice(&p_bytes).unwrap();
        let rt_bytes = amadeus_utils::vecpak::to_vec(&npwdr).unwrap();
        assert_eq!(rt_bytes, p_bytes);
    }
}
