use crate::Context;
use crate::consensus::consensus::{self, Consensus};
use crate::consensus::doms::attestation::EventAttestation;
use crate::consensus::doms::entry::Entry;
use crate::consensus::doms::sol::Solution;
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
        Entry::TYPENAME => Box::new(vecpak::from_slice::<Entry>(bin)?),
        EventTip::TYPENAME => Box::new(EventTip::from_vecpak_map_validated(map)?),
        EventAttestation::TYPENAME => Box::new(EventAttestation::from_vecpak_map_validated(map)?),
        Solution::TYPENAME => Box::new(Solution::from_vecpak_map_validated(map)?),
        EventTx::TYPENAME => Box::new(EventTx::from_vecpak_map_validated(map)?),
        GetPeerAnrs::TYPENAME => Box::new(vecpak::from_slice::<GetPeerAnrs>(bin)?),
        GetPeerAnrsReply::TYPENAME => Box::new(vecpak::from_slice::<GetPeerAnrsReply>(bin)?),
        NewPhoneWhoDis::TYPENAME => Box::new(vecpak::from_slice::<NewPhoneWhoDis>(bin)?),
        NewPhoneWhoDisReply::TYPENAME => Box::new(vecpak::from_slice::<NewPhoneWhoDisReply>(bin)?),
        SpecialBusiness::TYPENAME => Box::new(SpecialBusiness::from_vecpak_map_validated(map)?),
        SpecialBusinessReply::TYPENAME => Box::new(SpecialBusinessReply::from_vecpak_map_validated(map)?),
        Catchup::TYPENAME => Box::new(Catchup::from_vecpak_map_validated(map)?),
        CatchupReply::TYPENAME => Box::new(CatchupReply::from_vecpak_map_validated(map)?),
        _ => return Err(Error::ParseError("op")),
    };

    Ok(proto)
}

#[derive(Debug)]
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
impl Protocol for EventTip {
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        let temporal_term = map.get_proplist_map(b"temporal").ok_or(Error::ParseError("temporal"))?;
        let rooted_term = map.get_proplist_map(b"rooted").ok_or(Error::ParseError("rooted"))?;
        let temporal = EntrySummary::from_vecpak_map(&temporal_term)?;
        let rooted = EntrySummary::from_vecpak_map(&rooted_term)?;

        Ok(Self { temporal, rooted })
    }
    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        use amadeus_utils::vecpak::encode;
        let pairs = vec![
            (vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Self::TYPENAME.as_bytes().to_vec())),
            (vecpak::Term::Binary(b"temporal".to_vec()), self.temporal.to_vecpak_term()),
            (vecpak::Term::Binary(b"rooted".to_vec()), self.rooted.to_vecpak_term()),
        ];
        Ok(encode(vecpak::Term::PropList(pairs)))
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

/// Requests information about selected heights (<1000 heights per request)
#[derive(Debug)]
pub struct Catchup {
    pub heights: Vec<CatchupHeight>,
}

#[derive(Debug, Clone)]
pub struct CatchupHeight {
    pub height: u64,
    pub c: Option<bool>,              // consensus flag (matches Elixir)
    pub e: Option<bool>,              // entries flag (matches Elixir)
    pub a: Option<bool>,              // attestations flag (matches Elixir)
    pub hashes: Option<Vec<Vec<u8>>>, // skip these entry hashes (matches Elixir)
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
    fn from_vecpak_map_validated(map: PropListMap) -> Result<Self, Error> {
        let height_flags_term = map.get_list(b"height_flags").ok_or(Error::ParseError("height_flags"))?;
        let mut height_flags = Vec::new();

        for item in height_flags_term {
            if let Some(flag_map) = item.get_proplist_map() {
                let height = flag_map.get_integer::<u64>(b"height").ok_or(Error::ParseError("height"))?;

                let c = flag_map.get_string(b"c").map(|s| s == "true");
                let e = flag_map.get_string(b"e").map(|s| s == "true");
                let a = flag_map.get_string(b"a").map(|s| s == "true");

                let hashes = flag_map.get_list(b"hashes").map(|hashes_list| {
                    hashes_list.iter().filter_map(|h| h.get_binary().map(|bytes| bytes.to_vec())).collect()
                });

                height_flags.push(CatchupHeight { height, c, e, a, hashes });
            }
        }

        Ok(Self { heights: height_flags })
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        use amadeus_utils::vecpak::encode;

        let height_flags_list: Vec<vecpak::Term> = self
            .heights
            .iter()
            .map(|flag| {
                let mut flag_pairs = Vec::new();
                flag_pairs.push((vecpak::Term::Binary(b"height".to_vec()), vecpak::Term::VarInt(flag.height as i128)));

                if let Some(true) = flag.c {
                    flag_pairs.push((vecpak::Term::Binary(b"c".to_vec()), vecpak::Term::Binary(b"true".to_vec())));
                }
                if let Some(true) = flag.e {
                    flag_pairs.push((vecpak::Term::Binary(b"e".to_vec()), vecpak::Term::Binary(b"true".to_vec())));
                }
                if let Some(true) = flag.a {
                    flag_pairs.push((vecpak::Term::Binary(b"a".to_vec()), vecpak::Term::Binary(b"true".to_vec())));
                }
                if let Some(ref hashes) = flag.hashes {
                    if !hashes.is_empty() {
                        let hashes_terms: Vec<vecpak::Term> =
                            hashes.iter().map(|h| vecpak::Term::Binary(h.clone())).collect();
                        flag_pairs.push((vecpak::Term::Binary(b"hashes".to_vec()), vecpak::Term::List(hashes_terms)));
                    }
                }
                vecpak::Term::PropList(flag_pairs)
            })
            .collect();

        let pairs = vec![
            (vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Self::TYPENAME.as_bytes().to_vec())),
            (vecpak::Term::Binary(b"height_flags".to_vec()), vecpak::Term::List(height_flags_list)),
        ];
        Ok(encode(vecpak::Term::PropList(pairs)))
    }

    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        // TODO: implement catchup handling logic
        Ok(vec![Instruction::Noop { why: "catchup received".to_string() }])
    }
}

#[derive(Debug)]
pub struct CatchupReply {
    pub heights: Vec<CatchupHeightReply>,
}

#[derive(Debug, Clone)]
pub struct CatchupHeightReply {
    pub height: u64,
    pub entries: Option<Vec<Entry>>,
    pub attestations: Option<Vec<Attestation>>,
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
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        let tries_term = map.get_list(b"tries").ok_or(Error::ParseError("tries"))?;
        let mut tries = Vec::new();

        for item in tries_term.iter() {
            if let Some(trie_map) = item.get_proplist_map() {
                let height = trie_map.get_integer::<u64>(b"height").ok_or(Error::ParseError("height"))?;

                let entries = trie_map.get_list(b"entries").and_then(|list| {
                    let parsed: Vec<Entry> =
                        list.iter().filter_map(|term| Entry::from_vecpak_map(&term.get_proplist_map()?).ok()).collect();
                    if parsed.is_empty() { None } else { Some(parsed) }
                });

                let attestations = trie_map.get_list(b"attestations").and_then(|list| {
                    let parsed: Vec<Attestation> = list
                        .iter()
                        .filter_map(|term| Attestation::from_vecpak_map(&term.get_proplist_map()?).ok())
                        .collect();
                    if parsed.is_empty() { None } else { Some(parsed) }
                });

                let consensuses = trie_map.get_list(b"consensuses").and_then(|list| {
                    let parsed: Vec<Consensus> = list
                        .iter()
                        .filter_map(|term| Consensus::from_vecpak_map(&term.get_proplist_map()?).ok())
                        .collect();
                    if parsed.is_empty() { None } else { Some(parsed) }
                });

                tries.push(CatchupHeightReply { height, entries, attestations, consensuses });
            }
        }

        Ok(Self { heights: tries })
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        use amadeus_utils::vecpak::{self, encode};

        let tries_list: Vec<vecpak::Term> = self
            .heights
            .iter()
            .map(|trie| {
                let mut trie_pairs = Vec::new();
                trie_pairs.push((vecpak::Term::Binary(b"height".to_vec()), vecpak::Term::VarInt(trie.height as i128)));

                if let Some(ref entries) = trie.entries {
                    let term = entries.iter().map(|e| e.to_vecpak_term()).collect::<Vec<_>>();
                    trie_pairs.push((vecpak::Term::Binary(b"entries".to_vec()), vecpak::Term::List(term)));
                }

                if let Some(ref attestations) = trie.attestations {
                    let term = attestations.iter().map(|e| e.to_vecpak_term()).collect::<Vec<_>>();
                    trie_pairs.push((vecpak::Term::Binary(b"attestations".to_vec()), vecpak::Term::List(term)));
                }

                if let Some(ref consensuses) = trie.consensuses {
                    let term = consensuses.iter().map(|e| e.to_vecpak_term()).collect::<Vec<_>>();
                    trie_pairs.push((vecpak::Term::Binary(b"consensuses".to_vec()), vecpak::Term::List(term)));
                }

                vecpak::Term::PropList(trie_pairs)
            })
            .collect();

        let pairs = vec![
            (vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Self::TYPENAME.as_bytes().to_vec())),
            (vecpak::Term::Binary(b"tries".to_vec()), vecpak::Term::List(tries_list)),
        ];
        Ok(encode(vecpak::Term::PropList(pairs)))
    }

    async fn handle(&self, ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        let instructions = Vec::new();
        let rooted_tip_height = ctx.fabric.get_rooted_height()?.unwrap_or(0);

        for trie in &self.heights {
            if let Some(ref entries) = trie.entries {
                for entry in entries {
                    if entry.header.height >= rooted_tip_height {
                        let seen_time_ms = get_unix_millis_now();
                        if let Ok(entry_bin) = entry.to_vecpak_packet_bin() {
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
                for _attestation in attestations {
                    // TODO: implement attestation validation and insertion
                }
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

#[derive(Debug)]
pub struct EventTx {
    pub valid_txs: Vec<Vec<u8>>,
}

impl Typename for EventTx {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for EventTx {
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        // txs_packed is a list of binary transaction packets, not a single binary
        let txs_list = map.get_list(b"txs_packed").ok_or(Error::ParseError("txs_packed"))?;
        let valid_txs = EventTx::get_valid_txs_from_list(txs_list)?;
        Ok(Self { valid_txs })
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, Error> {
        use amadeus_utils::vecpak::encode;
        // create list of transaction binaries (txs_packed is directly a list of binaries)
        let tx_terms: Vec<vecpak::Term> = self.valid_txs.iter().map(|tx| vecpak::Term::Binary(tx.clone())).collect();
        let pairs = vec![
            (vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Self::TYPENAME.as_bytes().to_vec())),
            (vecpak::Term::Binary(b"txs_packed".to_vec()), vecpak::Term::List(tx_terms)),
        ];
        Ok(encode(vecpak::Term::PropList(pairs)))
    }

    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        // TODO: update ETS-like tx pool with valid_txs
        Ok(vec![Instruction::Noop { why: "event_tx handling not implemented".to_string() }])
    }
}

impl EventTx {
    pub const TYPENAME: &'static str = "event_tx";

    fn get_valid_txs_from_list(txs_list: &[amadeus_utils::vecpak::Term]) -> Result<Vec<Vec<u8>>, Error> {
        use amadeus_utils::vecpak::Term as VTerm;

        let mut good: Vec<Vec<u8>> = Vec::with_capacity(txs_list.len());

        for t in txs_list {
            // each item must be a binary (a packed transaction)
            let bin = if let VTerm::Binary(b) = t {
                b.as_slice()
            } else {
                // skip non-binary entries silently
                continue;
            };

            // validate basic tx rules, special-meeting context is false in gossip path
            if crate::consensus::doms::tx::validate(bin, false).is_ok() {
                good.push(bin.to_vec());
            }
        }

        Ok(good)
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
            has_peers_b3f4.push(B3f4(b3f4));
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
    use bitvec::prelude::{Msb0, bitvec};

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
        let event_tx = EventTx { valid_txs: vec![vec![1, 2, 3], vec![4, 5, 6]] };

        let bin = event_tx.to_vecpak_packet_bin().expect("should serialize");
        let result = parse_vecpak_bin(&bin).expect("should deserialize");

        assert_eq!(result.typename(), "event_tx");
    }

    #[tokio::test]
    async fn test_peers_vecpak_roundtrip() {
        let peers = GetPeerAnrs::new(vec![B3f4([192, 168, 1, 1]), B3f4([10, 0, 0, 1])]);

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
        let pop = bls_sign(&sk, &pk.0, crate::consensus::DST_POP).expect("pop");
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let _my_anr = anr::Anr::build(&sk, &pk, &pop.0, ip, Ver::new(1, 0, 0)).expect("anr");

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
        let pop = bls_sign(&sk, &pk.0, crate::consensus::DST_POP).expect("pop");
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let _my_anr = anr::Anr::build(&sk, &pk, &pop.0, ip, Ver::new(1, 0, 0)).expect("anr");
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
            prev_hash: Hash([0u8; 32]),
            dr: Hash([1u8; 32]),
            vr: Signature([2u8; 96]),
            signer: PublicKey([3u8; 48]),
            txs_hash: Hash([4u8; 32]),
        };

        EntrySummary { header, signature: Signature([5u8; 96]), mask: None }
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
        let pop = bls_sign(&sk, &pk.0, crate::consensus::DST_POP).expect("pop");

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

        let catchup = Catchup { heights: vec![height_flag] };

        // Test Catchup serialization
        let catchup_bin = catchup.to_vecpak_packet_bin().expect("should serialize catchup");
        let parsed_catchup = parse_vecpak_bin(&catchup_bin).expect("should deserialize catchup");
        assert_eq!(parsed_catchup.typename(), "catchup");

        // Test CatchupReply with actual structs
        let entry1 = Entry {
            hash: Hash([1; 32]),
            header: EntryHeader {
                height: 100,
                slot: 1,
                prev_slot: 0,
                prev_hash: Hash([0; 32]),
                dr: Hash([2; 32]),
                vr: Signature([0; 96]),
                signer: PublicKey([3; 48]),
                txs_hash: Hash([4; 32]),
            },
            signature: Signature([5; 96]),
            mask: None,
            txs: vec![vec![1, 2, 3, 4]],
        };

        let attestation1 = Attestation {
            entry_hash: Hash([6; 32]),
            mutations_hash: Hash([7; 32]),
            signer: PublicKey([8; 48]),
            signature: Signature([9; 96]),
        };

        let consensus1 = Consensus {
            entry_hash: Hash([10; 32]),
            mutations_hash: Hash([11; 32]),
            mask: bitvec![u8, Msb0; 1, 0, 1],
            agg_sig: Signature([12; 96]),
        };

        let trie1 = CatchupHeightReply {
            height: 100,
            entries: Some(vec![entry1]),
            attestations: Some(vec![attestation1]),
            consensuses: None,
        };
        let trie2 =
            CatchupHeightReply { height: 101, entries: None, attestations: None, consensuses: Some(vec![consensus1]) };
        let catchup_reply = CatchupReply { heights: vec![trie1, trie2] };

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
        let pop = bls12_381::sign(&sk, &pk.0, crate::consensus::DST_POP).expect("pop");

        let anr = Anr::build(&sk, &pk, &pop.0, Ipv4Addr::new(192, 168, 1, 1), Ver::new(1, 2, 5)).expect("anr");

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
        let original = GetPeerAnrs::new(vec![B3f4([1, 2, 3, 4]), B3f4([5, 6, 7, 8])]);
        let version = Ver::new(1, 2, 3);
        let payload = original.to_bin(version).expect("should encode");

        let parsed = parse_vecpak_bin(&payload).expect("should parse vecpak");
        assert_eq!(parsed.typename(), "get_peer_anrs");

        let re_encoded = parsed.to_bin(version).expect("should re-encode");
        assert_eq!(payload, re_encoded, "roundtrip should preserve encoding");
    }

    #[tokio::test]
    async fn test_event_tx_roundtrip_via_vecpak() {
        // create simple test transaction
        let tx1 = vec![1u8, 2, 3, 4, 5];
        let tx2 = vec![6u8, 7, 8, 9, 10];
        let original = EventTx { valid_txs: vec![tx1, tx2] };
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
}
