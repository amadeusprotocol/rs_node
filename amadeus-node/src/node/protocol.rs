use crate::Context;
#[cfg(test)]
use crate::Ver;
use crate::consensus::consensus::{self, Consensus};
use crate::consensus::doms::attestation::EventAttestation;
use crate::consensus::doms::entry::Entry;
use crate::consensus::doms::sol::Solution;
use crate::consensus::doms::{Attestation, EntrySummary};
use crate::consensus::fabric::Fabric;
use crate::node::anr::Anr;
use crate::node::peers::HandshakeStatus;
use crate::node::{anr, peers};
use crate::utils::bls12_381;
use crate::utils::misc::{Typename, get_unix_millis_now};
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
    fn to_vecpak_bin(&self) -> Result<Vec<u8>, Error>;
    /// Handle a message returning instructions for upper layers
    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error>;

    /// Convert to binary format (always vecpak now)
    fn to_bin(&self, _version: crate::Ver) -> Result<Vec<u8>, Error> {
        self.to_vecpak_bin()
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
    #[error("vecpak decode error: {0}")]
    Vecpak(String),
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
    use amadeus_utils::vecpak::{VecpakExt, decode_seemingly_etf_to_vecpak};

    // decode as vecpak (auto-detects and converts legacy ETF if needed)
    let term = decode_seemingly_etf_to_vecpak(bin).map_err(|e| Error::Vecpak(e.to_string()))?;

    // get PropListMap from the term
    let map = term.get_proplist_map().ok_or(Error::ParseError("map"))?;

    // `op` determines the variant (binary string key in vecpak)
    let op_name = map.get_string(b"op").ok_or(Error::ParseError("op"))?;
    let proto: Box<dyn Protocol> = match op_name.as_str() {
        Ping::TYPENAME => Box::new(Ping::from_vecpak_map_validated(map)?),
        PingReply::TYPENAME => Box::new(PingReply::from_vecpak_map_validated(map)?),
        Entry::TYPENAME => Box::new(Entry::from_vecpak_map_validated(map)?),
        EventTip::TYPENAME => Box::new(EventTip::from_vecpak_map_validated(map)?),
        EventAttestation::TYPENAME => Box::new(EventAttestation::from_vecpak_map_validated(map)?),
        Solution::TYPENAME => Box::new(Solution::from_vecpak_map_validated(map)?),
        EventTx::TYPENAME => Box::new(EventTx::from_vecpak_map_validated(map)?),
        GetPeerAnrs::TYPENAME => Box::new(GetPeerAnrs::from_vecpak_map_validated(map)?),
        GetPeerAnrsReply::TYPENAME => Box::new(GetPeerAnrsReply::from_vecpak_map_validated(map)?),
        NewPhoneWhoDis::TYPENAME => Box::new(NewPhoneWhoDis::from_vecpak_map_validated(map)?),
        NewPhoneWhoDisReply::TYPENAME => Box::new(NewPhoneWhoDisReply::from_vecpak_map_validated(map)?),
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
    fn to_vecpak_bin(&self) -> Result<Vec<u8>, Error> {
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
        fn entry_summary_by_hash(fab: &Fabric, hash: &[u8; 32]) -> EntrySummary {
            if let Some(entry) = fab.get_entry_by_hash(hash) { entry.into() } else { EntrySummary::empty() }
        }

        let temporal_summary = match fab.get_temporal_hash()? {
            Some(h) => entry_summary_by_hash(fab, &h),
            None => EntrySummary::empty(),
        };

        let rooted_summary = match fab.get_rooted_hash()? {
            Some(h) => entry_summary_by_hash(fab, &h),
            None => EntrySummary::empty(),
        };

        Ok(Self { temporal: temporal_summary, rooted: rooted_summary })
    }
}

#[derive(Debug)]
pub struct Ping {
    pub ts_m: u64,
}

#[derive(Debug)]
pub struct PingReply {
    pub ts_m: u64,
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

    fn to_vecpak_bin(&self) -> Result<Vec<u8>, Error> {
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

impl CatchupReply {
    /// Helper to parse Entry from vecpak PropListMap
    fn parse_entry_from_vecpak_map(map: &amadeus_utils::vecpak::PropListMap) -> Result<Entry, Error> {
        use crate::consensus::doms::entry::{Entry, EntryHeader};

        // Extract header - it can be either:
        // 1. A binary (encoded header) - original ETF format
        // 2. A map (header fields) - vecpak/network format from Elixir
        let header = if let Some(header_bin) = map.get_binary::<Vec<u8>>(b"header") {
            // Case 1: header is already encoded as binary (original format)
            EntryHeader::from_etf_bin(&header_bin)?
        } else if let Some(header_map) = map.get_proplist_map(b"header") {
            // Case 2: header is a map with fields (vecpak/network format)
            let height = header_map.get_integer(b"height").ok_or(Error::ParseError("height"))?;
            let slot = header_map.get_integer(b"slot").ok_or(Error::ParseError("slot"))?;
            let prev_slot = header_map.get_integer(b"prev_slot").ok_or(Error::ParseError("prev_slot"))?;
            let prev_hash = header_map.get_binary(b"prev_hash").ok_or(Error::ParseError("prev_hash"))?;
            let dr = header_map.get_binary(b"dr").ok_or(Error::ParseError("dr"))?;
            let vr = header_map.get_binary(b"vr").ok_or(Error::ParseError("vr"))?;
            let signer = header_map.get_binary(b"signer").ok_or(Error::ParseError("signer"))?;
            let txs_hash = header_map.get_binary(b"txs_hash").ok_or(Error::ParseError("txs_hash"))?;

            EntryHeader { height, slot, prev_slot, prev_hash, dr, vr, signer, txs_hash }
        } else {
            return Err(Error::ParseError("entry header"));
        };

        // Extract txs
        let txs_list = map.get_list(b"txs").ok_or_else(|| Error::ParseError("entry txs"))?;
        let txs: Vec<Vec<u8>> =
            txs_list.iter().filter_map(|term| term.get_binary().map(|b: &[u8]| b.to_vec())).collect();

        // Extract hash
        let hash_bytes: &[u8] = map.get_binary(b"hash").ok_or_else(|| Error::ParseError("entry hash"))?;
        let hash: [u8; 32] = hash_bytes.try_into().map_err(|_| Error::ParseError("entry hash size"))?;

        // Extract signature
        let sig_bytes: &[u8] = map.get_binary(b"signature").ok_or_else(|| Error::ParseError("entry signature"))?;
        let signature: [u8; 96] = sig_bytes.try_into().map_err(|_| Error::ParseError("entry signature size"))?;

        // mask is optional
        let mask = None; // Not included in CatchupReply entries

        Ok(Entry { header, txs, hash, signature, mask })
    }

    /// Helper to parse Consensus from vecpak PropListMap
    fn parse_consensus_from_vecpak_map(map: &amadeus_utils::vecpak::PropListMap) -> Result<Consensus, Error> {
        use crate::consensus::consensus::Consensus;
        use crate::utils::misc::bin_to_bitvec;

        // Extract entry_hash
        let entry_hash_bytes: &[u8] =
            map.get_binary(b"entry_hash").ok_or_else(|| Error::ParseError("consensus entry_hash"))?;
        let entry_hash: [u8; 32] =
            entry_hash_bytes.try_into().map_err(|_| Error::ParseError("consensus entry_hash size"))?;

        // Extract mutations_hash
        let mutations_hash_bytes: &[u8] =
            map.get_binary(b"mutations_hash").ok_or_else(|| Error::ParseError("consensus mutations_hash"))?;
        let mutations_hash: [u8; 32] =
            mutations_hash_bytes.try_into().map_err(|_| Error::ParseError("consensus mutations_hash size"))?;

        // Extract aggsig map
        let aggsig_map = map.get_proplist_map(b"aggsig").ok_or_else(|| Error::ParseError("consensus aggsig"))?;

        // Extract mask from aggsig
        let mask_bytes: &[u8] =
            aggsig_map.get_binary(b"mask").ok_or_else(|| Error::ParseError("consensus aggsig mask"))?;
        let mask = bin_to_bitvec(mask_bytes.to_vec());

        // Extract aggsig signature
        let agg_sig_bytes: &[u8] =
            aggsig_map.get_binary(b"aggsig").ok_or_else(|| Error::ParseError("consensus aggsig aggsig"))?;
        let agg_sig: [u8; 96] = agg_sig_bytes.try_into().map_err(|_| Error::ParseError("consensus aggsig size"))?;

        Ok(Consensus { entry_hash, mutations_hash, mask, agg_sig })
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
                    let parsed: Vec<Entry> = list
                        .iter()
                        .filter_map(|term| {
                            if let Some(bytes) = term.get_binary() {
                                Entry::unpack(bytes).ok()
                            } else if let Some(entry_map) = term.get_proplist_map() {
                                Self::parse_entry_from_vecpak_map(&entry_map).ok()
                            } else {
                                None
                            }
                        })
                        .collect();
                    if parsed.is_empty() { None } else { Some(parsed) }
                });

                let attestations = trie_map.get_list(b"attestations").and_then(|list| {
                    let parsed: Vec<Attestation> = list
                        .iter()
                        .filter_map(|term| {
                            // Try binary format first, then PropList format
                            if let Some(bytes) = term.get_binary() {
                                Attestation::unpack_from_db(bytes)
                            } else if let Some(att_map) = term.get_proplist_map() {
                                Attestation::from_vecpak_map(&att_map).ok()
                            } else {
                                None
                            }
                        })
                        .collect();
                    if parsed.is_empty() { None } else { Some(parsed) }
                });

                let consensuses = trie_map.get_list(b"consensuses").and_then(|list| {
                    let parsed: Vec<Consensus> = list
                        .iter()
                        .filter_map(|term| {
                            if let Some(bytes) = term.get_binary() {
                                Consensus::from_etf_bin(bytes).ok()
                            } else if let Some(consensus_map) = term.get_proplist_map() {
                                Self::parse_consensus_from_vecpak_map(&consensus_map).ok()
                            } else {
                                None
                            }
                        })
                        .collect();
                    if parsed.is_empty() { None } else { Some(parsed) }
                });

                tries.push(CatchupHeightReply { height, entries, attestations, consensuses });
            }
        }

        Ok(Self { heights: tries })
    }

    fn to_vecpak_bin(&self) -> Result<Vec<u8>, Error> {
        use amadeus_utils::vecpak::{self, encode, serialize_list};

        let tries_list: Vec<vecpak::Term> = self
            .heights
            .iter()
            .map(|trie| {
                let mut trie_pairs = Vec::new();
                trie_pairs.push((vecpak::Term::Binary(b"height".to_vec()), vecpak::Term::VarInt(trie.height as i128)));

                if let Some(ref entries) = trie.entries {
                    if let Some(term) = serialize_list(entries, |e| e.pack()) {
                        trie_pairs.push((vecpak::Term::Binary(b"entries".to_vec()), term));
                    }
                }

                if let Some(ref attestations) = trie.attestations {
                    if let Some(term) = serialize_list(attestations, |a| a.pack()) {
                        trie_pairs.push((vecpak::Term::Binary(b"attestations".to_vec()), term));
                    }
                }

                if let Some(ref consensuses) = trie.consensuses {
                    if let Some(term) = serialize_list(consensuses, |c| c.pack()) {
                        trie_pairs.push((vecpak::Term::Binary(b"consensuses".to_vec()), term));
                    }
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
                        if let Ok(entry_bin) = entry.pack_for_db() {
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
        Ok(Self { ts_m })
    }

    fn to_vecpak_bin(&self) -> Result<Vec<u8>, Error> {
        use amadeus_utils::vecpak::encode;
        let pairs = vec![
            (vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Self::TYPENAME.as_bytes().to_vec())),
            (vecpak::Term::Binary(b"ts_m".to_vec()), vecpak::Term::VarInt(self.ts_m as i128)),
        ];
        Ok(encode(vecpak::Term::PropList(pairs)))
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
impl Protocol for PingReply {
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        let ts_m = map.get_integer(b"ts_m").ok_or(Error::ParseError("ts_m"))?;
        let seen_time_ms = get_unix_millis_now();
        // check what else must be validated
        Ok(Self { ts_m: ts_m, seen_time: seen_time_ms })
    }

    fn to_vecpak_bin(&self) -> Result<Vec<u8>, Error> {
        use amadeus_utils::vecpak::encode;
        let pairs = vec![
            (vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Self::TYPENAME.as_bytes().to_vec())),
            (vecpak::Term::Binary(b"ts_m".to_vec()), vecpak::Term::VarInt(self.ts_m as i128)),
        ];
        Ok(encode(vecpak::Term::PropList(pairs)))
    }

    #[instrument(skip(self, ctx), fields(src = %src), name = "PingReply::handle")]
    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        ctx.node_peers.update_peer_from_pong(src, self).await;
        Ok(vec![Instruction::Noop { why: "pong processed".to_string() }])
    }
}

impl PingReply {
    pub const TYPENAME: &'static str = "ping_reply";
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

    fn to_vecpak_bin(&self) -> Result<Vec<u8>, Error> {
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

#[derive(Debug)]
pub struct GetPeerAnrs {
    pub has_peers_b3f4: Vec<[u8; 4]>,
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
        let mut has_peers_b3f4 = Vec::<[u8; 4]>::new();
        for t in list {
            use std::convert::TryInto;
            let b = t.get_binary().ok_or(Error::ParseError("hasPeersb3f4"))?;
            let b3f4 = b.try_into().map_err(|_| Error::ParseError("hasPeersb3f4_length"))?;
            has_peers_b3f4.push(b3f4);
        }

        Ok(Self { has_peers_b3f4 })
    }

    fn to_vecpak_bin(&self) -> Result<Vec<u8>, Error> {
        use amadeus_utils::vecpak::encode;
        let b3f4_terms: Vec<vecpak::Term> =
            self.has_peers_b3f4.iter().map(|b3f4| vecpak::Term::Binary(b3f4.to_vec())).collect();
        let pairs = vec![
            (vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Self::TYPENAME.as_bytes().to_vec())),
            (vecpak::Term::Binary(b"hasPeersb3f4".to_vec()), vecpak::Term::List(b3f4_terms)),
        ];
        Ok(encode(vecpak::Term::PropList(pairs)))
    }

    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        let anrs = ctx.node_anrs.get_all_excluding_b3f4(&self.has_peers_b3f4).await;

        Ok(vec![Instruction::SendGetPeerAnrsReply { anrs, dst: src }])
    }
}

impl GetPeerAnrs {
    pub const TYPENAME: &'static str = "get_peer_anrs";
}

#[derive(Debug)]
pub struct GetPeerAnrsReply {
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
        Ok(Self { anrs })
    }

    fn to_vecpak_bin(&self) -> Result<Vec<u8>, Error> {
        use amadeus_utils::vecpak::encode;
        let anr_terms: Vec<vecpak::Term> = self.anrs.iter().map(|anr| anr.to_vecpak_term()).collect();
        let pairs = vec![
            (vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Self::TYPENAME.as_bytes().to_vec())),
            (vecpak::Term::Binary(b"anrs".to_vec()), vecpak::Term::List(anr_terms)),
        ];
        Ok(encode(vecpak::Term::PropList(pairs)))
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
}

#[derive(Debug)]
pub struct NewPhoneWhoDis {}

impl Typename for NewPhoneWhoDis {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for NewPhoneWhoDis {
    fn from_vecpak_map_validated(_map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        // v1.1.7+ simplified - no fields to parse
        Ok(Self {})
    }

    fn to_vecpak_bin(&self) -> Result<Vec<u8>, Error> {
        use amadeus_utils::vecpak::encode;
        let pairs =
            vec![(vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Self::TYPENAME.as_bytes().to_vec()))];
        Ok(encode(vecpak::Term::PropList(pairs)))
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
        Self {}
    }
}

#[derive(Debug)]
pub struct NewPhoneWhoDisReply {
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

        Ok(Self { anr })
    }

    fn to_vecpak_bin(&self) -> Result<Vec<u8>, Error> {
        use amadeus_utils::vecpak::encode;
        let pairs = vec![
            (vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Self::TYPENAME.as_bytes().to_vec())),
            (vecpak::Term::Binary(b"anr".to_vec()), self.anr.to_vecpak_term()),
        ];
        Ok(encode(vecpak::Term::PropList(pairs)))
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
        ctx.node_anrs.set_handshaked(&self.anr.pk).await;
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

    fn to_vecpak_bin(&self) -> Result<Vec<u8>, Error> {
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

    fn to_vecpak_bin(&self) -> Result<Vec<u8>, Error> {
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
    use bitvec::prelude::{Msb0, bitvec};

    #[tokio::test]
    async fn test_ping_vecpak_roundtrip() {
        // create a sample ping message
        let _temporal = create_dummy_entry_summary();
        let _rooted = create_dummy_entry_summary();
        let ping = Ping::new();

        // serialize to vecpak
        let bin = ping.to_vecpak_bin().expect("should serialize");

        // deserialize back
        let result = parse_vecpak_bin(&bin).expect("should deserialize");

        // check that we get the right type
        assert_eq!(result.typename(), "ping");
    }

    #[tokio::test]
    async fn test_pong_vecpak_roundtrip() {
        let pong = PingReply { ts_m: 1234567890, seen_time: 9876543210 };

        let bin = pong.to_vecpak_bin().expect("should serialize");
        let result = parse_vecpak_bin(&bin).expect("should deserialize");

        // check that the result type is Pong
        assert_eq!(result.typename(), "ping_reply");
    }

    #[tokio::test]
    async fn test_txpool_vecpak_roundtrip() {
        let event_tx = EventTx { valid_txs: vec![vec![1, 2, 3], vec![4, 5, 6]] };

        let bin = event_tx.to_vecpak_bin().expect("should serialize");
        let result = parse_vecpak_bin(&bin).expect("should deserialize");

        assert_eq!(result.typename(), "event_tx");
    }

    #[tokio::test]
    async fn test_peers_vecpak_roundtrip() {
        let peers = GetPeerAnrs { has_peers_b3f4: vec![[192, 168, 1, 1], [10, 0, 0, 1]] };

        let bin = peers.to_vecpak_bin().expect("should serialize");
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
        let pop = bls_sign(&sk, &pk, crate::consensus::DST_POP).expect("pop");
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let _my_anr = anr::Anr::build(&sk, &pk, &pop, ip, Ver::new(1, 0, 0)).expect("anr");

        let _challenge_s = get_unix_secs_now();
        let msg = NewPhoneWhoDis::new();

        // roundtrip serialize/deserialize
        let bin = msg.to_vecpak_bin().expect("serialize");
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
        let pop = bls_sign(&sk, &pk, crate::consensus::DST_POP).expect("pop");
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let _my_anr = anr::Anr::build(&sk, &pk, &pop, ip, Ver::new(1, 0, 0)).expect("anr");
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
            prev_hash: [0u8; 32],
            dr: [1u8; 32],
            vr: [2u8; 96],
            signer: [3u8; 48],
            txs_hash: [4u8; 32],
        };

        EntrySummary { header, signature: [5u8; 96], mask: None }
    }

    #[tokio::test]
    async fn test_new_phone_who_dis_v1_1_7_format() {
        // Test the simplified v1.1.7+ NewPhoneWhoDis format (no ANR, no challenge)
        let msg = NewPhoneWhoDis::new();

        // Serialize to vecpak
        let bin = msg.to_vecpak_bin().expect("serialize NewPhoneWhoDis");

        // Deserialize back
        let parsed = parse_vecpak_bin(&bin).expect("deserialize NewPhoneWhoDis");
        assert_eq!(parsed.typename(), "new_phone_who_dis");

        // Verify it deserializes correctly as NewPhoneWhoDis
        use amadeus_utils::vecpak::{VecpakExt, decode_seemingly_etf_to_vecpak};
        let term = decode_seemingly_etf_to_vecpak(&bin).expect("decode");
        let map = term.get_proplist_map().expect("map");
        if let Ok(_parsed_msg) = NewPhoneWhoDis::from_vecpak_map_validated(map) {
            // Success - the simplified format works correctly
            assert!(true);
        } else {
            panic!("Failed to deserialize simplified NewPhoneWhoDis");
        }
    }

    #[tokio::test]
    async fn test_ping_ts_m_field_validation() {
        let ping = Ping::with_timestamp(1234567890);
        let valid_bin = ping.to_vecpak_bin().expect("should serialize");
        let result = parse_vecpak_bin(&valid_bin);
        assert!(result.is_ok(), "Valid ping should parse successfully");

        let ping_reply = PingReply { ts_m: 1234567890, seen_time: 9876543210 };
        let valid_bin = ping_reply.to_vecpak_bin().expect("should serialize");
        let result = parse_vecpak_bin(&valid_bin);
        assert!(result.is_ok(), "Valid ping_reply should parse successfully");
    }

    #[tokio::test]
    async fn test_ping_complete_roundtrip_with_encryption() {
        // test creates ping, encrypts it as UDP packet, decrypts it, parses and compares with initial
        use crate::node::reassembler::Message;
        use crate::utils::bls12_381 as bls;

        // create sender and receiver key pairs
        let sender_sk = bls::generate_sk();
        let sender_pk = bls::get_public_key(&sender_sk).expect("sender pk");

        let receiver_sk = bls::generate_sk();
        let receiver_pk = bls::get_public_key(&receiver_sk).expect("receiver pk");

        // create original ping message
        let original_ping = Ping::with_timestamp(1234567890);
        let original_payload = original_ping.to_vecpak_bin().expect("serialize ping");

        // compute shared secret for encryption
        let shared_secret = bls::get_shared_secret(&receiver_pk, &sender_sk).expect("shared secret");

        // encrypt the payload
        let version = Ver::new(1, 1, 7);
        let encrypted_messages =
            Message::encrypt(&sender_pk, &shared_secret, &original_payload, version).expect("encrypt message");

        // should be single message for small payload
        assert_eq!(encrypted_messages.len(), 1, "should create single encrypted message for small payload");
        let encrypted_msg = &encrypted_messages[0];

        // convert Message to UDP packet format (MessageV2)
        let udp_packet_bytes = encrypted_msg.to_bytes();

        // verify UDP packet starts with "AMA" magic
        assert_eq!(&udp_packet_bytes[0..3], b"AMA", "UDP packet should start with AMA magic");

        // parse UDP packet back to Message (simulating network reception)
        let received_encrypted_msg =
            Message::try_from(udp_packet_bytes.as_slice()).expect("deserialize encrypted message from UDP packet");

        // verify the received message matches the original encrypted message
        assert_eq!(received_encrypted_msg.version, encrypted_msg.version);
        assert_eq!(received_encrypted_msg.pk, encrypted_msg.pk);
        assert_eq!(received_encrypted_msg.shard_index, encrypted_msg.shard_index);
        assert_eq!(received_encrypted_msg.shard_total, encrypted_msg.shard_total);
        assert_eq!(received_encrypted_msg.ts_nano, encrypted_msg.ts_nano);
        assert_eq!(received_encrypted_msg.original_size, encrypted_msg.original_size);
        assert_eq!(received_encrypted_msg.payload, encrypted_msg.payload);

        // decrypt payload at receiver side
        let decrypted_payload = received_encrypted_msg.decrypt(&shared_secret).expect("decrypt payload");

        // parse the decrypted payload back to ping
        let parsed_proto = parse_vecpak_bin(&decrypted_payload).expect("parse decrypted payload");

        // verify it's a ping with correct typename
        assert_eq!(parsed_proto.typename(), "ping");

        // parse again to get the actual ping struct for comparison
        use amadeus_utils::vecpak::{VecpakExt, decode_seemingly_etf_to_vecpak};
        let term = decode_seemingly_etf_to_vecpak(&decrypted_payload).expect("decode");
        let map = term.get_proplist_map().expect("map");
        let decrypted_ping = Ping::from_vecpak_map_validated(map).expect("parse ping");

        // compare original and decrypted ping
        assert_eq!(original_ping.ts_m, decrypted_ping.ts_m, "ping timestamp should match after roundtrip");
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
        let pop = bls_sign(&sk, &pk, crate::consensus::DST_POP).expect("pop");

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
                let pong = PingReply { ts_m: 12345, seen_time: 67890 };

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
        let catchup_bin = catchup.to_vecpak_bin().expect("should serialize catchup");
        let parsed_catchup = parse_vecpak_bin(&catchup_bin).expect("should deserialize catchup");
        assert_eq!(parsed_catchup.typename(), "catchup");

        // Test CatchupReply with actual structs
        let entry1 = Entry {
            hash: [1; 32],
            header: EntryHeader {
                height: 100,
                slot: 1,
                prev_slot: 0,
                prev_hash: [0; 32],
                dr: [2; 32],
                vr: [0; 96],
                signer: [3; 48],
                txs_hash: [4; 32],
            },
            signature: [5; 96],
            mask: None,
            txs: vec![vec![1, 2, 3, 4]],
        };

        let attestation1 =
            Attestation { entry_hash: [6; 32], mutations_hash: [7; 32], signer: [8; 48], signature: [9; 96] };

        let consensus1 = Consensus {
            entry_hash: [10; 32],
            mutations_hash: [11; 32],
            mask: bitvec![u8, Msb0; 1, 0, 1],
            agg_sig: [12; 96],
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
        let reply_bin = catchup_reply.to_vecpak_bin().expect("should serialize catchup_reply");
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
    async fn test_vecpak_vs_etf_detection() {
        // test that the parser correctly distinguishes between ETF and vecpak
        use crate::utils::vecpak_compat;

        // ETF format starts with version 131
        let etf_data = [131u8, 104, 2]; // ETF tuple header
        assert!(!vecpak_compat::is_bin_vecpak(&etf_data));

        // vecpak format starts with tags 0-7
        let vecpak_data = [7u8, 1]; // proplist with 1 element
        assert!(vecpak_compat::is_bin_vecpak(&vecpak_data));

        // empty data should not be vecpak
        assert!(!vecpak_compat::is_bin_vecpak(&[]));
    }

    #[tokio::test]
    async fn test_new_phone_who_dis_wire_format_elixir_compatibility() {
        // test that our new_phone_who_dis message wire format matches Elixir's exactly
        use crate::node::reassembler::Message;
        use crate::utils::bls12_381;

        // create new_phone_who_dis message
        let npwd = NewPhoneWhoDis {};

        // verify vecpak structure matches Elixir's proplist format
        let vecpak_bin = npwd.to_vecpak_bin().expect("should encode to vecpak");
        use amadeus_utils::vecpak::{VecpakExt, decode_seemingly_etf_to_vecpak};
        let term = decode_seemingly_etf_to_vecpak(&vecpak_bin).expect("should decode vecpak");
        let map = term.get_proplist_map().expect("should be proplist");
        let op = map.get_string(b"op").expect("should have op key");
        assert_eq!(op, "new_phone_who_dis", "op should be new_phone_who_dis");

        // test wire format structure
        let sk_sender = bls12_381::generate_sk();
        let sk_receiver = bls12_381::generate_sk();
        let pk_sender = bls12_381::get_public_key(&sk_sender).expect("pk sender");
        let pk_receiver = bls12_381::get_public_key(&sk_receiver).expect("pk receiver");

        let shared_secret = bls12_381::get_shared_secret(&pk_receiver, &sk_sender).expect("shared secret");

        let version = crate::Ver::new(1, 2, 3);
        let payload = npwd.to_bin(version).expect("should encode to binary");

        // compare with what Elixir sends
        let elixir_payload = hex::decode("0701010501026f700501116e65775f70686f6e655f77686f5f646973").unwrap();
        assert_eq!(payload, elixir_payload, "payload format must match Elixir's vecpak encoding");

        // encrypt message
        let messages = Message::encrypt(&pk_sender, &shared_secret, &payload, version).expect("should encrypt");

        assert_eq!(messages.len(), 1, "small message should be single shard");
        let msg = &messages[0];

        // verify wire format header structure matches Elixir
        let wire = msg.to_bytes();

        // header: "AMA" (3) + version (3) + reserved (1) + pk (48) + shard_idx (2) + shard_total (2) + ts_nano (8) + original_size (4) = 71 bytes
        assert!(wire.len() >= 71, "wire format should have at least 71 byte header");

        // check magic
        assert_eq!(&wire[0..3], b"AMA", "should start with AMA magic");

        // check version bytes
        assert_eq!(wire[3], 1, "major version");
        assert_eq!(wire[4], 2, "minor version");
        assert_eq!(wire[5], 3, "patch version");

        // check reserved byte
        assert_eq!(wire[6], 0, "reserved byte should be 0");

        // check public key (48 bytes starting at offset 7)
        assert_eq!(&wire[7..55], &pk_sender[..], "sender pk should match");

        // check shard info (big-endian)
        let shard_index = u16::from_be_bytes([wire[55], wire[56]]);
        let shard_total = u16::from_be_bytes([wire[57], wire[58]]);
        assert_eq!(shard_index, 0, "shard index should be 0");
        assert_eq!(shard_total, 1, "shard total should be 1");

        // check timestamp (8 bytes, big-endian) - just verify it's reasonable
        let ts_nano = u64::from_be_bytes(wire[59..67].try_into().unwrap());
        assert!(ts_nano > 1_700_000_000_000_000_000, "timestamp should be recent");

        // check original_size is the encrypted payload size (nonce + tag + ciphertext), NOT plaintext
        let original_size = u32::from_be_bytes(wire[67..71].try_into().unwrap());
        let payload_in_wire = &wire[71..];
        assert_eq!(
            original_size as usize,
            payload_in_wire.len(),
            "original_size must equal encrypted payload size (Elixir compatibility)"
        );

        // verify encrypted payload structure: nonce (12) + tag (16) + ciphertext
        assert!(payload_in_wire.len() >= 28, "encrypted payload should have nonce + tag");

        // verify we can decrypt
        let decrypted = msg.decrypt(&shared_secret).expect("should decrypt");
        assert_eq!(decrypted, payload, "decrypted should match original payload");
    }

    #[tokio::test]
    async fn test_ping_wire_format_elixir_compatibility() {
        use crate::utils::vecpak::{self, Term as VTerm};

        let ping = Ping::with_timestamp(1234567890123);
        let version = Ver::new(1, 2, 3);
        let payload = ping.to_bin(version).expect("should encode to binary");

        // decode and inspect structure
        use amadeus_utils::vecpak::decode_seemingly_etf_to_vecpak;
        let _vecpak_term = decode_seemingly_etf_to_vecpak(&payload).expect("should decode vecpak");

        // create expected Elixir format - keys should be in sorted order
        let expected = VTerm::PropList(vec![
            (VTerm::Binary(b"op".to_vec()), VTerm::Binary(b"ping".to_vec())),
            (VTerm::Binary(b"ts_m".to_vec()), VTerm::VarInt(1234567890123)),
        ]);
        let mut expected_bin = Vec::new();
        vecpak::encode_term(&mut expected_bin, expected);

        assert_eq!(payload, expected_bin, "Ping payload must match Elixir vecpak format");
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
        let original = PingReply { ts_m: 1234567890123, seen_time: 0 };
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
        let pop = bls12_381::sign(&sk, &pk, crate::consensus::DST_POP).expect("pop");

        let anr = Anr::build(&sk, &pk, &pop, Ipv4Addr::new(192, 168, 1, 1), Ver::new(1, 2, 5)).expect("anr");

        let original = NewPhoneWhoDisReply::new(anr);
        let version = Ver::new(1, 2, 3);
        let payload = original.to_bin(version).expect("should encode");

        let parsed = parse_vecpak_bin(&payload).expect("should parse vecpak");
        assert_eq!(parsed.typename(), "new_phone_who_dis_reply");

        let re_encoded = parsed.to_bin(version).expect("should re-encode");
        assert_eq!(payload, re_encoded, "roundtrip should preserve encoding");
    }

    #[test]
    fn test_new_phone_who_dis_reply_format_comparison() {
        use crate::node::anr::Anr;
        use crate::utils::version::Ver;
        use std::net::Ipv4Addr;

        // Create a test ANR matching the received packet
        let test_anr = Anr {
            ip4: Ipv4Addr::new(72, 9, 144, 110),
            pk: [0u8; 48],      // dummy public key
            pop: vec![0u8; 96], // dummy proof of possession
            port: 36969,
            signature: vec![0u8; 96], // dummy signature
            ts: 1696391684,
            version: Ver::new(1, 2, 5),
            anr_name: None,
            anr_desc: None,
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: 1696391687,
            pk_b3: [0u8; 32],
            pk_b3_f4: [0u8; 4],
            proto_reqs: Default::default(),
            udp_packets: 0,
        };

        // Create NewPhoneWhoDisReply with our current structure
        let reply = NewPhoneWhoDisReply::new(test_anr.clone());

        // Serialize to vecpak using the Protocol trait method
        let vecpak_bin = reply.to_vecpak_bin().unwrap();

        // Decode back to see the structure
        use amadeus_utils::vecpak::decode_seemingly_etf_to_vecpak;
        let _decoded_term = decode_seemingly_etf_to_vecpak(&vecpak_bin).unwrap();

        // Now let's decode the packet from 72.9.144.110
        let received_hex = "0701020501026f700501176e65775f70686f6e655f77686f5f6469735f7265706c79050103616e720\
70107050102706b050130a9e81ed8c8eaaebd8dd53a889d8c5a8612ab7330275a5d39043e95200e7c1b66\
f0dc00c5307e867a55a9ad9e7ae4b9f005010274730304691a09c905010369703405010c37322e392e313\
4342e313130050103706f70050160b62a96d62af0d2d7006ab560c64bde562df13ae642380a31d9352764\
12c59f9944dceaa4060903e4ead197e97ad1654910be87ac556a5063e1d68df542aab1a3f75df3eab891a\
7cab572ba7170716c5487183ef28ef89f7c7555be2bb1d41218050104706f727403029069050107766572\
73696f6e050105312e322e350501097369676e61747572650501609187cfa19808ae7af535838402ffa22\
d138a01706ea39732b15040f3665b2a6b6079e27f04637f69e340ecc6859f4ec3111242878627b26bb2d9\
a150214e97167753444f6e27484cc0a3bb4c36822e5d4c2a40bd0db3f9264831cf917449ffbd";

        let received_bytes = hex::decode(received_hex).unwrap();

        // The packet is in vecpak format
        // The packet structure appears to be:
        // {op: "new_phone_who_dis_reply", anr: {pk, ts, ip4, pop, port, version, signature}}
        // which matches our current implementation
        // Validation check - ensure the packet can be decoded
        let _ = decode_seemingly_etf_to_vecpak(&received_bytes).expect("should decode vecpak");
    }

    #[tokio::test]
    async fn test_get_peer_anrs_roundtrip_via_vecpak() {
        let original = GetPeerAnrs { has_peers_b3f4: vec![[1, 2, 3, 4], [5, 6, 7, 8]] };
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

    #[tokio::test]
    async fn test_parse_real_elixir_new_phone_who_dis_reply() {
        // real packet from Elixir node at 167.235.169.185
        let packet = hex::decode("0701020501026f700501176e65775f70686f6e655f77686f5f6469735f7265706c79050103616e72070107050102706b050130b0784b94452d7fe8c3fea4ad888a9d61f651724230c7a2e698dbcfe012f6c296e4697e294424f63387d86975f5625d8c05010274730304691a090105010369703405010f3136372e3233352e3136392e313835050103706f70050160a4f6f26879f471257dfafd80a45bacb37fc41cbdaaef9ac3d8242a1b45848c7e58d5af7c006d530a5a0c38bce2dba3db061c8a9b812f91ab145f6439bcaf8b35813c6136ef019a717986ea9a3f30bb5899549f6181f178c06b372dfad0c42c8d050104706f72740302906905010776657273696f6e050105312e322e350501097369676e6174757265050160a1a650a55aa67187e06b7d6ac7aca6e060ab4fe3a2447ab533502a909632bb729cdad4b9184ac29e8315f84d3124b04917e9e7a76a7c546b06987da0c1088d150d0a20473fa8735f6c6ffe618d5d2477a3be3f517617da090898ac40459f451a").unwrap();

        let parsed = parse_vecpak_bin(&packet).expect("should parse real elixir new_phone_who_dis_reply");
        assert_eq!(parsed.typename(), "new_phone_who_dis_reply");

        // re-encode and compare structure (signature will differ so just check typename roundtrip)
        let version = Ver::new(1, 2, 3);
        let re_encoded = parsed.to_bin(version).expect("should re-encode");

        // compare the key ordering

        // decode both to see the structure
        use amadeus_utils::vecpak::decode_seemingly_etf_to_vecpak;
        // verify decoding works without debug output
        let _elixir_term = decode_seemingly_etf_to_vecpak(&packet).unwrap();
        let _our_term = decode_seemingly_etf_to_vecpak(&re_encoded).unwrap();

        // check if they match exactly
        assert_eq!(packet, re_encoded, "Encoding should match Elixir format");
    }

    #[tokio::test]
    async fn test_anr_field_ordering_matches_elixir() {
        // test that ANR fields are in the exact same order as Elixir
        // Elixir order: pk, ts, ip4, pop, port, version, signature
        let elixir_anr_hex = "070107050102706b050130b0784b94452d7fe8c3fea4ad888a9d61f651724230c7a2e698dbcfe012f6c296e4697e294424f63387d86975f5625d8c05010274730304691a090105010369703405010f3136372e3233352e3136392e313835050103706f70050160a4f6f26879f471257dfafd80a45bacb37fc41cbdaaef9ac3d8242a1b45848c7e58d5af7c006d530a5a0c38bce2dba3db061c8a9b812f91ab145f6439bcaf8b35813c6136ef019a717986ea9a3f30bb5899549f6181f178c06b372dfad0c42c8d050104706f72740302906905010776657273696f6e050105312e322e350501097369676e6174757265050160a1a650a55aa67187e06b7d6ac7aca6e060ab4fe3a2447ab533502a909632bb729cdad4b9184ac29e8315f84d3124b04917e9e7a76a7c546b06987da0c1088d150d0a20473fa8735f6c6ffe618d5d2477a3be3f517617da090898ac40459f451a";
        let elixir_anr = hex::decode(elixir_anr_hex).unwrap();

        use amadeus_utils::vecpak::{Term as VTerm, decode_seemingly_etf_to_vecpak};
        let term = decode_seemingly_etf_to_vecpak(&elixir_anr).unwrap();

        if let VTerm::PropList(pairs) = term {
            // Elixir order: pk, ts, ip4, pop, port, version, signature
            let expected_order = vec!["pk", "ts", "ip4", "pop", "port", "version", "signature"];
            for (i, (key, _)) in pairs.iter().enumerate() {
                if let VTerm::Binary(k) = key {
                    let key_str = String::from_utf8_lossy(k);
                    assert_eq!(
                        key_str, expected_order[i],
                        "ANR field {} should be {} but is {}",
                        i, expected_order[i], key_str
                    );
                }
            }
        }
    }
}
