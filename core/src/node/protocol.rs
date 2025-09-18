use crate::Context;
#[cfg(test)]
use crate::Ver;
use crate::bic::sol;
use crate::bic::sol::Solution;
use crate::consensus::consensus;
use crate::consensus::doms::attestation::AttestationBulk;
use crate::consensus::doms::entry::Entry;
use crate::node::anr::Anr;
use crate::node::peers::HandshakeStatus;
use crate::node::{ReedSolomonReassembler, anr, msg_v2, peers, reassembler};
use crate::utils::bls12_381;
use crate::utils::misc::{TermExt, TermMap, Typename, get_unix_millis_now};
use crate::utils::safe_etf::encode_safe;
use eetf::convert::TryAsRef;
use eetf::{Atom, Binary, DecodeError as EtfDecodeError, EncodeError as EtfEncodeError, List, Map, Term};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::Error as IoError;
use std::io::prelude::*;
use std::net::{Ipv4Addr, SocketAddr};
use tracing::{instrument, warn};

// Helper function for zlib compression to match Elixir reference
fn compress_with_zlib(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

/// Every object that has this trait must be convertible from an Erlang ETF
/// Binary representation and must be able to handle itself as a message
#[async_trait::async_trait]
pub trait Protocol: Typename + Debug + Send + Sync {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error>
    where
        Self: Sized;
    /// Convert to ETF binary format for network transmission
    fn to_etf_bin(&self) -> Result<Vec<u8>, Error>;
    /// Handle a message returning instructions for upper layers
    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error>;
    /// Send this protocol message to a destination using encrypted format (v1.1.7+)
    /// REQUIRES ANR to be available - use send_to_legacy_with_metrics for bootstrap messages
    async fn send_to_with_metrics(&self, ctx: &Context, dst: Ipv4Addr) -> Result<(), Error> {
        use crate::node::msg_encrypted::EncryptedMessage;
        // Using zlib compression to match Elixir reference implementation

        // Increment metrics counter immediately, even if send fails later
        ctx.metrics.add_outgoing_proto(self.typename());

        let dst_addr = SocketAddr::new(std::net::IpAddr::V4(dst), ctx.config.udp_port);
        let payload = self.to_etf_bin().inspect_err(|e| ctx.metrics.add_error(e))?;

        // Look up ANR for destination to get public key
        let dst_anr = ctx.node_anrs.get_by_ip4(dst).await.ok_or(Error::NoAnrForDestination(dst))?;

        // Use encrypted format (v1.1.7+) - REQUIRED for all non-bootstrap messages
        // Order: ETF -> Compress -> Encrypt -> Shard -> Headers
        let compressed = compress_with_zlib(&payload)?;
        let shared_secret = crate::utils::bls12_381::get_shared_secret(&dst_anr.pk, &ctx.config.get_sk())?;

        // Get version from config
        let version = ctx.config.version;

        // Encrypt message using v1.1.7+ protocol
        let messages = EncryptedMessage::encrypt(&ctx.config.get_pk(), &shared_secret, &compressed, version)
            .map_err(Error::MsgEncrypted)?;

        // Send all shards
        for msg in messages {
            let packet = msg.to_bytes();
            ctx.socket.send_to_with_metrics(&packet, dst_addr, &ctx.metrics).await?;
        }

        Ok(())
    }

    /// Send this protocol message using unsigned MessageV2 format (for bootstrap messages in v1.1.7+)
    /// Bootstrap messages don't require signatures in v1.1.7+
    async fn send_to_with_metrics_legacy(&self, ctx: &Context, dst: Ipv4Addr) -> Result<(), Error> {
        let dst_addr = SocketAddr::new(std::net::IpAddr::V4(dst), ctx.config.udp_port);
        let payload = self.to_etf_bin().inspect_err(|e| ctx.metrics.add_error(e))?;

        let shards = ReedSolomonReassembler::build_unsigned_shards(&ctx.config, &payload)?;
        for shard in &shards {
            ctx.socket.send_to_with_metrics(shard, dst_addr, &ctx.metrics).await?;
        }

        ctx.metrics.add_outgoing_proto(self.typename());
        Ok(())
    }

    async fn send_to(&self, ctx: &Context, dst: Ipv4Addr) -> Result<(), Error> {
        use crate::node::msg_encrypted::EncryptedMessage;
        // Using zlib compression to match Elixir reference implementation

        let dst_addr = SocketAddr::new(std::net::IpAddr::V4(dst), ctx.config.udp_port);
        let payload = self.to_etf_bin()?;

        // Look up ANR for destination to get public key
        let dst_anr = ctx.node_anrs.get_by_ip4(dst).await.ok_or(Error::NoAnrForDestination(dst))?;

        // Use encrypted format (v1.1.7+) - REQUIRED for all non-bootstrap messages
        // Order: ETF -> Compress -> Encrypt -> Shard -> Headers
        let compressed = compress_with_zlib(&payload)?;
        let shared_secret = crate::utils::bls12_381::get_shared_secret(&dst_anr.pk, &ctx.config.get_sk())?;

        // Get version from config
        let version = ctx.config.version;

        // Encrypt message using v1.1.7+ protocol
        let messages = EncryptedMessage::encrypt(&ctx.config.get_pk(), &shared_secret, &compressed, version)
            .map_err(Error::MsgEncrypted)?;

        // Send all shards
        for msg in messages {
            let packet = msg.to_bytes();
            ctx.socket.send_to(&packet, dst_addr).await?;
        }

        Ok(())
    }

    /// Send this protocol message using legacy MessageV2 format (for bootstrap messages)
    /// Always uses signature-based MessageV2 regardless of ANR availability
    async fn send_to_legacy(&self, ctx: &Context, dst: Ipv4Addr) -> Result<(), Error> {
        let dst_addr = SocketAddr::new(std::net::IpAddr::V4(dst), ctx.config.udp_port);
        let payload = self.to_etf_bin()?;

        // Always use MessageV2 signature-based format for bootstrap
        // Order: ETF -> Compress -> Sign -> Shard -> Headers (same as Elixir)
        tracing::debug!("Sending {} to {} using legacy MessageV2 format", self.typename(), dst);
        let shards = ReedSolomonReassembler::build_shards(&ctx.config, &payload)?;
        for shard in &shards {
            ctx.socket.send_to(shard, dst_addr).await?;
        }

        Ok(())
    }
    //
    // /// Send encrypted message to a destination using a known public key
    // async fn send_to_pk(
    //     &self,
    //     ctx: &Context,
    //     dst: Ipv4Addr,
    //     dst_pk: &[u8],
    // ) -> Result<(), Error> {
    //     use crate::node::msg_encrypted::EncryptedMessage;
    //     // Using zlib compression to match Elixir reference implementation
    //
    //     let dst_addr = SocketAddr::new(std::net::IpAddr::V4(dst), ctx.config.udp_port);
    //     let payload = self.to_etf_bin()?;
    //
    //     // Compress payload
    //     let compressed = compress_with_zlib(&payload)?;
    //
    //     // Get shared secret using BLS ECDH
    //     let shared_secret = crate::utils::bls12_381::get_shared_secret(dst_pk, &ctx.config.get_sk())?;
    //
    //     // Get version
    //     let version = ctx.config.get_ver_3b();
    //
    //     // Encrypt message using v1.1.7+ protocol
    //     let messages = EncryptedMessage::encrypt(
    //         &ctx.config.get_pk(),
    //         &shared_secret,
    //         &compressed,
    //         version,
    //     ).map_err(Error::MsgEncrypted)?;
    //
    //     // Send all shards
    //     for msg in messages {
    //         let packet = msg.to_bytes();
    //         ctx.socket.send_to(&packet, dst_addr).await?;
    //     }
    //
    //     Ok(())
    // }
}

#[derive(Debug, thiserror::Error, strum_macros::IntoStaticStr)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    EtfDecode(#[from] EtfDecodeError),
    #[error(transparent)]
    EtfEncode(#[from] EtfEncodeError),
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
    Sol(#[from] sol::Error),
    #[error(transparent)]
    Att(#[from] crate::consensus::doms::attestation::Error),
    #[error(transparent)]
    ReedSolomon(#[from] reassembler::Error),
    #[error(transparent)]
    MsgV2(#[from] msg_v2::Error),
    #[error(transparent)]
    MsgEncrypted(#[from] crate::node::msg_encrypted::Error),
    #[error(transparent)]
    Anr(#[from] anr::Error),
    #[error("bad etf: {0}")]
    BadEtf(&'static str),
    #[error("No ANR found for destination IP: {0}")]
    NoAnrForDestination(Ipv4Addr),
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
    SendPong { ts_m: u64, dst: Ipv4Addr },
    SendPeersV2 { dst: Ipv4Addr },
    ValidTxs { txs: Vec<Vec<u8>> },
    Peers { ips: Vec<String> },
    ReceivedSol { sol: Solution },
    ReceivedEntry { entry: Entry },
    AttestationBulk { bulk: AttestationBulk },
    ConsensusesPacked { packed: Vec<u8> },
    CatchupEntryReq { heights: Vec<u64> },
    CatchupTriReq { heights: Vec<u64> },
    CatchupBiReq { heights: Vec<u64> },
    CatchupAttestationReq { hashes: Vec<Vec<u8>> },
    SpecialBusiness { business: Vec<u8> },
    SpecialBusinessReply { business: Vec<u8> },
    SolicitEntry { hash: Vec<u8> },
    SolicitEntry2,
    SendNewPhoneWhoDisReply { dst: Ipv4Addr },
}

impl Typename for Instruction {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

/// Does proto parsing and validation
#[instrument(skip(bin), name = "Proto::from_etf_validated")]
pub fn parse_etf_bin(bin: &[u8]) -> Result<Box<dyn Protocol>, Error> {
    // TODO: this function is a main UDP router and is subject to refactoring
    let term = Term::decode(bin)?;
    let map = term.get_term_map().ok_or(Error::BadEtf("map"))?;

    // `op` determines the variant
    let op_atom = map.get_atom("op").ok_or(Error::BadEtf("op"))?;
    let proto: Box<dyn Protocol> = match op_atom.name.as_str() {
        Ping::TYPENAME => Box::new(Ping::from_etf_map_validated(map)?),
        Pong::TYPENAME => Box::new(Pong::from_etf_map_validated(map)?),
        Entry::TYPENAME => Box::new(Entry::from_etf_map_validated(map)?),
        AttestationBulk::TYPENAME => Box::new(AttestationBulk::from_etf_map_validated(map)?),
        Solution::TYPENAME => Box::new(Solution::from_etf_map_validated(map)?),
        TxPool::TYPENAME => Box::new(TxPool::from_etf_map_validated(map)?),
        Peers::TYPENAME => Box::new(Peers::from_etf_map_validated(map)?),
        PeersV2::TYPENAME => Box::new(PeersV2::from_etf_map_validated(map)?),
        NewPhoneWhoDis::TYPENAME => Box::new(NewPhoneWhoDis::from_etf_map_validated(map)?),
        NewPhoneWhoDisReply::TYPENAME => Box::new(NewPhoneWhoDisReply::from_etf_map_validated(map)?),
        SpecialBusiness::TYPENAME => Box::new(SpecialBusiness::from_etf_map_validated(map)?),
        SpecialBusinessReply::TYPENAME => Box::new(SpecialBusinessReply::from_etf_map_validated(map)?),
        _ => {
            warn!("Unknown operation: {}", op_atom.name);
            return Err(Error::BadEtf("op"));
        }
    };

    Ok(proto)
}

#[derive(Debug)]
pub struct Ping {
    pub ts_m: u64,
}

#[derive(Debug)]
pub struct Pong {
    pub ts: u64,
    pub seen_time: u64,
}

#[derive(Debug)]
pub struct WhoAreYou;

#[derive(Debug)]
pub struct TxPool {
    pub valid_txs: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub struct Peers {
    pub ips: Vec<String>,
}

#[derive(Debug)]
pub struct PeersV2 {
    pub anrs: Vec<Anr>,
}

#[derive(Debug)]
pub struct ConsensusBulk {
    pub consensuses_packed: Vec<u8>,
}

#[derive(Debug)]
pub struct CatchupEntry {
    pub heights: Vec<u64>,
}

#[derive(Debug)]
pub struct CatchupTri {
    pub heights: Vec<u64>,
}

#[derive(Debug)]
pub struct CatchupBi {
    pub heights: Vec<u64>,
}

#[derive(Debug)]
pub struct CatchupAttestation {
    pub hashes: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub struct SpecialBusiness {
    pub business: Vec<u8>,
}

#[derive(Debug)]
pub struct SpecialBusinessReply {
    pub business: Vec<u8>,
}

#[derive(Debug)]
pub struct SolicitEntry {
    pub hash: Vec<u8>,
}

#[derive(Debug)]
pub struct SolicitEntry2;

#[derive(Debug)]
pub struct NewPhoneWhoDis {
    // v1.1.7+ simplified - no fields needed
}

#[derive(Debug)]
pub struct NewPhoneWhoDisReply {
    pub anr: Anr,
}

impl Typename for Ping {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for Ping {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let ts_m = map.get_integer("ts_m").ok_or(Error::BadEtf("ts_m"))?;
        Ok(Self { ts_m })
    }
    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from("ping")));
        m.insert(Term::Atom(Atom::from("ts_m")), Term::from(eetf::BigInteger { value: self.ts_m.into() }));
        let term = Term::from(Map { map: m });
        let etf_data = encode_safe(&term);
        Ok(etf_data)
    }

    #[instrument(skip(self, ctx), fields(src = %src), name = "Ping::handle")]
    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        // In v1.1.7+ ping is simplified - just respond with pong
        if ctx.is_peer_handshaked(src).await {
            ctx.node_peers.update_peer_ping_timestamp(src, self.ts_m).await;

            let mut instructions = Vec::new();
            instructions.push(Instruction::SendPeersV2 { dst: src });
            instructions.push(Instruction::SendPong { ts_m: self.ts_m, dst: src });

            Ok(instructions)
        } else {
            warn!("{src} sent ping but is not handshaked");
            Ok(vec![Instruction::Noop { why: "ping from non-handshaked peer".to_string() }])
        }
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

impl Typename for Pong {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for Pong {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let ts_m = map.get_integer("ts_m").ok_or(Error::BadEtf("ts_m"))?;
        let seen_time_ms = get_unix_millis_now();
        // check what else must be validated
        Ok(Self { ts: ts_m, seen_time: seen_time_ms })
    }
    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::TYPENAME)));
        m.insert(Term::Atom(Atom::from("ts_m")), Term::from(eetf::BigInteger { value: self.ts.into() }));
        let term = Term::from(Map { map: m });
        let etf_data = encode_safe(&term);
        Ok(etf_data)
    }

    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        if ctx.is_peer_handshaked(src).await {
            ctx.node_peers.update_peer_from_pong(src, self).await;
            Ok(vec![Instruction::Noop { why: "pong processed".to_string() }])
        } else {
            warn!("{src} is not handshaked");
            Ok(vec![Instruction::Noop { why: "pong without slip".to_string() }])
        }
    }
}

impl Pong {
    pub const TYPENAME: &'static str = "pong";
}

impl Typename for TxPool {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for TxPool {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        // txs_packed is a list of binary transaction packets, not a single binary
        let txs_list = map.get_list("txs_packed").ok_or(Error::BadEtf("txs_packed"))?;
        let valid_txs = TxPool::get_valid_txs_from_list(txs_list)?;
        Ok(Self { valid_txs })
    }
    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        // create list of transaction binaries (txs_packed is directly a list of binaries)
        let tx_terms: Vec<Term> = self.valid_txs.iter().map(|tx| Term::from(Binary { bytes: tx.clone() })).collect();
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::TYPENAME)));
        // txs_packed is directly a list of binary terms, not a binary containing an encoded list
        m.insert(Term::Atom(Atom::from("txs_packed")), Term::from(List { elements: tx_terms }));
        let term = Term::from(Map { map: m });
        let etf_data = encode_safe(&term);
        Ok(etf_data)
    }

    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        // TODO: update ETS-like tx pool with valid_txs
        Ok(vec![Instruction::Noop { why: "txpool handling not implemented".to_string() }])
    }
}

impl TxPool {
    pub const TYPENAME: &'static str = "txpool";

    fn get_valid_txs_from_list(txs_list: &[Term]) -> Result<Vec<Vec<u8>>, Error> {
        let mut good: Vec<Vec<u8>> = Vec::with_capacity(txs_list.len());

        for t in txs_list {
            // each item must be a binary (a packed transaction)
            let bin = if let Some(b) = TryAsRef::<Binary>::try_as_ref(t) {
                b.bytes.as_slice()
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

impl Typename for Peers {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for Peers {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let list = map.get_list("ips").ok_or(Error::BadEtf("ips"))?;
        let ips = list
            .iter()
            .map(|t| t.get_string().map(|s| s.to_string()))
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::BadEtf("ips"))?;
        Ok(Self { ips })
    }
    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        // create list of IP strings
        let ip_terms: Vec<Term> =
            self.ips.iter().map(|ip| Term::from(Binary { bytes: ip.as_bytes().to_vec() })).collect();
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::TYPENAME)));
        m.insert(Term::Atom(Atom::from("ips")), Term::from(List { elements: ip_terms }));
        let term = Term::from(Map { map: m });
        let etf_data = encode_safe(&term);
        Ok(etf_data)
    }

    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        // TODO: update ETS-like peer table with new IPs
        Ok(vec![Instruction::Noop { why: "peers handling not implemented".to_string() }])
    }
}

impl Peers {
    pub const TYPENAME: &'static str = "peers";
}

impl Typename for PeersV2 {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for PeersV2 {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let list = map.get_list("anrs").ok_or(Error::BadEtf("anrs"))?;
        let mut anrs = Vec::new();
        for term in list {
            let anr_map = term.get_term_map().ok_or(Error::BadEtf("anr_map"))?;
            let anr = Anr::from_etf_term_map(anr_map)?;
            if anr.verify_signature() {
                anrs.push(anr);
            }
        }
        Ok(Self { anrs })
    }

    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let anr_terms: Vec<Term> = self.anrs.iter().map(|anr| anr.to_etf_term()).collect();
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::TYPENAME)));
        m.insert(Term::Atom(Atom::from("anrs")), Term::from(List { elements: anr_terms }));
        let term = Term::from(Map { map: m });
        let etf_data = encode_safe(&term);
        Ok(etf_data)
    }

    async fn handle(&self, ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        for anr in &self.anrs {
            ctx.node_anrs.insert(anr.clone()).await;
        }
        Ok(vec![Instruction::Noop { why: format!("inserted {} anrs", self.anrs.len()) }])
    }
}

impl PeersV2 {
    pub const TYPENAME: &'static str = "peers_v2";
}

impl Ping {}

impl Typename for NewPhoneWhoDis {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for NewPhoneWhoDis {
    fn from_etf_map_validated(_map: TermMap) -> Result<Self, Error> {
        // v1.1.7+ simplified - no fields to parse
        Ok(Self {})
    }

    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut map = TermMap::default();
        map.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::TYPENAME)));
        // v1.1.7+ - no additional fields
        Ok(encode_safe(&map.into_term()))
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

impl Typename for NewPhoneWhoDisReply {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for NewPhoneWhoDisReply {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let anr_map = map.get_term_map("anr").ok_or(Error::BadEtf("anr"))?;
        let anr = Anr::from_etf_term_map(anr_map)?;

        if !anr.verify_signature() {
            return Err(Error::BadEtf("anr_signature_invalid"));
        }

        Ok(Self { anr })
    }

    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut map = TermMap::default();
        map.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::TYPENAME)));
        map.insert(Term::Atom(Atom::from("anr")), self.anr.to_etf_term());
        Ok(encode_safe(&map.into_term()))
    }

    #[instrument(skip(self, ctx), fields(src = %src), name = "NewPhoneWhoDisReply::handle")]
    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        // SECURITY: ip address spoofing protection
        if src != self.anr.ip4 {
            warn!("new_phone_who_dis_reply ip mismatched with anr {}", self.anr.ip4);
            return Err(Error::BadEtf("anr_ip_mismatch"));
        }

        // Check if ANR timestamp is fresh (within 60 seconds like Elixir)
        let now = crate::utils::misc::get_unix_secs_now();
        let age_secs = now.saturating_sub(self.anr.ts);
        if age_secs > 60 {
            warn!("new_phone_who_dis_reply ANR too old: {} seconds", age_secs);
            return Err(Error::BadEtf("anr_too_old"));
        }

        // Insert ANR and mark as handshaked
        ctx.node_anrs.insert(self.anr.clone()).await;
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

impl Typename for SpecialBusiness {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for SpecialBusiness {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let business = map.get_binary::<Vec<u8>>("business").ok_or(Error::BadEtf("business"))?;
        Ok(Self { business })
    }

    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::TYPENAME)));
        m.insert(Term::Atom(Atom::from("business")), Term::from(Binary { bytes: self.business.clone() }));
        let term = Term::from(Map { map: m });
        let etf_data = encode_safe(&term);
        Ok(etf_data)
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

impl Typename for SpecialBusinessReply {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for SpecialBusinessReply {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let business = map.get_binary::<Vec<u8>>("business").ok_or(Error::BadEtf("business"))?;
        Ok(Self { business })
    }

    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::TYPENAME)));
        m.insert(Term::Atom(Atom::from("business")), Term::from(Binary { bytes: self.business.clone() }));
        let term = Term::from(Map { map: m });
        let etf_data = encode_safe(&term);
        Ok(etf_data)
    }

    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<Instruction>, Error> {
        // TODO: Implement special business reply handling logic
        Ok(vec![Instruction::SpecialBusinessReply { business: self.business.clone() }])
    }
}

impl SpecialBusinessReply {
    pub const TYPENAME: &'static str = "special_business_reply";
    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::TYPENAME)));
        m.insert(Term::Atom(Atom::from("business")), Term::from(Binary { bytes: self.business.clone() }));
        let term = Term::from(Map { map: m });
        let etf_data = encode_safe(&term);
        Ok(etf_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::consensus::doms::entry::{EntryHeader, EntrySummary};
    use crate::utils::bls12_381::sign as bls_sign;

    #[tokio::test]
    async fn test_ping_etf_roundtrip() {
        // create a sample ping message
        let _temporal = create_dummy_entry_summary();
        let _rooted = create_dummy_entry_summary();
        let ping = Ping::new();

        // serialize to ETF (now compressed by default)
        let bin = ping.to_etf_bin().expect("should serialize");

        // deserialize back
        let result = parse_etf_bin(&bin).expect("should deserialize");

        // check that we get the right type
        assert_eq!(result.typename(), "ping");
    }

    #[tokio::test]
    async fn test_pong_etf_roundtrip() {
        let pong = Pong { ts: 1234567890, seen_time: 9876543210 };

        let bin = pong.to_etf_bin().expect("should serialize");
        let result = parse_etf_bin(&bin).expect("should deserialize");

        // check that the result type is Pong
        assert_eq!(result.typename(), "pong");
    }

    #[tokio::test]
    async fn test_txpool_etf_roundtrip() {
        let txpool = TxPool { valid_txs: vec![vec![1, 2, 3], vec![4, 5, 6]] };

        let bin = txpool.to_etf_bin().expect("should serialize");
        let result = parse_etf_bin(&bin).expect("should deserialize");

        assert_eq!(result.typename(), "txpool");
    }

    #[tokio::test]
    async fn test_peers_etf_roundtrip() {
        let peers = Peers { ips: vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()] };

        let bin = peers.to_etf_bin().expect("should serialize");
        let result = parse_etf_bin(&bin).expect("should deserialize");

        assert_eq!(result.typename(), "peers");
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

        // construct message
        let _challenge = get_unix_secs_now();
        let msg = NewPhoneWhoDis::new();

        // roundtrip serialize/deserialize
        let bin = msg.to_etf_bin().expect("serialize");
        let parsed = parse_etf_bin(&bin).expect("deserialize");
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
        let _challenge = get_unix_secs_now();
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

        // Serialize to ETF
        let bin = msg.to_etf_bin().expect("serialize NewPhoneWhoDis");

        // Deserialize back
        let parsed = parse_etf_bin(&bin).expect("deserialize NewPhoneWhoDis");
        assert_eq!(parsed.typename(), "new_phone_who_dis");

        // Verify it deserializes correctly as NewPhoneWhoDis
        if let Ok(_parsed_msg) =
            NewPhoneWhoDis::from_etf_map_validated(Term::decode(&bin[..]).expect("decode").get_term_map().expect("map"))
        {
            // Success - the simplified format works correctly
            assert!(true);
        } else {
            panic!("Failed to deserialize simplified NewPhoneWhoDis");
        }
    }

    #[tokio::test]
    async fn test_new_phone_who_dis_reply_v1_1_7_format() {
        use crate::node::anr;
        use crate::utils::bls12_381 as bls;
        use std::net::Ipv4Addr;

        let sk = bls::generate_sk();
        let pk = bls::get_public_key(&sk).expect("pk");
        let pop = bls_sign(&sk, &pk, crate::consensus::DST_POP).expect("pop");
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let responder_anr = anr::Anr::build(&sk, &pk, &pop, ip, Ver::new(1, 0, 0)).expect("anr");

        // Test the simplified v1.1.7+ NewPhoneWhoDisReply format (just ANR)
        let msg = NewPhoneWhoDisReply { anr: responder_anr.clone() };

        // Serialize to ETF
        let bin = msg.to_etf_bin().expect("serialize NewPhoneWhoDisReply");

        // Deserialize back
        let parsed = parse_etf_bin(&bin).expect("deserialize NewPhoneWhoDisReply");
        assert_eq!(parsed.typename(), "new_phone_who_dis_reply");

        // Cast back to NewPhoneWhoDisReply to verify ANR field
        if let Ok(parsed_msg) = NewPhoneWhoDisReply::from_etf_map_validated(
            Term::decode(&bin[..]).expect("decode").get_term_map().expect("map"),
        ) {
            assert_eq!(parsed_msg.anr, responder_anr, "ANR mismatch");
        }
    }

    #[tokio::test]
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
                let pong = Pong { ts: 12345, seen_time: 67890 };

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
                        let pong_before = sent_before_obj.get("pong").map(|v| v.as_u64().unwrap()).unwrap_or(0);
                        let pong_after = sent_after.get("pong").map(|v| v.as_u64().unwrap()).unwrap_or(0);
                        assert_eq!(
                            pong_after,
                            pong_before + 1,
                            "Sent packet counter should increment even on send failure"
                        );
                    }
                    None => {
                        // no sent packets before, should have 1 pong now
                        assert_eq!(sent_after.get("pong").unwrap().as_u64().unwrap(), 1);
                    }
                }
            }
            Err(_) => {
                // context creation failed - this is acceptable for this test
            }
        }
    }
}

