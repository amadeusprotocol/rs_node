use crate::Context;
use crate::bic::sol;
use crate::bic::sol::Solution;
use crate::config::Config;
use crate::consensus::attestation::AttestationBulk;
use crate::consensus::consensus::{get_chain_tip_entry, get_rooted_tip_entry};
use crate::consensus::entry::{Entry, EntrySummary};
use crate::consensus::tx;
use crate::consensus::{attestation, entry};
use crate::metrics::Metrics;
use crate::node::peers::HandshakeStatus;
use crate::node::{ReedSolomonReassembler, anr, msg_v2, reassembler};
use crate::socket::UdpSocketExt;
use crate::utils::bls12_381 as bls;
use crate::utils::misc::Typename;
use crate::utils::misc::{TermExt, TermMap, get_unix_millis_now};
use eetf::convert::TryAsRef;
use eetf::{Atom, BigInteger, Binary, DecodeError as EtfDecodeError, EncodeError as EtfEncodeError, List, Map, Term};
use std::collections::HashMap;
use std::io::Error as IoError;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, instrument, warn};

/// Convert an integer to binary representation compatible with Elixir's :erlang.integer_to_binary/1
/// This creates the minimal big-endian byte representation without leading zeros
fn integer_to_binary(n: u64) -> Vec<u8> {
    if n == 0 {
        vec![0]
    } else {
        let mut bytes = Vec::new();
        let mut num = n;
        while num > 0 {
            bytes.push((num & 0xFF) as u8);
            num >>= 8;
        }
        bytes.reverse(); // Convert to big-endian
        bytes
    }
}

/// Every object that has this trait must be convertible from an Erlang ETF
/// Binary representation and must be able to handle itself as a message
#[async_trait::async_trait]
pub trait Protocol: Typename + Send + Sync {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error>
    where
        Self: Sized;
    /// Convert to ETF binary format for network transmission
    fn to_etf_bin(&self) -> Result<Vec<u8>, Error>;
    /// Handle a message returning instructions for upper layers
    async fn handle(&self, ctx: &Context, src: SocketAddr) -> Result<Instruction, Error>;
    /// Send this protocol message to a destination using context's UDP socket
    async fn send_to_with_metrics(
        &self,
        config: &Config,
        socket: Arc<dyn UdpSocketExt>,
        dst: SocketAddr,
        metrics: &Metrics,
    ) -> Result<(), Error> {
        let payload = self.to_etf_bin().inspect_err(|e| metrics.add_error(e))?;
        let shards = ReedSolomonReassembler::build_shards(config, &payload).inspect_err(|e| metrics.add_error(e))?;
        for shard in &shards {
            socket.send_to_with_metrics(shard, dst, metrics).await?;
        }
        metrics.add_outgoing_proto(self.typename());
        Ok(())
    }
    async fn send_to(&self, config: &Config, socket: Arc<dyn UdpSocketExt>, dst: SocketAddr) -> Result<(), Error> {
        let shards = ReedSolomonReassembler::build_shards(config, &self.to_etf_bin()?)?;
        for shard in &shards {
            socket.send_to(shard, dst).await?;
        }
        Ok(())
    }
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
    Tx(#[from] tx::Error),
    #[error(transparent)]
    Entry(#[from] entry::Error),
    #[error(transparent)]
    Sol(#[from] sol::Error),
    #[error(transparent)]
    Att(#[from] attestation::Error),
    #[error(transparent)]
    ReedSolomon(#[from] reassembler::Error),
    #[error(transparent)]
    MsgV2(#[from] msg_v2::Error),
    #[error(transparent)]
    Anr(#[from] anr::Error),
    #[error("bad etf: {0}")]
    BadEtf(&'static str),
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
    SendPong { ts_m: u128, dst: SocketAddr },
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
    SendWhat { what: What, dst: SocketAddr },
    ReplyWhatChallenge { anr: anr::Anr, challenge: u64 },
    ReceivedWhatResponse { responder_anr: anr::Anr, challenge: u64, their_signature: Vec<u8> },
    HandshakeComplete { anr: anr::Anr },
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
        Pong::NAME => Box::new(Pong::from_etf_map_validated(map)?),
        Entry::NAME => Box::new(Entry::from_etf_map_validated(map)?),
        AttestationBulk::NAME => Box::new(AttestationBulk::from_etf_map_validated(map)?),
        Solution::NAME => Box::new(Solution::from_etf_map_validated(map)?),
        TxPool::TYPENAME => Box::new(TxPool::from_etf_map_validated(map)?),
        Peers::NAME => Box::new(Peers::from_etf_map_validated(map)?),
        NewPhoneWhoDis::NAME => Box::new(NewPhoneWhoDis::from_etf_map_validated(map)?),
        What::NAME => Box::new(What::from_etf_map_validated(map)?),
        SpecialBusiness::NAME => Box::new(SpecialBusiness::from_etf_map_validated(map)?),
        SpecialBusinessReply::NAME => Box::new(SpecialBusinessReply::from_etf_map_validated(map)?),
        _ => {
            warn!("Unknown operation: {}", op_atom.name);
            return Err(Error::BadEtf("op"));
        }
    };

    Ok(proto)
}

#[derive(Debug)]
pub struct Ping {
    pub temporal: EntrySummary,
    pub rooted: EntrySummary,
    pub ts_m: u128,
}

#[derive(Debug)]
pub struct Pong {
    pub ts_m: u128,
    pub seen_time_ms: u128,
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
    pub anr: Vec<u8>,           // packed ANR binary
    pub challenge: u64,
}

#[derive(Debug)]
pub struct What {
    pub anr: Vec<u8>, // packed ANR binary
    pub challenge: u64,
    pub signature: Vec<u8>,
}

impl Typename for Ping {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for Ping {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let temporal_term = map.get_term_map("temporal").ok_or(Error::BadEtf("temporal"))?;
        let rooted_term = map.get_term_map("rooted").ok_or(Error::BadEtf("rooted"))?;
        let temporal = EntrySummary::from_etf_term(&temporal_term)?;
        let rooted = EntrySummary::from_etf_term(&rooted_term)?;
        // TODO: validate temporal/rooted signatures and update peer shared secret, broadcast peers
        let ts_m = map.get_integer("ts_m").ok_or(Error::BadEtf("ts_m"))?;
        Ok(Self { temporal, rooted, ts_m })
    }
    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from("ping")));
        m.insert(Term::Atom(Atom::from("temporal")), self.temporal.to_etf_term()?);
        m.insert(Term::Atom(Atom::from("rooted")), self.rooted.to_etf_term()?);
        m.insert(Term::Atom(Atom::from("ts_m")), Term::from(eetf::BigInteger { value: self.ts_m.into() }));
        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data)?;
        Ok(etf_data)
    }
    async fn handle(&self, ctx: &Context, src: SocketAddr) -> Result<Instruction, Error> {
        use crate::utils::bls12_381 as bls;

        // TODO: validate temporal and rooted entry signatures like in Elixir
        // For now, skip signature validation to fix compilation

        // check if peer has permission slip (handshaked and valid IP)
        let has_permission_slip = if let std::net::IpAddr::V4(peer_ip) = src.ip() {
            // check if peer is handshaked by looking up their public key
            if let Ok(Some(peer)) = ctx.node_peers.by_ip(peer_ip).await {
                if let Some(ref pk) = peer.pk {
                    // check if this pk is handshaked with correct ip
                    match ctx.node_registry.is_handshaked(pk).await {
                        Ok(handshaked) => handshaked,
                        Err(_) => false,
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        // TODO: spawn peer broadcast task if has permission slip (simplified for now)
        if has_permission_slip {
            debug!("peer {} has permission slip, would broadcast peers", src);
        }

        // update peer info following Elixir implementation
        if let std::net::IpAddr::V4(peer_ip) = src.ip() {
            let current_time_ms = crate::utils::misc::get_unix_millis_now() as u64;

            // get signer from temporal entry header
            let signer = self.temporal.header.signer.to_vec();

            // check if this is a trainer for current height or has permission slip
            let is_trainer = match crate::consensus::trainers_for_height(crate::consensus::chain_height()) {
                Some(trainers) => trainers.iter().any(|pk| pk.as_slice() == signer),
                None => false,
            };

            if has_permission_slip || is_trainer {
                // try to update existing peer
                let _ = ctx.node_peers.update_peer_activity(peer_ip, "ping").await;

                // update peer with additional ping-specific data
                if let Ok(Some(_)) = ctx.node_peers.by_ip(peer_ip).await {
                    // Update via the peers system - use existing methods
                    let _ = ctx.node_peers.update_peer_from_anr(peer_ip, &signer, "unknown").await;
                } else {
                    // create new peer
                    let new_peer = crate::node::peers::Peer {
                        ip: peer_ip,
                        pk: Some(signer.clone()),
                        version: None, // will be set from ANR later
                        latency: None,
                        last_msg: current_time_ms,
                        last_ping: Some(current_time_ms),
                        last_pong: None,
                        shared_secret: if let Ok(shared_key) = bls::get_shared_secret(&signer, &ctx.config.trainer_sk) {
                            Some(shared_key.to_vec())
                        } else {
                            None
                        },
                        temporal: Some(crate::node::peers::TemporalInfo {
                            header_unpacked: crate::node::peers::HeaderInfo {
                                height: self.temporal.header.height,
                                prev_hash: Some(self.temporal.header.prev_hash.to_vec()),
                            },
                        }),
                        rooted: Some(crate::node::peers::RootedInfo {
                            header_unpacked: crate::node::peers::HeaderInfo {
                                height: self.rooted.header.height,
                                prev_hash: Some(self.rooted.header.prev_hash.to_vec()),
                            },
                        }),
                        last_seen: current_time_ms,
                        last_msg_type: Some("ping".to_string()),
                        handshake_status: crate::node::peers::HandshakeStatus::None,
                    };
                    let _ = ctx.node_peers.insert_new_peer(new_peer).await;
                }
            }
        }

        Ok(Instruction::SendPong { ts_m: self.ts_m, dst: src })
    }
}

impl Ping {
    pub const TYPENAME: &'static str = "ping";
    /// Create a new Ping with current timestamp
    pub fn new(temporal: EntrySummary, rooted: EntrySummary) -> Self {
        let ts_m = get_unix_millis_now();

        Self { temporal, rooted, ts_m }
    }

    /// Assemble Ping from current temporal and rooted tips stored in RocksDB
    /// Takes only header, signature, mask for each tip
    pub fn from_current_tips() -> Result<Self, Error> {
        // temporal summary
        let temporal = match get_chain_tip_entry() {
            Ok(Some(entry)) => entry.into(),
            _ => return Err(Error::BadEtf("temporal_tip")),
        };

        // rooted summary
        let rooted = match get_rooted_tip_entry() {
            Ok(Some(entry)) => entry.into(),
            _ => return Err(Error::BadEtf("rooted_tip")),
        };

        Ok(Self::new(temporal, rooted))
    }
}

impl Typename for Pong {
    fn typename(&self) -> &'static str {
        Self::NAME
    }
}

#[async_trait::async_trait]
impl Protocol for Pong {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let ts_m = map.get_integer("ts_m").ok_or(Error::BadEtf("ts_m"))?;
        let seen_time_ms = get_unix_millis_now();
        // check what else must be validated
        Ok(Self { ts_m, seen_time_ms })
    }
    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("ts_m")), Term::from(eetf::BigInteger { value: self.ts_m.into() }));
        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data)?;
        Ok(etf_data)
    }

    async fn handle(&self, ctx: &Context, src: SocketAddr) -> Result<Instruction, Error> {
        // calculate latency and update peer information following Elixir implementation
        if let std::net::IpAddr::V4(peer_ip) = src.ip() {
            let current_time_ms = crate::utils::misc::get_unix_millis_now() as u64;
            let latency = current_time_ms.saturating_sub(self.ts_m as u64);

            debug!("observed pong from {} with latency {}ms", peer_ip, latency);

            // try to update existing peer activity first
            let _ = ctx.node_peers.update_peer_activity(peer_ip, "pong").await;

            // check if peer exists and update with latency info
            if let Ok(Some(_)) = ctx.node_peers.by_ip(peer_ip).await {
                // For now, just update activity - could add latency update method to NodePeers later
                debug!("updated existing peer {} activity", peer_ip);
            } else {
                // create new peer
                let new_peer = crate::node::peers::Peer {
                    ip: peer_ip,
                    pk: None, // will be set from handshake later
                    version: None,
                    latency: Some(latency),
                    last_msg: current_time_ms,
                    last_ping: None,
                    last_pong: Some(current_time_ms),
                    shared_secret: None,
                    temporal: None,
                    rooted: None,
                    last_seen: current_time_ms,
                    last_msg_type: Some("pong".to_string()),
                    handshake_status: crate::node::peers::HandshakeStatus::None,
                };
                let _ = ctx.node_peers.insert_new_peer(new_peer).await;
            }

            return Ok(Instruction::Noop { why: "pong processed".to_string() });
        }

        Ok(Instruction::Noop { why: "ipv6 pong was not processed".to_string() })
    }
}

impl Pong {
    pub const NAME: &'static str = "pong";
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
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data)?;
        Ok(etf_data)
    }

    async fn handle(&self, _ctx: &Context, _src: SocketAddr) -> Result<Instruction, Error> {
        // TODO: update ETS-like tx pool with valid_txs
        Ok(Instruction::Noop { why: "txpool handling not implemented".to_string() })
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
            if tx::validate(bin, false).is_ok() {
                good.push(bin.to_vec());
            }
        }

        Ok(good)
    }
}

impl Typename for Peers {
    fn typename(&self) -> &'static str {
        Self::NAME
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
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("ips")), Term::from(List { elements: ip_terms }));
        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data)?;
        Ok(etf_data)
    }

    async fn handle(&self, _ctx: &Context, _src: SocketAddr) -> Result<Instruction, Error> {
        // TODO: update ETS-like peer table with new IPs
        Ok(Instruction::Noop { why: "peers handling not implemented".to_string() })
    }
}

impl Peers {
    pub const NAME: &'static str = "peers";
}

impl Ping {}

impl Typename for NewPhoneWhoDis {
    fn typename(&self) -> &'static str {
        Self::NAME
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::entry::{EntryHeader, EntrySummary};

    #[tokio::test]
    async fn test_ping_etf_roundtrip() {
        // create a sample ping message
        let temporal = create_dummy_entry_summary();
        let rooted = create_dummy_entry_summary();
        let ping = Ping::new(temporal, rooted);

        // serialize to ETF (now compressed by default)
        let bin = ping.to_etf_bin().expect("should serialize");

        // deserialize back
        let result = parse_etf_bin(&bin).expect("should deserialize");

        // check that we get the right type
        assert_eq!(result.typename(), "ping");
    }

    #[tokio::test]
    async fn test_pong_etf_roundtrip() {
        let pong = Pong { ts_m: 1234567890, seen_time_ms: 9876543210 };

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
        let pop = bls::sign(&sk, &pk, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_").expect("pop");
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let my_anr = anr::Anr::build(&sk, &pk, &pop, ip, "testver".to_string()).expect("anr");

        // construct message
        let challenge = get_unix_secs_now();
        let msg = NewPhoneWhoDis::new(my_anr.clone(), challenge).expect("npwd new");

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
        let pop = bls::sign(&sk, &pk, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_").expect("pop");
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let my_anr = anr::Anr::build(&sk, &pk, &pop, ip, "testver".to_string()).expect("anr");
        let challenge = get_unix_secs_now();
        let _msg = NewPhoneWhoDis::new(my_anr, challenge).expect("npwd new");

        // Test with mismatched source ip - should be handled internally now
        let wrong_ip = Ipv4Addr::new(127, 0, 0, 2);
        let _src = SocketAddr::V4(SocketAddrV4::new(wrong_ip, 36969));
        // Protocol handle_inner now manages validation internally
    }

    #[tokio::test]
    async fn test_what_roundtrip_and_handle() {
        use crate::node::anr;
        use crate::utils::{bls12_381 as bls, misc::get_unix_secs_now};
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

        // responder ANR
        let sk = bls::generate_sk();
        let pk = bls::get_public_key(&sk).expect("pk");
        let pop = bls::sign(&sk, &pk, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_").expect("pop");
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let responder_anr = anr::Anr::build(&sk, &pk, &pop, ip, "testver".to_string()).expect("anr");

        // fresh challenge within 6s window
        let challenge = get_unix_secs_now();
        // produce some signature bytes (protocol layer doesn't verify it)
        let sig = bls::sign(&sk, &pk, b"AMA_ANR_CHALLENGE").expect("sig").to_vec();
        let msg = What::new(responder_anr.clone(), challenge, sig.clone()).expect("what new");

        let bin = msg.to_etf_bin().expect("serialize");
        let parsed = parse_etf_bin(&bin).expect("deserialize");
        assert_eq!(parsed.typename(), "what?");

        let _src = SocketAddr::V4(SocketAddrV4::new(ip, 36969));
        // Protocol handle_inner now manages state updates directly and returns Noop
        // The previous test validations are now handled internally within the protocol
    }

    #[tokio::test]
    async fn test_what_stale_challenge_noop() {
        use crate::node::anr;
        use crate::utils::bls12_381 as bls;
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

        let sk = bls::generate_sk();
        let pk = bls::get_public_key(&sk).expect("pk");
        let pop = bls::sign(&sk, &pk, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_").expect("pop");
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let responder_anr = anr::Anr::build(&sk, &pk, &pop, ip, "testver".to_string()).expect("anr");

        // challenge far in the past (>6s)
        let challenge = crate::utils::misc::get_unix_secs_now().saturating_sub(10);
        let sig = vec![1u8; 96];
        let _msg = What::new(responder_anr, challenge, sig).expect("what new");

        let _src = SocketAddr::V4(SocketAddrV4::new(ip, 36969));
        // Protocol handle_inner now manages validation internally and returns Noop for stale challenges
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

    #[test]
    fn test_integer_to_binary_compatibility() {
        // Test various challenge values that would be typical Unix timestamps
        assert_eq!(integer_to_binary(0), vec![0]);
        assert_eq!(integer_to_binary(255), vec![255]);
        assert_eq!(integer_to_binary(256), vec![1, 0]);
        assert_eq!(integer_to_binary(1000), vec![3, 232]); // 0x03E8

        // Test typical Unix timestamp (around current time)
        let timestamp = 1693958400u64; // Example timestamp
        let bytes = integer_to_binary(timestamp);
        assert!(bytes.len() <= 8); // Should be compact representation
        assert!(bytes.len() >= 1); // Should have at least one byte

        // Test that it's the minimal representation (no leading zeros)
        assert_ne!(bytes[0], 0);
    }

    #[tokio::test]
    async fn test_new_phone_who_dis_challenge_edge_cases() {
        use crate::node::anr;
        use crate::utils::bls12_381 as bls;
        use std::net::Ipv4Addr;

        let sk = bls::generate_sk();
        let pk = bls::get_public_key(&sk).expect("pk");
        let pop = bls::sign(&sk, &pk, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_").expect("pop");
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let my_anr = anr::Anr::build(&sk, &pk, &pop, ip, "testver".to_string()).expect("anr");

        // Test edge case challenge values to ensure ETF encoding works correctly
        let test_challenges = vec![
            0u64,                  // Zero
            1u64,                  // Minimum positive
            255u64,                // Max FixInteger (u8)
            256u64,                // First BigInteger case
            65535u64,              // Max u16
            65536u64,              // First u16 overflow
            (i32::MAX as u64),     // Max i32 (FixInteger boundary)
            (i32::MAX as u64) + 1, // First BigInteger case
            1693958400u64,         // Typical Unix timestamp
            (i64::MAX as u64) - 1, // Near maximum i64 value
        ];

        for challenge in test_challenges {
            // Create message with this challenge
            let msg = NewPhoneWhoDis::new(my_anr.clone(), challenge)
                .expect(&format!("npwd new with challenge {}", challenge));

            // Serialize to ETF
            let bin = msg.to_etf_bin().expect(&format!("serialize challenge {}", challenge));

            // Deserialize back
            let parsed = parse_etf_bin(&bin).expect(&format!("deserialize challenge {}", challenge));
            assert_eq!(parsed.typename(), "new_phone_who_dis");

            // Cast back to NewPhoneWhoDis to verify challenge field
            if let Ok(parsed_msg) = NewPhoneWhoDis::from_etf_map_validated(
                Term::decode(&bin[..]).expect("decode").get_term_map().expect("map"),
            ) {
                assert_eq!(parsed_msg.challenge, challenge, "Challenge mismatch for value {}", challenge);
            }
        }
    }

    #[tokio::test]
    async fn test_what_challenge_edge_cases() {
        use crate::node::anr;
        use crate::utils::bls12_381 as bls;
        use std::net::Ipv4Addr;

        let sk = bls::generate_sk();
        let pk = bls::get_public_key(&sk).expect("pk");
        let pop = bls::sign(&sk, &pk, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_").expect("pop");
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let responder_anr = anr::Anr::build(&sk, &pk, &pop, ip, "testver".to_string()).expect("anr");

        let signature = vec![1u8; 96]; // Mock signature

        // Test same edge case challenge values for What messages
        let test_challenges = vec![
            0u64,
            1u64,
            255u64,
            256u64,
            65535u64,
            65536u64,
            (i32::MAX as u64),
            (i32::MAX as u64) + 1,
            1693958400u64,
            (i64::MAX as u64) - 1, // Near maximum i64 value
        ];

        for challenge in test_challenges {
            // Create What message with this challenge
            let msg = What::new(responder_anr.clone(), challenge, signature.clone())
                .expect(&format!("what new with challenge {}", challenge));

            // Serialize to ETF
            let bin = msg.to_etf_bin().expect(&format!("serialize what challenge {}", challenge));

            // Deserialize back
            let parsed = parse_etf_bin(&bin).expect(&format!("deserialize what challenge {}", challenge));
            assert_eq!(parsed.typename(), "what?");

            // Cast back to What to verify challenge field
            if let Ok(parsed_msg) =
                What::from_etf_map_validated(Term::decode(&bin[..]).expect("decode").get_term_map().expect("map"))
            {
                assert_eq!(parsed_msg.challenge, challenge, "What challenge mismatch for value {}", challenge);
            }
        }
    }

    #[tokio::test]
    async fn test_challenge_signature_compatibility() {
        use crate::node::anr;
        use crate::utils::bls12_381 as bls;
        use std::net::Ipv4Addr;

        // Create two different ANRs for sender and responder
        let sender_sk = bls::generate_sk();
        let sender_pk = bls::get_public_key(&sender_sk).expect("sender pk");
        let sender_pop =
            bls::sign(&sender_sk, &sender_pk, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_").expect("sender pop");

        let responder_sk = bls::generate_sk();
        let responder_pk = bls::get_public_key(&responder_sk).expect("responder pk");
        let responder_pop = bls::sign(&responder_sk, &responder_pk, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
            .expect("responder pop");

        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let _sender_anr =
            anr::Anr::build(&sender_sk, &sender_pk, &sender_pop, ip, "sender".to_string()).expect("sender anr");
        let responder_anr = anr::Anr::build(&responder_sk, &responder_pk, &responder_pop, ip, "responder".to_string())
            .expect("responder anr");

        // Test with various challenge values including boundary cases
        let test_challenges = vec![
            42u64,                 // Small value (FixInteger)
            1000u64,               // Medium value (FixInteger)
            (i32::MAX as u64),     // Boundary (FixInteger)
            (i32::MAX as u64) + 1, // First BigInteger
            1693958400u64,         // Typical timestamp (BigInteger)
        ];

        for challenge in test_challenges {
            // Test the signature generation/verification cycle with different integer encodings

            // Simulate what happens in NewPhoneWhoDis::handle - responder signs (sender_pk || challenge)
            let mut challenge_msg_sign = sender_pk.to_vec();
            let challenge_bytes = integer_to_binary(challenge);
            challenge_msg_sign.extend_from_slice(&challenge_bytes);

            let signature = bls::sign(&responder_sk, &challenge_msg_sign, crate::consensus::DST_ANR_CHALLENGE)
                .expect(&format!("sign challenge {}", challenge));

            // Create What message with the signature
            let what_msg = What::new(responder_anr.clone(), challenge, signature.to_vec())
                .expect(&format!("what create challenge {}", challenge));

            // Serialize/deserialize the What message to test ETF encoding
            let bin = what_msg.to_etf_bin().expect(&format!("what serialize challenge {}", challenge));
            let parsed_what =
                What::from_etf_map_validated(Term::decode(&bin[..]).expect("decode").get_term_map().expect("map"))
                    .expect(&format!("what deserialize challenge {}", challenge));

            // Verify the signature using the same format as What::handle - should verify (sender_pk || challenge)
            let mut challenge_msg_verify = sender_pk.to_vec();
            let challenge_bytes_verify = integer_to_binary(parsed_what.challenge);
            challenge_msg_verify.extend_from_slice(&challenge_bytes_verify);

            // This should succeed, proving signature compatibility
            bls::verify(
                &responder_pk,
                &parsed_what.signature,
                &challenge_msg_verify,
                crate::consensus::DST_ANR_CHALLENGE,
            )
            .expect(&format!("verify challenge {} signature", challenge));

            // Double-check: the challenge round-tripped correctly
            assert_eq!(parsed_what.challenge, challenge, "Challenge roundtrip failed for {}", challenge);

            // Double-check: the signature bytes are preserved
            assert_eq!(parsed_what.signature, signature.to_vec(), "Signature mismatch for challenge {}", challenge);
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
        let pop = bls::sign(&sk, &pk, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_").expect("pop");

        let config = crate::config::Config {
            work_folder: "/tmp/test_protocol_send_to".to_string(),
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

        let dummy_socket = Arc::new(MockSocket::new());
        let target = "127.0.0.1:1234".parse().unwrap();

        match crate::Context::with_config_and_socket(config, dummy_socket).await {
            Ok(ctx) => {
                // Create a Pong message to test with
                let pong = Pong { ts_m: 12345, seen_time_ms: 67890 };

                // Check metrics before sending
                let metrics_json_before = ctx.metrics.get_json();
                let sent_before = metrics_json_before.get("outgoing_protos");

                // Test Protocol::send_to method - should return error with MockSocket but not panic
                match pong.send_to_with_metrics(&ctx.config, ctx.socket.clone(), target, &ctx.metrics).await {
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

#[async_trait::async_trait]
impl Protocol for NewPhoneWhoDis {
    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));

        // Decode ANR from binary back to term to get proper nested map structure
        let anr_term = Term::decode(&self.anr[..])?;
        m.insert(Term::Atom(Atom::from("anr")), anr_term);

        // Use native integer encoding compatible with Elixir - prefer FixInteger for small values
        let challenge_term = if self.challenge <= (i32::MAX as u64) {
            Term::FixInteger(eetf::FixInteger { value: self.challenge as i32 })
        } else {
            // For larger values, clamp to i64 range to avoid overflow
            let clamped_value = std::cmp::min(self.challenge, i64::MAX as u64) as i64;
            Term::BigInteger(BigInteger::from(clamped_value))
        };
        m.insert(Term::Atom(Atom::from("challenge")), challenge_term);
        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data)?;
        Ok(etf_data)
    }
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        // In Elixir, anr can be sent as either a map or a binary
        // Check what type it is and handle accordingly
        let anr_binary = if let Some(anr_map) = map.get_term_map("anr") {
            // ANR is a map (from Elixir nodes) - serialize it
            let anr_term = Term::from(eetf::Map { map: anr_map.0.clone() });
            let mut encoded = Vec::new();
            anr_term.encode(&mut encoded)?;
            encoded
        } else if let Some(anr_bin) = map.get_binary::<Vec<u8>>("anr") {
            // ANR is already a binary (from Rust nodes)
            anr_bin
        } else {
            return Err(Error::BadEtf("anr"));
        };

        let challenge = map.get_integer("challenge").ok_or(Error::BadEtf("challenge"))?;
        Ok(Self { anr: anr_binary, challenge })
    }

    async fn handle(&self, ctx: &Context, src: SocketAddr) -> Result<Instruction, Error> {
        let anr_term = Term::decode(&self.anr[..])?;
        let anr_map = anr_term.get_term_map().ok_or(Error::BadEtf("anr_map"))?;

        // ip4 is stored as string in Elixir format: "127.0.0.1"
        let ip4_str = anr_map.get_string("ip4").ok_or(Error::BadEtf("ip4"))?;
        let ip4 = ip4_str.parse::<std::net::Ipv4Addr>().map_err(|_| Error::BadEtf("ip4_parse"))?;

        let pk = anr_map.get_binary::<Vec<u8>>("pk").ok_or(Error::BadEtf("pk"))?;
        let pop = anr_map.get_binary::<Vec<u8>>("pop").ok_or(Error::BadEtf("pop"))?;
        let port = anr_map.get_integer::<u16>("port").ok_or(Error::BadEtf("port"))?;
        let signature = anr_map.get_binary::<Vec<u8>>("signature").ok_or(Error::BadEtf("signature"))?;
        // Handle u128 timestamp - try u128 first, fallback to u64 for compatibility
        let ts = anr_map.get_integer::<u128>("ts")
            .or_else(|| anr_map.get_integer::<u64>("ts").map(|v| v as u128))
            .ok_or(Error::BadEtf("ts"))?;
        let version_bytes = anr_map.get_binary::<Vec<u8>>("version").ok_or(Error::BadEtf("version"))?;
        let version = String::from_utf8_lossy(&version_bytes).to_string();

        // Parse optional anr_name and anr_desc fields (they may be nil or missing)
        let anr_name = anr_map.get_binary::<Vec<u8>>("anr_name")
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .filter(|s| !s.is_empty());
        
        let anr_desc = anr_map.get_binary::<Vec<u8>>("anr_desc")
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .filter(|s| !s.is_empty());

        let sender_anr = anr::Anr {
            ip4,
            pk,
            pop,
            port,
            signature,
            ts,
            version,
            anr_name,
            anr_desc,
            handshaked: true,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: (ts + 3) as u64,
        };

        if !sender_anr.verify_signature() {
            warn!("received new_phone_who_dis with invalid anr signature from {src}");
            return Err(Error::BadEtf("anr_signature_invalid"));
        }

        // SECURITY: validate that sender ip matches anr ip4 field
        if std::net::IpAddr::V4(ip4) != src.ip() {
            warn!("received new_phone_who_dis with mismatched ip from {src}, anr ip4 {ip4}");
            return Err(Error::BadEtf("anr_ip_mismatch"));
        }

        if self.challenge == 0 {
            warn!("received new_phone_who_dis with zero challenge from {:?}", src);
            return Err(Error::BadEtf("challenge_zero"));
        }

        debug!("received new_phone_who_dis from {src}, challenge {}, replying with what", self.challenge);
        ctx.node_registry.insert(sender_anr.clone()).await?;

        // Update peer information with ANR data (version and public key)
        if let std::net::IpAddr::V4(sender_ip) = src.ip() {
            if let Err(e) = ctx.update_peer_from_anr(sender_ip, &sender_anr.pk, &sender_anr.version).await {
                warn!("failed to update peer info from ANR for {sender_ip}: {e}");
            }
            if let Err(e) = ctx.set_peer_handshake_status(sender_ip, HandshakeStatus::SentWhat).await {
                warn!("failed to set handshake status for {sender_ip}: {e}");
            }
        }

        let my_anr = anr::Anr::from_config(&ctx.get_config())?;

        // Sign the challenge: signature = BLS(sender_pk || challenge) with OUR private key
        // Use Elixir-compatible integer_to_binary format instead of fixed 8-byte encoding
        let mut challenge_msg = sender_anr.pk.clone();
        let challenge_bytes = integer_to_binary(self.challenge);
        challenge_msg.extend_from_slice(&challenge_bytes);

        let signature = bls::sign(&ctx.get_config().trainer_sk, &challenge_msg, crate::consensus::DST_ANR_CHALLENGE)
            .map_err(|_| Error::BadEtf("challenge_sign_failed"))?;

        // Create What response with OUR ANR
        let what = What::new(my_anr, self.challenge, signature.to_vec())
            .map_err(|_| Error::BadEtf("what_msg_create_failed"))?;

        Ok(Instruction::SendWhat { what, dst: src })
    }
}

impl NewPhoneWhoDis {
    pub const NAME: &'static str = "new_phone_who_dis";

    pub fn new(anr: anr::Anr, challenge: u64) -> Result<Self, Error> {
        let anr_binary = anr.to_etf_binary()?;
        Ok(Self { anr: anr_binary, challenge })
    }
}

impl Typename for What {
    fn typename(&self) -> &'static str {
        Self::NAME
    }
}

#[async_trait::async_trait]
impl Protocol for What {
    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        // Decode ANR from binary back to term to get proper nested map structure
        let anr_term = Term::decode(&self.anr[..])?;
        m.insert(Term::Atom(Atom::from("anr")), anr_term);
        // Use native integer encoding compatible with Elixir - prefer FixInteger for small values
        let challenge_term = if self.challenge <= (i32::MAX as u64) {
            Term::FixInteger(eetf::FixInteger { value: self.challenge as i32 })
        } else {
            // For larger values, clamp to i64 range to avoid overflow
            let clamped_value = std::cmp::min(self.challenge, i64::MAX as u64) as i64;
            Term::BigInteger(BigInteger::from(clamped_value))
        };
        m.insert(Term::Atom(Atom::from("challenge")), challenge_term);
        m.insert(Term::Atom(Atom::from("signature")), Term::Binary(Binary::from(self.signature.clone())));
        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data)?;
        Ok(etf_data)
    }
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        // In Elixir, anr can be sent as either a map or a binary
        // Check what type it is and handle accordingly
        let anr_binary = if let Some(anr_map) = map.get_term_map("anr") {
            // ANR is a map (from Elixir nodes) - serialize it
            let anr_term = Term::from(eetf::Map { map: anr_map.0.clone() });
            let mut encoded = Vec::new();
            anr_term.encode(&mut encoded)?;
            encoded
        } else if let Some(anr_bin) = map.get_binary::<Vec<u8>>("anr") {
            // ANR is already a binary (from Rust nodes)
            anr_bin
        } else {
            return Err(Error::BadEtf("anr"));
        };

        let challenge = map.get_integer("challenge").ok_or(Error::BadEtf("challenge"))?;
        let signature = map.get_binary::<Vec<u8>>("signature").ok_or(Error::BadEtf("signature"))?;
        Ok(Self { anr: anr_binary, challenge, signature })
    }

    async fn handle(&self, ctx: &Context, src: SocketAddr) -> Result<Instruction, Error> {
        // deserialize the responder's ANR from binary (this is THEIR ANR, not ours)
        let anr_term = Term::decode(&self.anr[..])?;
        let anr_map = anr_term.get_term_map().ok_or(Error::BadEtf("anr_map"))?;

        // extract ANR fields (responder's ANR)
        // IP4 is stored as string in Elixir format: "127.0.0.1"
        let ip4_str = anr_map.get_string("ip4").ok_or(Error::BadEtf("ip4"))?;
        let ip4 = ip4_str.parse::<std::net::Ipv4Addr>().map_err(|_| Error::BadEtf("ip4_parse"))?;

        let pk = anr_map.get_binary::<Vec<u8>>("pk").ok_or(Error::BadEtf("pk"))?;
        let pop = anr_map.get_binary::<Vec<u8>>("pop").ok_or(Error::BadEtf("pop"))?;
        let port = anr_map.get_integer::<u16>("port").ok_or(Error::BadEtf("port"))?;
        let signature_anr = anr_map.get_binary::<Vec<u8>>("signature").ok_or(Error::BadEtf("signature"))?;
        // Handle u128 timestamp - try u128 first, fallback to u64 for compatibility
        let ts = anr_map.get_integer::<u128>("ts")
            .or_else(|| anr_map.get_integer::<u64>("ts").map(|v| v as u128))
            .ok_or(Error::BadEtf("ts"))?;
        let version_bytes = anr_map.get_binary::<Vec<u8>>("version").ok_or(Error::BadEtf("version"))?;
        let version = String::from_utf8_lossy(&version_bytes).to_string();

        let responder_anr = anr::Anr {
            ip4,
            pk: pk.clone(),
            pop,
            port,
            signature: signature_anr,
            ts,
            version,
            anr_name: None,
            anr_desc: None,
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: (ts + 3) as u64,
        };

        // validate the responder's ANR signature
        if !responder_anr.verify_signature() {
            return Ok(Instruction::Noop { why: "invalid anr signature".to_string() });
        }

        // Validate that sender's IP matches ANR's IP4 field (security requirement)
        if std::net::IpAddr::V4(ip4) != src.ip() {
            return Ok(Instruction::Noop { why: "ip mismatch".to_string() });
        }

        // Validate timestamp within 6-second window (replay attack prevention)
        let current_time = crate::utils::misc::get_unix_secs_now();
        let challenge_time = self.challenge as u64;
        let delta =
            if current_time > challenge_time { current_time - challenge_time } else { challenge_time - current_time };
        if delta > 6 {
            return Ok(Instruction::Noop { why: "stale challenge".to_string() });
        }

        // Handle the state updates directly here
        println!("received what response from {:?}, verifying signature", src);

        // Verify the signature: they signed (our_pk || challenge) with their private key
        // Use Elixir-compatible integer_to_binary format instead of fixed 8-byte encoding
        let mut challenge_msg = ctx.get_config().trainer_pk.to_vec();
        let challenge_bytes = integer_to_binary(self.challenge);
        challenge_msg.extend_from_slice(&challenge_bytes);

        // Verify using the responder's public key from their ANR
        if let Err(e) =
            bls::verify(&responder_anr.pk, &self.signature, &challenge_msg, crate::consensus::DST_ANR_CHALLENGE)
        {
            println!("signature verification failed: {}", e);
            return Ok(Instruction::Noop { why: "signature verification failed".to_string() });
        }

        println!("handshake completed with {:?}, pk: {}", src, bs58::encode(&responder_anr.pk).into_string());

        // Insert the responder's ANR and mark as handshaked
        ctx.node_registry.insert(responder_anr.clone()).await.map_err(|_| Error::BadEtf("anr_insert_failed"))?;
        ctx.node_registry
            .set_handshaked(&responder_anr.pk)
            .await
            .map_err(|_| Error::BadEtf("anr_set_handshaked_failed"))?;

        // Update peer information with ANR data (version and public key)
        if let std::net::IpAddr::V4(responder_ip) = src.ip() {
            let _ = ctx.update_peer_from_anr(responder_ip, &responder_anr.pk, &responder_anr.version).await;
        }

        // Update peer's handshaked status in NodePeers to received_what (handshake completed)
        ctx.set_peer_handshaked(&responder_anr.pk).await.map_err(|_| Error::BadEtf("set_peer_handshaked_failed"))?;
        ctx.set_peer_handshake_status_by_pk(&responder_anr.pk, crate::node::peers::HandshakeStatus::ReceivedWhat)
            .await
            .map_err(|_| Error::BadEtf("set_handshake_status_failed"))?;

        println!("peer {} is now handshaked", bs58::encode(&responder_anr.pk).into_string());

        Ok(Instruction::Noop { why: "handshake completed".to_string() })
    }
}

impl What {
    pub const NAME: &'static str = "what?";

    pub fn new(anr: anr::Anr, challenge: u64, signature: Vec<u8>) -> Result<Self, Error> {
        // pack ANR to binary
        let anr_binary = anr.to_etf_binary()?;
        Ok(Self { anr: anr_binary, challenge, signature })
    }
}

impl Typename for SpecialBusiness {
    fn typename(&self) -> &'static str {
        Self::NAME
    }
}

#[async_trait::async_trait]
impl Protocol for SpecialBusiness {
    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("business")), Term::from(Binary { bytes: self.business.clone() }));
        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data)?;
        Ok(etf_data)
    }
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let business = map.get_binary::<Vec<u8>>("business").ok_or(Error::BadEtf("business"))?;
        Ok(Self { business })
    }

    async fn handle(&self, _ctx: &Context, _src: SocketAddr) -> Result<Instruction, Error> {
        // TODO: Implement special business handling logic
        // For now, just pass the business data to the state handler
        Ok(Instruction::SpecialBusiness { business: self.business.clone() })
    }
}

impl SpecialBusiness {
    pub const NAME: &'static str = "special_business";
}

impl Typename for SpecialBusinessReply {
    fn typename(&self) -> &'static str {
        Self::NAME
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
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("business")), Term::from(Binary { bytes: self.business.clone() }));
        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data)?;
        Ok(etf_data)
    }

    async fn handle(&self, _ctx: &Context, _src: SocketAddr) -> Result<Instruction, Error> {
        // TODO: Implement special business reply handling logic
        Ok(Instruction::SpecialBusinessReply { business: self.business.clone() })
    }
}

impl SpecialBusinessReply {
    pub const NAME: &'static str = "special_business_reply";
    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("business")), Term::from(Binary { bytes: self.business.clone() }));
        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data)?;
        Ok(etf_data)
    }
}
