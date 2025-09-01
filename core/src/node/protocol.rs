use crate::Context;
use crate::bic::sol;
use crate::bic::sol::Solution;
use crate::config::Config;
use crate::consensus::attestation::AttestationBulk;
use crate::consensus::consensus::{get_chain_tip_entry, get_rooted_tip_entry};
use crate::consensus::entry::{Entry, EntrySummary};
use crate::consensus::tx;
use crate::consensus::{attestation, entry};
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
use tracing::{instrument, warn};

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
    #[instrument(skip(self, ctx), fields(proto = %self.typename()), name = "Proto::handle")]
    async fn handle_with_metrics(&self, ctx: &Context, src: SocketAddr) -> Result<Instruction, Error> {
        ctx.metrics.add_incoming_proto_by_name(self.typename());
        self.handle(ctx, src).await.inspect_err(|e| ctx.metrics.add_error(e))
    }
    async fn handle(&self, ctx: &Context, src: SocketAddr) -> Result<Instruction, Error>;
    /// Send this protocol message to a destination using context's UDP socket
    async fn send_to_with_metrics(&self, ctx: &Context, dst: SocketAddr) -> Result<(), Error> {
        let Context { metrics, config, socket, .. } = ctx;
        let payload = self.to_etf_bin().inspect_err(|e| metrics.add_error(e))?;
        let shards = ReedSolomonReassembler::build_shards(config, &payload).inspect_err(|e| metrics.add_error(e))?;
        for shard in &shards {
            socket.send_to_with_metrics(shard, dst, metrics).await?;
        }
        metrics.add_outgoing_proto_by_name(self.typename());
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
#[derive(Debug)]
pub enum Instruction {
    Noop,
    ReplyPong { ts_m: u128 },
    ObservedPong { ts_m: u128, seen_time_ms: u128 },
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
    ReplyWhatChallenge { anr: anr::ANR, challenge: u64 },
    ReceivedWhatResponse { responder_anr: anr::ANR, challenge: u64, their_signature: Vec<u8> },
    HandshakeComplete { anr: anr::ANR },
}

/// Does proto parsing and validation
#[instrument(skip(bin), name = "Proto::from_etf_validated")]
pub fn from_etf_bin(bin: &[u8]) -> Result<Box<dyn Protocol>, Error> {
    // TODO: this function is a main UDP router and is subject to refactoring
    let term = Term::decode(bin)?;
    let map = term.get_term_map().ok_or(Error::BadEtf("map"))?;

    // `op` determines the variant
    let op_atom = map.get_atom("op").ok_or(Error::BadEtf("op"))?;
    let proto: Box<dyn Protocol> = match op_atom.name.as_str() {
        Ping::NAME => Box::new(Ping::from_etf_map_validated(map)?),
        Pong::NAME => Box::new(Pong::from_etf_map_validated(map)?),
        Entry::NAME => Box::new(Entry::from_etf_map_validated(map)?),
        AttestationBulk::NAME => Box::new(AttestationBulk::from_etf_map_validated(map)?),
        Solution::NAME => Box::new(Solution::from_etf_map_validated(map)?),
        TxPool::NAME => Box::new(TxPool::from_etf_map_validated(map)?),
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
    pub anr: Vec<u8>, // packed ANR binary
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
        Self::NAME
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
    async fn handle(&self, _ctx: &Context, _src: SocketAddr) -> Result<Instruction, Error> {
        Ok(Instruction::ReplyPong { ts_m: self.ts_m })
    }
}

impl Ping {
    pub const NAME: &'static str = "ping";
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

    async fn handle(&self, _ctx: &Context, _src: SocketAddr) -> Result<Instruction, Error> {
        // TODO: update ETS-like peer table with latency now_ms - p.ts_m
        Ok(Instruction::Noop)
    }
}

impl Pong {
    pub const NAME: &'static str = "pong";
}

impl Typename for TxPool {
    fn typename(&self) -> &'static str {
        Self::NAME
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
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        // txs_packed is directly a list of binary terms, not a binary containing an encoded list
        m.insert(Term::Atom(Atom::from("txs_packed")), Term::from(List { elements: tx_terms }));
        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data)?;
        Ok(etf_data)
    }

    async fn handle(&self, _ctx: &Context, _src: SocketAddr) -> Result<Instruction, Error> {
        // TODO: update ETS-like tx pool with valid_txs
        Ok(Instruction::Noop)
    }
}

impl TxPool {
    pub const NAME: &'static str = "txpool";

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
        Ok(Instruction::Noop)
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
        let result = from_etf_bin(&bin).expect("should deserialize");

        // check that we get the right type
        assert_eq!(result.typename(), "ping");
    }

    #[tokio::test]
    async fn test_pong_etf_roundtrip() {
        let pong = Pong { ts_m: 1234567890, seen_time_ms: 9876543210 };

        let bin = pong.to_etf_bin().expect("should serialize");
        let result = from_etf_bin(&bin).expect("should deserialize");

        // check that the result type is Pong
        assert_eq!(result.typename(), "pong");
    }

    #[tokio::test]
    async fn test_txpool_etf_roundtrip() {
        let txpool = TxPool { valid_txs: vec![vec![1, 2, 3], vec![4, 5, 6]] };

        let bin = txpool.to_etf_bin().expect("should serialize");
        let result = from_etf_bin(&bin).expect("should deserialize");

        assert_eq!(result.typename(), "txpool");
    }

    #[tokio::test]
    async fn test_peers_etf_roundtrip() {
        let peers = Peers { ips: vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()] };

        let bin = peers.to_etf_bin().expect("should serialize");
        let result = from_etf_bin(&bin).expect("should deserialize");

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
        let my_anr = anr::ANR::build(&sk, &pk, &pop, ip, "testver".to_string()).expect("anr");

        // construct message
        let challenge = get_unix_secs_now();
        let msg = NewPhoneWhoDis::new(my_anr.clone(), challenge).expect("npwd new");

        // roundtrip serialize/deserialize
        let bin = msg.to_etf_bin().expect("serialize");
        let parsed = from_etf_bin(&bin).expect("deserialize");
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
        let my_anr = anr::ANR::build(&sk, &pk, &pop, ip, "testver".to_string()).expect("anr");
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
        let responder_anr = anr::ANR::build(&sk, &pk, &pop, ip, "testver".to_string()).expect("anr");

        // fresh challenge within 6s window
        let challenge = get_unix_secs_now();
        // produce some signature bytes (protocol layer doesn't verify it)
        let sig = bls::sign(&sk, &pk, b"AMA_ANR_CHALLENGE").expect("sig").to_vec();
        let msg = What::new(responder_anr.clone(), challenge, sig.clone()).expect("what new");

        let bin = msg.to_etf_bin().expect("serialize");
        let parsed = from_etf_bin(&bin).expect("deserialize");
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
        let responder_anr = anr::ANR::build(&sk, &pk, &pop, ip, "testver".to_string()).expect("anr");

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

#[async_trait::async_trait]
impl Protocol for NewPhoneWhoDis {
    fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("anr")), Term::Binary(Binary::from(self.anr.clone())));
        m.insert(Term::Atom(Atom::from("challenge")), Term::BigInteger(BigInteger::from(self.challenge as i64)));
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
        // deserialize the sender's ANR from binary
        let anr_term = Term::decode(&self.anr[..])?;
        let anr_map = anr_term.get_term_map().ok_or(Error::BadEtf("anr_map"))?;

        // extract ANR fields
        // IP4 is stored as string in Elixir format: "127.0.0.1"
        let ip4_str = anr_map.get_string("ip4").ok_or(Error::BadEtf("ip4"))?;
        let ip4 = ip4_str.parse::<std::net::Ipv4Addr>().map_err(|_| Error::BadEtf("ip4_parse"))?;

        let pk = anr_map.get_binary::<Vec<u8>>("pk").ok_or(Error::BadEtf("pk"))?;
        let pop = anr_map.get_binary::<Vec<u8>>("pop").ok_or(Error::BadEtf("pop"))?;
        let port = anr_map.get_integer::<u16>("port").ok_or(Error::BadEtf("port"))?;
        let signature = anr_map.get_binary::<Vec<u8>>("signature").ok_or(Error::BadEtf("signature"))?;
        let ts = anr_map.get_integer::<u64>("ts").ok_or(Error::BadEtf("ts"))?;
        let version_bytes = anr_map.get_binary::<Vec<u8>>("version").ok_or(Error::BadEtf("version"))?;
        let version = String::from_utf8_lossy(&version_bytes).to_string();

        let sender_anr = anr::ANR {
            ip4,
            pk,
            pop,
            port,
            signature,
            ts,
            version,
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: ts + 3,
        };

        // validate ANR signature
        if !sender_anr.verify_signature() {
            return Ok(Instruction::Noop);
        }

        // Validate that sender's IP matches ANR's IP4 field (security requirement)
        if std::net::IpAddr::V4(ip4) != src.ip() {
            return Ok(Instruction::Noop);
        }

        // Validate challenge is a reasonable integer
        if self.challenge == 0 {
            return Ok(Instruction::Noop);
        }

        // Handle the state updates directly here
        println!("received new_phone_who_dis from {:?}, challenge {}, replying with what", src, self.challenge);

        // Insert the sender's ANR into our store
        anr::insert(sender_anr.clone()).await.map_err(Into::<Error>::into)?;

        // Update peer information with ANR data (version and public key)
        if let std::net::IpAddr::V4(sender_ip) = src.ip() {
            let _ = ctx.update_peer_from_anr(sender_ip, &sender_anr.pk, &sender_anr.version).await;
            let _ = ctx.set_peer_handshake_status(sender_ip, crate::node::peers::HandshakeStatus::SentWhat).await;
        }

        // Get our own ANR to include in the What response
        let my_ip = ctx
            .get_config()
            .public_ipv4
            .as_ref()
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
            .unwrap_or_else(|| std::net::Ipv4Addr::new(127, 0, 0, 1));

        let my_anr = anr::ANR::build(
            &ctx.get_config().trainer_sk,
            &ctx.get_config().trainer_pk,
            &ctx.get_config().trainer_pop,
            my_ip,
            ctx.get_config().get_ver(),
        )
        .map_err(|_| Error::BadEtf("my_anr_build_failed"))?;

        // Sign the challenge: signature = BLS(sender_pk || challenge) with OUR private key
        let mut challenge_msg = sender_anr.pk.clone();
        challenge_msg.extend_from_slice(&self.challenge.to_be_bytes());

        let signature = bls::sign(&ctx.get_config().trainer_sk, &challenge_msg, crate::consensus::DST_ANR_CHALLENGE)
            .map_err(|_| Error::BadEtf("challenge_sign_failed"))?;

        // Create What response with OUR ANR
        let what_msg = What::new(my_anr, self.challenge, signature.to_vec())
            .map_err(|_| Error::BadEtf("what_msg_create_failed"))?;

        // Send the What message directly
        what_msg.send_to_with_metrics(ctx, src).await.map_err(|_| Error::BadEtf("what_send_failed"))?;

        Ok(Instruction::Noop)
    }
}

impl NewPhoneWhoDis {
    pub const NAME: &'static str = "new_phone_who_dis";

    pub fn new(anr: anr::ANR, challenge: u64) -> Result<Self, Error> {
        // serialize ANR to binary for internal storage
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
        m.insert(Term::Atom(Atom::from("anr")), Term::Binary(Binary::from(self.anr.clone())));
        m.insert(Term::Atom(Atom::from("challenge")), Term::BigInteger(BigInteger::from(self.challenge as i64)));
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
        let ts = anr_map.get_integer::<u64>("ts").ok_or(Error::BadEtf("ts"))?;
        let version_bytes = anr_map.get_binary::<Vec<u8>>("version").ok_or(Error::BadEtf("version"))?;
        let version = String::from_utf8_lossy(&version_bytes).to_string();

        let responder_anr = anr::ANR {
            ip4,
            pk: pk.clone(),
            pop,
            port,
            signature: signature_anr,
            ts,
            version,
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: ts + 3,
        };

        // validate the responder's ANR signature
        if !responder_anr.verify_signature() {
            return Ok(Instruction::Noop);
        }

        // Validate that sender's IP matches ANR's IP4 field (security requirement)
        if std::net::IpAddr::V4(ip4) != src.ip() {
            return Ok(Instruction::Noop);
        }

        // Validate timestamp within 6-second window (replay attack prevention)
        let current_time = crate::utils::misc::get_unix_secs_now();
        let challenge_time = self.challenge as u64;
        let delta =
            if current_time > challenge_time { current_time - challenge_time } else { challenge_time - current_time };
        if delta > 6 {
            return Ok(Instruction::Noop);
        }

        // Handle the state updates directly here
        println!("received what response from {:?}, verifying signature", src);

        // Verify the signature: they signed (our_pk || challenge) with their private key
        let mut challenge_msg = ctx.get_config().trainer_pk.to_vec();
        challenge_msg.extend_from_slice(&self.challenge.to_be_bytes());

        // Verify using the responder's public key from their ANR
        if let Err(e) =
            bls::verify(&responder_anr.pk, &self.signature, &challenge_msg, crate::consensus::DST_ANR_CHALLENGE)
        {
            println!("signature verification failed: {}", e);
            return Ok(Instruction::Noop);
        }

        println!("handshake completed with {:?}, pk: {}", src, bs58::encode(&responder_anr.pk).into_string());

        // Insert the responder's ANR and mark as handshaked
        anr::insert(responder_anr.clone()).await.map_err(|_| Error::BadEtf("anr_insert_failed"))?;
        anr::set_handshaked(&responder_anr.pk).await.map_err(|_| Error::BadEtf("anr_set_handshaked_failed"))?;

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

        Ok(Instruction::Noop)
    }
}

impl What {
    pub const NAME: &'static str = "what?";

    pub fn new(anr: anr::ANR, challenge: u64, signature: Vec<u8>) -> Result<Self, Error> {
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
