use crate::bic::sol;
use crate::bic::sol::Solution;
use crate::consensus::attestation::AttestationBulk;
use crate::consensus::consensus::{get_chain_tip_entry, get_rooted_tip_entry};
use crate::consensus::entry::{Entry, EntrySummary};
use crate::consensus::tx;
use crate::consensus::{DST_NODE, attestation, entry};
use crate::node::{msg_v2, anr};
use crate::node::msg_v2::MessageV2;
use crate::utils::misc::Typename;
use crate::utils::misc::{TermExt, TermMap, get_unix_millis_now, get_unix_nanos_now};
use crate::utils::reed_solomon::ReedSolomonResource;
use crate::utils::{bls12_381 as bls, reed_solomon};
use crate::{Context, config};
use eetf::convert::TryAsRef;
use eetf::{Atom, Binary, DecodeError as EtfDecodeError, EncodeError as EtfEncodeError, FixInteger, List, Map, Term};
use miniz_oxide::deflate::{CompressionLevel, compress_to_vec};
use miniz_oxide::inflate::{DecompressError, decompress_to_vec};
use std::collections::HashMap;
use std::io::Error as IoError;
use tracing::{instrument, warn};

/// Every object that has this trait must be convertible from an Erlang ETF
/// Binary representation and must be able to handle itself as a message
#[async_trait::async_trait]
pub trait Protocol: Typename + Send + Sync {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error>
    where
        Self: Sized;
    /// Handle a message returning instructions for upper layers
    #[instrument(skip(self, ctx), fields(proto = %self.typename()), name = "Proto::handle")]
    async fn handle(&self, ctx: &Context) -> Result<Instruction, Error> {
        ctx.metrics.add_handled_proto_by_name(self.typename());
        self.handle_inner().await.inspect_err(|e| ctx.metrics.add_error(e))
    }
    async fn handle_inner(&self) -> Result<Instruction, Error>;
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
    ReedSolomon(#[from] reed_solomon::Error),
    #[error(transparent)]
    MsgV2(#[from] msg_v2::Error),
    #[error(transparent)]
    Anr(#[from] anr::Error),
    #[error("failed to decompress: {0}")]
    Decompress(DecompressError),
    #[error("bad etf: {0}")]
    BadEtf(&'static str),
}

impl crate::utils::misc::Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

impl From<DecompressError> for Error {
    fn from(e: DecompressError) -> Self {
        Self::Decompress(e)
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
    let decompressed = decompress_to_vec(bin)?;
    let term = Term::decode(decompressed.as_slice())?;
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
    pub anr: Vec<u8>,  // packed ANR binary
    pub challenge: u64,
}

#[derive(Debug)]
pub struct What {
    pub anr: Vec<u8>,  // packed ANR binary
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
    async fn handle_inner(&self) -> Result<Instruction, Error> {
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

    pub fn to_msg_v2(&self, config: &config::Config) -> Result<MessageV2, Error> {
        // create a MessageV2 from this Ping
        let compressed_payload = self.to_compressed_etf_bin()?;

        // get signing keys from config
        let pk = config.get_pk();
        let trainer_sk = config.get_sk();

        // create message metadata
        let ts_nano = get_unix_nanos_now() as u64;

        let original_size = compressed_payload.len() as u32;
        let version = config.get_ver();

        // for single shard (no Reed-Solomon needed)
        let shard_index = 0;
        let shard_total = 1;

        // create message signature over blake3(pk || payload)
        let mut hasher = crate::utils::blake3::Hasher::new();
        hasher.update(&pk);
        hasher.update(&compressed_payload);
        let msg_hash = hasher.finalize();
        let signature = bls::sign(&trainer_sk, &msg_hash, DST_NODE).map_err(|_| Error::BadEtf("signing_failed"))?;

        Ok(MessageV2 {
            version,
            pk,
            signature,
            shard_index,
            shard_total,
            ts_nano,
            original_size,
            payload: compressed_payload,
        })
    }

    /// Convert Ping to ETF binary format (compressed, symmetric with from_etf_bin)
    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from("ping")));
        m.insert(Term::Atom(Atom::from("temporal")), self.temporal.to_etf_term()?);
        m.insert(Term::Atom(Atom::from("rooted")), self.rooted.to_etf_term()?);
        m.insert(Term::Atom(Atom::from("ts_m")), Term::from(eetf::BigInteger { value: self.ts_m.into() }));

        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data).map_err(Error::EtfEncode)?;

        // compress to be symmetric with from_etf_bin
        let compressed = compress_to_vec(&etf_data, CompressionLevel::DefaultLevel as u8);
        Ok(compressed)
    }

    /// Create compressed ETF binary for transmission (same as to_etf_bin now)
    pub fn to_compressed_etf_bin(&self) -> Result<Vec<u8>, Error> {
        // to_etf_bin now returns compressed data, so this is the same
        self.to_etf_bin()
    }

    /// Create a signed MessageV2 from this Ping (single shard)
    pub fn to_message_v2(&self, config: &config::Config) -> Result<MessageV2, Error> {
        let compressed_payload = self.to_compressed_etf_bin()?;

        // get signing keys from config
        let pk = config.get_pk();
        let trainer_sk = config.get_sk();

        // create message metadata
        let ts_nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let original_size = compressed_payload.len() as u32;
        let version = config.get_ver();

        // for single shard (no Reed-Solomon needed)
        let shard_index = 0;
        let shard_total = 1;

        // create message signature over blake3(pk || payload)
        let mut hasher = crate::utils::blake3::Hasher::new();
        hasher.update(&pk);
        hasher.update(&compressed_payload);
        let msg_hash = hasher.finalize();
        let signature = bls::sign(&trainer_sk, &msg_hash, DST_NODE).map_err(|_| Error::BadEtf("signing_failed"))?;

        Ok(MessageV2 {
            version,
            pk,
            signature,
            shard_index,
            shard_total,
            ts_nano,
            original_size,
            payload: compressed_payload,
        })
    }

    /// Create multiple signed MessageV2 packets with Reed-Solomon sharding for large payloads
    pub fn to_message_v2_sharded(&self, config: &config::Config) -> Result<Vec<Vec<u8>>, Error> {
        const MAX_UDP_SIZE: usize = 1300; // ~1.3KB UDP limit
        const HEADER_SIZE: usize = 167; // messagev2 header size from protocol spec

        let compressed_payload = self.to_compressed_etf_bin()?;

        // check if we need sharding
        let total_size = HEADER_SIZE + compressed_payload.len();
        if total_size <= MAX_UDP_SIZE {
            // single packet - no sharding needed
            let msg = self.to_message_v2(config)?;
            let packet: Vec<u8> = msg.try_into()?;
            return Ok(vec![packet]);
        }

        // need Reed-Solomon sharding
        let mut rs = ReedSolomonResource::new(4, 4)?; // 4 data + 4 recovery shards
        let shards = rs.encode_shards(&compressed_payload)?;

        // get signing keys from config
        let pk = config.get_pk();
        let trainer_sk = config.get_sk();

        let ts_nano = get_unix_nanos_now() as u64; // TODO: check if this is fine

        let original_size = compressed_payload.len() as u32;
        let version = config.get_ver();
        let total_shards = (shards.len() * 2) as u16; // total shards * 2 as per protocol

        let mut packets = Vec::new();

        // create a MessageV2 for each shard
        for (shard_index, shard_data) in shards {
            // sign the shard data
            let signature =
                bls::sign(&trainer_sk, &shard_data, DST_NODE).map_err(|_| Error::BadEtf("signing_failed"))?;

            let msg = MessageV2 {
                version: version.clone(),
                pk,
                signature,
                shard_index: shard_index as u16,
                shard_total: total_shards,
                ts_nano,
                original_size,
                payload: shard_data,
            };

            let packet: Vec<u8> = msg.try_into()?;
            packets.push(packet);
        }

        Ok(packets)
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

    async fn handle_inner(&self) -> Result<Instruction, Error> {
        // TODO: update ETS-like peer table with latency now_ms - p.ts_m
        Ok(Instruction::Noop)
    }
}

impl Pong {
    pub const NAME: &'static str = "pong";

    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("ts_m")), Term::from(eetf::BigInteger { value: self.ts_m.into() }));

        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data).map_err(Error::EtfEncode)?;

        // compress to be symmetric with from_etf_bin
        let compressed = compress_to_vec(&etf_data, CompressionLevel::DefaultLevel as u8);
        Ok(compressed)
    }
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

    async fn handle_inner(&self) -> Result<Instruction, Error> {
        // TODO: update ETS-like tx pool with valid_txs
        Ok(Instruction::Noop)
    }
}

impl TxPool {
    pub const NAME: &'static str = "txpool";

    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        // create list of transaction binaries (txs_packed is directly a list of binaries)
        let tx_terms: Vec<Term> = self.valid_txs.iter().map(|tx| Term::from(Binary { bytes: tx.clone() })).collect();

        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        // txs_packed is directly a list of binary terms, not a binary containing an encoded list
        m.insert(Term::Atom(Atom::from("txs_packed")), Term::from(List { elements: tx_terms }));

        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data).map_err(Error::EtfEncode)?;

        // compress to be symmetric with from_etf_bin
        let compressed = compress_to_vec(&etf_data, CompressionLevel::DefaultLevel as u8);
        Ok(compressed)
    }

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

    async fn handle_inner(&self) -> Result<Instruction, Error> {
        // TODO: update ETS-like peer table with new IPs
        Ok(Instruction::Noop)
    }
}

impl Peers {
    pub const NAME: &'static str = "peers";

    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        // create list of IP strings
        let ip_terms: Vec<Term> =
            self.ips.iter().map(|ip| Term::from(Binary { bytes: ip.as_bytes().to_vec() })).collect();

        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("ips")), Term::from(List { elements: ip_terms }));

        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data).map_err(Error::EtfEncode)?;

        // compress to be symmetric with from_etf_bin
        let compressed = compress_to_vec(&etf_data, CompressionLevel::DefaultLevel as u8);
        Ok(compressed)
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
        let compressed_bin = ping.to_etf_bin().expect("should serialize");

        // deserialize back
        let result = from_etf_bin(&compressed_bin).expect("should deserialize");

        // check that we get the right type
        assert_eq!(result.typename(), "ping");
    }

    #[tokio::test]
    async fn test_pong_etf_roundtrip() {
        let pong = Pong { ts_m: 1234567890, seen_time_ms: 9876543210 };

        let compressed_bin = pong.to_etf_bin().expect("should serialize");
        let result = from_etf_bin(&compressed_bin).expect("should deserialize");

        // check that the result type is Pong
        assert_eq!(result.typename(), "pong");
    }

    #[tokio::test]
    async fn test_txpool_etf_roundtrip() {
        let txpool = TxPool { valid_txs: vec![vec![1, 2, 3], vec![4, 5, 6]] };

        let compressed_bin = txpool.to_etf_bin().expect("should serialize");
        let result = from_etf_bin(&compressed_bin).expect("should deserialize");

        assert_eq!(result.typename(), "txpool");
    }

    #[tokio::test]
    async fn test_peers_etf_roundtrip() {
        let peers = Peers { ips: vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()] };

        let compressed_bin = peers.to_etf_bin().expect("should serialize");
        let result = from_etf_bin(&compressed_bin).expect("should deserialize");

        assert_eq!(result.typename(), "peers");
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
}


impl Ping {
    /// Build compressed ETF payload for Ping with optional tips.
    /// When temporal/rooted are None, emits empty maps (Elixir-compatible bootstrap behavior).
    /// If ts_m is None, uses current unix millis.
    pub fn build_compressed_payload_optional(
        temporal: Option<EntrySummary>,
        rooted: Option<EntrySummary>,
        ts_m: Option<u128>,
    ) -> Result<Vec<u8>, Error> {
        let empty_map = Term::from(Map { map: HashMap::new() });
        let temporal_term = match temporal {
            Some(es) => es.to_etf_term()?,
            None => empty_map.clone(),
        };
        let rooted_term = match rooted {
            Some(es) => es.to_etf_term()?,
            None => empty_map.clone(),
        };

        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("temporal")), temporal_term);
        m.insert(Term::Atom(Atom::from("rooted")), rooted_term);
        let ts = ts_m.unwrap_or_else(get_unix_millis_now);
        m.insert(
            Term::Atom(Atom::from("ts_m")),
            Term::from(eetf::BigInteger { value: ts.into() }),
        );

        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data).map_err(Error::EtfEncode)?;
        let compressed = compress_to_vec(&etf_data, CompressionLevel::DefaultLevel as u8);
        Ok(compressed)
    }
}

impl Typename for NewPhoneWhoDis {
    fn typename(&self) -> &'static str {
        Self::NAME
    }
}

#[async_trait::async_trait]
impl Protocol for NewPhoneWhoDis {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let anr = map.get_binary::<Vec<u8>>("anr").ok_or(Error::BadEtf("anr"))?;
        let challenge = map.get_integer("challenge").ok_or(Error::BadEtf("challenge"))?;
        Ok(Self { anr, challenge })
    }

    async fn handle_inner(&self) -> Result<Instruction, Error> {
        // deserialize the sender's ANR from binary
        let anr_term = Term::decode(&self.anr[..])?;
        let anr_map = anr_term.get_term_map().ok_or(Error::BadEtf("anr_map"))?;
        
        // extract ANR fields
        let ip4_bytes = anr_map.get_binary::<Vec<u8>>("ip4").ok_or(Error::BadEtf("ip4"))?;
        let pk = anr_map.get_binary::<Vec<u8>>("pk").ok_or(Error::BadEtf("pk"))?;
        let pop = anr_map.get_binary::<Vec<u8>>("pop").ok_or(Error::BadEtf("pop"))?;
        let port = anr_map.get_integer::<u16>("port").ok_or(Error::BadEtf("port"))?;
        let signature = anr_map.get_binary::<Vec<u8>>("signature").ok_or(Error::BadEtf("signature"))?;
        let ts = anr_map.get_integer::<u64>("ts").ok_or(Error::BadEtf("ts"))?;
        let version_bytes = anr_map.get_binary::<Vec<u8>>("version").ok_or(Error::BadEtf("version"))?;
        let version = String::from_utf8_lossy(&version_bytes).to_string();
        
        // convert ip4 bytes to Ipv4Addr
        if ip4_bytes.len() != 4 {
            return Err(Error::BadEtf("ip4_len"));
        }
        let ip4 = std::net::Ipv4Addr::new(ip4_bytes[0], ip4_bytes[1], ip4_bytes[2], ip4_bytes[3]);
        
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

        // Return instruction to reply with What message
        // The handler will need to sign: sender_pk || challenge with OUR private key
        Ok(Instruction::ReplyWhatChallenge { anr: sender_anr, challenge: self.challenge })
    }
}

impl NewPhoneWhoDis {
    pub const NAME: &'static str = "new_phone_who_dis";

    pub fn new(anr: anr::ANR, challenge: u64) -> Result<Self, Error> {
        // pack ANR to binary
        let anr_binary = anr.to_etf_binary()?;
        Ok(Self { anr: anr_binary, challenge })
    }

    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("anr")), Term::Binary(Binary::from(self.anr.clone())));
        m.insert(Term::Atom(Atom::from("challenge")), Term::FixInteger(FixInteger::from(self.challenge as i32)));

        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data).map_err(Error::EtfEncode)?;

        // compress to be symmetric with from_etf_bin
        let compressed = compress_to_vec(&etf_data, CompressionLevel::DefaultLevel as u8);
        Ok(compressed)
    }
}

impl Typename for What {
    fn typename(&self) -> &'static str {
        Self::NAME
    }
}

#[async_trait::async_trait]
impl Protocol for What {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, Error> {
        let anr = map.get_binary::<Vec<u8>>("anr").ok_or(Error::BadEtf("anr"))?;
        let challenge = map.get_integer("challenge").ok_or(Error::BadEtf("challenge"))?;
        let signature = map.get_binary::<Vec<u8>>("signature").ok_or(Error::BadEtf("signature"))?;
        Ok(Self { anr, challenge, signature })
    }

    async fn handle_inner(&self) -> Result<Instruction, Error> {
        // deserialize the responder's ANR from binary (this is THEIR ANR, not ours)
        let anr_term = Term::decode(&self.anr[..])?;
        let anr_map = anr_term.get_term_map().ok_or(Error::BadEtf("anr_map"))?;
        
        // extract ANR fields (responder's ANR)
        let ip4_bytes = anr_map.get_binary::<Vec<u8>>("ip4").ok_or(Error::BadEtf("ip4"))?;
        let pk = anr_map.get_binary::<Vec<u8>>("pk").ok_or(Error::BadEtf("pk"))?;
        let pop = anr_map.get_binary::<Vec<u8>>("pop").ok_or(Error::BadEtf("pop"))?;
        let port = anr_map.get_integer::<u16>("port").ok_or(Error::BadEtf("port"))?;
        let signature_anr = anr_map.get_binary::<Vec<u8>>("signature").ok_or(Error::BadEtf("signature"))?;
        let ts = anr_map.get_integer::<u64>("ts").ok_or(Error::BadEtf("ts"))?;
        let version_bytes = anr_map.get_binary::<Vec<u8>>("version").ok_or(Error::BadEtf("version"))?;
        let version = String::from_utf8_lossy(&version_bytes).to_string();
        
        // convert ip4 bytes to Ipv4Addr
        if ip4_bytes.len() != 4 {
            return Err(Error::BadEtf("ip4_len"));
        }
        let ip4 = std::net::Ipv4Addr::new(ip4_bytes[0], ip4_bytes[1], ip4_bytes[2], ip4_bytes[3]);
        
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

        // The What message contains:
        // - anr: responder's ANR
        // - challenge: our challenge echoed back (should match what we stored when we sent new_phone_who_dis)
        // - signature: BLS(our_pk || challenge) signed with responder's private key
        // We need our own pk to verify, which we get from the context at higher level
        
        Ok(Instruction::ReceivedWhatResponse { 
            responder_anr: responder_anr, 
            challenge: self.challenge,
            their_signature: self.signature.clone()
        })
    }
}

impl What {
    pub const NAME: &'static str = "what?";

    pub fn new(anr: anr::ANR, challenge: u64, signature: Vec<u8>) -> Result<Self, Error> {
        // pack ANR to binary
        let anr_binary = anr.to_etf_binary()?;
        Ok(Self { anr: anr_binary, challenge, signature })
    }

    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("anr")), Term::Binary(Binary::from(self.anr.clone())));
        m.insert(Term::Atom(Atom::from("challenge")), Term::FixInteger(FixInteger::from(self.challenge as i32)));
        m.insert(Term::Atom(Atom::from("signature")), Term::Binary(Binary::from(self.signature.clone())));

        let term = Term::from(Map { map: m });
        let mut etf_data = Vec::new();
        term.encode(&mut etf_data).map_err(Error::EtfEncode)?;

        // compress to be symmetric with from_etf_bin
        let compressed = compress_to_vec(&etf_data, CompressionLevel::DefaultLevel as u8);
        Ok(compressed)
    }
}
