use crate::config::{Config, SeedANR};
use crate::utils::blake3;
use crate::utils::bls12_381::{sign, verify};
use crate::utils::misc::get_unix_secs_now;
use crate::utils::version::Ver;
use crate::utils::{Hash, PublicKey};
use amadeus_utils::B3f4;
use amadeus_utils::vecpak;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
const UDP_PACKETS_LIMIT: u64 = 40_000;

pub static PROTO_RATE_LIMITS: Lazy<HashMap<&'static str, u64>> = Lazy::new(|| {
    use crate::consensus::doms::attestation::EventAttestation;
    use crate::consensus::doms::entry::Entry;
    use crate::consensus::doms::sol::Solution;
    use crate::node::protocol::{
        Catchup, CatchupReply, EventTip, EventTx, GetPeerAnrs, GetPeerAnrsReply, NewPhoneWhoDis, NewPhoneWhoDisReply,
        Ping, PingReply, SpecialBusiness, SpecialBusinessReply,
    };

    [
        (Ping::TYPENAME, 30),
        (PingReply::TYPENAME, 30),
        (EventTip::TYPENAME, 30),
        (EventTx::TYPENAME, 8000),
        (GetPeerAnrs::TYPENAME, 10),
        (GetPeerAnrsReply::TYPENAME, 10),
        (NewPhoneWhoDis::TYPENAME, 20),
        (NewPhoneWhoDisReply::TYPENAME, 20),
        (SpecialBusiness::TYPENAME, 200),
        (SpecialBusinessReply::TYPENAME, 200),
        (Catchup::TYPENAME, 20),
        (CatchupReply::TYPENAME, 20),
        (Entry::TYPENAME, 30),
        (EventAttestation::TYPENAME, 8000),
        (Solution::TYPENAME, 10_000),
    ]
    .into_iter()
    .collect()
});

#[derive(Debug, thiserror::Error, strum_macros::IntoStaticStr)]
pub enum Error {
    #[error("Failed to sign ANR: {0}")]
    SigningError(String),
    #[error("Failed to serialize ANR: {0}")]
    SerializationError(String),
    #[error("Invalid timestamp: ANR is from the future")]
    InvalidTimestamp,
    #[error("ANR too large: {0} bytes (max 390)")]
    TooLarge(usize),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid port: {0} (expected 36969)")]
    InvalidPort(u16),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("BLS error: {0}")]
    BlsError(#[from] crate::utils::bls12_381::Error),
    #[error("Parse error: {0}")]
    ParseError(&'static str),
}

impl crate::utils::misc::Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

#[derive(Debug, Clone, PartialEq, bincode::Encode, bincode::Decode)]
#[allow(non_snake_case)]
pub struct Anr {
    pub ip4: Ipv4Addr,
    pub pk: PublicKey,
    pub pop: Vec<u8>,
    pub port: u16,
    pub signature: Vec<u8>,
    pub ts: u32,
    pub version: Ver,
    pub anr_name: Option<String>,
    pub anr_desc: Option<String>,
    // runtime fields
    pub handshaked: bool,
    #[allow(non_snake_case)]
    pub hasChainPop: bool,
    pub error: Option<String>,
    pub error_tries: u32,
    pub next_check: u32,
    // Blake3 indexing fields (added in v1.1.8)
    pub pk_b3: Hash,
    pub pk_b3_f4: B3f4,
    pub proto_reqs: HashMap<String, u64>,
    pub udp_packets: u64,
}

impl serde::Serialize for Anr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("pk", &serde_bytes::Bytes::new(self.pk.as_ref()))?;
        map.serialize_entry("ts", &self.ts)?;
        map.serialize_entry("ip4", &self.ip4.to_string())?;
        map.serialize_entry("pop", &serde_bytes::Bytes::new(self.pop.as_ref()))?;
        map.serialize_entry("port", &self.port)?;
        map.serialize_entry("version", &self.version.to_string())?;
        map.serialize_entry("signature", &serde_bytes::Bytes::new(self.signature.as_ref()))?;
        if let Some(ref name) = self.anr_name {
            map.serialize_entry("anr_name", name)?;
        }
        if let Some(ref desc) = self.anr_desc {
            map.serialize_entry("anr_desc", desc)?;
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for Anr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};
        use std::fmt;

        struct AnrVisitor;

        impl<'de> Visitor<'de> for AnrVisitor {
            type Value = Anr;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Anr")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Anr, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut pk: Option<Vec<u8>> = None;
                let mut ts = None;
                let mut ip4_str: Option<String> = None;
                let mut pop = None;
                let mut port = None;
                let mut version_str: Option<String> = None;
                let mut signature = None;
                let mut anr_name = None;
                let mut anr_desc = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "pk" => {
                            pk = Some(map.next_value::<serde_bytes::ByteBuf>()?.into_vec());
                        }
                        "ts" => ts = Some(map.next_value()?),
                        "ip4" => ip4_str = Some(map.next_value()?),
                        "pop" => pop = Some(map.next_value::<serde_bytes::ByteBuf>()?.into_vec()),
                        "port" => port = Some(map.next_value()?),
                        "version" => version_str = Some(map.next_value()?),
                        "signature" => signature = Some(map.next_value::<serde_bytes::ByteBuf>()?.into_vec()),
                        "anr_name" => anr_name = Some(map.next_value()?),
                        "anr_desc" => anr_desc = Some(map.next_value()?),
                        _ => {
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                let pk_vec = pk.ok_or_else(|| serde::de::Error::missing_field("pk"))?;
                let pk_array: PublicKey =
                    pk_vec.try_into().map_err(|_| serde::de::Error::custom("pk must be 48 bytes"))?;
                let ts = ts.ok_or_else(|| serde::de::Error::missing_field("ts"))?;
                let ip4_str = ip4_str.ok_or_else(|| serde::de::Error::missing_field("ip4"))?;
                let ip4: Ipv4Addr = ip4_str.parse().map_err(|_| serde::de::Error::custom("invalid IPv4 address"))?;
                let pop = pop.ok_or_else(|| serde::de::Error::missing_field("pop"))?;
                let port = port.ok_or_else(|| serde::de::Error::missing_field("port"))?;
                let version_str = version_str.ok_or_else(|| serde::de::Error::missing_field("version"))?;
                let version =
                    Ver::try_from(version_str.as_str()).map_err(|_| serde::de::Error::custom("invalid version"))?;
                let signature = signature.ok_or_else(|| serde::de::Error::missing_field("signature"))?;

                let pk_b3 = Hash::from(blake3::hash(pk_array.as_ref()));
                let pk_b3_f4 = B3f4::new(pk_b3.as_ref());

                Ok(Anr {
                    ip4,
                    pk: pk_array,
                    pop,
                    port,
                    signature,
                    ts,
                    version,
                    anr_name,
                    anr_desc,
                    handshaked: false,
                    hasChainPop: false,
                    error: None,
                    error_tries: 0,
                    next_check: 0,
                    pk_b3,
                    pk_b3_f4,
                    proto_reqs: HashMap::new(),
                    udp_packets: 0,
                })
            }
        }

        deserializer.deserialize_map(AnrVisitor)
    }
}

impl From<SeedANR> for Anr {
    fn from(seed: SeedANR) -> Self {
        // Compute Blake3 hash fields for indexing
        let pk_b3 = Hash::from(blake3::hash(seed.pk.as_ref()));
        let pk_b3_f4 = B3f4::new(pk_b3.as_ref());

        Anr {
            ip4: seed.ip4.parse().unwrap_or(Ipv4Addr::new(0, 0, 0, 0)),
            pk: seed.pk,
            pop: vec![0u8; 96], // seed anrs don't include pop in config
            port: seed.port,
            signature: seed.signature,
            ts: seed.ts,
            version: seed.version,
            anr_name: None,
            anr_desc: None,
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: seed.ts + 3,
            pk_b3,
            pk_b3_f4,
            proto_reqs: HashMap::new(),
            udp_packets: 0,
        }
    }
}

impl Anr {
    // build a new anr with signature
    pub fn from_config(config: &Config) -> Result<Self, Error> {
        Self::build_with_name_desc(
            &config.get_sk(),
            &config.get_pk(),
            &config.get_pop(),
            config.get_public_ipv4(),
            config.get_ver(),
            config.anr_name.clone(),
            config.anr_desc.clone(),
        )
    }

    pub fn build(sk: &[u8], pk: &PublicKey, pop: &[u8], ip4: Ipv4Addr, version: Ver) -> Result<Self, Error> {
        Self::build_with_name_desc(sk, pk, pop, ip4, version, None, None)
    }

    pub fn build_with_name_desc(
        sk: &[u8],
        pk: &PublicKey,
        pop: &[u8],
        ip4: Ipv4Addr,
        version: Ver,
        anr_name: Option<String>,
        anr_desc: Option<String>,
    ) -> Result<Self, Error> {
        let ts_s = get_unix_secs_now();

        let pk_b3 = Hash::from(blake3::hash(pk.as_ref()));
        let pk_b3_f4 = B3f4::new(pk_b3.as_ref());

        let mut anr = Anr {
            ip4,
            pk: *pk,
            pop: pop.to_vec(),
            port: 36969,
            ts: ts_s,
            version,
            anr_name,
            anr_desc,
            signature: vec![],
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: ts_s + 3,
            pk_b3,
            pk_b3_f4,
            proto_reqs: HashMap::new(),
            udp_packets: 0,
        };

        // create signature over vecpak format (matching Elixir's RDB.vecpak_encode)
        let to_sign = anr.to_vecpak_for_signing();
        let dst = crate::consensus::DST_ANR;
        let sig_array = sign(sk, &to_sign, dst)?;
        anr.signature = sig_array.to_vec();

        Ok(anr)
    }

    /// Parse ANR from vecpak PropListMap (primary format)
    pub fn from_vecpak_map(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        // ip4 is stored as string in elixir format: "127.0.0.1"
        let ip4_str = map.get_string(b"ip4").ok_or(Error::ParseError("ip4"))?;
        let ip4 = ip4_str.parse::<Ipv4Addr>().map_err(|_| Error::ParseError("ip4_parse"))?;

        let pk = map.get_binary::<PublicKey>(b"pk").ok_or(Error::ParseError("pk"))?;
        let pop = map.get_binary::<Vec<u8>>(b"pop").ok_or(Error::ParseError("pop"))?;
        let port = map.get_integer::<u16>(b"port").ok_or(Error::ParseError("port"))?;
        let signature = map.get_binary::<Vec<u8>>(b"signature").ok_or(Error::ParseError("signature"))?;

        // handle timestamp - try u32 first, fallback to u64 for compatibility
        let ts = map
            .get_integer::<u32>(b"ts")
            .or_else(|| map.get_integer::<u64>(b"ts").map(|v| v as u32))
            .ok_or(Error::ParseError("ts"))?;

        let version_bytes = map.get_binary::<Vec<u8>>(b"version").ok_or(Error::ParseError("version"))?;
        let version_str = String::from_utf8_lossy(&version_bytes);
        let version = Ver::try_from(version_str.as_ref()).map_err(|_| Error::ParseError("invalid_version_format"))?;

        // parse optional anr_name and anr_desc fields (they may be nil atom or binary)
        let anr_name = map
            .get_binary::<Vec<u8>>(b"anr_name")
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .filter(|s| !s.is_empty());

        let anr_desc = map
            .get_binary::<Vec<u8>>(b"anr_desc")
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .filter(|s| !s.is_empty());

        // Compute Blake3 hash fields for indexing (v1.1.8 compatibility)
        let pk_b3 = Hash::from(blake3::hash(pk.as_ref()));
        let pk_b3_f4 = B3f4::new(pk_b3.as_ref());

        Ok(Self {
            ip4,
            pk,
            pop,
            port,
            signature,
            ts,
            version,
            anr_name,
            anr_desc,
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: 0,
            pk_b3,
            pk_b3_f4,
            proto_reqs: HashMap::new(),
            udp_packets: 0,
        })
    }

    // verify anr signature and proof of possession
    pub fn verify_signature(&self) -> bool {
        // verify proof of possession (pop is signature of pk with pk as key)
        // this proves the sender owns the private key for pk
        if verify(&self.pk.0, &self.pop, &self.pk.0, crate::consensus::DST_POP).is_err() {
            return false;
        }

        // verify main signature using vecpak encoding (matching Elixir's RDB.vecpak_encode)
        let to_sign = self.to_vecpak_for_signing();
        if verify(&self.pk.0, &self.signature, &to_sign, crate::consensus::DST_ANR).is_err() {
            return false;
        }

        true
    }

    // verify and unpack anr from untrusted source
    pub fn verify_and_unpack(anr: Anr) -> Result<Anr, Error> {
        let now_s = get_unix_secs_now();
        if (anr.ts as i64) - (now_s as i64) > 3600 {
            return Err(Error::InvalidTimestamp);
        }

        // check size limit (390 bytes in elixir) using vecpak format
        let packed_anr = anr.pack();
        let serialized = amadeus_utils::vecpak::encode(packed_anr.to_vecpak_term());
        if serialized.len() > 390 {
            return Err(Error::TooLarge(serialized.len()));
        }

        // verify signature
        if !anr.verify_signature() {
            return Err(Error::InvalidSignature);
        }

        Ok(packed_anr)
    }

    pub fn to_vecpak_for_signing(&self) -> Vec<u8> {
        // convert ANR to vecpak format for signing (matching Elixir's RDB.vecpak_encode)
        use amadeus_utils::vecpak::encode;
        let term = self.to_vecpak_term_without_signature();
        encode(term)
    }

    pub fn to_vecpak_term(&self) -> vecpak::Term {
        let mut pairs = self.to_vecpak_term_without_signature();
        if let vecpak::Term::PropList(ref mut p) = pairs {
            p.push((vecpak::Term::Binary(b"signature".to_vec()), vecpak::Term::Binary(self.signature.clone())));
        }
        pairs
    }

    fn to_vecpak_term_without_signature(&self) -> vecpak::Term {
        let mut pairs = Vec::new();

        // NOTE: anr_desc and anr_name are only included if they have a value.
        // if they're None, the field is NOT added to the map. this matches
        // elixir behavior where nil fields are not added during signing.
        if let Some(desc) = &self.anr_desc {
            pairs.push((vecpak::Term::Binary(b"anr_desc".to_vec()), vecpak::Term::Binary(desc.as_bytes().to_vec())));
        }

        if let Some(name) = &self.anr_name {
            pairs.push((vecpak::Term::Binary(b"anr_name".to_vec()), vecpak::Term::Binary(name.as_bytes().to_vec())));
        }

        pairs.push((
            vecpak::Term::Binary(b"ip4".to_vec()),
            vecpak::Term::Binary(self.ip4.to_string().as_bytes().to_vec()),
        ));
        pairs.push((vecpak::Term::Binary(b"pk".to_vec()), vecpak::Term::Binary(self.pk.to_vec())));
        pairs.push((vecpak::Term::Binary(b"pop".to_vec()), vecpak::Term::Binary(self.pop.clone())));
        pairs.push((vecpak::Term::Binary(b"port".to_vec()), vecpak::Term::VarInt(self.port as i128)));
        pairs.push((vecpak::Term::Binary(b"ts".to_vec()), vecpak::Term::VarInt(self.ts as i128)));
        pairs.push((
            vecpak::Term::Binary(b"version".to_vec()),
            vecpak::Term::Binary(self.version.to_string().as_bytes().to_vec()),
        ));

        vecpak::Term::PropList(pairs)
    }

    // unpack anr with port validation like elixir
    pub fn unpack(anr: Anr) -> Result<Anr, Error> {
        if anr.port == 36969 {
            // Compute Blake3 hash fields for compatibility
            let pk_b3 = Hash::from(blake3::hash(anr.pk.as_ref()));
            let pk_b3_f4 = B3f4::new(pk_b3.as_ref());

            Ok(Anr {
                ip4: anr.ip4,
                pk: anr.pk,
                pop: anr.pop,
                port: anr.port,
                signature: anr.signature,
                ts: anr.ts,
                version: anr.version,
                anr_name: anr.anr_name,
                anr_desc: anr.anr_desc,
                handshaked: false,
                hasChainPop: false,
                pk_b3,
                pk_b3_f4,
                error: None,
                error_tries: 0,
                next_check: 0,
                proto_reqs: HashMap::new(),
                udp_packets: 0,
            })
        } else {
            Err(Error::InvalidPort(anr.port))
        }
    }

    // pack anr for network transmission
    pub fn pack(&self) -> Anr {
        Anr {
            ip4: self.ip4.clone(),
            pk: self.pk,
            pop: self.pop.clone(),
            port: self.port,
            signature: self.signature.clone(),
            ts: self.ts,
            version: self.version.clone(),
            anr_name: self.anr_name.clone(),
            anr_desc: self.anr_desc.clone(),
            handshaked: false,
            hasChainPop: false,
            pk_b3: self.pk_b3,
            pk_b3_f4: self.pk_b3_f4,
            error: None,
            error_tries: 0,
            next_check: 0,
            proto_reqs: HashMap::new(),
            udp_packets: 0,
        }
    }
}

/// NodeRegistry manages the network-wide identity verification system
/// Tracks ANR (Amadeus Network Record) entries with cryptographic signatures
#[derive(Debug, Clone)]
pub struct NodeAnrs {
    store: Arc<RwLock<HashMap<PublicKey, Anr>>>,
}

impl NodeAnrs {
    /// Create a new NodeRegistry instance
    pub fn new() -> Self {
        Self { store: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Create with default configuration
    pub fn default() -> Self {
        Self::new()
    }

    /// Insert or update anr record
    pub async fn insert(&self, mut anr: Anr) {
        // check if we have chain pop for this pk (would need consensus module)
        // let hasChainPop = consensus::chain_pop(&anr.pk).is_some();
        anr.hasChainPop = false; // placeholder

        let pk = anr.pk;

        // check if anr already exists and update accordingly
        let mut map = self.store.write().await;
        map.entry(pk.clone())
            .and_modify(|old| {
                // only update if newer timestamp
                if anr.ts > old.ts {
                    // check if ip4/port changed
                    let same_ip4_port = old.ip4 == anr.ip4 && old.port == anr.port;
                    if !same_ip4_port {
                        // reset handshake status
                        anr.handshaked = false;
                        anr.error = None;
                        anr.error_tries = 0;
                        anr.next_check = get_unix_secs_now() + 3;
                    } else {
                        // preserve handshake status
                        anr.handshaked = old.handshaked;
                    }
                    *old = anr.clone();
                }
            })
            .or_insert_with(|| {
                // new anr
                anr.handshaked = false;
                anr.error = None;
                anr.error_tries = 0;
                anr.next_check = get_unix_secs_now() + 3;
                anr
            });
    }

    /// Get anr by public key
    pub async fn get(&self, pk: &[u8]) -> Option<Anr> {
        let map = self.store.read().await;
        map.get(pk).cloned()
    }

    /// Get anr by IP address
    pub async fn get_by_ip4(&self, ip4: Ipv4Addr) -> Option<Anr> {
        let map = self.store.read().await;
        map.values().find(|anr| anr.ip4 == ip4).cloned()
    }

    /// Get all anrs
    pub async fn get_all_b3f4(&self) -> Vec<B3f4> {
        let map = self.store.read().await;
        let anrs: Vec<B3f4> = map.values().cloned().map(|a| a.pk_b3_f4).collect();
        anrs
    }

    /// Get all anrs
    pub async fn get_all(&self) -> Vec<Anr> {
        let map = self.store.read().await;
        let anrs: Vec<Anr> = map.values().cloned().collect();
        anrs
    }

    /// Increment and return the frames counter
    pub async fn is_within_udp_limit(&self, ip4: Ipv4Addr) -> Option<bool> {
        let mut map = self.store.write().await;
        if let Some(anr) = map.values_mut().find(|anr| anr.ip4 == ip4) {
            anr.udp_packets += 1;
            return Some(anr.udp_packets < UDP_PACKETS_LIMIT);
        }
        None
    }

    /// Check if protocol message is within rate limit for this peer
    pub async fn is_within_proto_limit(&self, pk: &[u8], typename: &str) -> Option<bool> {
        let mut map = self.store.write().await;
        if let Some(anr) = map.get_mut(pk)
            && let Some(limit) = PROTO_RATE_LIMITS.get(typename)
        {
            let counter = anr.proto_reqs.entry(typename.to_string()).or_insert(0);
            *counter += 1;
            return Some(*counter < *limit);
        }
        None
    }

    /// Reset rate limiting counters for all anrs
    pub async fn update_rate_limiting_counters(&self) {
        let mut map = self.store.write().await;
        for anr in map.values_mut() {
            anr.udp_packets = anr.udp_packets.saturating_sub(UDP_PACKETS_LIMIT / 2);
            // decrement all proto counters by half their limits
            for (typename, limit) in PROTO_RATE_LIMITS.iter() {
                if let Some(counter) = anr.proto_reqs.get_mut(*typename) {
                    *counter = counter.saturating_sub(*limit / 2);
                }
            }
        }
    }

    /// Reset handshaked status (will silently return if pk not found)
    pub async fn unset_handshaked(&self, pk: &[u8]) {
        let mut map = self.store.write().await;
        if let Some(anr) = map.get_mut(pk) {
            anr.handshaked = false;
        }
    }

    /// Set handshaked status (will silently return if pk not found)
    pub async fn set_handshaked(&self, pk: &[u8]) {
        let mut map = self.store.write().await;
        if let Some(anr) = map.get_mut(pk) {
            anr.handshaked = true;
        }
    }

    /// Get all handshaked node public keys
    pub async fn handshaked(&self) -> Vec<PublicKey> {
        let map = self.store.read().await;
        let mut pks = Vec::new();
        for (k, v) in map.iter() {
            if v.handshaked {
                pks.push(k.clone());
            }
        }
        pks
    }

    /// Get all not handshaked (pk, ip4) pairs
    pub async fn get_all_not_handshaked_ip4(&self) -> Vec<Ipv4Addr> {
        let map = self.store.read().await;
        let mut results = Vec::new();

        for (_, v) in map.iter() {
            if !v.handshaked {
                results.push(v.ip4);
            }
        }

        results
    }

    /// Check if node is handshaked
    pub async fn is_handshaked(&self, pk: &[u8]) -> bool {
        let map = self.store.read().await;
        map.get(pk).map(|v| v.handshaked).unwrap_or(false)
    }

    /// Check if node is handshaked with valid ip4
    pub async fn handshaked_and_valid_ip4(&self, pk: &[u8], ip4: &Ipv4Addr) -> bool {
        let map = self.store.read().await;
        map.get(pk).map(|v| v.handshaked && v.ip4 == *ip4).unwrap_or(false)
    }

    /// Get random verified nodes
    pub async fn get_random_verified(&self, count: usize) -> Vec<Ipv4Addr> {
        use rand::seq::IndexedRandom;
        use std::collections::HashSet;

        // deduplicate by ip4
        let mut seen_ips = HashSet::new();
        let mut unique_pairs = Vec::new();
        for ip4 in self.get_all_handshaked_ip4().await {
            if seen_ips.insert(ip4) {
                unique_pairs.push(ip4);
            }
        }

        let mut rng = rand::rng();
        let selected: Vec<_> = unique_pairs.choose_multiple(&mut rng, count).cloned().collect();

        selected
    }

    /// Get random unverified nodes
    pub async fn get_random_not_verified(&self, count: usize) -> Vec<Ipv4Addr> {
        use rand::seq::IndexedRandom;
        use std::collections::HashSet;

        // deduplicate by ip4
        let mut seen_ips = HashSet::new();
        let mut unique_pairs = Vec::new();
        for ip4 in self.get_all_not_handshaked_ip4().await {
            if seen_ips.insert(ip4) {
                unique_pairs.push(ip4);
            }
        }

        let mut rng = rand::rng();
        let selected: Vec<_> = unique_pairs.choose_multiple(&mut rng, count).cloned().collect();

        selected
    }

    /// Get all handshaked (pk, ip4) pairs
    pub async fn get_all_excluding_b3f4(&self, b3f4: &[B3f4]) -> Vec<Anr> {
        let map = self.store.read().await;
        let mut results = Vec::new();
        for (_, v) in map.iter() {
            if !b3f4.contains(&v.pk_b3_f4) {
                results.push(v.clone());
            }
        }
        results
    }

    /// Get all handshaked (pk, ip4) pairs
    pub async fn get_all_handshaked_ip4(&self) -> Vec<Ipv4Addr> {
        let map = self.store.read().await;
        let mut results = Vec::new();

        for (_, v) in map.iter() {
            if v.handshaked {
                results.push(v.ip4);
            }
        }

        results
    }

    /// Get ip addresses for given public keys
    pub async fn by_pks_ip<T: AsRef<[u8]>>(&self, pks: &[T]) -> Vec<Ipv4Addr> {
        // build a set of owned pk bytes for efficient lookup
        let pk_set: std::collections::HashSet<PublicKey> = pks
            .iter()
            .filter_map(|p| {
                let bytes = p.as_ref();
                if bytes.len() == 48 {
                    let mut array = [0u8; 48];
                    array.copy_from_slice(bytes);
                    Some(PublicKey::from(array))
                } else {
                    None
                }
            })
            .collect();
        let mut ips = Vec::new();

        let map = self.store.read().await;
        for v in map.values() {
            if pk_set.contains(&v.pk) {
                ips.push(v.ip4);
            }
        }

        ips
    }

    /// Seed initial anrs (called on startup)
    pub async fn seed(&self, config: &Config) {
        for anr in config.seed_anrs.iter().cloned().map(Into::<Anr>::into) {
            self.insert(anr).await;
        }

        if let Ok(my_anr) = Anr::from_config(config) {
            self.insert(my_anr).await;
            self.set_handshaked(config.get_pk().as_ref()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::protocol::{NewPhoneWhoDis, NewPhoneWhoDisReply};
    use amadeus_utils::bls12_381;

    impl NodeAnrs {
        pub async fn clear_all(&self) {
            self.store.write().await.clear()
        }

        pub async fn count(&self) -> usize {
            self.store.read().await.len()
        }
    }

    #[tokio::test]
    async fn test_anr_operations() {
        let registry = NodeAnrs::new();

        // create test keys with unique pk to avoid conflicts
        let _sk = [1; 32];
        let mut pk = [2; 48];
        let pid_bytes = std::process::id().to_le_bytes();
        let now_ns_bytes = crate::utils::misc::get_unix_nanos_now().to_le_bytes();
        pk[..4].copy_from_slice(&pid_bytes);
        pk[4..12].copy_from_slice(&now_ns_bytes[..8]);

        let pop = vec![3; 96];
        let ip4 = Ipv4Addr::new(127, 0, 0, 1);
        let version = Ver::new(1, 0, 0);

        // manually create ANR without signature verification for testing
        let pk_b3 = blake3::hash(&pk);
        let pk_b3_f4 = B3f4::new(&pk_b3);

        let pk_wrapped = PublicKey(pk);
        let anr = Anr {
            ip4,
            pk: pk_wrapped,
            pop,
            port: 36969,
            signature: vec![0; 96],
            ts: 1234567890,
            version,
            anr_name: None,
            anr_desc: None,
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: 1234567893,
            pk_b3: Hash(pk_b3.into()),
            pk_b3_f4,
            proto_reqs: HashMap::new(),
            udp_packets: 0,
        };

        // test insert
        registry.insert(anr.clone()).await;

        // test get
        let retrieved = registry.get(&pk_wrapped.0).await.unwrap();
        assert_eq!(retrieved.pk.0, pk);
        assert!(!retrieved.handshaked, "Expected handshaked to be false after insert, got true");

        // test set_handshaked
        registry.set_handshaked(&pk_wrapped.0).await;
        let retrieved = registry.get(&pk_wrapped.0).await.unwrap();
        assert!(retrieved.handshaked, "Expected handshaked to be true after set_handshaked");

        // test handshaked query
        let handshaked_pks = registry.handshaked().await;
        assert!(handshaked_pks.iter().any(|p| p.0 == pk), "pk should be in handshaked list");

        // test is_handshaked
        assert!(registry.is_handshaked(&pk_wrapped.0).await, "is_handshaked should return true");

        // test get_all
        let all = registry.get_all().await;
        assert!(!all.is_empty());
        assert!(all.iter().any(|a| a.pk.0 == pk));

        // test count functions
        let total_count = registry.count().await;
        assert!(total_count >= 1, "Expected at least 1 ANR, got {}", total_count);

        // cleanup
        registry.clear_all().await;

        // verify our pk was removed
        assert!(registry.get(&pk_wrapped.0).await.is_none(), "Our pk should be removed");
    }

    #[tokio::test]
    async fn test_anr_update() {
        let registry = NodeAnrs::new();

        // create unique pk for this test
        let mut pk = [1; 48];
        let pid_bytes = std::process::id().to_le_bytes();
        let now_ns_bytes = crate::utils::misc::get_unix_nanos_now().to_le_bytes();
        pk[..4].copy_from_slice(&pid_bytes);
        pk[4..12].copy_from_slice(&now_ns_bytes[..8]);
        let pop = vec![2; 96];
        let ip4 = Ipv4Addr::new(192, 168, 1, 1);
        let version = Ver::new(1, 0, 0);

        // compute Blake3 fields for testing
        let pk_b3 = blake3::hash(&pk);
        let pk_b3_f4 = B3f4::new(&pk_b3);

        let pk_wrapped = PublicKey(pk);
        // insert initial anr
        let anr1 = Anr {
            ip4,
            pk: pk_wrapped,
            pop: pop.clone(),
            port: 36969,
            signature: vec![0; 96],
            ts: 1000,
            version: version.clone(),
            anr_name: None,
            anr_desc: None,
            handshaked: true,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: 1003,
            pk_b3: Hash(pk_b3.into()),
            pk_b3_f4,
            proto_reqs: HashMap::new(),
            udp_packets: 0,
        };
        registry.insert(anr1).await;
        registry.set_handshaked(&pk_wrapped.0).await;

        // try to insert older anr (should not update)
        let anr2 = Anr {
            ip4: Ipv4Addr::new(10, 0, 0, 1),
            pk: pk_wrapped,
            pop: pop.clone(),
            port: 36969,
            signature: vec![0; 96],
            ts: 999,
            version: version.clone(),
            anr_name: None,
            anr_desc: None,
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: 1002,
            pk_b3: Hash(pk_b3.into()),
            pk_b3_f4,
            proto_reqs: HashMap::new(),
            udp_packets: 0,
        };
        registry.insert(anr2).await;

        // verify old anr was not updated
        let retrieved = registry.get(&pk_wrapped.0).await.unwrap();
        assert_eq!(retrieved.ip4, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(retrieved.ts, 1000);
        assert!(retrieved.handshaked);

        // insert newer anr with same ip (should preserve handshake)
        let anr3 = Anr {
            ip4,
            pk: pk_wrapped,
            pop: pop.clone(),
            port: 36969,
            signature: vec![0; 96],
            ts: 2000,
            version: Ver::new(2, 0, 0),
            anr_name: None,
            anr_desc: None,
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: 2003,
            pk_b3: Hash(pk_b3.into()),
            pk_b3_f4,
            proto_reqs: HashMap::new(),
            udp_packets: 0,
        };
        registry.insert(anr3).await;

        let retrieved = registry.get(&pk_wrapped.0).await.unwrap();
        assert_eq!(retrieved.ts, 2000);
        assert_eq!(retrieved.version, Ver::new(2, 0, 0));
        assert!(retrieved.handshaked); // should be preserved

        // insert newer anr with different ip (should reset handshake)
        let anr4 = Anr {
            ip4: Ipv4Addr::new(10, 0, 0, 1),
            pk: pk_wrapped,
            pop,
            port: 36969,
            signature: vec![0; 96],
            ts: 3000,
            version: Ver::new(3, 0, 0),
            anr_name: None,
            anr_desc: None,
            handshaked: true,
            hasChainPop: false,
            error: Some("old error".to_string()),
            error_tries: 5,
            next_check: 3003,
            pk_b3: Hash(pk_b3.into()),
            pk_b3_f4,
            proto_reqs: HashMap::new(),
            udp_packets: 0,
        };
        registry.insert(anr4).await;

        let retrieved = registry.get(&pk_wrapped.0).await.unwrap();
        assert_eq!(retrieved.ts, 3000);
        assert_eq!(retrieved.ip4, Ipv4Addr::new(10, 0, 0, 1));
        assert!(!retrieved.handshaked); // should be reset
        assert_eq!(retrieved.error, None); // should be reset
        assert_eq!(retrieved.error_tries, 0); // should be reset

        // cleanup
        registry.clear_all().await;
    }

    #[tokio::test]
    async fn test_get_random_not_handshaked_multiple() {
        let registry = NodeAnrs::new();

        // Create 5 unique not-handshaked ANRs
        for i in 1..=5 {
            let mut pk = [i as u8; 48];
            let now_ns_bytes = crate::utils::misc::get_unix_nanos_now().to_le_bytes();
            pk[40..48].copy_from_slice(&now_ns_bytes[..8]);

            // compute Blake3 fields for this pk
            let pk_b3 = blake3::hash(&pk);
            let pk_b3_f4 = B3f4::new(&pk_b3);

            let anr = Anr {
                ip4: Ipv4Addr::new(192, 168, 1, i), // different IPs
                pk: PublicKey(pk),
                pop: vec![i as u8; 96],
                port: 36969,
                signature: vec![i as u8; 96],
                ts: 1000 + i as u32,
                version: Ver::new(1, 0, i as u8),
                anr_name: None,
                anr_desc: None,
                handshaked: false, // Explicitly not handshaked
                hasChainPop: false,
                error: None,
                error_tries: 0,
                next_check: 2000,
                pk_b3: Hash(pk_b3.into()),
                pk_b3_f4,
                proto_reqs: HashMap::new(),
                udp_packets: 0,
            };

            registry.insert(anr).await;
        }

        // Test multiple calls to ensure randomness and correct count
        for run in 1..=10 {
            let result = registry.get_random_not_verified(3).await;

            // Should return 3 results since we have 5 candidates
            assert_eq!(result.len(), 3, "Run {}: expected 3 results, got {}", run, result.len());

            // All should have different IPs (uniqueness check)
            let mut ips = std::collections::HashSet::new();
            for ip in &result {
                assert!(ips.insert(*ip), "Run {}: duplicate IP found: {}", run, ip);
            }
        }

        // Test asking for more than available
        let result = registry.get_random_not_verified(10).await;
        assert_eq!(result.len(), 5, "Should return all 5 when asking for 10");

        // cleanup
        registry.clear_all().await;
    }

    #[test]
    fn test_anr_vecpak_signature() {
        // Generate test keys
        let sk = bls12_381::generate_sk();
        let pk = bls12_381::get_public_key(&sk).expect("get pk");
        let pop = bls12_381::sign(&sk, &pk.0, crate::consensus::DST_POP).expect("sign pop");

        // Build ANR with vecpak signature
        let anr = Anr::build(&sk, &pk, &pop.0, Ipv4Addr::new(127, 0, 0, 1), Ver::new(1, 2, 5)).expect("build anr");

        // Verify the signature works
        assert!(anr.verify_signature(), "ANR signature should verify");

        // Print the vecpak encoded data for debugging
        let vecpak_data = anr.to_vecpak_for_signing();
        println!("Vecpak encoded ANR (hex): {}", hex::encode(&vecpak_data));
        println!("Vecpak size: {} bytes", vecpak_data.len());

        // Ensure it's using vecpak format, not ETF
        // Vecpak starts with tags 0-7, ETF starts with 131
        assert!(vecpak_data[0] <= 7, "Should be vecpak format, not ETF");
    }

    #[test]
    fn test_anr_signature_compatibility() {
        // This test verifies that our ANR signatures match Elixir's format
        // by checking the structure of the signed data

        let sk = bls12_381::generate_sk();
        let pk = bls12_381::get_public_key(&sk).expect("get pk");
        let pop = bls12_381::sign(&sk, &pk.0, crate::consensus::DST_POP).expect("sign pop");

        let anr = Anr::build(&sk, &pk, &pop.0, Ipv4Addr::new(192, 168, 1, 1), Ver::new(1, 2, 3)).expect("build anr");

        // Get the data we're signing
        let to_sign = anr.to_vecpak_for_signing();

        // Decode it to see the structure
        let decoded = vecpak::decode(&to_sign).expect("decode vecpak");

        println!("Decoded vecpak term: {:?}", decoded);

        // Verify it's a PropList (map in vecpak)
        match decoded {
            vecpak::Term::PropList(pairs) => {
                println!("ANR has {} fields", pairs.len());
                for (key, _value) in &pairs {
                    if let vecpak::Term::Binary(key_bytes) = key {
                        let key_str = String::from_utf8_lossy(key_bytes);
                        println!("Field: {}", key_str);
                    }
                }
            }
            _ => panic!("Expected PropList for ANR"),
        }
    }

    #[test]
    fn handshake_compatibility() {
        let p_hex = "0701010501026f700501116e65775f70686f6e655f77686f5f646973";
        let p_bytes = hex::decode(p_hex).expect("valid hex");
        let npwd: NewPhoneWhoDis = amadeus_utils::vecpak::from_slice(&p_bytes).unwrap();
        let rt_bytes = amadeus_utils::vecpak::to_vec(&npwd).unwrap();
        assert_eq!(rt_bytes, p_bytes);

        let p_hex = "0701020501026f700501176e65775f70686f6e655f77686f5f6469735f7265706c79050103616e72070107050102706b050130a9e81ed8c8eaaebd8dd53a889d8c5a8612ab7330275a5d39043e95200e7c1b66f0dc00c5307e867a55a9ad9e7ae4b9f005010274730304692634f205010369703405010c37322e392e3134342e313130050103706f70050160b62a96d62af0d2d7006ab560c64bde562df13ae642380a31d935276412c59f9944dceaa4060903e4ead197e97ad1654910be87ac556a5063e1d68df542aab1a3f75df3eab891a7cab572ba7170716c5487183ef28ef89f7c7555be2bb1d41218050104706f72740302906905010776657273696f6e050105312e332e300501097369676e6174757265050160b62d43994fa7614138d205ecefeb1677d4998574aac1db8fdd5673de4e1d2ae8391c4cf703007ce37778e20624650143068c59596b5838536ecfd05a0d0805b0baa04dcae97caf9f199232fbfff462ebb35bfc653576af43007ba9666a2952a7";
        let p_bytes = hex::decode(p_hex).expect("valid hex");
        let npwdr: NewPhoneWhoDisReply = amadeus_utils::vecpak::from_slice(&p_bytes).unwrap();
        let rt_bytes = amadeus_utils::vecpak::to_vec(&npwdr).unwrap();
        assert_eq!(rt_bytes, p_bytes);
    }
}
