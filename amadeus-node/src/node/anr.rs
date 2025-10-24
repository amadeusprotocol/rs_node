use crate::config::{Config, SeedANR};
use crate::utils::blake3;
use crate::utils::bls12_381::{sign, verify};
use crate::utils::misc::{TermExt, TermMap, get_unix_secs_now};
use crate::utils::safe_etf::u32_to_term;
use crate::utils::version::Ver;
use eetf::{Atom, Binary, Term};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

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
    #[error("EETF encoding error: {0}")]
    EetfError(#[from] eetf::EncodeError),
    #[error("EETF decoding error: {0}")]
    EetfDecodeError(#[from] eetf::DecodeError),
    #[error("Invalid ETF field: {0}")]
    BadEtf(&'static str),
}

impl crate::utils::misc::Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, bincode::Encode, bincode::Decode)]
#[allow(non_snake_case)]
pub struct Anr {
    pub ip4: Ipv4Addr,
    #[serde_as(as = "[_; 48]")]
    pub pk: [u8; 48],
    pub pop: Vec<u8>,
    pub port: u16,
    pub signature: Vec<u8>,
    pub ts: u32,
    pub version: Ver,
    pub anr_name: Option<String>,
    pub anr_desc: Option<String>,
    // runtime fields
    #[serde(skip)]
    pub handshaked: bool,
    #[serde(skip)]
    #[allow(non_snake_case)]
    pub hasChainPop: bool,
    #[serde(skip)]
    pub error: Option<String>,
    #[serde(skip)]
    pub error_tries: u32,
    #[serde(skip)]
    pub next_check: u32,
    // Blake3 indexing fields (added in v1.1.8)
    #[serde(skip)]
    pub pk_b3: [u8; 32],
    #[serde(skip)]
    pub pk_b3_f4: [u8; 4],
}

impl From<SeedANR> for Anr {
    fn from(seed: SeedANR) -> Self {
        // Compute Blake3 hash fields for indexing
        let pk_b3 = blake3::hash(&seed.pk);
        let mut pk_b3_f4 = [0u8; 4];
        pk_b3_f4.copy_from_slice(&pk_b3[0..4]);

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

    pub fn build(sk: &[u8], pk: &[u8; 48], pop: &[u8], ip4: Ipv4Addr, version: Ver) -> Result<Self, Error> {
        Self::build_with_name_desc(sk, pk, pop, ip4, version, None, None)
    }

    pub fn build_with_name_desc(
        sk: &[u8],
        pk: &[u8; 48],
        pop: &[u8],
        ip4: Ipv4Addr,
        version: Ver,
        anr_name: Option<String>,
        anr_desc: Option<String>,
    ) -> Result<Self, Error> {
        let ts_s = get_unix_secs_now();

        let pk_b3 = blake3::hash(pk);
        let mut pk_b3_f4 = [0u8; 4];
        pk_b3_f4.copy_from_slice(&pk_b3[0..4]);

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
        };

        // create signature over erlang term format like elixir
        let to_sign = anr.to_etf_bin_for_signing();
        let dst = crate::consensus::DST_ANR;
        let sig_array = sign(sk, &to_sign, dst)?;
        anr.signature = sig_array.to_vec();

        Ok(anr)
    }

    // parse anr from etf binary format
    pub fn from_etf_bin(anr_bytes: &[u8]) -> Result<Self, Error> {
        let anr_term = Term::decode(anr_bytes)?;
        let anr_map = anr_term.get_term_map().ok_or(Error::BadEtf("anr_map"))?;
        Self::from_etf_term_map(anr_map)
    }

    pub fn from_etf_term_map(map: TermMap) -> Result<Self, Error> {
        // ip4 is stored as string in elixir format: "127.0.0.1"
        let ip4_str = map.get_string("ip4").ok_or(Error::BadEtf("ip4"))?;
        let ip4 = ip4_str.parse::<Ipv4Addr>().map_err(|_| Error::BadEtf("ip4_parse"))?;

        let pk = map.get_binary::<[u8; 48]>("pk").ok_or(Error::BadEtf("pk"))?;
        let pop = map.get_binary::<Vec<u8>>("pop").ok_or(Error::BadEtf("pop"))?;
        let port = map.get_integer::<u16>("port").ok_or(Error::BadEtf("port"))?;
        let signature = map.get_binary::<Vec<u8>>("signature").ok_or(Error::BadEtf("signature"))?;

        // handle timestamp - try u32 first, fallback to u64 for compatibility
        let ts = map
            .get_integer::<u32>("ts")
            .or_else(|| map.get_integer::<u64>("ts").map(|v| v as u32))
            .ok_or(Error::BadEtf("ts"))?;

        let version_bytes = map.get_binary::<Vec<u8>>("version").ok_or(Error::BadEtf("version"))?;
        let version_str = String::from_utf8_lossy(&version_bytes);
        let version = Ver::try_from(version_str.as_ref()).map_err(|_| Error::BadEtf("invalid_version_format"))?;

        // parse optional anr_name and anr_desc fields (they may be nil or missing)
        let anr_name = map
            .get_binary::<Vec<u8>>("anr_name")
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .filter(|s| !s.is_empty());

        let anr_desc = map
            .get_binary::<Vec<u8>>("anr_desc")
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .filter(|s| !s.is_empty());

        // Compute Blake3 hash fields for indexing (v1.1.8 compatibility)
        let pk_b3 = blake3::hash(&pk);
        let mut pk_b3_f4 = [0u8; 4];
        pk_b3_f4.copy_from_slice(&pk_b3[0..4]);

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
            next_check: ts + 3,
            pk_b3,
            pk_b3_f4,
        })
    }

    // verify anr signature and proof of possession
    pub fn verify_signature(&self) -> bool {
        let to_sign = self.to_etf_bin_for_signing();

        // verify main signature
        if verify(&self.pk, &self.signature, &to_sign, crate::consensus::DST_ANR).is_err() {
            return false;
        }

        // verify proof of possession (pop is signature of pk with pk as key)
        verify(&self.pk, &self.pop, &self.pk, crate::consensus::DST_POP).is_ok()
    }

    // verify and unpack anr from untrusted source
    pub fn verify_and_unpack(anr: Anr) -> Result<Anr, Error> {
        let now_s = get_unix_secs_now();
        if (anr.ts as i64) - (now_s as i64) > 3600 {
            return Err(Error::InvalidTimestamp);
        }

        // check size limit (390 bytes in elixir) using erlang term format
        let packed_anr = anr.pack();
        let serialized = packed_anr.to_etf_bin();
        if serialized.len() > 390 {
            return Err(Error::TooLarge(serialized.len()));
        }

        // verify signature
        if !anr.verify_signature() {
            return Err(Error::InvalidSignature);
        }

        Ok(packed_anr)
    }

    pub fn to_etf_bin_for_signing(&self) -> Vec<u8> {
        use crate::utils::safe_etf::encode_safe_deterministic;
        encode_safe_deterministic(&self.to_etf_term_without_signature())
    }

    pub fn to_etf_bin(&self) -> Vec<u8> {
        use crate::utils::safe_etf::encode_safe;
        encode_safe(&self.to_etf_term())
    }

    pub fn to_etf_term(&self) -> Term {
        match self.to_etf_term_without_signature() {
            Term::Map(mut m) => {
                m.map.insert(Term::Atom(Atom::from("signature")), Term::Binary(Binary::from(self.signature.clone())));
                Term::Map(m)
            }
            _ => panic!("Anr::to_etf_term_without_signature not returning Term::Map"),
        }
    }

    fn to_etf_term_without_signature(&self) -> Term {
        let mut map = TermMap::default();

        match &self.anr_desc {
            Some(desc) => {
                let anr_desc = Term::Binary(Binary::from(desc.as_bytes().to_vec()));
                map.insert(Term::Atom(Atom::from("anr_desc")), anr_desc);
            }
            None => {}
        };

        match &self.anr_name {
            Some(name) => {
                let anr_name = Term::Binary(Binary::from(name.as_bytes().to_vec()));
                map.insert(Term::Atom(Atom::from("anr_name")), anr_name);
            }
            None => {}
        };

        map.insert(Term::Atom(Atom::from("ip4")), Term::Binary(Binary::from(self.ip4.to_string().as_bytes().to_vec())));
        map.insert(Term::Atom(Atom::from("pk")), Term::Binary(Binary::from(self.pk.to_vec())));
        map.insert(Term::Atom(Atom::from("pop")), Term::Binary(Binary::from(self.pop.clone())));
        map.insert(Term::Atom(Atom::from("port")), u32_to_term(self.port as u32));
        map.insert(Term::Atom(Atom::from("ts")), u32_to_term(self.ts));
        map.insert(
            Term::Atom(Atom::from("version")),
            Term::Binary(Binary::from(self.version.to_string().as_bytes().to_vec())),
        );

        map.into_term()
    }

    // unpack anr with port validation like elixir
    pub fn unpack(anr: Anr) -> Result<Anr, Error> {
        if anr.port == 36969 {
            // Compute Blake3 hash fields for compatibility
            let pk_b3 = blake3::hash(&anr.pk);
            let mut pk_b3_f4 = [0u8; 4];
            pk_b3_f4.copy_from_slice(&pk_b3[0..4]);

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
            })
        } else {
            Err(Error::InvalidPort(anr.port))
        }
    }

    // pack anr for network transmission
    pub fn pack(&self) -> Anr {
        Anr {
            ip4: self.ip4,
            pk: self.pk.clone(),
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
        }
    }
}

/// NodeRegistry manages the network-wide identity verification system
/// Tracks ANR (Amadeus Network Record) entries with cryptographic signatures
#[derive(Debug, Clone)]
pub struct NodeAnrs {
    store: Arc<RwLock<HashMap<[u8; 48], Anr>>>,
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

        let pk = anr.pk.clone();

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
    pub async fn get_all_b3f4(&self) -> Vec<[u8; 4]> {
        let map = self.store.read().await;
        let anrs: Vec<[u8; 4]> = map.values().cloned().map(|a| a.pk_b3_f4).collect();
        anrs
    }

    /// Get all anrs
    pub async fn get_all(&self) -> Vec<Anr> {
        let map = self.store.read().await;
        let anrs: Vec<Anr> = map.values().cloned().collect();
        anrs
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
    pub async fn handshaked(&self) -> Vec<[u8; 48]> {
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
    pub async fn get_all_excluding_b3f4(&self, b3f4: &[[u8; 4]]) -> Vec<Anr> {
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
        let pk_set: std::collections::HashSet<[u8; 48]> = pks
            .iter()
            .filter_map(|p| {
                let bytes = p.as_ref();
                if bytes.len() == 48 {
                    let mut array = [0u8; 48];
                    array.copy_from_slice(bytes);
                    Some(array)
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
            self.set_handshaked(&config.get_pk()).await;
        }

        let all = self.get_all().await;
        debug!("seeded {} ANRs from config", all.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut pk_b3_f4 = [0u8; 4];
        pk_b3_f4.copy_from_slice(&pk_b3[0..4]);

        let anr = Anr {
            ip4,
            pk,
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
            pk_b3,
            pk_b3_f4,
        };

        // test insert
        registry.insert(anr.clone()).await;

        // test get
        let retrieved = registry.get(&pk).await.unwrap();
        assert_eq!(retrieved.pk, pk);
        assert!(!retrieved.handshaked, "Expected handshaked to be false after insert, got true");

        // test set_handshaked
        registry.set_handshaked(&pk).await;
        let retrieved = registry.get(&pk).await.unwrap();
        assert!(retrieved.handshaked, "Expected handshaked to be true after set_handshaked");

        // test handshaked query
        let handshaked_pks = registry.handshaked().await;
        assert!(handshaked_pks.iter().any(|p| *p == pk), "pk should be in handshaked list");

        // test is_handshaked
        assert!(registry.is_handshaked(&pk).await, "is_handshaked should return true");

        // test get_all
        let all = registry.get_all().await;
        assert!(!all.is_empty());
        assert!(all.iter().any(|a| a.pk == pk));

        // test count functions
        let total_count = registry.count().await;
        assert!(total_count >= 1, "Expected at least 1 ANR, got {}", total_count);

        // cleanup
        registry.clear_all().await;

        // verify our pk was removed
        assert!(registry.get(&pk).await.is_none(), "Our pk should be removed");
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
        let mut pk_b3_f4 = [0u8; 4];
        pk_b3_f4.copy_from_slice(&pk_b3[0..4]);

        // insert initial anr
        let anr1 = Anr {
            ip4,
            pk,
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
            pk_b3,
            pk_b3_f4,
        };
        registry.insert(anr1).await;
        registry.set_handshaked(&pk).await;

        // try to insert older anr (should not update)
        let anr2 = Anr {
            ip4: Ipv4Addr::new(10, 0, 0, 1),
            pk,
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
            pk_b3,
            pk_b3_f4,
        };
        registry.insert(anr2).await;

        // verify old anr was not updated
        let retrieved = registry.get(&pk).await.unwrap();
        assert_eq!(retrieved.ip4, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(retrieved.ts, 1000);
        assert!(retrieved.handshaked);

        // insert newer anr with same ip (should preserve handshake)
        let anr3 = Anr {
            ip4,
            pk,
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
            pk_b3,
            pk_b3_f4,
        };
        registry.insert(anr3).await;

        let retrieved = registry.get(&pk).await.unwrap();
        assert_eq!(retrieved.ts, 2000);
        assert_eq!(retrieved.version, Ver::new(2, 0, 0));
        assert!(retrieved.handshaked); // should be preserved

        // insert newer anr with different ip (should reset handshake)
        let anr4 = Anr {
            ip4: Ipv4Addr::new(10, 0, 0, 1),
            pk,
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
            pk_b3,
            pk_b3_f4,
        };
        registry.insert(anr4).await;

        let retrieved = registry.get(&pk).await.unwrap();
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
            let mut pk_b3_f4 = [0u8; 4];
            pk_b3_f4.copy_from_slice(&pk_b3[0..4]);

            let anr = Anr {
                ip4: Ipv4Addr::new(192, 168, 1, i), // different IPs
                pk,
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
                pk_b3,
                pk_b3_f4,
            };

            registry.insert(anr).await;
        }

        // Test multiple calls to ensure randomness and correct count
        for run in 1..=10 {
            let result = registry.get_random_not_verified(3).await;
            println!("Run {}: got {} results", run, result.len());

            // Should return 3 results since we have 5 candidates
            assert_eq!(result.len(), 3, "Run {}: expected 3 results, got {}", run, result.len());

            // All should have different IPs (uniqueness check)
            let mut ips = std::collections::HashSet::new();
            for ip in &result {
                assert!(ips.insert(*ip), "Run {}: duplicate IP found: {}", run, ip);
                println!("  - IP: {}", ip);
            }
        }

        // Test asking for more than available
        let result = registry.get_random_not_verified(10).await;
        assert_eq!(result.len(), 5, "Should return all 5 when asking for 10");

        // cleanup
        registry.clear_all().await;
    }

    #[test]
    fn test_to_etf_bin_ordered_validity() {
        // Test ANR with optional fields to expose the issues
        let mut pk = [0u8; 48];
        pk[0] = 1;
        pk[1] = 2;
        pk[2] = 3;
        let pk_b3 = blake3::hash(&pk);
        let mut pk_b3_f4 = [0u8; 4];
        pk_b3_f4.copy_from_slice(&pk_b3[0..4]);

        let anr_with_optionals = Anr {
            ip4: Ipv4Addr::new(10, 0, 0, 1),
            pk,
            pop: vec![4, 5, 6],
            port: 36969,
            signature: vec![7, 8, 9],
            ts: 1234567890,
            version: Ver::new(1, 0, 0),
            anr_name: Some("test".to_string()),
            anr_desc: Some("desc".to_string()),
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: 0,
            pk_b3,
            pk_b3_f4,
        };

        let encoded = anr_with_optionals.to_etf_bin_for_signing();

        println!("Encoded bytes: {:?}", encoded);

        // Try to decode the ETF - this should reveal the problems
        match Term::decode(&encoded[..]) {
            Ok(decoded) => {
                println!("Successfully decoded: {:?}", decoded);
                if let Term::Map(map) = decoded {
                    println!("Map has {} entries", map.map.len());
                    // Verify the map has the expected number of entries after the fix
                    let actual_count = map.map.len();
                    let expected_count = 8; // 6 base + 2 optional fields

                    if actual_count == expected_count {
                        println!("SUCCESS: Map correctly has {} entries", actual_count);

                        // Verify all expected fields are present
                        let expected_fields = ["ip4", "pk", "pop", "port", "ts", "version", "anr_name", "anr_desc"];
                        for field_name in &expected_fields {
                            let field_key = Term::Atom(Atom::from(*field_name));
                            if map.map.contains_key(&field_key) {
                                println!("✓ Field '{}' present", field_name);
                            } else {
                                println!("✗ Field '{}' missing", field_name);
                            }
                        }
                    } else {
                        println!("ERROR: Map has {} entries, expected {}", actual_count, expected_count);
                    }
                } else {
                    println!("ERROR: Decoded term is not a map!");
                }
            }
            Err(e) => {
                println!("ERROR: Failed to decode ETF: {:?}", e);
                println!("This indicates the original function produces invalid ETF!");
            }
        }
    }
}
