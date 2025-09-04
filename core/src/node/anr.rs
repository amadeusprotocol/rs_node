use crate::config::{Config, SeedANR};
use crate::utils::bls12_381::{sign, verify};
use crate::utils::misc::{get_unix_millis_now, get_unix_secs_now};
use crate::utils::safe_etf::{encode_map_with_ordered_keys, encode_with_small_atoms};
use eetf::{Atom, Binary, FixInteger, Map, Term};
use serde::{Deserialize, Serialize};
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
}

impl crate::utils::misc::Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

// ama node record
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, bincode::Encode, bincode::Decode)]
#[allow(non_snake_case)]
pub struct Anr {
    pub ip4: Ipv4Addr,
    pub pk: Vec<u8>,
    pub pop: Vec<u8>,
    pub port: u16,
    pub signature: Vec<u8>,
    pub ts: u32,
    pub version: String,
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
    pub next_check: u64,
}

impl From<SeedANR> for Anr {
    fn from(seed: SeedANR) -> Self {
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
            next_check: seed.ts as u64 + 3,
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

    pub fn build(sk: &[u8], pk: &[u8], pop: &[u8], ip4: Ipv4Addr, version: String) -> Result<Self, Error> {
        Self::build_with_name_desc(sk, pk, pop, ip4, version, None, None)
    }

    pub fn build_with_name_desc(
        sk: &[u8],
        pk: &[u8],
        pop: &[u8],
        ip4: Ipv4Addr,
        version: String,
        anr_name: Option<String>,
        anr_desc: Option<String>,
    ) -> Result<Self, Error> {
        let ts = get_unix_secs_now() as u32;
        let mut anr = Anr {
            ip4,
            pk: pk.to_vec(),
            pop: pop.to_vec(),
            port: 36969,
            ts,
            version,
            anr_name,
            anr_desc,
            signature: vec![],
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: ts as u64 + 3,
        };

        // create signature over erlang term format like elixir
        let to_sign = anr.to_etf_bin_ordered();
        let dst = crate::consensus::DST_ANR;
        let sig_array = sign(sk, &to_sign, dst)?;
        anr.signature = sig_array.to_vec();

        Ok(anr)
    }

    // convert to erlang term format for signing (excludes signature field)
    // matches elixir :erlang.term_to_binary([:deterministic])
    // Since the ETF library doesn't preserve order, manually create the exact bytes Elixir produces
    fn to_etf_bin_ordered(&self) -> Vec<u8> {
        encode_map_with_ordered_keys(
            &self.to_etf_term().try_into().unwrap(),
            &[
                "ip4", "pk", "pop", "port", "ts", "version", // Optional fields
                "anr_name", "anr_desc",
            ],
        )
    }

    // fn to_erlang_term_for_signing(&self) -> Vec<u8> {
    //     // Manually construct ETF bytes to match Elixir's deterministic encoding
    //     // Elixir excludes nil fields and uses small atoms (119) in deterministic order: ip4, pk, pop, port, ts, version
    //     let mut buf = Vec::new();
    //
    //     // ETF version marker
    //     buf.push(131);
    //
    //     let fields = 6 + self.anr_name.is_some() as u32 + self.anr_desc.is_some() as u32;
    //
    //     // Map header: type (116) + 4 bytes for count
    //     buf.push(116);
    //     buf.extend_from_slice(&fields.to_be_bytes());
    //
    //     // Field 1: ip4 (small atom + binary)
    //     buf.push(119); // small atom
    //     buf.push(3); // length
    //     buf.extend_from_slice(b"ip4");
    //
    //     // ip4 value as binary string
    //     let ip4_str = self.ip4.to_string();
    //     buf.push(109); // binary
    //     buf.extend_from_slice(&(ip4_str.len() as u32).to_be_bytes());
    //     buf.extend_from_slice(ip4_str.as_bytes());
    //
    //     // Field 2: pk (small atom + binary)
    //     buf.push(119); // small atom
    //     buf.push(2); // length
    //     buf.extend_from_slice(b"pk");
    //
    //     // pk value as binary
    //     buf.push(109); // binary
    //     buf.extend_from_slice(&(self.pk.len() as u32).to_be_bytes());
    //     buf.extend_from_slice(&self.pk);
    //
    //     // Field 3: pop (small atom + binary)
    //     buf.push(119); // small atom
    //     buf.push(3); // length
    //     buf.extend_from_slice(b"pop");
    //
    //     // pop value as binary
    //     buf.push(109); // binary
    //     buf.extend_from_slice(&(self.pop.len() as u32).to_be_bytes());
    //     buf.extend_from_slice(&self.pop);
    //
    //     // Field 4: port (small atom + integer)
    //     buf.push(119); // small atom
    //     buf.push(4); // length
    //     buf.extend_from_slice(b"port");
    //
    //     // port value as integer
    //     buf.push(98); // integer
    //     buf.extend_from_slice(&(self.port as u32).to_be_bytes());
    //
    //     // Field 5: ts (small atom + big integer)
    //     buf.push(119); // small atom
    //     buf.push(2); // length
    //     buf.extend_from_slice(b"ts");
    //
    //     // ts value as big integer
    //     buf.push(98); // integer (fits in 32-bit)
    //     buf.extend_from_slice(&(self.ts as u32).to_be_bytes());
    //
    //     // Field 6: version (small atom + binary)
    //     buf.push(119); // small atom
    //     buf.push(7); // length
    //     buf.extend_from_slice(b"version");
    //
    //     // version value as binary
    //     buf.push(109); // binary
    //     buf.extend_from_slice(&(self.version.len() as u32).to_be_bytes());
    //     buf.extend_from_slice(self.version.as_bytes());
    //
    //     if let Some(anr_name) = self.anr_name.as_ref() {
    //         // Field 7: anr_name (small atom + binary)
    //         buf.push(119); // small atom
    //         buf.push(8); // length
    //         buf.extend_from_slice(b"anr_name");
    //         // anr_name value as binary
    //         buf.push(109); // binary
    //         buf.extend_from_slice(&(anr_name.len() as u32).to_be_bytes());
    //         buf.extend_from_slice(anr_name.as_bytes());
    //     }
    //
    //     if let Some(anr_desc) = self.anr_desc.as_ref() {
    //         // Field 8: anr_desc (small atom + binary)
    //         buf.push(119); // small atom
    //         buf.push(8); // length
    //         buf.extend_from_slice(b"anr_desc");
    //         // anr_desc value as binary
    //         buf.push(109); // binary
    //         buf.extend_from_slice(&(anr_desc.len() as u32).to_be_bytes());
    //         buf.extend_from_slice(anr_desc.as_bytes());
    //     }
    //
    //     buf
    // }

    // verify anr signature and proof of possession
    pub fn verify_signature(&self) -> bool {
        let to_sign = self.to_etf_bin_ordered();

        // verify main signature
        if verify(&self.pk, &self.signature, &to_sign, crate::consensus::DST_ANR).is_err() {
            return false;
        }

        // verify proof of possession (pop is signature of pk with pk as key)
        verify(&self.pk, &self.pop, &self.pk, crate::consensus::DST_POP).is_ok()
    }

    // verify and unpack anr from untrusted source
    pub fn verify_and_unpack(anr: Anr) -> Result<Anr, Error> {
        // check not wound into future (10 min tolerance)
        // elixir uses :os.system_time(1000) for milliseconds
        let now_ms = get_unix_millis_now() as u64;

        let delta_ms = (now_ms as i64) - (anr.ts as i64 * 1000); // convert ts from seconds to ms
        let min10_ms = 60 * 10 * 1000;
        if delta_ms < -(min10_ms as i64) {
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

    pub fn to_etf_bin(&self) -> Vec<u8> {
        encode_with_small_atoms(&self.to_etf_term())
    }

    // convert full anr to erlang term format for size validation
    // matches elixir :erlang.term_to_binary(anr, [:deterministic])
    fn to_etf_term(&self) -> Term {
        let mut map = HashMap::new();

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
        map.insert(Term::Atom(Atom::from("pk")), Term::Binary(Binary::from(self.pk.clone())));
        map.insert(Term::Atom(Atom::from("pop")), Term::Binary(Binary::from(self.pop.clone())));
        map.insert(Term::Atom(Atom::from("port")), Term::FixInteger(FixInteger::from(self.port as i32)));
        map.insert(Term::Atom(Atom::from("signature")), Term::Binary(Binary::from(self.signature.clone())));
        // Handle u32 timestamp - use FixInteger for compatibility with manual encoding
        map.insert(Term::Atom(Atom::from("ts")), Term::FixInteger(FixInteger::from(self.ts as i32)));
        map.insert(Term::Atom(Atom::from("version")), Term::Binary(Binary::from(self.version.as_bytes().to_vec())));

        Term::Map(Map { map })
    }

    // unpack anr with port validation like elixir
    pub fn unpack(anr: Anr) -> Result<Anr, Error> {
        if anr.port == 36969 {
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
    store: Arc<RwLock<HashMap<Vec<u8>, Anr>>>,
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
    pub async fn insert(&self, mut anr: Anr) -> Result<(), Error> {
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

        Ok(())
    }

    /// Get anr by public key
    pub async fn get(&self, pk: &[u8]) -> Result<Option<Anr>, Error> {
        let map = self.store.read().await;
        Ok(map.get(pk).cloned())
    }

    /// Get all anrs
    pub async fn get_all(&self) -> Result<Vec<Anr>, Error> {
        let map = self.store.read().await;
        let anrs: Vec<Anr> = map.values().cloned().collect();
        Ok(anrs)
    }

    /// Set handshaked status
    pub async fn set_handshaked(&self, pk: &[u8]) -> Result<(), Error> {
        let mut map = self.store.write().await;
        if let Some(anr) = map.get_mut(pk) {
            anr.handshaked = true;
        }
        Ok(())
    }

    /// Get all handshaked node public keys
    pub async fn handshaked(&self) -> Result<Vec<Vec<u8>>, Error> {
        let map = self.store.read().await;
        let mut pks = Vec::new();
        for (k, v) in map.iter() {
            if v.handshaked {
                pks.push(k.clone());
            }
        }
        Ok(pks)
    }

    /// Get all not handshaked (pk, ip4) pairs
    pub async fn not_handshaked_pk_ip4(&self) -> Result<Vec<(Vec<u8>, Ipv4Addr)>, Error> {
        let map = self.store.read().await;
        let mut results = Vec::new();

        for (k, v) in map.iter() {
            if !v.handshaked {
                results.push((k.clone(), v.ip4));
            }
        }

        Ok(results)
    }

    /// Check if node is handshaked
    pub async fn is_handshaked(&self, pk: &[u8]) -> Result<bool, Error> {
        let map = self.store.read().await;
        Ok(map.get(pk).map(|v| v.handshaked).unwrap_or(false))
    }

    /// Check if node is handshaked with valid ip4
    pub async fn handshaked_and_valid_ip4(&self, pk: &[u8], ip4: &Ipv4Addr) -> Result<bool, Error> {
        let map = self.store.read().await;
        Ok(map.get(pk).map(|v| v.handshaked && v.ip4 == *ip4).unwrap_or(false))
    }

    /// Get random verified nodes
    pub async fn get_random_verified(&self, count: usize) -> Result<Vec<Anr>, Error> {
        use rand::seq::SliceRandom;

        let pks = self.handshaked().await?;
        let mut rng = rand::thread_rng();
        let selected: Vec<_> = pks.choose_multiple(&mut rng, count).cloned().collect();

        let mut anrs = Vec::new();
        for pk in selected {
            if let Some(anr) = self.get(&pk).await? {
                anrs.push(anr.pack());
            }
        }

        Ok(anrs)
    }

    /// Get random unverified nodes
    pub async fn get_random_not_handshaked(&self, count: usize) -> Result<Vec<(Vec<u8>, Ipv4Addr)>, Error> {
        use rand::seq::SliceRandom;
        use std::collections::HashSet;

        // deduplicate by ip4
        let mut seen_ips = HashSet::new();
        let mut unique_pairs = Vec::new();
        for (pk, ip4) in self.not_handshaked_pk_ip4().await? {
            if seen_ips.insert(ip4) {
                unique_pairs.push((pk, ip4));
            }
        }

        debug!("selecting {count} unverified anrs from {}", unique_pairs.len());

        let mut rng = rand::thread_rng();
        let selected: Vec<_> = unique_pairs.choose_multiple(&mut rng, count).cloned().collect();

        Ok(selected)
    }

    /// Get all validators from handshaked nodes
    pub async fn all_validators(&self) -> Result<Vec<Anr>, Error> {
        // this would need integration with consensus module to get validator set
        // for now, return all handshaked nodes
        let pks = self.handshaked().await?;
        let mut anrs = Vec::new();

        for pk in pks {
            if let Some(anr) = self.get(&pk).await? {
                anrs.push(anr);
            }
        }

        Ok(anrs)
    }

    /// Get all handshaked (pk, ip4) pairs
    pub async fn handshaked_pk_ip4(&self) -> Result<Vec<(Vec<u8>, Ipv4Addr)>, Error> {
        let map = self.store.read().await;
        let mut results = Vec::new();
        for (k, v) in map.iter() {
            if v.handshaked {
                results.push((k.clone(), v.ip4));
            }
        }
        Ok(results)
    }

    /// Get ip addresses for given public keys
    pub async fn by_pks_ip<T: AsRef<[u8]>>(&self, pks: &[T]) -> Result<Vec<Ipv4Addr>, Error> {
        // build a set of owned pk bytes for efficient lookup
        let pk_set: std::collections::HashSet<Vec<u8>> = pks.iter().map(|p| p.as_ref().to_vec()).collect();
        let mut ips = Vec::new();

        let map = self.store.read().await;
        for v in map.values() {
            if pk_set.contains(&v.pk) {
                ips.push(v.ip4);
            }
        }

        Ok(ips)
    }

    /// Seed initial anrs (called on startup)
    pub async fn seed(&self, config: &Config) -> Result<(), Error> {
        for anr in config.seed_anrs.iter().cloned().map(Into::<Anr>::into) {
            self.insert(anr).await?;
        }

        if let Ok(my_anr) = Anr::from_config(config) {
            self.insert(my_anr).await?;
            self.set_handshaked(&config.get_pk()).await?;
        }

        let all = self.get_all().await?;
        debug!("seeded {} ANRs from config", all.len());

        Ok(())
    }

    /// Clear all anrs (useful for testing)
    pub async fn clear_all(&self) -> Result<(), Error> {
        self.store.write().await.clear();
        Ok(())
    }

    /// Get count of anrs
    pub async fn count(&self) -> usize {
        self.store.read().await.len()
    }

    /// Get count of handshaked anrs
    pub async fn count_handshaked(&self) -> usize {
        let map = self.store.read().await;
        map.values().filter(|v| v.handshaked).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_anr_operations() {
        let registry = NodeAnrs::new();

        // create test keys with unique pk to avoid conflicts
        let _sk = [1; 32];
        let mut pk = vec![2; 48];
        // make pk unique per test run to avoid collision with parallel tests
        let pid_bytes = std::process::id().to_le_bytes();
        let time_bytes =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos().to_le_bytes();
        pk[..4].copy_from_slice(&pid_bytes);
        pk[4..12].copy_from_slice(&time_bytes[..8]);

        let pop = vec![3; 96];
        let ip4 = Ipv4Addr::new(127, 0, 0, 1);
        let version = "1.0.0".to_string();

        // manually create ANR without signature verification for testing
        let anr = Anr {
            ip4,
            pk: pk.clone(),
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
        };

        // test insert
        registry.insert(anr.clone()).await.unwrap();

        // test get
        let retrieved = registry.get(&pk).await.unwrap().unwrap();
        assert_eq!(retrieved.pk, pk);
        assert!(!retrieved.handshaked, "Expected handshaked to be false after insert, got true");

        // test set_handshaked
        registry.set_handshaked(&pk).await.unwrap();
        let retrieved = registry.get(&pk).await.unwrap().unwrap();
        assert!(retrieved.handshaked, "Expected handshaked to be true after set_handshaked");

        // test handshaked query
        let handshaked_pks = registry.handshaked().await.unwrap();
        assert!(handshaked_pks.iter().any(|p| p == &pk), "pk should be in handshaked list");

        // test is_handshaked
        assert!(registry.is_handshaked(&pk).await.unwrap(), "is_handshaked should return true");

        // test get_all
        let all = registry.get_all().await.unwrap();
        assert!(!all.is_empty());
        assert!(all.iter().any(|a| a.pk == pk));

        // test count functions
        let total_count = registry.count().await;
        assert!(total_count >= 1, "Expected at least 1 ANR, got {}", total_count);

        // cleanup
        registry.clear_all().await.unwrap();

        // verify our pk was removed
        assert!(registry.get(&pk).await.unwrap().is_none(), "Our pk should be removed");
    }

    #[tokio::test]
    async fn test_anr_update() {
        let registry = NodeAnrs::new();

        // create unique pk for this test
        let mut pk = vec![1; 48];
        let pid_bytes = std::process::id().to_le_bytes();
        let time_bytes =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos().to_le_bytes();
        pk[..4].copy_from_slice(&pid_bytes);
        pk[4..12].copy_from_slice(&time_bytes[..8]);
        let pop = vec![2; 96];
        let ip4 = Ipv4Addr::new(192, 168, 1, 1);
        let version = "1.0.0".to_string();

        // insert initial anr
        let anr1 = Anr {
            ip4,
            pk: pk.clone(),
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
        };
        registry.insert(anr1).await.unwrap();
        registry.set_handshaked(&pk).await.unwrap();

        // try to insert older anr (should not update)
        let anr2 = Anr {
            ip4: Ipv4Addr::new(10, 0, 0, 1),
            pk: pk.clone(),
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
        };
        registry.insert(anr2).await.unwrap();

        // verify old anr was not updated
        let retrieved = registry.get(&pk).await.unwrap().unwrap();
        assert_eq!(retrieved.ip4, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(retrieved.ts, 1000);
        assert!(retrieved.handshaked);

        // insert newer anr with same ip (should preserve handshake)
        let anr3 = Anr {
            ip4,
            pk: pk.clone(),
            pop: pop.clone(),
            port: 36969,
            signature: vec![0; 96],
            ts: 2000,
            version: "2.0.0".to_string(),
            anr_name: None,
            anr_desc: None,
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: 2003,
        };
        registry.insert(anr3).await.unwrap();

        let retrieved = registry.get(&pk).await.unwrap().unwrap();
        assert_eq!(retrieved.ts, 2000);
        assert_eq!(retrieved.version, "2.0.0");
        assert!(retrieved.handshaked); // should be preserved

        // insert newer anr with different ip (should reset handshake)
        let anr4 = Anr {
            ip4: Ipv4Addr::new(10, 0, 0, 1),
            pk: pk.clone(),
            pop,
            port: 36969,
            signature: vec![0; 96],
            ts: 3000,
            version: "3.0.0".to_string(),
            anr_name: None,
            anr_desc: None,
            handshaked: true,
            hasChainPop: false,
            error: Some("old error".to_string()),
            error_tries: 5,
            next_check: 3003,
        };
        registry.insert(anr4).await.unwrap();

        let retrieved = registry.get(&pk).await.unwrap().unwrap();
        assert_eq!(retrieved.ts, 3000);
        assert_eq!(retrieved.ip4, Ipv4Addr::new(10, 0, 0, 1));
        assert!(!retrieved.handshaked); // should be reset
        assert_eq!(retrieved.error, None); // should be reset
        assert_eq!(retrieved.error_tries, 0); // should be reset

        // cleanup
        registry.clear_all().await.unwrap();
    }

    #[tokio::test]
    async fn test_get_random_not_handshaked_multiple() {
        let registry = NodeAnrs::new();

        // Create 5 unique not-handshaked ANRs
        for i in 1..=5 {
            let mut pk = vec![i as u8; 48];
            // Make unique by adding time component
            let time_bytes =
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos().to_le_bytes();
            pk[40..48].copy_from_slice(&time_bytes[..8]);

            let anr = Anr {
                ip4: Ipv4Addr::new(192, 168, 1, i), // different IPs
                pk: pk.clone(),
                pop: vec![i as u8; 96],
                port: 36969,
                signature: vec![i as u8; 96],
                ts: 1000 + i as u32,
                version: format!("1.0.{}", i),
                anr_name: None,
                anr_desc: None,
                handshaked: false, // Explicitly not handshaked
                hasChainPop: false,
                error: None,
                error_tries: 0,
                next_check: 2000,
            };

            registry.insert(anr).await.unwrap();
        }

        // Test multiple calls to ensure randomness and correct count
        for run in 1..=10 {
            let result = registry.get_random_not_handshaked(3).await.unwrap();
            println!("Run {}: got {} results", run, result.len());

            // Should return 3 results since we have 5 candidates
            assert_eq!(result.len(), 3, "Run {}: expected 3 results, got {}", run, result.len());

            // All should have different IPs (uniqueness check)
            let mut ips = std::collections::HashSet::new();
            for (pk, ip) in &result {
                assert!(ips.insert(*ip), "Run {}: duplicate IP found: {}", run, ip);
                println!("  - IP: {}, PK: {}", ip, bs58::encode(pk).into_string());
            }
        }

        // Test asking for more than available
        let result = registry.get_random_not_handshaked(10).await.unwrap();
        assert_eq!(result.len(), 5, "Should return all 5 when asking for 10");

        // cleanup
        registry.clear_all().await.unwrap();
    }

    #[test]
    fn test_to_etf_bin_ordered_validity() {
        // Test ANR with optional fields to expose the issues
        let anr_with_optionals = Anr {
            ip4: Ipv4Addr::new(10, 0, 0, 1),
            pk: vec![1, 2, 3],
            pop: vec![4, 5, 6],
            port: 36969,
            signature: vec![7, 8, 9],
            ts: 1234567890,
            version: "1.0.0".to_string(),
            anr_name: Some("test".to_string()),
            anr_desc: Some("desc".to_string()),
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: 0,
        };

        let encoded = anr_with_optionals.to_etf_bin_ordered();

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
