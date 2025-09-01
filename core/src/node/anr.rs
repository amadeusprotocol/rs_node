use crate::config::{Config, SeedANR};
use crate::utils::bls12_381::{sign, verify};
use crate::utils::misc::{get_unix_millis_now, get_unix_secs_now};
use eetf::{Atom, BigInteger, Binary, FixInteger, Map, Term, Tuple};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;

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
    pub ts: u64,
    pub version: String,
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
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: seed.ts + 3,
        }
    }
}

impl Anr {
    // build a new anr with signature
    pub fn from_config(config: &Config) -> Result<Self, Error> {
        let ts = get_unix_secs_now();
        let mut anr = Anr {
            ip4: config.get_public_ipv4(),
            pk: config.get_pk().to_vec(),
            pop: config.get_pop(),
            port: 36969,
            ts,
            version: config.get_ver(),
            signature: vec![],
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: ts + 3,
        };

        // create signature over erlang term format like elixir
        let to_sign = anr.to_erlang_term_for_signing()?;
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ANR";
        let sig_array = sign(&config.get_sk(), &to_sign, dst)?;
        anr.signature = sig_array.to_vec();

        Ok(anr)
    }

    pub fn build(sk: &[u8], pk: &[u8], pop: &[u8], ip4: Ipv4Addr, version: String) -> Result<Self, Error> {
        let ts = get_unix_secs_now();
        let mut anr = Anr {
            ip4,
            pk: pk.to_vec(),
            pop: pop.to_vec(),
            port: 36969,
            ts,
            version,
            signature: vec![],
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: ts + 3,
        };

        // create signature over erlang term format like elixir
        let to_sign = anr.to_erlang_term_for_signing()?;
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ANR";
        let sig_array = sign(sk, &to_sign, dst)?;
        anr.signature = sig_array.to_vec();

        Ok(anr)
    }

    // convert to erlang term format for signing (excludes signature field)
    // matches elixir :erlang.term_to_binary([:deterministic])
    fn to_erlang_term_for_signing(&self) -> Result<Vec<u8>, Error> {
        // create a tuple instead of map for deterministic ordering
        // order: ip4, pk, pop, port, ts, version
        let tuple = Tuple::from(vec![
            Term::Binary(Binary::from(self.ip4.octets().to_vec())),
            Term::Binary(Binary::from(self.pk.clone())),
            Term::Binary(Binary::from(self.pop.clone())),
            Term::FixInteger(FixInteger::from(self.port as i32)),
            Term::BigInteger(BigInteger::from(self.ts as i64)),
            Term::Binary(Binary::from(self.version.as_bytes().to_vec())),
        ]);

        let term = Term::Tuple(tuple);
        let mut buf = Vec::new();
        term.encode(&mut buf)?;
        Ok(buf)
    }

    // verify anr signature and proof of possession
    pub fn verify_signature(&self) -> bool {
        if let Ok(to_sign) = self.to_erlang_term_for_signing() {
            let dst_anr = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ANR";
            let dst_pop = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

            // verify main signature
            if verify(&self.pk, &self.signature, &to_sign, dst_anr).is_err() {
                return false;
            }

            // verify proof of possession (pop is signature of pk with pk as key)
            verify(&self.pk, &self.pop, &self.pk, dst_pop).is_ok()
        } else {
            false
        }
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
        let serialized = packed_anr.to_erlang_term_binary()?;
        if serialized.len() > 390 {
            return Err(Error::TooLarge(serialized.len()));
        }

        // verify signature
        if !anr.verify_signature() {
            return Err(Error::InvalidSignature);
        }

        Ok(packed_anr)
    }

    // convert full anr to erlang term format for size validation
    // matches elixir :erlang.term_to_binary(anr, [:deterministic])
    fn to_erlang_term_binary(&self) -> Result<Vec<u8>, Error> {
        // create map with fields in deterministic order using IndexMap
        use indexmap::IndexMap;
        let mut index_map = IndexMap::new();
        // alphabetical order: ip4, pk, pop, port, signature, ts, version
        // Use Elixir format: ip4 as string (not binary)
        index_map.insert(
            Term::Atom(Atom::from("ip4")),
            Term::Binary(Binary::from(self.ip4.to_string().as_bytes().to_vec())),
        );
        index_map.insert(Term::Atom(Atom::from("pk")), Term::Binary(Binary::from(self.pk.clone())));
        index_map.insert(Term::Atom(Atom::from("pop")), Term::Binary(Binary::from(self.pop.clone())));
        index_map.insert(Term::Atom(Atom::from("port")), Term::FixInteger(FixInteger::from(self.port as i32)));
        index_map.insert(Term::Atom(Atom::from("signature")), Term::Binary(Binary::from(self.signature.clone())));
        index_map.insert(Term::Atom(Atom::from("ts")), Term::BigInteger(BigInteger::from(self.ts as i64)));
        index_map
            .insert(Term::Atom(Atom::from("version")), Term::Binary(Binary::from(self.version.as_bytes().to_vec())));

        let map = Map { map: index_map.into_iter().collect() };
        let term = Term::Map(map);
        let mut buf = Vec::new();
        term.encode(&mut buf)?;
        Ok(buf)
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
            handshaked: false,
            hasChainPop: false,
            error: None,
            error_tries: 0,
            next_check: 0,
        }
    }

    // convert ANR to ETF binary format for protocol transmission
    pub fn to_etf_binary(&self) -> Result<Vec<u8>, Error> {
        self.to_erlang_term_binary()
    }
}

/// NodeRegistry manages the network-wide identity verification system
/// Tracks ANR (Amadeus Network Record) entries with cryptographic signatures
#[derive(Debug, Clone)]
pub struct NodeRegistry {
    store: Arc<RwLock<HashMap<Vec<u8>, Anr>>>,
}

impl NodeRegistry {
    /// Create a new NodeRegistry instance
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with default configuration
    pub fn default() -> Self {
        Self::new()
    }

    /// Insert or update anr record
    pub async fn insert(&self, anr: Anr) -> Result<(), Error> {
        // check if we have chain pop for this pk (would need consensus module)
        // let hasChainPop = consensus::chain_pop(&anr.pk).is_some();
        let mut anr = anr;
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

        let pairs = self.not_handshaked_pk_ip4().await?;

        // deduplicate by ip4
        let mut seen_ips = HashSet::new();
        let mut unique_pairs = Vec::new();
        for (pk, ip4) in pairs {
            if seen_ips.insert(ip4) {
                unique_pairs.push((pk, ip4));
            }
        }

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
        for anr in config.seed_anrs.iter().cloned().map(Into::into) {
            self.insert(anr).await?;
        }

        if let Ok(my_anr) = Anr::from_config(config) {
            self.insert(my_anr).await?;
            self.set_handshaked(&config.get_pk()).await?;
        }

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
        let registry = NodeRegistry::new();
        
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
        let registry = NodeRegistry::new();
        
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
}