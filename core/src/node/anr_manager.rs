use crate::config::Config;
use crate::node::anr::{Anr, Error as AnrError};
use crate::utils::misc::get_unix_millis_now;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// ANR Manager with caching and validation
pub struct AnrManager {
    /// All known ANRs by public key
    anrs: Arc<RwLock<HashMap<Vec<u8>, Anr>>>,
    /// Our own ANR cache (refreshed every 60 minutes)
    my_anr: Arc<RwLock<Option<Anr>>>,
    /// Next refresh time for our ANR
    next_refresh: Arc<RwLock<u64>>,
    /// Shared secret cache
    shared_secrets: Arc<RwLock<HashMap<Vec<u8>, [u8; 48]>>>,
    /// Config reference
    config: Arc<Config>,
}

impl AnrManager {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            anrs: Arc::new(RwLock::new(HashMap::new())),
            my_anr: Arc::new(RwLock::new(None)),
            next_refresh: Arc::new(RwLock::new(0)),
            shared_secrets: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Get or build our ANR with 60-minute caching
    pub async fn get_or_build_my_anr(&self) -> Result<Anr, AnrError> {
        let now = get_unix_millis_now();
        let next_refresh = *self.next_refresh.read().await;

        if now < next_refresh {
            if let Some(anr) = &*self.my_anr.read().await {
                return Ok(anr.clone());
            }
        }

        // Build new ANR
        let anr = Anr::from_config(&self.config)?;

        // Update cache
        *self.my_anr.write().await = Some(anr.clone());
        *self.next_refresh.write().await = now + 60_000 * 60; // 60 minutes

        info!("Built new ANR, next refresh in 60 minutes");
        Ok(anr)
    }

    /// Insert a new ANR with validation
    pub async fn insert(&self, anr: Anr) -> Result<(), AnrError> {
        // Check if it has chain PoP
        let has_chain_pop = self.check_chain_pop(&anr.pk).await;
        let mut anr = anr;
        anr.hasChainPop = has_chain_pop;

        let pk = anr.pk.clone();
        let mut anrs = self.anrs.write().await;

        // Check if we have an existing ANR
        if let Some(old_anr) = anrs.get(&pk) {
            // Only update if newer and same IP/port OR if completely new connection
            if anr.ts <= old_anr.ts {
                return Ok(()); // Ignore older ANR
            }

            if old_anr.ip4 == anr.ip4 && old_anr.port == anr.port {
                // Same connection, just update
                anrs.insert(pk, anr);
            } else {
                // New connection, reset handshake status
                anr.handshaked = false;
                anr.error = None;
                anr.error_tries = 0;
                anr.next_check = anr.ts + 9; // Check in 9 seconds
                anrs.insert(pk, anr);
            }
        } else {
            // Brand new ANR
            anr.handshaked = false;
            anr.error = None;
            anr.error_tries = 0;
            anr.next_check = anr.ts + 9;
            anrs.insert(pk, anr);
        }

        Ok(())
    }

    /// Get shared secret with caching
    pub async fn get_shared_secret(&self, pk: &[u8]) -> Result<[u8; 48], AnrError> {
        // Check cache first
        {
            let cache = self.shared_secrets.read().await;
            if let Some(secret) = cache.get(pk) {
                return Ok(*secret);
            }
        }

        // Compute shared secret
        let sk = self.config.get_sk();
        let shared_secret = crate::utils::bls12_381::get_shared_secret(pk, &sk)?;

        // Store in cache
        {
            let mut cache = self.shared_secrets.write().await;
            cache.insert(pk.to_vec(), shared_secret);
        }

        debug!("Computed and cached shared secret for peer");
        Ok(shared_secret)
    }

    /// Set ANR as handshaked
    pub async fn set_handshaked(&self, pk: &[u8]) -> bool {
        let mut anrs = self.anrs.write().await;
        if let Some(anr) = anrs.get_mut(pk) {
            anr.handshaked = true;
            true
        } else {
            false
        }
    }

    /// Set last message time
    pub async fn set_last_message(&self, pk: &[u8]) {
        let mut anrs = self.anrs.write().await;
        if let Some(anr) = anrs.get_mut(pk) {
            anr.next_check = get_unix_millis_now() as u32 / 1000 + 60; // 60 seconds
        }
    }

    /// Get ANR by public key
    pub async fn get(&self, pk: &[u8]) -> Option<Anr> {
        let anrs = self.anrs.read().await;
        anrs.get(pk).cloned()
    }

    /// Check if ANR is handshaked and has valid IP
    pub async fn handshaked_and_valid_ip4(&self, pk: &[u8], ip: Ipv4Addr) -> bool {
        let anrs = self.anrs.read().await;
        if let Some(anr) = anrs.get(pk) {
            anr.handshaked && anr.ip4 == ip
        } else {
            false
        }
    }

    /// Get random unverified ANRs for handshaking
    pub async fn get_random_unverified(&self, count: usize) -> Vec<Anr> {
        let anrs = self.anrs.read().await;
        let now = get_unix_millis_now() as u32 / 1000;

        let mut unverified: Vec<_> = anrs
            .values()
            .filter(|anr| !anr.handshaked && anr.next_check <= now)
            .cloned()
            .collect();

        // Shuffle and take requested count
        use rand::seq::SliceRandom;
        let mut rng = rand::rng();
        unverified.shuffle(&mut rng);
        unverified.truncate(count);

        unverified
    }

    /// Get random verified ANRs
    pub async fn get_random_verified(&self, count: usize) -> Vec<Anr> {
        let anrs = self.anrs.read().await;

        let mut verified: Vec<_> = anrs
            .values()
            .filter(|anr| anr.handshaked)
            .cloned()
            .collect();

        // Shuffle and take requested count
        use rand::seq::SliceRandom;
        let mut rng = rand::rng();
        verified.shuffle(&mut rng);
        verified.truncate(count);

        verified
    }

    /// Get handshaked validators and peers for broadcasting
    pub async fn get_handshaked_and_online(&self) -> (Vec<Anr>, Vec<Anr>) {
        let anrs = self.anrs.read().await;
        let now = get_unix_millis_now() as u32 / 1000;

        let handshaked: Vec<_> = anrs
            .values()
            .filter(|anr| anr.handshaked && anr.next_check > now)
            .cloned()
            .collect();

        // Split into validators (with chain PoP) and regular peers
        let (validators, peers): (Vec<_>, Vec<_>) = handshaked
            .into_iter()
            .partition(|anr| anr.hasChainPop);

        (validators, peers)
    }

    /// Clear offline verified ANRs
    pub async fn clear_verified_offline(&self) {
        let mut anrs = self.anrs.write().await;
        let now = get_unix_millis_now() as u32 / 1000;

        anrs.retain(|_, anr| {
            // Keep if not handshaked OR still online
            !anr.handshaked || anr.next_check > now
        });

        info!("Cleared offline ANRs");
    }

    /// Cleanup old ANRs (v1.1.7 migration)
    pub async fn cleanup_old_anrs(&self) {
        let mut anrs = self.anrs.write().await;

        anrs.retain(|_, anr| {
            // Keep ANRs version 1.1.7 or higher
            let parts: Vec<&str> = anr.version.split('.').collect();
            if parts.len() != 3 {
                return false;
            }

            let major = parts[0].parse::<u8>().unwrap_or(0);
            let minor = parts[1].parse::<u8>().unwrap_or(0);
            let patch = parts[2].parse::<u8>().unwrap_or(0);

            major > 1 || (major == 1 && minor > 1) || (major == 1 && minor == 1 && patch >= 7)
        });

        info!("Cleaned up pre-v1.1.7 ANRs");
    }

    /// Seed initial ANRs from config
    pub async fn seed(&self) {
        // Add our own ANR
        if let Ok(my_anr) = self.get_or_build_my_anr().await {
            let _ = self.insert(my_anr.clone()).await;
            self.set_handshaked(&my_anr.pk).await;
        }

        // Add seed ANRs from config
        for seed_anr in &self.config.seed_anrs {
            let anr = Anr::from(seed_anr.clone());
            let _ = self.insert(anr).await;
        }

        // Cleanup old ANRs
        self.cleanup_old_anrs().await;

        // Set last message for all handshaked peers
        let anrs = self.anrs.read().await;
        let handshaked_pks: Vec<_> = anrs
            .values()
            .filter(|anr| anr.handshaked && anr.pk != self.config.get_pk())
            .map(|anr| anr.pk.clone())
            .collect();
        drop(anrs);

        for pk in handshaked_pks {
            self.set_last_message(&pk).await;
        }

        info!("Seeded {} initial ANRs", self.anrs.read().await.len());
    }

    // Check if a public key has a chain PoP (placeholder)
    async fn check_chain_pop(&self, _pk: &[u8]) -> bool {
        // TODO: Implement actual chain PoP check
        false
    }
}