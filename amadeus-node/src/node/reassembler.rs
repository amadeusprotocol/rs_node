use crate::utils::PublicKey;
use crate::utils::{bls12_381, misc::get_unix_millis_now, misc::get_unix_nanos_now};
use crate::{Config, Ver};
use aes_gcm::aead::{Aead, AeadCore, OsRng};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use std::collections::HashMap;
use std::hash::{Hash as StdHash, Hasher};
use tokio::sync::RwLock;

#[derive(Debug, thiserror::Error, strum_macros::IntoStaticStr)]
pub enum Error {
    #[error("AES encryption error")]
    AesError,
    #[error("BLS error: {0}")]
    BlsError(#[from] bls12_381::Error),
    #[error("Reed-Solomon error: {0}")]
    ReedSolomonError(#[from] crate::utils::reed_solomon::Error),
    #[error("Compression error: {0}")]
    CompressionError(#[from] std::io::Error),
    #[error("Invalid message format")]
    InvalidFormat,
    #[error("Invalid nonce length, expected 12 bytes, got {0}")]
    InvalidNonceLength(usize),
    #[error("Payload too small for nonce")]
    PayloadTooSmall,
}

impl crate::utils::misc::Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

/// Message format with AES-256-GCM encryption and Reed-Solomon sharding
/// Compatible with Elixir implementation using BLS-compatible shared secrets
#[derive(Debug, Clone)]
pub struct Message {
    pub version: Ver,
    pub pk: PublicKey,      // Sender's public key
    pub shard_index: u16,   // Current shard index
    pub shard_total: u16,   // Total number of shards
    pub ts_nano: u64,       // Timestamp in nanoseconds
    pub original_size: u32, // Size of original plaintext
    pub payload: Vec<u8>,   // Encrypted data (for single shard) or encrypted Reed-Solomon shard
}

impl Message {
    /// Calculate Reed-Solomon parameters based on payload size
    fn calculate_reed_solomon_params(payload_len: usize) -> (usize, usize, u16, usize) {
        let data_shards = payload_len.div_ceil(1024);
        let parity_shards = data_shards;
        let total_shards = (data_shards + parity_shards) as u16;
        let shards_to_send = data_shards + 1 + (data_shards / 4);
        (data_shards, parity_shards, total_shards, shards_to_send)
    }
    /// Derive AES-256 key using Elixir-compatible method: SHA256(shared_secret + timestamp_in_nanoseconds + iv)
    /// IMPORTANT: Elixir uses :binary.encode_unsigned which strips leading zeros
    fn derive_aes_key(shared_secret: &[u8], ts_nano: u64, iv: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        // encode_unsigned strips leading zeros - match Elixir behavior
        let ts_bytes = ts_nano.to_be_bytes();
        let first_nonzero = ts_bytes.iter().position(|&b| b != 0).unwrap_or(7);
        hasher.update(&ts_bytes[first_nonzero..]);
        hasher.update(iv);

        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Encrypt a message and optionally shard it using Reed-Solomon
    /// Returns a vector of Message instances (one per shard)
    pub fn encrypt(
        sender_pk: &PublicKey,
        shared_secret: &[u8],
        plaintext: &[u8],
        version: Ver,
    ) -> Result<Vec<Self>, Error> {
        let ts_nano = get_unix_nanos_now() as u64;

        // Compress first - use zstd for v1.2.3+, zlib for older versions
        let compressed = if version >= Ver::new(1, 2, 3) {
            zstd::encode_all(plaintext, 3).map_err(|e| Error::CompressionError(e.into()))?
        } else {
            crate::utils::compression::compress_with_zlib(plaintext)?
        };

        // AES-256-GCM encryption with Elixir-compatible key derivation
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let key_bytes = Self::derive_aes_key(shared_secret, ts_nano, &nonce);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let ciphertext_with_tag = cipher.encrypt(&nonce, compressed.as_slice()).map_err(|_| Error::AesError)?;

        // Combine in Elixir format: nonce + tag + ciphertext
        let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);
        let mut encrypted_payload = Vec::with_capacity(12 + 16 + ciphertext.len());
        encrypted_payload.extend_from_slice(&nonce);
        encrypted_payload.extend_from_slice(tag);
        encrypted_payload.extend_from_slice(ciphertext);

        // Check if we need Reed-Solomon sharding
        if encrypted_payload.len() < 1300 {
            // Single shard
            Ok(vec![Self {
                version,
                pk: *sender_pk,
                shard_index: 0,
                shard_total: 1,
                ts_nano,
                original_size: encrypted_payload.len() as u32,
                payload: encrypted_payload,
            }])
        } else {
            // Multi-shard with Reed-Solomon
            let (data_shards, parity_shards, total_shards, shards_to_send) =
                Self::calculate_reed_solomon_params(encrypted_payload.len());

            let mut rs = crate::utils::reed_solomon::ReedSolomonResource::new(data_shards, parity_shards)?;
            let encoded_shards = rs.encode_shards(&encrypted_payload)?;

            let limited_shards: Vec<_> = encoded_shards.into_iter().take(shards_to_send).collect();

            let mut messages = Vec::new();
            for (shard_index, shard_payload) in limited_shards {
                messages.push(Self {
                    version,
                    pk: *sender_pk,
                    shard_index: shard_index as u16,
                    shard_total: total_shards,
                    ts_nano,
                    original_size: encrypted_payload.len() as u32,
                    payload: shard_payload,
                });
            }

            Ok(messages)
        }
    }

    /// Decrypt a single Message (includes decompression for direct use)
    pub fn decrypt(&self, shared_secret: &[u8]) -> Result<Vec<u8>, Error> {
        let compressed = self.decrypt_raw(shared_secret)?;
        // Decompress based on sender version
        // v1.2.3+ uses zstd, older uses deflate
        let plaintext = if self.version >= Ver::new(1, 2, 3) {
            zstd::decode_all(compressed.as_slice()).map_err(|e| Error::CompressionError(e.into()))?
        } else {
            crate::utils::compression::decompress_with_zlib(&compressed)?
        };
        Ok(plaintext)
    }

    /// Raw decryption without decompression (for reassembler use)
    fn decrypt_raw(&self, shared_secret: &[u8]) -> Result<Vec<u8>, Error> {
        if self.payload.len() < 28 {
            // 12 (nonce) + 16 (tag) + minimum ciphertext
            return Err(Error::PayloadTooSmall);
        }

        // Extract nonce, tag, and ciphertext in Elixir format: nonce + tag + ciphertext
        let nonce_bytes = &self.payload[0..12];
        let tag_bytes = &self.payload[12..28];
        let ciphertext = &self.payload[28..];

        // Reconstruct ciphertext_with_tag for AES-GCM decryption
        let mut ciphertext_with_tag = Vec::with_capacity(ciphertext.len() + 16);
        ciphertext_with_tag.extend_from_slice(ciphertext);
        ciphertext_with_tag.extend_from_slice(tag_bytes);

        // Decrypt with Elixir-compatible key derivation
        let key_bytes = Self::derive_aes_key(shared_secret, self.ts_nano, nonce_bytes);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce, ciphertext_with_tag.as_slice()).map_err(|_e| {
            tracing::debug!(
                "AES decrypt failed. pk={} ts_nano={} nonce={} tag={} ciphertext_len={} key={}",
                hex::encode(&self.pk),
                self.ts_nano,
                hex::encode(nonce_bytes),
                hex::encode(tag_bytes),
                ciphertext.len(),
                hex::encode(&key_bytes)
            );
            Error::AesError
        })
    }

    /// Serialize to binary format
    pub fn to_bytes(&self) -> Vec<u8> {
        let ver = self.version.as_bytes();
        let capacity = 3 + 3 + 1 + 48 + 2 + 2 + 8 + 4 + self.payload.len();
        let mut out = Vec::with_capacity(capacity);

        // "AMA" (Amadeus Message Authentication)
        out.extend_from_slice(b"AMA");

        // version_3byte
        out.extend_from_slice(&ver);

        // reserved byte
        out.push(0);

        // pk (48 bytes)
        out.extend_from_slice(self.pk.as_ref());

        // shard_index::16, shard_total::16 (big-endian)
        out.extend_from_slice(&self.shard_index.to_be_bytes());
        out.extend_from_slice(&self.shard_total.to_be_bytes());

        // ts_nano::64 (big-endian)
        out.extend_from_slice(&self.ts_nano.to_be_bytes());

        // original_size::32 (big-endian)
        out.extend_from_slice(&self.original_size.to_be_bytes());

        // encrypted payload
        out.extend_from_slice(&self.payload);

        out
    }
}

impl TryFrom<&[u8]> for Message {
    type Error = Error;

    fn try_from(bin: &[u8]) -> Result<Self, Self::Error> {
        // Minimum header length (including reserved byte)
        if bin.len() < 3 + 3 + 1 + 48 + 2 + 2 + 8 + 4 {
            return Err(Error::InvalidFormat);
        }

        // Check magic
        if &bin[0..3] != b"AMA" {
            return Err(Error::InvalidFormat);
        }

        let version_bytes = &bin[3..6];
        let version = Ver::new(version_bytes[0], version_bytes[1], version_bytes[2]);

        // Skip reserved byte at position 6
        let pk_start = 7; // Was 6, now 7 to skip the reserved byte
        let pk_end = pk_start + 48;
        let pk = bin[pk_start..pk_end].try_into().expect("pk should be 48 bytes");

        let shard_index = u16::from_be_bytes(bin[pk_end..pk_end + 2].try_into().unwrap());
        let shard_total = u16::from_be_bytes(bin[pk_end + 2..pk_end + 4].try_into().unwrap());

        let ts_nano = u64::from_be_bytes(bin[pk_end + 4..pk_end + 12].try_into().unwrap());
        let original_size = u32::from_be_bytes(bin[pk_end + 12..pk_end + 16].try_into().unwrap());

        let payload = bin[pk_end + 16..].to_vec();

        Ok(Self { version, pk, shard_index, shard_total, ts_nano, original_size, payload })
    }
}

/// Reassembler for encrypted message shards with Reed-Solomon error correction
pub struct ReedSolomonReassembler {
    reorg: RwLock<HashMap<ReassemblyKey, TimedEntryState>>,
    cache: RwLock<HashMap<PublicKey, TimedSharedSecret>>,
}

struct TimedSharedSecret {
    shared_secret: PublicKey,
    ts_m: u64,
}

impl TimedSharedSecret {
    fn new(shared_secret: PublicKey) -> Self {
        let ts_m = get_unix_millis_now();
        Self { shared_secret, ts_m }
    }
}

#[derive(Clone, Debug, Eq)]
struct ReassemblyKey {
    pk: PublicKey,
    ts_nano: u64,
    shard_total: u16,
    original_size: u32,
    version: Ver,
}

impl From<&Message> for ReassemblyKey {
    fn from(msg: &Message) -> Self {
        Self {
            pk: msg.pk,
            ts_nano: msg.ts_nano,
            shard_total: msg.shard_total,
            original_size: msg.original_size,
            version: msg.version,
        }
    }
}

impl PartialEq for ReassemblyKey {
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk && self.ts_nano == other.ts_nano && self.shard_total == other.shard_total
    }
}

impl StdHash for ReassemblyKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pk.hash(state);
        self.ts_nano.hash(state);
        self.shard_total.hash(state);
    }
}

#[derive(Debug)]
enum EntryState {
    Collecting(HashMap<u16, Vec<u8>>), // shard_index -> encrypted shard data
    Spent,
}

struct TimedEntryState {
    ts_m: u64,
    state: EntryState,
}

impl TimedEntryState {
    fn new(state: EntryState) -> Self {
        let ts_m = get_unix_millis_now();
        Self { ts_m, state }
    }
}

impl Default for ReedSolomonReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl ReedSolomonReassembler {
    pub fn new() -> Self {
        Self { reorg: RwLock::new(HashMap::new()), cache: RwLock::new(HashMap::new()) }
    }

    /// Clean up stale incomplete reassembly entries older than `seconds`
    pub async fn clear_stale(&self) -> usize {
        let threshold_ms = get_unix_millis_now().saturating_sub(8_000);
        let mut map = self.reorg.write().await;
        let size_before = map.len();
        map.retain(|_k, v| v.ts_m > threshold_ms);
        let cleared = size_before - map.len();
        let mut map = self.cache.write().await;
        map.retain(|_k, v| v.ts_m > threshold_ms);

        cleared
    }

    /// Add a shard to the reassembly, return complete message if ready
    /// Takes binary data and parses it as Message
    pub async fn add_shard(&self, bin: &[u8], config_sk: &[u8]) -> Result<Option<(Vec<u8>, PublicKey)>, Error> {
        let encrypted_msg = Message::try_from(bin)?;
        let key = ReassemblyKey::from(&encrypted_msg);

        // Single shard message
        if key.shard_total == 1 {
            let shared_secret = bls12_381::get_shared_secret(&key.pk, config_sk)?;
            // Decrypt and then decompress (reverse of build_shards process)
            let decrypted_compressed = encrypted_msg.decrypt_raw(shared_secret.as_ref())?;
            // Decompress based on sender version - must match what Message::encrypt uses
            let payload = if key.version >= Ver::new(1, 2, 3) {
                zstd::decode_all(decrypted_compressed.as_slice()).map_err(|e| Error::CompressionError(e.into()))?
            } else {
                crate::utils::compression::decompress_with_zlib(&decrypted_compressed)?
            };
            return Ok(Some((payload, key.pk)));
        }

        let data_shards = (key.shard_total / 2) as usize;

        // Insert or update under lock; if threshold met, collect shards and mark Spent
        let mut maybe_shards: Option<Vec<(usize, Vec<u8>)>> = None;
        {
            let mut map = self.reorg.write().await;
            use std::collections::hash_map::Entry;
            match map.entry(key.clone()) {
                Entry::Vacant(v) => {
                    let mut state_map = HashMap::new();
                    state_map.insert(encrypted_msg.shard_index, encrypted_msg.payload.clone());
                    v.insert(TimedEntryState::new(EntryState::Collecting(state_map)));
                }
                Entry::Occupied(mut occ) => {
                    match occ.get_mut() {
                        TimedEntryState { state: EntryState::Spent, .. } => {
                            // nothing to do
                        }
                        TimedEntryState { state: EntryState::Collecting(shards_map), .. } => {
                            shards_map.insert(encrypted_msg.shard_index, encrypted_msg.payload.clone());
                            if shards_map.len() >= data_shards {
                                let shards: Vec<(usize, Vec<u8>)> =
                                    shards_map.iter().map(|(idx, bytes)| (*idx as usize, bytes.clone())).collect();
                                // Mark as spent to avoid reuse and release memory
                                *occ.get_mut() = TimedEntryState::new(EntryState::Spent);
                                maybe_shards = Some(shards);
                            }
                        }
                    }
                }
            }
        }

        if let Some(shards) = maybe_shards {
            // Decode outside the lock - note: we reconstruct the encrypted payload, not the original
            let mut rs_res = crate::utils::reed_solomon::ReedSolomonResource::new(data_shards, data_shards)?;
            // For Message, we reconstruct to get the encrypted payload (nonce + ciphertext)
            // The original_size in the key refers to the encrypted payload size, not the plaintext size
            let encrypted_payload =
                rs_res.decode_shards(shards, key.shard_total as usize, key.original_size as usize)?;

            let shared_secret = bls12_381::get_shared_secret(&key.pk, config_sk)?;

            // Create a temporary Message for decryption
            let temp_msg = Message {
                version: key.version,
                pk: key.pk,
                shard_index: 0,
                shard_total: 1,
                ts_nano: key.ts_nano,
                original_size: key.original_size,
                payload: encrypted_payload,
            };

            // Decrypt and then decompress (reverse of build_shards process)
            let decrypted_compressed = temp_msg.decrypt_raw(shared_secret.as_ref())?;
            // Decompress based on sender version - must match what Message::encrypt uses
            let payload = if key.version >= Ver::new(1, 2, 3) {
                zstd::decode_all(decrypted_compressed.as_slice()).map_err(|e| Error::CompressionError(e.into()))?
            } else {
                crate::utils::compression::decompress_with_zlib(&decrypted_compressed)?
            };
            return Ok(Some((payload, key.pk)));
        }

        Ok(None)
    }

    /// Creates encrypted message shards from payload and target public key
    /// This is the main method for sending encrypted messages to specific recipients
    pub async fn build_shards(
        &self,
        config: &Config,
        payload: &[u8],
        target_pk: &PublicKey,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let version = config.get_ver();
        let sender_pk = config.get_pk();
        let shared_secret = self.get_shared_secret(config, target_pk).await?;
        let encrypted_messages = Message::encrypt(&sender_pk, shared_secret.as_ref(), payload, version)?;

        let mut shards = Vec::new();
        for encrypted_msg in encrypted_messages {
            shards.push(encrypted_msg.to_bytes());
        }

        Ok(shards)
    }

    async fn get_shared_secret(&self, config: &Config, pk: &PublicKey) -> Result<PublicKey, Error> {
        use std::collections::hash_map::Entry;

        let mut map = self.cache.write().await;
        match map.entry(pk.clone()) {
            Entry::Vacant(v) => {
                let shared_secret = bls12_381::get_shared_secret(pk, &config.get_sk())?;
                v.insert(TimedSharedSecret::new(shared_secret));
                Ok(shared_secret)
            }
            Entry::Occupied(e) => Ok(e.get().shared_secret),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::bls12_381;

    #[test]
    fn test_encrypted_message_round_trip() {
        // Use valid test keys generated by our key generation function
        let sk_alice = bls12_381::generate_sk();
        let sk_bob = bls12_381::generate_sk();

        let pk_alice = bls12_381::get_public_key(&sk_alice).expect("get pk alice");
        let pk_bob = bls12_381::get_public_key(&sk_bob).expect("get pk bob");

        // Compute shared secrets (should be symmetric)
        let shared_secret_alice = bls12_381::get_shared_secret(&pk_bob, &sk_alice).expect("shared secret alice");
        let shared_secret_bob = bls12_381::get_shared_secret(&pk_alice, &sk_bob).expect("shared secret bob");

        assert_eq!(shared_secret_alice, shared_secret_bob, "Shared secrets should be symmetric");

        // Test message
        let test_message = b"Hello from Alice to Bob via encrypted message!";
        let version = Ver::new(1, 1, 8);

        // Alice encrypts a message to Bob
        let encrypted_messages = Message::encrypt(&pk_alice, &shared_secret_alice.0, test_message, version)
            .expect("encryption should succeed");

        assert_eq!(encrypted_messages.len(), 1, "Should create single message for small payload");
        let encrypted_msg = &encrypted_messages[0];

        // Verify message structure
        assert_eq!(encrypted_msg.version, version);
        assert_eq!(encrypted_msg.pk.0, pk_alice.0);
        assert_eq!(encrypted_msg.shard_index, 0);
        assert_eq!(encrypted_msg.shard_total, 1);
        // original_size is the encrypted payload size (nonce + tag + ciphertext), not plaintext size
        assert_eq!(encrypted_msg.original_size, encrypted_msg.payload.len() as u32);

        // Bob decrypts the message
        let decrypted = encrypted_msg.decrypt(&shared_secret_bob.0).expect("decryption should succeed");

        assert_eq!(decrypted, test_message, "Decrypted message should match original");

        // Test serialization/deserialization
        let serialized = encrypted_msg.to_bytes();
        let deserialized = Message::try_from(serialized.as_slice()).expect("deserialization should succeed");

        assert_eq!(deserialized.version, encrypted_msg.version);
        assert_eq!(deserialized.pk, encrypted_msg.pk);
        assert_eq!(deserialized.shard_index, encrypted_msg.shard_index);
        assert_eq!(deserialized.shard_total, encrypted_msg.shard_total);
        assert_eq!(deserialized.ts_nano, encrypted_msg.ts_nano);
        assert_eq!(deserialized.original_size, encrypted_msg.original_size);
        assert_eq!(deserialized.payload, encrypted_msg.payload);

        // Bob can still decrypt the deserialized message
        let decrypted2 =
            deserialized.decrypt(&shared_secret_bob.0).expect("decryption of deserialized message should succeed");
        assert_eq!(decrypted2, test_message, "Decrypted deserialized message should match original");
    }

    #[test]
    fn test_elixir_compatible_64_byte_keys() {
        // Test with 64-byte secret keys like Elixir generates
        let sk_64_alice = bls12_381::generate_sk();
        let sk_64_bob = bls12_381::generate_sk();

        let pk_alice = bls12_381::get_public_key(&sk_64_alice).expect("get pk alice 64");
        let pk_bob = bls12_381::get_public_key(&sk_64_bob).expect("get pk bob 64");

        let shared_secret_alice = bls12_381::get_shared_secret(&pk_bob, &sk_64_alice).expect("shared secret alice 64");
        let shared_secret_bob = bls12_381::get_shared_secret(&pk_alice, &sk_64_bob).expect("shared secret bob 64");

        assert_eq!(shared_secret_alice, shared_secret_bob, "64-byte shared secrets should be symmetric");

        let test_message = b"64-byte key compatibility test message";
        let version = Ver::new(1, 1, 7);

        let encrypted_messages = Message::encrypt(&pk_alice, &shared_secret_alice.0, test_message, version)
            .expect("64-byte key encryption should succeed");

        let decrypted =
            encrypted_messages[0].decrypt(&shared_secret_bob.0).expect("64-byte key decryption should succeed");

        assert_eq!(decrypted, test_message, "64-byte key messages should round-trip correctly");
    }

    #[tokio::test]
    async fn test_encrypted_message_reassembler() {
        let sk_alice = bls12_381::generate_sk();
        let sk_bob = bls12_381::generate_sk();

        let pk_alice = bls12_381::get_public_key(&sk_alice).expect("get pk alice");

        let shared_secret = bls12_381::get_shared_secret(&pk_alice, &sk_bob).expect("shared secret");

        let test_message = b"Test message for reassembler";
        let version = Ver::new(1, 1, 8);

        let encrypted_messages =
            Message::encrypt(&pk_alice, &shared_secret.0, test_message, version).expect("encryption should succeed");

        let reassembler = ReedSolomonReassembler::new();

        // For single shard, should work immediately
        if encrypted_messages.len() == 1 {
            let serialized = encrypted_messages[0].to_bytes();
            let result = reassembler.add_shard(&serialized, &sk_bob).await.expect("reassembly should succeed");
            assert_eq!(result.map(|(msg, _)| msg), Some(test_message.to_vec()));
        }
    }

    #[tokio::test]
    async fn test_build_shards() {
        use crate::config::Config;

        // Create test config
        let sk = bls12_381::generate_sk();

        let config = Config::new_daemonless(sk);

        // Create target public key (different from sender)
        let target_sk = bls12_381::generate_sk();
        let target_pk = bls12_381::get_public_key(&target_sk).expect("get target pk");

        // Test payload
        let test_payload = b"Test payload for build_shards functionality";

        // Build shards via instance method
        let reassembler = ReedSolomonReassembler::new();
        let shards =
            reassembler.build_shards(&config, test_payload, &target_pk).await.expect("build_shards should succeed");

        assert!(!shards.is_empty(), "Should create at least one shard");

        // Each shard should be valid Message binary
        for shard in &shards {
            assert!(shard.len() > 20, "Shard should be large enough to contain header");
            assert_eq!(&shard[0..3], b"AMA", "Shard should start with AMA magic");
        }
    }

    #[tokio::test]
    async fn test_build_broadcast_shards() {
        use crate::config::Config;

        // Create test config
        let sk = bls12_381::generate_sk();

        let config = Config::new_daemonless(sk);

        // Test payload
        let test_payload = b"Test payload for broadcast build_shards functionality";

        // Test broadcast shards (using own key as target)
        let sender_pk = config.get_pk();
        let reassembler = ReedSolomonReassembler::new();
        let shards =
            reassembler.build_shards(&config, test_payload, &sender_pk).await.expect("build_shards should succeed");

        assert!(!shards.is_empty(), "Should create at least one shard");

        // Each shard should be valid Message binary
        for shard in &shards {
            assert!(shard.len() > 20, "Shard should be large enough to contain header");
            assert_eq!(&shard[0..3], b"AMA", "Shard should start with AMA magic");
        }
    }

    #[test]
    fn special_compatibility_test() {
        let src_pk = [
            169, 28, 174, 71, 198, 45, 103, 77, 154, 232, 203, 244, 17, 34, 237, 129, 66, 93, 94, 78, 141, 226, 51,
            166, 153, 186, 221, 114, 128, 18, 56, 100, 37, 178, 123, 55, 51, 197, 165, 109, 247, 71, 136, 163, 211,
            255, 114, 7,
        ];
        let src_sk = [
            9, 150, 210, 55, 28, 239, 9, 161, 68, 62, 249, 195, 10, 127, 86, 17, 19, 41, 143, 189, 9, 205, 85, 30, 245,
            51, 80, 235, 135, 77, 62, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        let dst_pk = [
            169, 61, 121, 32, 15, 191, 174, 241, 143, 231, 124, 53, 186, 69, 28, 212, 233, 130, 22, 18, 34, 244, 13,
            106, 212, 255, 255, 47, 184, 178, 49, 111, 90, 90, 184, 84, 230, 115, 5, 143, 205, 208, 136, 138, 2, 252,
            27, 222,
        ];
        let dst_sk = [
            97, 100, 58, 216, 121, 14, 255, 149, 44, 165, 1, 88, 100, 35, 75, 192, 138, 138, 67, 9, 134, 210, 6, 88,
            155, 3, 21, 197, 119, 155, 33, 163, 103, 4, 46, 229, 62, 157, 185, 90, 19, 106, 206, 72, 245, 133, 133,
            183, 132, 250, 78, 92, 40, 160, 223, 244, 177, 53, 84, 31, 128, 185, 176, 166,
        ];
        let expected_shared_secret = [
            145, 211, 143, 152, 146, 107, 226, 184, 193, 178, 234, 80, 224, 201, 239, 165, 131, 124, 241, 141, 235,
            118, 201, 148, 206, 156, 92, 207, 137, 41, 12, 197, 10, 84, 128, 170, 183, 98, 125, 37, 158, 197, 73, 174,
            140, 4, 177, 64,
        ];
        let enc_msg_bin = [
            65, 77, 65, 1, 1, 8, 0, 169, 28, 174, 71, 198, 45, 103, 77, 154, 232, 203, 244, 17, 34, 237, 129, 66, 93,
            94, 78, 141, 226, 51, 166, 153, 186, 221, 114, 128, 18, 56, 100, 37, 178, 123, 55, 51, 197, 165, 109, 247,
            71, 136, 163, 211, 255, 114, 7, 0, 0, 0, 1, 24, 102, 118, 222, 246, 28, 196, 24, 0, 0, 0, 29, 174, 153,
            105, 150, 110, 19, 115, 132, 10, 128, 192, 116, 95, 183, 109, 90, 36, 47, 94, 235, 25, 153, 6, 60, 1, 52,
            179, 109, 43, 112, 31, 229, 100, 116, 222, 232, 93, 45, 153, 183, 142, 186, 250, 130, 127, 209, 21, 245,
            77, 243, 34, 160, 38, 105, 188, 253, 167, 218, 80,
        ];

        // Test 1: Verify shared secret computation (src sending to dst)
        let computed_shared_secret =
            bls12_381::get_shared_secret(&dst_pk, &src_sk).expect("Should compute shared secret from src to dst");
        assert_eq!(
            computed_shared_secret.0, expected_shared_secret,
            "Computed shared secret should match expected value"
        );

        // Test 2: Verify symmetric shared secret (dst receiving from src)
        let symmetric_shared_secret =
            bls12_381::get_shared_secret(&src_pk, &dst_sk).expect("Should compute shared secret from dst to src");
        assert_eq!(
            symmetric_shared_secret.0, expected_shared_secret,
            "Symmetric shared secret should match expected value"
        );

        // Test 3: Parse the encrypted message
        let encrypted_msg =
            Message::try_from(enc_msg_bin.as_slice()).expect("Should parse encrypted message from binary");

        // Verify message structure matches expected format
        assert_eq!(encrypted_msg.version, Ver::new(1, 1, 8), "Version should be 1.1.8");
        assert_eq!(encrypted_msg.pk.0, src_pk, "Sender public key should match src_pk");
        assert_eq!(encrypted_msg.shard_index, 0, "Should be single shard (index 0)");
        assert_eq!(encrypted_msg.shard_total, 1, "Should be single shard (total 1)");
        assert_eq!(encrypted_msg.original_size, 29, "Original plaintext size should be 37");

        // Test 4: Decrypt the message using dst's secret key
        let decrypted = encrypted_msg.decrypt(&computed_shared_secret.0).expect("Should decrypt message successfully");

        // Verify decrypted content
        assert_eq!(decrypted.len(), 29, "Decrypted length should match original_size");
        assert!(!decrypted.is_empty(), "Decrypted message should not be empty");
    }
}
