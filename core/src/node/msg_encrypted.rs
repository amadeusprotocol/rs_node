use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use crate::utils::misc::get_unix_nanos_now;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, thiserror::Error, strum_macros::IntoStaticStr)]
pub enum Error {
    #[error("message is only {0} bytes")]
    WrongLength(usize),
    #[error("version format is invalid")]
    VersionFormat,
    #[error("version {0} is too old (minimum 1.1.7)")]
    VersionTooOld(String),
    #[error("bad public key length, expected 48 bytes, got {0}")]
    BadPkLen(usize),
    #[error("invalid magic, expected 'AMA'")]
    InvalidMagic,
    #[error("message to self")]
    MsgToSelf,
    #[error("shard total too large: {0} (max 10000)")]
    ShardTotalTooLarge(u16),
    #[error("original size too large: {0} (max 10MB)")]
    OriginalSizeTooLarge(u32),
    #[error("encryption error: {0}")]
    EncryptionError(String),
    #[error("decryption error: {0}")]
    DecryptionError(String),
}

impl crate::utils::misc::Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

/// Encrypted Message Format (v1.1.7+)
///
/// <<"AMA", va, vb, vc, 0::8, pk::48-binary,
///   shard_index::16, shard_total::16, ts_n::64, original_size::32,
///   payload::binary>>
///
/// Where payload is: <<iv::12-binary, tag::16-binary, ciphertext::binary>>
///
/// Offset  Length  Field               Description
/// ──────────────────────────────────────────────────────────────────
/// 0-2     3       Magic               "AMA" (0x414D41)
/// 3       1       Version Major       Major version number
/// 4       1       Version Minor       Minor version number
/// 5       1       Version Patch       Patch version number
/// 6       1       Reserved            0x00 (was flags in v2)
/// 7-54    48      Public Key          BLS12-381 public key
/// 55-56   2       Shard Index         Current shard number (big-endian)
/// 57-58   2       Shard Total         Total number of shards (big-endian)
/// 59-66   8       Timestamp           Nanosecond timestamp (big-endian)
/// 67-70   4       Original Size       Size of original message (big-endian)
/// 71+     N       Encrypted Payload   IV(12) + Tag(16) + Ciphertext
#[derive(Debug, Clone)]
pub struct EncryptedMessage {
    pub version: (u8, u8, u8),
    pub pk: [u8; 48],
    pub shard_index: u16,
    pub shard_total: u16,
    pub ts_nano: u64,
    pub original_size: u32,
    pub payload: Vec<u8>,
}

impl TryFrom<&[u8]> for EncryptedMessage {
    type Error = Error;

    fn try_from(bin: &[u8]) -> Result<Self, Self::Error> {
        // Minimum header size: 3 + 3 + 1 + 48 + 2 + 2 + 8 + 4 = 71
        if bin.len() < 71 {
            return Err(Error::WrongLength(bin.len()));
        }

        // Check magic
        if &bin[0..3] != b"AMA" {
            return Err(Error::InvalidMagic);
        }

        // Parse version
        let version = (bin[3], bin[4], bin[5]);
        let version_str = format!("{}.{}.{}", version.0, version.1, version.2);

        // Enforce minimum version 1.1.7
        if version.0 < 1 || (version.0 == 1 && version.1 < 1) ||
           (version.0 == 1 && version.1 == 1 && version.2 < 7) {
            return Err(Error::VersionTooOld(version_str));
        }

        // Reserved byte must be 0
        if bin[6] != 0 {
            return Err(Error::VersionFormat);
        }

        // Parse public key
        let pk: [u8; 48] = bin[7..55].try_into()
            .map_err(|_| Error::BadPkLen(bin[7..55].len()))?;

        // Parse shard info
        let shard_index = u16::from_be_bytes([bin[55], bin[56]]);
        let shard_total = u16::from_be_bytes([bin[57], bin[58]]);

        // Validate shard total
        if shard_total >= 10_000 {
            return Err(Error::ShardTotalTooLarge(shard_total));
        }

        // Parse timestamp and size
        let ts_nano = u64::from_be_bytes(bin[59..67].try_into().unwrap());
        let original_size = u32::from_be_bytes(bin[67..71].try_into().unwrap());

        // Validate size
        if original_size >= 10_240_000 {  // 10MB
            return Err(Error::OriginalSizeTooLarge(original_size));
        }

        // Rest is encrypted payload
        let payload = bin[71..].to_vec();

        Ok(EncryptedMessage {
            version,
            pk,
            shard_index,
            shard_total,
            ts_nano,
            original_size,
            payload,
        })
    }
}

impl EncryptedMessage {
    /// Encrypt a message using shared secret
    pub fn encrypt(
        pk: &[u8],
        shared_secret: &[u8],
        payload: &[u8],
        version: (u8, u8, u8),
    ) -> Result<Vec<Self>, Error> {
        let ts_nano = get_unix_nanos_now() as u64;

        // Generate random IV (same as Elixir: :crypto.strong_rand_bytes(12))
        let mut iv_bytes = [0u8; 12];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut iv_bytes);

        // Derive key exactly like Elixir: :crypto.hash(:sha256, [shared_key, :binary.encode_unsigned(ts_n), iv])
        let mut key_input = Vec::new();
        key_input.extend_from_slice(shared_secret);
        key_input.extend_from_slice(&ts_nano.to_be_bytes()); // :binary.encode_unsigned(ts_n)
        key_input.extend_from_slice(&iv_bytes);

        let key = sha2::Sha256::digest(&key_input);
        let iv = &iv_bytes;

        // Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| Error::EncryptionError(e.to_string()))?;
        let nonce = Nonce::from_slice(iv);

        let ciphertext = cipher.encrypt(nonce, payload)
            .map_err(|e| Error::EncryptionError(e.to_string()))?;

        // Split tag and ciphertext (GCM appends 16-byte tag)
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);

        // Build encrypted payload: IV + Tag + Ciphertext
        let mut encrypted_payload = Vec::with_capacity(12 + 16 + ct.len());
        encrypted_payload.extend_from_slice(iv);
        encrypted_payload.extend_from_slice(tag);
        encrypted_payload.extend_from_slice(ct);

        let pk_array: [u8; 48] = pk.try_into()
            .map_err(|_| Error::BadPkLen(pk.len()))?;

        // Check if we need sharding
        if encrypted_payload.len() < 1360 {
            // Single message
            Ok(vec![EncryptedMessage {
                version,
                pk: pk_array,
                shard_index: 0,
                shard_total: 1,
                ts_nano,
                original_size: payload.len() as u32,
                payload: encrypted_payload,
            }])
        } else {
            // Need to shard using Reed-Solomon
            let shard_size = 1024;
            let total_shards = ((encrypted_payload.len() + shard_size - 1) / shard_size) as u16;
            let redundancy = total_shards / 4 + 1;  // 25% redundancy

            // TODO: Implement Reed-Solomon sharding
            // For now, return error
            Err(Error::EncryptionError("Sharding not yet implemented".to_string()))
        }
    }

    /// Decrypt payload using shared secret
    pub fn decrypt(&self, shared_secret: &[u8]) -> Result<Vec<u8>, Error> {
        if self.payload.len() < 28 {  // IV(12) + Tag(16)
            return Err(Error::DecryptionError("Payload too short".to_string()));
        }

        let iv = &self.payload[0..12];
        let tag = &self.payload[12..28];
        let ciphertext = &self.payload[28..];

        // Derive key exactly like Elixir: :crypto.hash(:sha256, [shared_key, :binary.encode_unsigned(ts_n), iv])
        let mut key_input = Vec::new();
        key_input.extend_from_slice(shared_secret);
        key_input.extend_from_slice(&self.ts_nano.to_be_bytes()); // :binary.encode_unsigned(ts_n)
        key_input.extend_from_slice(iv);

        let key = Sha256::digest(&key_input);

        // Decrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| Error::DecryptionError(e.to_string()))?;
        let nonce = Nonce::from_slice(iv);

        // Combine ciphertext and tag for decryption
        let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + 16);
        ct_with_tag.extend_from_slice(ciphertext);
        ct_with_tag.extend_from_slice(tag);

        cipher.decrypt(nonce, ct_with_tag.as_slice())
            .map_err(|e| Error::DecryptionError(e.to_string()))
    }

    /// Convert to binary format for network transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(71 + self.payload.len());

        // Magic
        out.extend_from_slice(b"AMA");

        // Version
        out.push(self.version.0);
        out.push(self.version.1);
        out.push(self.version.2);

        // Reserved
        out.push(0);

        // Public key
        out.extend_from_slice(&self.pk);

        // Shard info
        out.extend_from_slice(&self.shard_index.to_be_bytes());
        out.extend_from_slice(&self.shard_total.to_be_bytes());

        // Timestamp and size
        out.extend_from_slice(&self.ts_nano.to_be_bytes());
        out.extend_from_slice(&self.original_size.to_be_bytes());

        // Encrypted payload
        out.extend_from_slice(&self.payload);

        out
    }
}

/// Cache for shared secrets to avoid repeated BLS computations
pub struct SharedSecretCache {
    cache: Arc<RwLock<HashMap<[u8; 48], [u8; 48]>>>,
}

impl SharedSecretCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_or_compute(
        &self,
        pk: &[u8],
        sk: &[u8],
    ) -> Result<[u8; 48], Error> {
        let pk_array: [u8; 48] = pk.try_into()
            .map_err(|_| Error::BadPkLen(pk.len()))?;

        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(secret) = cache.get(&pk_array) {
                return Ok(*secret);
            }
        }

        // Compute shared secret
        let shared_secret = crate::utils::bls12_381::get_shared_secret(pk, sk)
            .map_err(|e| Error::EncryptionError(e.to_string()))?;

        // Store in cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(pk_array, shared_secret);
        }

        Ok(shared_secret)
    }
}