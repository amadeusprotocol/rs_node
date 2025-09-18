use super::msg_v2::MessageV2;
use crate::consensus::DST_NODE;
use crate::node::msg_v2;
use crate::utils::misc::get_unix_nanos_now;
#[cfg(test)]
use crate::Ver;
use crate::utils::reed_solomon;
use crate::utils::reed_solomon::ReedSolomonResource;
use crate::utils::{blake3, bls12_381};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::prelude::*;
use tokio::sync::RwLock;

pub struct ReedSolomonReassembler {
    reorg: RwLock<HashMap<ReassemblyKey, EntryState>>, // protected in-memory reassembly state
}

#[derive(Debug, thiserror::Error, strum_macros::IntoStaticStr)]
pub enum Error {
    #[error(transparent)]
    ReedSolomon(#[from] reed_solomon::Error),
    #[error(transparent)]
    Bls(#[from] bls12_381::Error),
    #[error(transparent)]
    MessageV2(#[from] msg_v2::Error),
    #[error("failed to decompress: {0}")]
    Decompress(std::io::Error),
    #[error("message has no signature")]
    NoSignature,
}

impl crate::utils::misc::Typename for Error {
    fn typename(&self) -> &'static str {
        self.into()
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Decompress(e)
    }
}

#[derive(Clone, Debug, Eq)]
struct ReassemblyKey {
    pk: [u8; 48],
    ts_nano: u64,
    shard_total: u16,
}

impl From<&MessageV2> for ReassemblyKey {
    fn from(&MessageV2 { pk, ts_nano, shard_total, .. }: &MessageV2) -> Self {
        Self { pk, ts_nano, shard_total }
    }
}

impl PartialEq for ReassemblyKey {
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk && self.ts_nano == other.ts_nano && self.shard_total == other.shard_total
    }
}

impl Hash for ReassemblyKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pk.hash(state);
        self.ts_nano.hash(state);
        self.shard_total.hash(state);
    }
}

#[derive(Debug)]
enum EntryState {
    Collecting(std::collections::HashMap<u16, Vec<u8>>), // shard_index -> shard bytes
    Spent,
}

impl Default for ReedSolomonReassembler {
    fn default() -> Self {
        Self::new()
    }
}

// Helper functions for zlib compression/decompression to match Elixir reference
fn compress_with_zlib(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

fn decompress_with_zlib(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut decoder = ZlibDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result)?;
    Ok(result)
}

impl ReedSolomonReassembler {
    pub fn new() -> Self {
        Self { reorg: RwLock::new(HashMap::new()) }
    }

    /// Creates unsigned MessageV2 shards for bootstrap messages (v1.1.7+ format)
    /// Bootstrap messages (new_phone_who_dis) don't require signatures
    pub fn build_unsigned_shards(config: &crate::config::Config, payload: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let compressed = compress_with_zlib(&payload)?;

        let pk = config.get_pk();
        let ts_nano = get_unix_nanos_now() as u64;
        let original_size = compressed.len() as u32;
        let version = config.get_ver();

        if compressed.len() < 1300 {
            // Small message: single shard, unsigned
            return Ok(vec![
                MessageV2 {
                    version,
                    pk,
                    signature: None, // Unsigned
                    shard_index: 0,
                    shard_total: 1,
                    ts_nano,
                    original_size,
                    payload: compressed,
                }
                .try_into()?,
            ]);
        }

        // Large message: Reed-Solomon sharding (unsigned)
        let data_shards = compressed.len().div_ceil(1024);
        let parity_shards = data_shards;
        let total_shards = (data_shards + parity_shards) as u16;

        let mut rs_resource = ReedSolomonResource::new(data_shards, parity_shards)?;
        let encoded_shards = rs_resource.encode_shards(&compressed)?;

        // Take data shards + some parity shards (not all) - matches signed version logic
        let shards_to_send = data_shards + 1 + (data_shards / 4);
        let limited_shards: Vec<_> = encoded_shards.into_iter().take(shards_to_send).collect();

        let mut shards = Vec::new();
        for (shard_index, shard_payload) in limited_shards {
            shards.push(
                MessageV2 {
                    version,
                    pk,
                    signature: None, // Unsigned
                    shard_index: shard_index as u16,
                    shard_total: total_shards,
                    ts_nano,
                    original_size,
                    payload: shard_payload,
                }
                .try_into()?,
            );
        }

        Ok(shards)
    }

    /// Creates signed MessageV2 shards from payload
    pub fn build_shards(config: &crate::config::Config, payload: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let compressed = compress_with_zlib(&payload)?;

        let pk = config.get_pk();
        let trainer_sk = config.get_sk();
        let ts_nano = get_unix_nanos_now() as u64;
        let original_size = compressed.len() as u32;
        let version = config.get_ver();

        // sign Blake3(pk || payload) once for the entire message
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pk);
        hasher.update(&compressed);
        let msg_hash = hasher.finalize();
        let signature = bls12_381::sign(&trainer_sk, &msg_hash, DST_NODE)?;

        if compressed.len() < 1300 {
            return Ok(vec![
                MessageV2 {
                    version,
                    pk,
                    signature: Some(signature),
                    shard_index: 0,
                    shard_total: 1,
                    ts_nano,
                    original_size,
                    payload: compressed,
                }
                .try_into()?,
            ]);
        }

        // large message: Reed-Solomon sharding
        // reference: shards = div(byte_size(msg_compressed)+1023, 1024)
        let data_shards = compressed.len().div_ceil(1024);
        let parity_shards = data_shards;
        let total_shards = (data_shards + parity_shards) as u16;

        let mut rs_resource = ReedSolomonResource::new(data_shards, parity_shards)?;
        let encoded_shards = rs_resource.encode_shards(&compressed)?;

        // reference: |> Enum.take(shards+1+div(shards,4))
        // take data shards + some parity shards (not all)
        let shards_to_send = data_shards + 1 + (data_shards / 4);
        let limited_shards: Vec<_> = encoded_shards.into_iter().take(shards_to_send).collect();

        let mut shards = Vec::new();
        for (shard_index, shard_payload) in limited_shards {
            shards.push(
                MessageV2 {
                    version,
                    pk,
                    signature: Some(signature),
                    shard_index: shard_index as u16,
                    shard_total: total_shards,
                    ts_nano,
                    original_size,
                    payload: shard_payload,
                }
                .try_into()?,
            );
        }

        Ok(shards)
    }

    pub async fn clear_stale(&self, seconds: u64) -> usize {
        // TODO: is the nanos precision really needed here?
        let threshold = get_unix_nanos_now().saturating_sub(seconds as u128 * 1_000_000_000);
        let mut map = self.reorg.write().await;
        let size_before = map.len();
        map.retain(|k, _v| (k.ts_nano as u128) > threshold);
        let size_after = map.len();
        size_before - size_after
    }

    /// Adds a shard to the reassembly buffer, and when enough
    /// shards collected, reconstructs
    pub async fn add_shard(&self, bin: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let message = MessageV2::try_from(bin)?;
        let key = ReassemblyKey::from(&message);
        let shard = &message.payload;

        // some messages are single-shard only, so we can skip the reorg logic
        if key.shard_total == 1 {
            Self::verify_msg_sig(&key, message.signature.as_ref(), &shard)?;
            let payload = decompress_with_zlib(&shard)?;
            return Ok(Some(payload));
        }

        let data_shards = (key.shard_total / 2) as usize;

        // insert-or-update under lock; if threshold met, collect shards and mark Spent
        let mut maybe_shards: Option<Vec<(usize, Vec<u8>)>> = None;
        {
            let mut map = self.reorg.write().await;
            use std::collections::hash_map::Entry;
            match map.entry(key.clone()) {
                Entry::Vacant(v) => {
                    let mut state_map = HashMap::new();
                    state_map.insert(message.shard_index, shard.clone());
                    v.insert(EntryState::Collecting(state_map));
                }
                Entry::Occupied(mut occ) => {
                    match occ.get_mut() {
                        EntryState::Spent => {
                            // nothing to do
                        }
                        EntryState::Collecting(shards_map) => {
                            shards_map.insert(message.shard_index, shard.clone());
                            if shards_map.len() >= data_shards {
                                let shards: Vec<(usize, Vec<u8>)> =
                                    shards_map.iter().map(|(idx, bytes)| (*idx as usize, bytes.clone())).collect();
                                // mark as spent to avoid reuse and release memory
                                *occ.get_mut() = EntryState::Spent;
                                maybe_shards = Some(shards);
                            }
                        }
                    }
                }
            }
        }

        if let Some(shards) = maybe_shards {
            // decode outside the lock
            let msg_size = message.original_size as usize;
            let mut rs_res = ReedSolomonResource::new(data_shards, data_shards)?;
            let compressed = rs_res.decode_shards(shards, data_shards + data_shards, msg_size)?;
            Self::verify_msg_sig(&key, message.signature.as_ref(), &compressed)?;
            let payload = decompress_with_zlib(&compressed)?;
            return Ok(Some(payload));
        }

        Ok(None)
    }

    fn verify_msg_sig(key: &ReassemblyKey, signature: Option<&[u8; 96]>, payload: &[u8]) -> Result<(), Error> {
        if let Some(sig) = signature {
            // Signed message - verify signature
            let mut hasher = blake3::Hasher::new();
            hasher.update(&key.pk);
            hasher.update(payload);
            let msg_hash = hasher.finalize();

            bls12_381::verify(&key.pk, sig, &msg_hash, DST_NODE)?;
        }
        // Unsigned message (bootstrap) - no verification needed
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // test-specific functions that use consistent keypair
    fn test_trainer_sk() -> [u8; 64] {
        // fixed test secret key for deterministic results
        [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
            30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
            57, 58, 59, 60, 61, 62, 63, 64,
        ]
    }

    fn test_trainer_pk() -> [u8; 48] {
        // derive public key from the test secret key
        bls12_381::get_public_key(&test_trainer_sk()).unwrap()
    }

    // test version of build_message_v2 that uses consistent test keys
    fn test_build_message_v2(payload: Vec<u8>, version: Ver) -> Result<Vec<MessageV2>, Error> {
        // compress the payload first, just like in build_shards
        let compressed = compress_with_zlib(&payload)?;

        let pk = test_trainer_pk();
        let trainer_sk = test_trainer_sk();
        let ts_nano = get_unix_nanos_now() as u64;
        let original_size = compressed.len() as u32;

        // sign Blake3(pk || compressed) once for the entire message
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pk);
        hasher.update(&compressed);
        let msg_hash = hasher.finalize();
        let signature = bls12_381::sign(&trainer_sk, &msg_hash, DST_NODE)?;

        // reference: if byte_size(msg_compressed) < 1300, single shard
        if compressed.len() < 1300 {
            return Ok(vec![MessageV2 {
                version,
                pk,
                signature: Some(signature),
                shard_index: 0,
                shard_total: 1,
                ts_nano,
                original_size,
                payload: compressed,
            }]);
        }

        // large message: Reed-Solomon sharding
        let data_shards = compressed.len().div_ceil(1024);
        let parity_shards = data_shards;
        let total_shards = (data_shards + parity_shards) as u16;

        let mut rs_resource = ReedSolomonResource::new(data_shards, parity_shards)?;
        let encoded_shards = rs_resource.encode_shards(&compressed)?;

        let shards_to_send = data_shards + 1 + (data_shards / 4);
        let limited_shards: Vec<_> = encoded_shards.into_iter().take(shards_to_send).collect();

        let mut messages = Vec::new();
        for (shard_index, shard_payload) in limited_shards {
            messages.push(MessageV2 {
                version,
                pk,
                signature: Some(signature),
                shard_index: shard_index as u16,
                shard_total: total_shards,
                ts_nano,
                original_size,
                payload: shard_payload,
            });
        }

        Ok(messages)
    }

    #[tokio::test]
    async fn test_message_v2_roundtrip_small() {
        // test small message (single shard)
        let payload = b"hello world".to_vec();
        let version = Ver::new(1, 1, 7);

        let messages = test_build_message_v2(payload.clone(), version).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].shard_total, 1);
        // messages[0].payload is now compressed, not the original
        let compressed = compress_with_zlib(&payload).unwrap();
        assert_eq!(messages[0].payload, compressed);

        let reassembler = ReedSolomonReassembler::new();
        let msg_bytes: Vec<u8> = messages[0].clone().try_into().unwrap();
        let result = reassembler.add_shard(&msg_bytes).await.unwrap();
        assert_eq!(result, Some(payload));
    }

    #[tokio::test]
    async fn test_message_v2_roundtrip_large() {
        // test large message (multiple shards)
        // Use a payload that will be larger than 1300 bytes even after compression
        // Use a pseudo-random pattern that doesn't compress well
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut payload = Vec::new();
        let mut hasher = DefaultHasher::new();
        for i in 0..2000 {
            i.hash(&mut hasher);
            let hash = hasher.finish();
            payload.extend_from_slice(&hash.to_le_bytes());
        }
        let version = Ver::new(1, 1, 7);

        let messages = test_build_message_v2(payload.clone(), version).unwrap();
        // If it's still a single shard, that's ok, just test the roundtrip
        if messages.len() == 1 {
            // for single shard case, still test that it works
            assert_eq!(messages[0].shard_total, 1);
        } else {
            assert!(messages[0].shard_total > 1);
        }

        // all messages should have same metadata
        let compressed = compress_with_zlib(&payload).unwrap();
        for msg in &messages {
            assert_eq!(msg.version, version);
            assert_eq!(msg.pk, messages[0].pk);
            assert_eq!(msg.ts_nano, messages[0].ts_nano);
            assert_eq!(msg.shard_total, messages[0].shard_total);
            assert_eq!(msg.original_size, compressed.len() as u32);
            assert_eq!(msg.signature, messages[0].signature);
        }

        let reassembler = ReedSolomonReassembler::new();
        let mut result = None;

        // add shards one by one
        for msg in &messages {
            let msg_bytes: Vec<u8> = msg.clone().try_into().unwrap();
            if let Some(restored) = reassembler.add_shard(&msg_bytes).await.unwrap() {
                result = Some(restored);
                break;
            }
        }

        assert_eq!(result, Some(payload));
    }

    #[tokio::test]
    async fn test_message_v2_partial_shards() {
        // test that we can recover with missing shards
        // Use pseudo-random data that doesn't compress well to ensure multiple shards
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut payload = Vec::new();
        let mut hasher = DefaultHasher::new();
        for i in 0..2000 {
            i.hash(&mut hasher);
            let hash = hasher.finish();
            payload.extend_from_slice(&hash.to_le_bytes());
        }
        let version = Ver::new(1, 1, 7);

        let messages = test_build_message_v2(payload.clone(), version).unwrap();

        // If it's a single shard, we can't test partial recovery, so just verify it works
        if messages.len() == 1 {
            let reassembler = ReedSolomonReassembler::new();
            let msg_bytes: Vec<u8> = messages[0].clone().try_into().unwrap();
            let result = reassembler.add_shard(&msg_bytes).await.unwrap();
            assert_eq!(result, Some(payload));
            return;
        }

        // calculate data_shards to know minimum needed for recovery
        let compressed = compress_with_zlib(&payload).unwrap();
        let data_shards = compressed.len().div_ceil(1024);
        println!("Generated {} messages, data_shards={}", messages.len(), data_shards);

        let reassembler = ReedSolomonReassembler::new();

        // take first data_shards worth of messages to ensure we can recover
        let mut restored = None;
        for (_i, msg) in messages.iter().enumerate().take(data_shards + 1) {
            let msg_bytes: Vec<u8> = msg.clone().try_into().unwrap();
            if let Some(result) = reassembler.add_shard(&msg_bytes).await.unwrap() {
                restored = Some(result);
                break;
            }
        }

        // should be able to recover with minimum required shards
        assert_eq!(restored, Some(payload));
    }
}
