/// Translated from https://github.com/amadeus-robot/reedsolomon_ex
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

pub const SHARD_SIZE: usize = 1024;

pub struct ReedSolomonResource {
    pub encoder: ReedSolomonEncoder,
    pub decoder: ReedSolomonDecoder,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ReedSolomonSimd(#[from] reed_solomon_simd::Error),
}

impl ReedSolomonResource {
    pub fn new(data_shards: usize, recovery_shards: usize) -> Result<ReedSolomonResource, Error> {
        let encoder = ReedSolomonEncoder::new(data_shards, recovery_shards, SHARD_SIZE)?;
        let decoder = ReedSolomonDecoder::new(data_shards, recovery_shards, SHARD_SIZE)?;
        Ok(ReedSolomonResource { encoder, decoder })
    }

    pub fn encode_shards(&mut self, data: &[u8]) -> Result<Vec<(usize, Vec<u8>)>, Error> {
        let chunk_size = SHARD_SIZE;

        let chunk_count = (data.len() + 1023) / SHARD_SIZE;
        let mut encoded_shards = Vec::with_capacity(chunk_count * 2);
        let mut itr = 0;

        // step through `data` in increments of `chunk_size`
        for chunk_start in (0..data.len()).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size).min(data.len());
            let chunk = &data[chunk_start..chunk_end];

            // create a 1024-byte buffer initialized to 0
            let mut buffer = [0u8; SHARD_SIZE];
            buffer[..chunk.len()].copy_from_slice(chunk);

            self.encoder.add_original_shard(buffer)?;

            let bin = buffer.to_vec();
            encoded_shards.push((itr, bin));
            itr += 1;
        }

        let result = self.encoder.encode()?;
        let recovery: Vec<_> = result.recovery_iter().collect();
        for recovered_shard in recovery {
            let bin = recovered_shard.to_vec();
            encoded_shards.push((itr, bin));
            itr += 1;
        }

        Ok(encoded_shards)
    }

    pub fn decode_shards(
        &mut self,
        shards: Vec<(usize, Vec<u8>)>,
        total_shards: usize,
        original_size: usize,
    ) -> Result<Vec<u8>, Error> {
        let mut combined = vec![0u8; original_size];

        let half = total_shards / 2;
        for (index, bin) in shards {
            if index < half {
                let shard_data = bin.as_slice();

                let offset = index * SHARD_SIZE;
                // protect against going past original_size
                let end = (offset + shard_data.len()).min(original_size);
                combined[offset..end].copy_from_slice(&shard_data[..(end - offset)]);

                self.decoder.add_original_shard(index, shard_data)?;
            } else {
                self.decoder.add_recovery_shard(index - half, bin.as_slice())?;
            }
        }
        let result = self.decoder.decode()?;

        for idx in 0..half {
            if let Some(shard_data) = result.restored_original(idx) {
                let offset = idx * SHARD_SIZE;
                let end = (offset + shard_data.len()).min(original_size);
                combined[offset..end].copy_from_slice(&shard_data[..(end - offset)]);
            }
        }

        Ok(combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rs_roundtrip_multi_shard() {
        // prepare data that spans 3 shards (last shard partial)
        let len = SHARD_SIZE * 3 - 10;
        let mut data = vec![0u8; len];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        // set data_shards = recovery_shards = chunk_count = 3 for this test
        let mut rs = ReedSolomonResource::new(3, 3).expect("new");
        let shards = rs.encode_shards(&data).expect("encode");
        assert_eq!(shards.len(), 6);

        // drop one original shard and one recovery shard randomly
        let mut kept: Vec<(usize, Vec<u8>)> =
            shards.into_iter().enumerate().filter(|(i, _)| *i != 1 && *i != 4).map(|(_, v)| v).collect();
        // total_shards = originals(3) + recovery(3)
        let restored = rs.decode_shards(kept.drain(..).collect(), 6, len).expect("decode");
        assert_eq!(restored, data);
    }
}
