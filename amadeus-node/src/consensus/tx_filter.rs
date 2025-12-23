use crate::consensus::doms::tx::TxU;
use amadeus_utils::constants::{CF_TX, CF_TX_FILTER};
use amadeus_utils::rocksdb::{Direction, IteratorMode, ReadOptions, RocksDb, RocksDbError};
use amadeus_utils::blake3::Hasher;

const ZERO: &[u8] = &[0u8];

#[inline(always)]
pub fn create_filter_key(parts: &[&[u8]]) -> [u8; 16] {
    let mut hasher = Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    let output_vec = hasher.finalize_xof(16);
    let mut output = [0u8; 16];
    output.copy_from_slice(&output_vec);
    output
}

pub fn build_tx_hashfilters(txs: &[TxU]) -> Vec<([u8; 24], [u8; 8])> {
    let mut all_filters = Vec::with_capacity(txs.len() * 8);

    for txu in txs {
        let mut tx_hash8 = [0u8; 8];
        tx_hash8.copy_from_slice(&txu.hash[0..8]);

        let nonce_bytes = txu.tx.nonce.to_be_bytes();
        let signer = txu.tx.signer.as_ref();
        let contract = txu.tx.action.contract.as_slice();
        let function = txu.tx.action.function.as_slice();
        let arg0 = txu.tx.action.args.first().map(|a| a.as_slice()).unwrap_or(ZERO);

        let mut push_key = |parts: &[&[u8]]| {
            let raw_hash = create_filter_key(parts);
            let mut filter_key = [0u8; 24];
            filter_key[0..16].copy_from_slice(&raw_hash);
            filter_key[16..24].copy_from_slice(&nonce_bytes);
            all_filters.push((filter_key, tx_hash8));
        };

        match (contract, function) {
            (b"Epoch", b"submit_sol") => {
                push_key(&[signer, ZERO, ZERO, ZERO]);
                push_key(&[ZERO, arg0, ZERO, ZERO]);
                push_key(&[signer, ZERO, contract, ZERO]);
                push_key(&[signer, ZERO, contract, function]);
                push_key(&[ZERO, ZERO, contract, ZERO]);
                push_key(&[ZERO, ZERO, contract, function]);
            },
            _ => {
                push_key(&[signer, ZERO, ZERO, ZERO]);
                push_key(&[ZERO, arg0, ZERO, ZERO]);
                push_key(&[signer, arg0, ZERO, ZERO]);
                push_key(&[ZERO, ZERO, contract, ZERO]);
                push_key(&[ZERO, ZERO, contract, function]);
                push_key(&[signer, ZERO, contract, ZERO]);
                push_key(&[signer, ZERO, contract, function]);
                push_key(&[ZERO, arg0, contract, ZERO]);
                push_key(&[ZERO, arg0, contract, function]);
                push_key(&[signer, arg0, contract, function]);
            }
        }
    }

    all_filters
}

pub fn query_tx_hashfilter(
    db: &RocksDb,
    signer: &[u8],
    arg0: &[u8],
    contract: &[u8],
    function: &[u8],
    limit: usize,
    desc: bool,
    cursor: Option<&[u8]>,
) -> Result<(Option<Vec<u8>>, Vec<Vec<u8>>), RocksDbError> {
    let key = create_filter_key(&[signer, arg0, contract, function]);
    let prefix = &key[0..16];

    let start_key = if let Some(c) = cursor {
        c.to_vec()
    } else {
        let mut k = Vec::with_capacity(24);
        k.extend_from_slice(prefix);
        k.extend_from_slice(if desc { &[0xFF; 8] } else { &[0x00; 8] });
        k
    };

    let mut opts = ReadOptions::default();
    opts.set_prefix_same_as_start(true);

    let mut results = Vec::new();
    let mut last_cursor: Option<Vec<u8>> = None;

    let mode = if desc {
        IteratorMode::From(&start_key, Direction::Reverse)
    } else {
        IteratorMode::From(&start_key, Direction::Forward)
    };

    let iter = db.inner.iterator_cf_opt(&db.inner.cf_handle(CF_TX_FILTER).unwrap(), opts, mode);

    for item in iter {
        let (k, v) = item?;

        if k.len() < 16 || &k[0..16] != prefix {
            break;
        }

        if cursor.is_some() && k.as_ref() == start_key.as_slice() {
            continue;
        }

        last_cursor = Some(k.to_vec());

        if v.len() != 8 {
            continue;
        }

        let mut tx_opts = ReadOptions::default();
        tx_opts.set_prefix_same_as_start(true);
        let tx_iter = db.inner.iterator_cf_opt(&db.inner.cf_handle(CF_TX).unwrap(), tx_opts, IteratorMode::From(v.as_ref(), Direction::Forward));

        for tx_item in tx_iter {
            let (tx_key, tx_data) = tx_item?;

            if tx_key.len() < 8 || &tx_key[0..8] != v.as_ref() {
                break;
            }

            results.push(tx_data.to_vec());

            if results.len() >= limit {
                return Ok((last_cursor, results));
            }
        }
    }

    Ok((last_cursor, results))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_filter_key() {
        let key1 = create_filter_key(&[b"signer", b"arg0", b"contract", b"function"]);
        let key2 = create_filter_key(&[b"signer", b"arg0", b"contract", b"function"]);
        let key3 = create_filter_key(&[b"different", b"arg0", b"contract", b"function"]);

        assert_eq!(key1, key2, "Same inputs should produce same key");
        assert_ne!(key1, key3, "Different inputs should produce different keys");
        assert_eq!(key1.len(), 16, "Key should be 16 bytes");
    }
}
