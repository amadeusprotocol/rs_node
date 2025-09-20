use crate::consensus;
use crate::consensus::doms::attestation::Attestation;
use crate::consensus::doms::entry::Entry;
use crate::utils::misc::{TermExt, bitvec_to_bools, bools_to_bitvec};
use crate::utils::rocksdb;
use crate::utils::safe_etf::encode_safe_deterministic;
use eetf::{Atom, BigInteger, Binary, Term};
use std::collections::HashMap;
use tracing::{Instrument, info};
// TODO: make the database trait that the fabric will use

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),
    #[error(transparent)]
    EtfDecode(#[from] eetf::DecodeError),
    #[error(transparent)]
    EtfEncode(#[from] eetf::EncodeError),
    #[error(transparent)]
    BinDecode(#[from] bincode::error::DecodeError),
    #[error(transparent)]
    BinEncode(#[from] bincode::error::EncodeError),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
    // #[error(transparent)]
    // Entry(#[from] consensus::entry::Error),
    #[error(transparent)]
    Att(#[from] crate::consensus::doms::attestation::Error),
    #[error("invalid kv cell: {0}")]
    KvCell(&'static str),
    #[error("invalid etf: {0}")]
    BadEtf(&'static str),
}

const CF_DEFAULT: &str = "default";
const CF_ENTRY_BY_HEIGHT: &str = "entry_by_height|height:entryhash";
const CF_ENTRY_BY_SLOT: &str = "entry_by_slot|slot:entryhash";
const CF_MY_SEEN_TIME_FOR_ENTRY: &str = "my_seen_time_entry|entryhash";
const CF_MY_ATTESTATION_FOR_ENTRY: &str = "my_attestation_for_entry|entryhash";
const CF_CONSENSUS_BY_ENTRYHASH: &str = "consensus_by_entryhash|Map<mutationshash,consensus>";
const CF_SYSCONF: &str = "sysconf";

/// Initialize Fabric DB area (creates/open RocksDB with the required CFs)
pub async fn init_kvdb(base: &str) -> Result<(), Error> {
    let long_init_hint = tokio::spawn(
        async {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            info!("rocksdb needs time to seal memtables to SST and compact L0 files...");
        }
        .instrument(tracing::Span::current()),
    );

    // spawn_blocking + block_on is moving the init off the async runtime since
    // it never yields (nasty rocksdb) and the hint would never be scheduled
    let path = format!("{}/fabric", base);
    tokio::task::spawn_blocking(move || tokio::runtime::Handle::current().block_on(rocksdb::init(path))).await??;
    long_init_hint.abort();

    Ok(())
}

pub fn close() {
    rocksdb::close();
}

/// Insert an entry into RocksDB: default CF by hash, seen time, and index by height/slot
pub fn insert_entry(hash: &[u8; 32], height: u32, slot: u32, entry_bin: &[u8], seen_millis: u64) -> Result<(), Error> {
    // idempotent: if already present under default CF, do nothing
    if rocksdb::get(CF_DEFAULT, hash)?.is_none() {
        rocksdb::put(CF_DEFAULT, hash, entry_bin)?;

        // Store seen time using ETF deterministic format like Elixir
        let seen_time_term = Term::from(BigInteger { value: seen_millis.into() });
        let seen_time_bin = encode_safe_deterministic(&seen_time_term);
        rocksdb::put(CF_MY_SEEN_TIME_FOR_ENTRY, hash, &seen_time_bin)?;

        // index by height and slot -> key format allows efficient range queries
        // use compound key to support multiple entries per height/slot
        let b58_hash = bs58::encode(hash).into_string();
        let height_key = format!("{:016}:{}", height, &b58_hash);
        rocksdb::put(CF_ENTRY_BY_HEIGHT, height_key.as_bytes(), hash)?;

        let slot_key = format!("{:016}:{}", slot, &b58_hash);
        rocksdb::put(CF_ENTRY_BY_SLOT, slot_key.as_bytes(), hash)?;
    }

    Ok(())
}

/// Get all entries (ETF-encoded) for a specific height
pub fn entries_by_height(height: u64) -> Result<Vec<Vec<u8>>, Error> {
    let height_prefix = format!("{:016}:", height);
    let kvs = rocksdb::iter_prefix(CF_ENTRY_BY_HEIGHT, height_prefix.as_bytes())?;
    let mut out = Vec::new();
    for (_k, v) in kvs.into_iter() {
        // v is entry hash
        if let Some(entry_bin) = rocksdb::get(CF_DEFAULT, &v)? {
            out.push(entry_bin);
        }
    }
    Ok(out)
}

/// Get all entries (ETF-encoded) for a specific slot
pub fn entries_by_slot(slot: u32) -> Result<Vec<Vec<u8>>, Error> {
    let slot_prefix = format!("{:016}:", slot);
    let kvs = rocksdb::iter_prefix(CF_ENTRY_BY_SLOT, slot_prefix.as_bytes())?;
    let mut out = Vec::new();
    for (_k, v) in kvs.into_iter() {
        // v is entry hash
        if let Some(entry_bin) = rocksdb::get(CF_DEFAULT, &v)? {
            out.push(entry_bin);
        }
    }
    Ok(out)
}

/// Insert the genesis entry and initial state markers if not present yet
// pub fn insert_genesis() -> Result<(), Error> {
//     let genesis_entry = genesis::get_gen_entry();
//     if rocksdb::get(CF_DEFAULT, &genesis_entry.hash)?.is_some() {
//         return Ok(()); // already inserted, no-op
//     }
//
//     println!("🌌  Ahhh... Fresh Fabric. Marking genesis..");
//
//     let hash = genesis_entry.hash;
//     let height = genesis_entry.header.height;
//     let slot = genesis_entry.header.slot;
//     let entry_bin: Vec<u8> = genesis_entry.try_into()?;
//     insert_entry(&hash, height, slot, &entry_bin, get_unix_millis_now())?;
//
//     // insert genesis attestation aggregate (no-op until full trainers implemented)
//     let att = genesis::attestation();
//     aggregate_attestation(&att)?;
//
//     // set rooted_tip = genesis.hash and temporal_height = 0
//     set_rooted_tip(&hash)?;
//     rocksdb::put(CF_SYSCONF, b"temporal_height", &height.to_be_bytes())?;
//
//     Ok(())
// }

/// Read Entry from CF_DEFAULT by entry hash (32 bytes) using ETF format
pub fn get_entry_by_hash(hash: &[u8; 32]) -> Option<Entry> {
    let bin = rocksdb::get(CF_DEFAULT, hash).ok()??;
    let entry = Entry::unpack(&bin).ok()?;
    Some(entry)
}

#[derive(Debug, Clone)]
pub struct EntryStub {
    pub hash: [u8; 32],
    pub header_height: u64,
}

/// Get seen time for entry hash using ETF format
pub fn get_seen_time_for_entry(hash: &[u8; 32]) -> Result<Option<u64>, Error> {
    if let Some(bin) = rocksdb::get(CF_MY_SEEN_TIME_FOR_ENTRY, hash)? {
        let term = Term::decode(bin.as_slice())?;
        if let Some(integer_val) = TermExt::get_integer(&term) {
            let seen_millis: u64 = integer_val.try_into().map_err(|_| Error::BadEtf("seen_time"))?;
            return Ok(Some(seen_millis));
        }
        return Err(Error::BadEtf("seen_time_format"));
    }
    Ok(None)
}

pub fn my_attestation_by_entryhash(hash: &[u8]) -> Result<Option<Attestation>, Error> {
    if let Some(bin) = rocksdb::get(CF_MY_ATTESTATION_FOR_ENTRY, hash)? {
        let a = Attestation::from_etf_bin(&bin)?;
        return Ok(Some(a));
    }
    Ok(None)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredConsensus {
    pub mask: Vec<bool>,
    pub agg_sig: [u8; 96],
}

fn pack_consensus_map(map: &HashMap<[u8; 32], StoredConsensus>) -> Result<Vec<u8>, Error> {
    // Encode as ETF map: key: mutations_hash (binary 32); val: map{mask: bitstring, aggsig: binary}
    let mut outer = HashMap::<Term, Term>::new();
    for (mut_hash, v) in map.iter() {
        let key = Term::from(Binary { bytes: mut_hash.to_vec() });
        // pack mask into bytes (bitstring, MSB first)
        let mask_bytes = bools_to_bitvec(&v.mask);
        let mut inner = HashMap::new();
        inner.insert(Term::Atom(Atom::from("mask")), Term::from(Binary { bytes: mask_bytes }));
        inner.insert(Term::Atom(Atom::from("aggsig")), Term::from(Binary { bytes: v.agg_sig.to_vec() }));
        outer.insert(key, Term::from(eetf::Map { map: inner }));
    }
    let term = Term::from(eetf::Map { map: outer });
    let out = encode_safe_deterministic(&term);
    Ok(out)
}

fn unpack_consensus_map(bin: &[u8]) -> Result<HashMap<[u8; 32], StoredConsensus>, Error> {
    let term = Term::decode(bin)?;
    let Some(map) = TermExt::get_term_map(&term) else { return Ok(HashMap::new()) };

    let mut out: HashMap<[u8; 32], StoredConsensus> = HashMap::new();
    for (k, v) in map.0.into_iter() {
        // key: mutations_hash (binary 32)
        let mh_bytes = TermExt::get_binary(&k).ok_or(Error::BadEtf("mutations_hash"))?;
        let mh: [u8; 32] = mh_bytes.try_into().map_err(|_| Error::KvCell("mutations_hash"))?;

        // value: map with keys mask (bitstring), agg_sig (binary)
        let inner = TermExt::get_term_map(&v).ok_or(Error::BadEtf("consensus_inner"))?;
        let mask = inner.get_binary("mask").map(bitvec_to_bools).ok_or(Error::BadEtf("mask"))?;
        let agg_sig = inner.get_binary("aggsig").ok_or(Error::BadEtf("aggsig"))?;

        out.insert(mh, StoredConsensus { mask, agg_sig });
    }
    Ok(out)
}

/// If DB has an attestation for entry_hash signed by a different trainer than current
/// config::trainer_pk, then resign with current keys, update DB and return new attestation.
pub fn get_or_resign_my_attestation(
    config: &crate::config::Config,
    entry_hash: &[u8; 32],
) -> Result<Option<Attestation>, Error> {
    let packed = rocksdb::get(CF_MY_ATTESTATION_FOR_ENTRY, entry_hash)?;
    let Some(bin) = packed else { return Ok(None) };
    let att = Attestation::from_etf_bin(&bin)?;
    if att.signer == config.get_pk() {
        return Ok(Some(att));
    }
    println!("imported database, resigning attestation {}", bs58::encode(entry_hash).into_string());
    let pk = config.get_pk();
    let sk = config.get_sk();
    let new_a = Attestation::sign_with(&pk, &sk, entry_hash, &att.mutations_hash)?;
    let packed = new_a.to_etf_bin()?;
    rocksdb::put(CF_MY_ATTESTATION_FOR_ENTRY, entry_hash, packed.as_slice())?;
    Ok(Some(new_a))
}

/// Update aggregate consensus under entry_hash for attestations with matching mutations_hash
pub fn aggregate_attestation(_a: &Attestation) -> Result<(), Error> {
    // Fetch entry if available (not implemented yet)
    // let entry = entry_by_hash(&a.entry_hash);
    // let trainers = entry.as_ref().and_then(|e| consensus::trainers_for_height(e.header_height));
    // if trainers.is_none() { return Ok(()); }
    // let trainers = trainers.unwrap();

    // For now, without trainers we cannot aggregate reliably; exit early.
    // TODO: implement trainers_for_height and entry storage then enable below code.
    if consensus::trainers_for_height(0).is_none() {
        return Ok(());
    }

    // The code below is kept as reference when trainers are implemented.
    // let trainers = trainers;
    // let mut consensuses = match rocksdb::get(CF_CONSENSUS_BY_ENTRYHASH, &a.entry_hash)? {
    //     Some(bin) => unpack_consensus_map(&bin)?,
    //     None => HashMap::new(),
    // };
    // let cur = consensuses.get(&a.mutations_hash).cloned();
    // let mut agg = match cur {
    //     None => AggSig::new(&trainers, &a.signer, &a.signature).map_err(|_| Error::Missing("agg_sig"))?,
    //     Some(sc) => {
    //         if sc.mask.len() < trainers.len() {
    //             AggSig::new(&trainers, &a.signer, &a.signature).map_err(|_| Error::Missing("agg_sig"))?
    //         } else {
    //             let mut ag = AggSig { mask: sc.mask, aggsig: sc.aggsig };
    //             ag.add(&trainers, &a.signer, &a.signature).map_err(|_| Error::Missing("agg_sig_add"))?;
    //             ag
    //         }
    //     }
    // };
    // consensuses.insert(a.mutations_hash, StoredConsensus { mask: agg.mask.clone(), aggsig: agg.aggsig });
    // let packed = pack_consensus_map(&consensuses)?;
    // rocksdb::put(CF_CONSENSUS_BY_ENTRYHASH, &a.entry_hash, &packed)?;

    Ok(())
}

/// Insert externally computed consensus if its score is better than previous and >= 0.67
pub fn insert_consensus(
    entry_hash: [u8; 32],
    mutations_hash: [u8; 32],
    consensus_mask: Vec<bool>,
    consensus_agg_sig: [u8; 96],
    score: f64,
) -> Result<(), Error> {
    if score < 0.67 {
        return Ok(());
    }

    let mut map = match rocksdb::get(CF_CONSENSUS_BY_ENTRYHASH, &entry_hash)? {
        Some(bin) => unpack_consensus_map(&bin)?,
        None => HashMap::new(),
    };

    // Only update if this consensus is stronger than previously stored for this mutations_hash
    if let Some(existing) = map.get(&mutations_hash) {
        let old_cnt = existing.mask.iter().filter(|&&b| b).count();
        let new_cnt = consensus_mask.iter().filter(|&&b| b).count();
        if new_cnt <= old_cnt {
            return Ok(());
        }
    }

    map.insert(mutations_hash, StoredConsensus { mask: consensus_mask, agg_sig: consensus_agg_sig });
    let packed = pack_consensus_map(&map)?;
    rocksdb::put(CF_CONSENSUS_BY_ENTRYHASH, &entry_hash, &packed)?;
    Ok(())
}

/// Best consensus by weight for a given entry hash and trainers list (weights TODO: all 1.0)
pub fn best_consensus_by_entryhash(
    trainers: &[[u8; 48]],
    entry_hash: &[u8],
) -> Result<(Option<[u8; 32]>, Option<f64>, Option<StoredConsensus>), Error> {
    let Some(bin) = rocksdb::get(CF_CONSENSUS_BY_ENTRYHASH, entry_hash)? else { return Ok((None, None, None)) };
    let map = unpack_consensus_map(&bin)?;
    let max_score = trainers.len() as f64;
    let mut best: Option<([u8; 32], f64, StoredConsensus)> = None;
    for (k, v) in map.into_iter() {
        // Compute score as number of set bits among trainers (unit weight)
        let mut score_units = 0f64;
        for (i, bit) in v.mask.iter().enumerate() {
            if i < trainers.len() && *bit {
                score_units += 1.0;
            }
        }
        let score = if max_score > 0.0 { score_units / max_score } else { 0.0 };
        match &mut best {
            None => best = Some((k, score, v)),
            Some((_bk, bs, _bv)) if score > *bs => best = Some((k, score, v)),
            _ => {}
        }
    }
    if let Some((k, s, v)) = best { Ok((Some(k), Some(s), Some(v))) } else { Ok((None, None, None)) }
}

pub fn set_temporal_height(height: u32) -> Result<(), Error> {
    Ok(rocksdb::put(CF_SYSCONF, b"temporal_height", &(height as u64).to_be_bytes())?)
}

pub fn get_temporal_height() -> Result<Option<u32>, Error> {
    match rocksdb::get(CF_SYSCONF, b"temporal_height")? {
        Some(hb) => Ok(Some(u64::from_be_bytes(hb.try_into().map_err(|_| Error::KvCell("temporal_height"))?) as u32)),
        None => Ok(None),
    }
}

pub fn set_rooted_tip(hash: &[u8; 32]) -> Result<(), Error> {
    Ok(rocksdb::put(CF_SYSCONF, b"rooted_tip", hash)?)
}

pub fn get_rooted_tip() -> Result<Option<[u8; 32]>, Error> {
    match rocksdb::get(CF_SYSCONF, b"rooted_tip")? {
        Some(rt) => Ok(Some(rt.try_into().map_err(|_| Error::KvCell("rooted_tip"))?)),
        None => Ok(None),
    }
}

pub fn set_temporal_tip(hash: &[u8; 32]) -> Result<(), Error> {
    Ok(rocksdb::put(CF_SYSCONF, b"temporal_tip", hash)?)
}

pub fn get_temporal_tip() -> Result<Option<[u8; 32]>, Error> {
    match rocksdb::get(CF_SYSCONF, b"temporal_tip")? {
        Some(rt) => Ok(Some(rt.try_into().map_err(|_| Error::KvCell("temporal_tip"))?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_height_slot_indexing() {
        // initialize db for testing
        let test_path = format!("target/test_fabric_{}", std::process::id());
        let _ = init_kvdb(&test_path).await;

        // create test entry data
        let entry_hash1: [u8; 32] = [1; 32];
        let entry_hash2: [u8; 32] = [2; 32];
        let entry_bin1 = vec![1, 2, 3, 4];
        let entry_bin2 = vec![5, 6, 7, 8];
        let height = 12345;
        let slot1 = 67890;
        let slot2 = 67891;
        let seen_time = 1234567890;

        // insert two entries with same height but different slots
        insert_entry(&entry_hash1, height, slot1, &entry_bin1, seen_time).unwrap();
        insert_entry(&entry_hash2, height, slot2, &entry_bin2, seen_time).unwrap();

        // test querying by height should return both entries
        let entries = entries_by_height(height).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&entry_bin1));
        assert!(entries.contains(&entry_bin2));

        // test querying by slot should return one entry each
        let entries_slot1 = entries_by_slot(slot1).unwrap();
        assert_eq!(entries_slot1.len(), 1);
        assert_eq!(entries_slot1[0], entry_bin1);

        let entries_slot2 = entries_by_slot(slot2).unwrap();
        assert_eq!(entries_slot2.len(), 1);
        assert_eq!(entries_slot2[0], entry_bin2);

        // test querying non-existent height/slot returns empty
        let empty_entries = entries_by_height(99999).unwrap();
        assert!(empty_entries.is_empty());

        let empty_slot = entries_by_slot(99999).unwrap();
        assert!(empty_slot.is_empty());

        println!("height/slot indexing test passed");
    }
}
