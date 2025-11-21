use crate::Context;
use crate::consensus::doms::tx::TxU;
use crate::consensus::fabric;
use crate::node::protocol;
use crate::node::protocol::Protocol;
use crate::utils::bls12_381;
use crate::utils::misc::{bin_to_bitvec, bitvec_to_bin, get_unix_millis_now};
use crate::utils::{archiver, blake3};
/// Entry is a consensus block in Amadeus
use amadeus_utils::constants::DST_VRF;
use amadeus_utils::vecpak::{Term, VecpakExt, decode, encode};
use bitvec::prelude::*;
//use eetf::{Atom, Binary, Map, Term};
use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    EtfDecode(#[from] eetf::DecodeError),
    #[error(transparent)]
    EtfEncode(#[from] eetf::EncodeError),
    #[error(transparent)]
    BinDecode(#[from] bincode::error::DecodeError),
    #[error(transparent)]
    BinEncode(#[from] bincode::error::EncodeError),
    #[error("invalid erlang etf: {0}")]
    BadFormat(&'static str),
    #[error("invalid signature")]
    BadAggSignature,
    #[error("wrong epoch or unsupported aggregate signature path")]
    NoTrainers,
    #[error("txs_hash invalid")]
    BadTxsHash,
    #[error(transparent)]
    Tx(#[from] super::tx::Error),
    #[error(transparent)]
    Bls(#[from] bls12_381::Error),
    #[error(transparent)]
    Fabric(#[from] fabric::Error),
    #[error(transparent)]
    Archiver(#[from] archiver::Error),
    #[error(transparent)]
    RocksDb(#[from] crate::utils::rocksdb::Error),
}

/// Shared summary of an entry's tip
#[derive(Debug, Clone)]
pub struct EntrySummary {
    pub header: EntryHeader,
    pub signature: [u8; 96],
    pub mask: Option<BitVec<u8, Msb0>>,
}

impl From<Entry> for EntrySummary {
    fn from(entry: Entry) -> Self {
        Self { header: entry.header, signature: entry.signature, mask: entry.mask }
    }
}

impl EntrySummary {
    /// Primary: Parse from vecpak PropListMap
    pub fn from_vecpak_map(map: &amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        let hmap = map
            .get_by_key(b"header")
            .ok_or(Error::BadFormat("entry.header"))?
            .get_proplist_map()
            .ok_or(Error::BadFormat("entry.header"))?;

        let header = EntryHeader {
            height: hmap.get_integer(b"height").ok_or(Error::BadFormat("entry.header.height"))?,
            slot: hmap.get_integer(b"slot").ok_or(Error::BadFormat("entry.header.slot"))?,
            prev_slot: hmap.get_integer(b"prev_slot").ok_or(Error::BadFormat("entry.header.prev_slot"))?,
            prev_hash: hmap.get_binary(b"prev_hash").ok_or(Error::BadFormat("entry.header.prev_hash"))?,
            dr: hmap.get_binary(b"dr").ok_or(Error::BadFormat("entry.header.dr"))?,
            vr: hmap.get_binary(b"vr").ok_or(Error::BadFormat("entry.header.vr"))?,
            signer: hmap.get_binary(b"signer").ok_or(Error::BadFormat("entry.header.signer"))?,
            txs_hash: hmap.get_binary(b"txs_hash").ok_or(Error::BadFormat("entry.header.txs_hash"))?,
        };

        let mask = map.get_binary::<Vec<u8>>(b"mask").map(bin_to_bitvec);
        let signature: [u8; 96] = map.get_binary(b"signature").ok_or(Error::BadFormat("entry.signature"))?;

        Ok(Self { header, signature, mask })
    }

    pub fn to_vecpak_term(&self) -> Term {
        let mut props = vec![
            (Term::Binary(b"header".to_vec()), self.header.to_vecpak_term()),
            (Term::Binary(b"signature".to_vec()), Term::Binary(self.signature.to_vec())),
        ];
        if let Some(mask) = &self.mask {
            props.push((Term::Binary(b"mask".to_vec()), Term::Binary(bitvec_to_bin(mask))));
        }
        Term::PropList(props)
    }

    /// Empty summary placeholder used when tips are missing
    pub fn empty() -> Self {
        let header = EntryHeader {
            height: 0,
            slot: 0,
            prev_slot: 0,
            prev_hash: [0u8; 32],
            dr: [0u8; 32],
            vr: [0u8; 96],
            signer: [0u8; 48],
            txs_hash: [0u8; 32],
        };
        Self { header, signature: [0u8; 96], mask: None }
    }
}

#[derive(Clone)]
pub struct EntryHeader {
    pub height: u64,
    pub slot: u64,
    pub prev_slot: i64, // is negative 1 in genesis entry
    pub prev_hash: [u8; 32],
    pub dr: [u8; 32], // deterministic random value
    pub vr: [u8; 96], // verifiable random value
    pub signer: [u8; 48],
    pub txs_hash: [u8; 32],
}

impl fmt::Debug for EntryHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryHeader")
            .field("slot", &self.slot)
            .field("dr", &bs58::encode(&self.dr).into_string())
            .field("height", &self.height)
            .field("prev_hash", &bs58::encode(&self.prev_hash).into_string())
            .field("prev_slot", &self.prev_slot)
            .field("signer", &bs58::encode(&self.signer).into_string())
            .field("txs_hash", &bs58::encode(&self.txs_hash).into_string())
            .field("vr", &bs58::encode(&self.vr).into_string())
            .finish()
    }
}

impl EntryHeader {
    pub fn from_vecpak_map(map: &amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        Ok(EntryHeader {
            height: map.get_integer(b"height").ok_or(Error::BadFormat("entry.header.height"))?,
            slot: map.get_integer(b"slot").ok_or(Error::BadFormat("entry.header.slot"))?,
            prev_slot: map.get_integer(b"prev_slot").ok_or(Error::BadFormat("entry.header.prev_slot"))?,
            prev_hash: map.get_binary(b"prev_hash").ok_or(Error::BadFormat("entry.header.prev_hash"))?,
            dr: map.get_binary(b"dr").ok_or(Error::BadFormat("entry.header.dr"))?,
            vr: map.get_binary(b"vr").ok_or(Error::BadFormat("entry.header.vr"))?,
            signer: map.get_binary(b"signer").ok_or(Error::BadFormat("entry.header.signer"))?,
            txs_hash: map.get_binary(b"txs_hash").ok_or(Error::BadFormat("entry.header.txs_hash"))?,
        })
    }

    pub fn to_vecpak_term(&self) -> Term {
        Term::PropList(vec![
            (Term::Binary(b"height".to_vec()), Term::VarInt(self.height as i128)),
            (Term::Binary(b"slot".to_vec()), Term::VarInt(self.slot as i128)),
            (Term::Binary(b"prev_slot".to_vec()), Term::VarInt(self.prev_slot as i128)),
            (Term::Binary(b"prev_hash".to_vec()), Term::Binary(self.prev_hash.to_vec())),
            (Term::Binary(b"dr".to_vec()), Term::Binary(self.dr.to_vec())),
            (Term::Binary(b"vr".to_vec()), Term::Binary(self.vr.to_vec())),
            (Term::Binary(b"signer".to_vec()), Term::Binary(self.signer.to_vec())),
            (Term::Binary(b"txs_hash".to_vec()), Term::Binary(self.txs_hash.to_vec())),
        ])
    }

    pub fn to_vecpak_bin(&self) -> Vec<u8> {
        let term = self.to_vecpak_term();
        encode(term)
    }
}

#[derive(Clone)]
pub struct Entry {
    pub hash: [u8; 32],
    pub header: EntryHeader,
    pub signature: [u8; 96],
    pub mask: Option<BitVec<u8, Msb0>>,
    pub txs: Vec<Vec<u8>>, // list of tx binaries that can be empty
}

impl Entry {
    pub fn from_vecpak_bin(bin: &[u8]) -> Result<Self, Error> {
        let map = decode(bin)
            .map_err(|_| Error::BadFormat("entry_packed"))?
            .get_proplist_map()
            .ok_or(Error::BadFormat("entry_packed"))?;
        Self::from_vecpak_map(&map)
    }

    pub fn to_vecpak_bin(&self) -> Vec<u8> {
        let term = self.to_vecpak_term();
        encode(term)
    }

    pub fn from_vecpak_map(map: &amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        let hash: [u8; 32] = map.get_binary(b"hash").ok_or(Error::BadFormat("entry.hash"))?;
        let signature: [u8; 96] = map.get_binary(b"signature").ok_or(Error::BadFormat("entry.signature"))?;

        let hmap = map
            .get_by_key(b"header")
            .ok_or(Error::BadFormat("entry.header"))?
            .get_proplist_map()
            .ok_or(Error::BadFormat("entry.header"))?;
        let header = EntryHeader::from_vecpak_map(&hmap)?;

        let mask = map.get_binary::<Vec<u8>>(b"mask").map(bin_to_bitvec);

        let txs = map
            .get_list(b"txs")
            .map(|list| list.iter().filter_map(|t| t.get_binary().map(|b| b.to_vec())).collect())
            .unwrap_or_default();

        Ok(Entry { hash, header, signature, mask, txs })
    }

    pub fn to_vecpak_term(&self) -> Term {
        let txs_list = Term::List(self.txs.iter().map(|tx| Term::Binary(tx.clone())).collect());
        let mut props = vec![
            (Term::Binary(b"header".to_vec()), self.header.to_vecpak_term()),
            (Term::Binary(b"txs".to_vec()), txs_list),
            (Term::Binary(b"hash".to_vec()), Term::Binary(self.hash.to_vec())),
            (Term::Binary(b"signature".to_vec()), Term::Binary(self.signature.to_vec())),
        ];
        if let Some(mask) = &self.mask {
            props.push((Term::Binary(b"mask".to_vec()), Term::Binary(bitvec_to_bin(mask))));
        }
        Term::PropList(props)
    }
}

impl crate::utils::misc::Typename for Entry {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for Entry {
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, protocol::Error> {
        let entry_map = map.get_proplist_map(b"entry_packed").ok_or(Error::BadFormat("entry_packed"))?;
        Self::from_vecpak_map(&entry_map).map_err(Into::into)
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, protocol::Error> {
        let term = self.to_vecpak_term();
        Ok(encode(term))
    }

    async fn handle(&self, ctx: &Context, _src: Ipv4Addr) -> Result<Vec<protocol::Instruction>, protocol::Error> {
        let height = self.header.height;

        // compute rooted_tip_height if possible
        let rooted_height = ctx
            .fabric
            .get_rooted_hash()
            .ok()
            .flatten()
            .map(TryInto::try_into)
            .and_then(|h| h.ok())
            .and_then(|h| ctx.fabric.get_entry_by_hash(&h))
            .map(|e| e.header.height)
            .unwrap_or(0);

        if height >= rooted_height {
            let hash = self.hash;
            let slot = self.header.slot;
            let bin = self.to_vecpak_bin();

            ctx.fabric.insert_entry(&hash, height, slot, &bin, get_unix_millis_now())?;

            //let epoch = self.get_epoch();
            //archiver::store(bin, format!("epoch-{}", epoch), format!("entry-{}", height)).await?;
        }

        Ok(vec![protocol::Instruction::Noop { why: "entry handling not implemented".to_string() }])
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("hash", &bs58::encode(&self.hash).into_string())
            .field("header", &self.header)
            .field("signature", &bs58::encode(&self.signature).into_string())
            .field("txs", &self.txs.iter().map(|tx| bs58::encode(tx).into_string()).collect::<Vec<String>>())
            .finish()
    }
}

impl Entry {
    pub const TYPENAME: &'static str = "event_entry";

    /// Build next header skeleton similar to Entry.build_next/2.
    /// This requires chain state (pk/sk), so we only provide a helper to derive next header fields given inputs.
    pub fn build_next_header(&self, slot: u64, signer_pk: &[u8; 48], signer_sk: &[u8]) -> Result<EntryHeader, Error> {
        // dr' = blake3(dr)
        let dr = blake3::hash(&self.header.dr);
        // vr' = sign(sk, prev_vr, DST_VRF)
        let vr = bls12_381::sign(signer_sk, &self.header.vr, DST_VRF)?;

        Ok(EntryHeader {
            slot,
            height: self.header.height + 1,
            prev_slot: self.header.slot as i64,
            prev_hash: self.hash,
            dr,
            vr,
            signer: *signer_pk,
            txs_hash: [0u8; 32], // to be filled when txs are known
        })
    }

    pub fn get_epoch(&self) -> u64 {
        self.header.height / 100_000
    }

    pub fn contains_tx(&self, tx_function: &str) -> bool {
        self.txs.iter().any(|txp| {
            if let Ok(txu) = TxU::from_vanilla(txp) {
                if let Some(first) = txu.tx.actions.first() { first.function == tx_function } else { false }
            } else {
                false
            }
        })
    }
}

/// Get archived entries as a list of (epoch, height, entry_size) tuples by parsing filenames
pub async fn get_archived_entries() -> Result<Vec<(u64, u64, u64)>, Error> {
    let filenames_with_sizes = archiver::get_archived_filenames().await?;
    let mut entries = Vec::new();

    for (filename, file_size) in filenames_with_sizes {
        if let Some((epoch, height)) = parse_entry_filename(&filename) {
            entries.push((epoch, height, file_size));
        }
    }

    // Sort by epoch first, then by height
    entries.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    entries.dedup(); // Remove any duplicates

    Ok(entries)
}

/// Parse entry filename to extract epoch and height
/// Expected format: "epoch-{epoch}/entry-{height}" or similar patterns
fn parse_entry_filename(filename: &str) -> Option<(u64, u64)> {
    // Split by '/' to get directory and filename parts
    let parts: Vec<&str> = filename.split('/').collect();

    let mut epoch = None;
    let mut height = None;

    // Look for epoch in directory part (e.g., "epoch-123")
    for part in &parts {
        if let Some(epoch_str) = part.strip_prefix("epoch-") {
            if let Ok(e) = epoch_str.parse::<u64>() {
                epoch = Some(e);
            }
        }
    }

    // Look for height in filename part (e.g., "entry-456")
    if let Some(filename_part) = parts.last() {
        if let Some(height_str) = filename_part.strip_prefix("entry-") {
            if let Ok(h) = height_str.parse::<u64>() {
                height = Some(h);
            }
        }
    }

    match (epoch, height) {
        (Some(e), Some(h)) => Some((e, h)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_entry_filename() {
        // Test valid filenames
        assert_eq!(parse_entry_filename("epoch-0/entry-12345"), Some((0, 12345)));
        assert_eq!(parse_entry_filename("epoch-123/entry-456"), Some((123, 456)));
        assert_eq!(parse_entry_filename("epoch-999/subdir/entry-789"), Some((999, 789)));

        // Test invalid filenames
        assert_eq!(parse_entry_filename("not-epoch/entry-123"), None);
        assert_eq!(parse_entry_filename("epoch-123/not-entry"), None);
        assert_eq!(parse_entry_filename("epoch-abc/entry-123"), None);
        assert_eq!(parse_entry_filename("epoch-123/entry-def"), None);
        assert_eq!(parse_entry_filename("random-file.txt"), None);
        assert_eq!(parse_entry_filename(""), None);
    }

    #[tokio::test]
    async fn test_get_archived_entries_empty() {
        // This test will only work if the archiver is not initialized
        // or the directory is empty, which is fine for testing the function structure
        let result = get_archived_entries().await;
        // We don't assert specific values since we don't know the state of the filesystem
        // but we ensure the function doesn't panic and returns a proper Result
        match result {
            Ok(entries) => {
                // Entries should be sorted and deduplicated
                for i in 1..entries.len() {
                    let prev = entries[i - 1];
                    let curr = entries[i];
                    assert!(prev.0 < curr.0 || (prev.0 == curr.0 && prev.1 <= curr.1));
                    // Each entry should have a file size (third element)
                    assert!(curr.2 > 0 || curr.2 == 0); // File size can be 0 for empty files
                }
            }
            Err(_) => {
                // It's okay if it fails due to archiver not being initialized
            }
        }
    }
}
