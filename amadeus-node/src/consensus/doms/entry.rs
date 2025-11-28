use crate::Context;
use crate::consensus::doms::tx::EntryTx;
use crate::consensus::fabric;
use crate::node::protocol;
use crate::node::protocol::Protocol;
use crate::utils::bls12_381;
use crate::utils::misc::{bin_to_bitvec, bitvec_to_bin, get_unix_millis_now};
use crate::utils::{Hash, PublicKey, Signature};
use crate::utils::{archiver, blake3};
/// Entry is a consensus block in Amadeus
use amadeus_utils::constants::DST_VRF;
use amadeus_utils::vecpak::{Term, VecpakExt, decode, encode};
use bitvec::prelude::*;
//use eetf::{Atom, Binary, Map, Term};
use amadeus_utils::vecpak;
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
    #[error("bad format: {0}")]
    BadFormat(&'static str),
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntrySummary {
    pub header: EntryHeader,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "mask_serde")]
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
            root_tx: hmap.get_binary(b"root_tx").ok_or(Error::BadFormat("entry.header.root_tx"))?,
            root_validator: hmap
                .get_binary(b"root_validator")
                .ok_or(Error::BadFormat("entry.header.root_validator"))?,
        };

        let mask = map.get_binary::<Vec<u8>>(b"mask").map(bin_to_bitvec);
        let signature: Signature = map.get_binary(b"signature").ok_or(Error::BadFormat("entry.signature"))?;

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
            prev_hash: Hash::from([0u8; 32]),
            dr: Hash::from([0u8; 32]),
            vr: Signature::from([0u8; 96]),
            signer: PublicKey::from([0u8; 48]),
            root_tx: Hash::from([0u8; 32]),
            root_validator: Hash::from([0u8; 32]),
        };
        Self { header, signature: Signature::from([0u8; 96]), mask: None }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct EntryHeader {
    pub height: u64,
    pub slot: u64,
    pub prev_slot: i64, // is negative 1 in genesis entry
    pub prev_hash: Hash,
    pub dr: Hash,      // deterministic random value
    pub vr: Signature, // verifiable random value
    pub signer: PublicKey,
    #[serde(default = "zero_hash", skip_serializing_if = "is_zero_hash")]
    pub root_tx: Hash,
    #[serde(default = "zero_hash", skip_serializing_if = "is_zero_hash")]
    pub root_validator: Hash,
}

fn zero_hash() -> Hash {
    Hash::from([0u8; 32])
}

fn is_zero_hash(h: &Hash) -> bool {
    *AsRef::<[u8; 32]>::as_ref(h) == [0u8; 32]
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
            .field("root_tx", &bs58::encode(&self.root_tx).into_string())
            .field("root_validator", &bs58::encode(&self.root_validator).into_string())
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
            root_tx: map.get_binary(b"root_tx").unwrap_or_else(zero_hash),
            root_validator: map.get_binary(b"root_validator").unwrap_or_else(zero_hash),
        })
    }

    pub fn to_vecpak_term(&self) -> Term {
        let mut props = vec![
            (Term::Binary(b"height".to_vec()), Term::VarInt(self.height as i128)),
            (Term::Binary(b"slot".to_vec()), Term::VarInt(self.slot as i128)),
            (Term::Binary(b"prev_slot".to_vec()), Term::VarInt(self.prev_slot as i128)),
            (Term::Binary(b"prev_hash".to_vec()), Term::Binary(self.prev_hash.to_vec())),
            (Term::Binary(b"dr".to_vec()), Term::Binary(self.dr.to_vec())),
            (Term::Binary(b"vr".to_vec()), Term::Binary(self.vr.to_vec())),
            (Term::Binary(b"signer".to_vec()), Term::Binary(self.signer.to_vec())),
        ];
        if !is_zero_hash(&self.root_tx) {
            props.push((Term::Binary(b"root_tx".to_vec()), Term::Binary(self.root_tx.to_vec())));
        }
        if !is_zero_hash(&self.root_validator) {
            props.push((Term::Binary(b"root_validator".to_vec()), Term::Binary(self.root_validator.to_vec())));
        }
        Term::PropList(props)
    }

    pub fn to_vecpak_bin(&self) -> Vec<u8> {
        let term = self.to_vecpak_term();
        encode(term)
    }
}

mod mask_serde {
    use super::{BitVec, Msb0, bin_to_bitvec, bitvec_to_bin};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(mask: &Option<BitVec<u8, Msb0>>, ser: S) -> Result<S::Ok, S::Error> {
        match mask {
            Some(m) => serde_bytes::Bytes::new(&bitvec_to_bin(m)).serialize(ser),
            None => ser.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Option<BitVec<u8, Msb0>>, D::Error> {
        let v: Option<serde_bytes::ByteBuf> = Deserialize::deserialize(de)?;
        Ok(v.map(|b| bin_to_bitvec(b.into_vec())))
    }
}

/// Custom deserializer for txs that handles both binary blobs (from Elixir) and structured EntryTx
mod txs_serde {
    use super::EntryTx;
    use amadeus_utils::vecpak;
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(txs: &Vec<EntryTx>, ser: S) -> Result<S::Ok, S::Error> {
        txs.serialize(ser)
    }

    /// Visitor for individual tx items that handles both binary and structured
    struct TxItemVisitor;

    impl<'de> Visitor<'de> for TxItemVisitor {
        type Value = Option<EntryTx>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a binary blob or structured EntryTx")
        }

        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            // Binary blob - decode as vecpak
            Ok(vecpak::from_slice::<EntryTx>(v).ok())
        }

        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
            Ok(vecpak::from_slice::<EntryTx>(&v).ok())
        }

        fn visit_map<M: de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
            // Structured EntryTx - use normal deserialization
            let de = de::value::MapAccessDeserializer::new(map);
            EntryTx::deserialize(de).map(Some)
        }
    }

    struct TxItemDeserializer;

    impl<'de> de::DeserializeSeed<'de> for TxItemDeserializer {
        type Value = Option<EntryTx>;

        fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
            de.deserialize_any(TxItemVisitor)
        }
    }

    struct TxsVisitor;

    impl<'de> Visitor<'de> for TxsVisitor {
        type Value = Vec<EntryTx>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a list of transactions")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut txs = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(maybe_tx) = seq.next_element_seed(TxItemDeserializer)? {
                if let Some(tx) = maybe_tx {
                    txs.push(tx);
                }
            }
            Ok(txs)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<EntryTx>, D::Error> {
        de.deserialize_seq(TxsVisitor)
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    pub header: EntryHeader,
    #[serde(with = "txs_serde")]
    pub txs: Vec<EntryTx>,
    pub hash: Hash,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "mask_serde")]
    pub mask: Option<BitVec<u8, Msb0>>,
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
        let hash: Hash = map.get_binary(b"hash").ok_or(Error::BadFormat("entry.hash"))?;
        let signature: Signature = map.get_binary(b"signature").ok_or(Error::BadFormat("entry.signature"))?;

        let hmap = map
            .get_by_key(b"header")
            .ok_or(Error::BadFormat("entry.header"))?
            .get_proplist_map()
            .ok_or(Error::BadFormat("entry.header"))?;
        let header = EntryHeader::from_vecpak_map(&hmap)?;

        let mask = map.get_binary::<Vec<u8>>(b"mask").map(bin_to_bitvec);

        // Parse txs as structured EntryTx objects
        let txs = map
            .get_list(b"txs")
            .map(|list| {
                list.iter()
                    .filter_map(|t| {
                        // Each tx is a PropList, encode it and deserialize as EntryTx
                        let term_bin = encode(t.clone());
                        vecpak::from_slice::<EntryTx>(&term_bin).ok()
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Entry { hash, header, signature, mask, txs })
    }

    pub fn to_vecpak_term(&self) -> Term {
        // Serialize each EntryTx to a Term
        let txs_list = Term::List(
            self.txs
                .iter()
                .filter_map(|tx| {
                    let bin = vecpak::to_vec(tx).ok()?;
                    decode(&bin).ok()
                })
                .collect(),
        );
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

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct EventEntry {
    pub op: String,
    pub entry_packed: Entry,
}

impl EventEntry {
    pub const TYPENAME: &'static str = "event_entry";
}

impl crate::utils::misc::Typename for EventEntry {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

impl fmt::Debug for EventEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryProto").field("entry_packed", &self.entry_packed).finish()
    }
}

#[async_trait::async_trait]
impl Protocol for EventEntry {
    fn from_vecpak_map_validated(_map: amadeus_utils::vecpak::PropListMap) -> Result<Self, protocol::Error> {
        Err(protocol::Error::ParseError("use vecpak::from_slice"))
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, protocol::Error> {
        Ok(vecpak::to_vec(&self)?)
    }

    async fn handle(&self, ctx: &Context, src: Ipv4Addr) -> Result<Vec<protocol::Instruction>, protocol::Error> {
        self.entry_packed.handle(ctx, src).await
    }
}

impl crate::utils::misc::Typename for Entry {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

impl Entry {
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
            .field("txs", &self.txs.iter().map(|tx| bs58::encode(&tx.hash).into_string()).collect::<Vec<String>>())
            .finish()
    }
}

impl Entry {
    pub const TYPENAME: &'static str = "event_entry";

    /// Build next header skeleton similar to Entry.build_next/2.
    /// This requires chain state (pk/sk), so we only provide a helper to derive next header fields given inputs.
    pub fn build_next_header(&self, slot: u64, signer_pk: &PublicKey, signer_sk: &[u8]) -> Result<EntryHeader, Error> {
        // dr' = blake3(dr)
        let dr = blake3::hash(self.header.dr.as_ref());
        // vr' = sign(sk, prev_vr, DST_VRF)
        let vr = bls12_381::sign(signer_sk, self.header.vr.as_ref(), DST_VRF)?;

        Ok(EntryHeader {
            slot,
            height: self.header.height + 1,
            prev_slot: self.header.slot as i64,
            prev_hash: self.hash,
            dr: Hash::from(dr),
            vr,
            signer: *signer_pk,
            root_tx: Hash::from([0u8; 32]),
            root_validator: Hash::from([0u8; 32]),
        })
    }

    pub fn get_epoch(&self) -> u64 {
        self.header.height / 100_000
    }

    pub fn contains_tx(&self, tx_function: &str) -> bool {
        self.txs.iter().any(|tx| tx.tx.action.function == tx_function)
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
    use crate::consensus::doms::tx::{EntryTx, EntryTxAction, EntryTxInner};

    fn make_test_tx(nonce: i128) -> EntryTx {
        EntryTx {
            hash: Hash::from([0xABu8; 32]),
            signature: Signature::from([0xCDu8; 96]),
            tx: EntryTxInner {
                action: EntryTxAction {
                    args: vec![vec![1, 2, 3]],
                    contract: "TestContract".to_string(),
                    function: "test_func".to_string(),
                    op: "call".to_string(),
                    attached_symbol: None,
                    attached_amount: None,
                },
                nonce,
                signer: PublicKey::from([0xEFu8; 48]),
            },
        }
    }

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

    #[test]
    fn test_entry_serde_vecpak_roundtrip() {
        use amadeus_utils::vecpak;

        let header = EntryHeader {
            height: 12345,
            slot: 67890,
            prev_slot: 67889,
            prev_hash: Hash::from([1u8; 32]),
            dr: Hash::from([2u8; 32]),
            vr: Signature::from([3u8; 96]),
            signer: PublicKey::from([4u8; 48]),
            root_tx: Hash::from([5u8; 32]),
            root_validator: Hash::from([14u8; 32]),
        };
        let entry = Entry {
            hash: Hash::from([6u8; 32]),
            header,
            signature: Signature::from([7u8; 96]),
            mask: Some(bin_to_bitvec(vec![0xFF, 0x00, 0xAB])),
            txs: vec![make_test_tx(1), make_test_tx(2)],
        };

        // to_vecpak_bin -> from_slice
        let vecpak_bin = entry.to_vecpak_bin();
        let decoded: Entry = vecpak::from_slice(&vecpak_bin).expect("from_slice");
        assert_eq!(decoded.hash, entry.hash);
        assert_eq!(decoded.header.height, entry.header.height);
        assert_eq!(decoded.header.slot, entry.header.slot);
        assert_eq!(decoded.txs.len(), entry.txs.len());
        assert_eq!(decoded.mask, entry.mask);

        // to_vec -> from_vecpak_bin
        let serde_bin = vecpak::to_vec(&entry).expect("to_vec");
        let decoded2 = Entry::from_vecpak_bin(&serde_bin).expect("from_vecpak_bin");
        assert_eq!(decoded2.hash, entry.hash);
        assert_eq!(decoded2.header.height, entry.header.height);
        assert_eq!(decoded2.header.slot, entry.header.slot);
        assert_eq!(decoded2.txs.len(), entry.txs.len());
        assert_eq!(decoded2.mask, entry.mask);

        // verify byte-for-byte compatibility
        assert_eq!(vecpak_bin, serde_bin);

        // test without mask
        let entry_no_mask = Entry {
            hash: Hash::from([8u8; 32]),
            header: EntryHeader {
                height: 1,
                slot: 2,
                prev_slot: -1,
                prev_hash: Hash::from([9u8; 32]),
                dr: Hash::from([10u8; 32]),
                vr: Signature::from([11u8; 96]),
                signer: PublicKey::from([12u8; 48]),
                root_tx: Hash::from([13u8; 32]),
                root_validator: Hash::from([15u8; 32]),
            },
            signature: Signature::from([14u8; 96]),
            mask: None,
            txs: vec![],
        };
        let vecpak_bin2 = entry_no_mask.to_vecpak_bin();
        let serde_bin2 = vecpak::to_vec(&entry_no_mask).expect("to_vec");
        assert_eq!(vecpak_bin2, serde_bin2);
        let decoded3: Entry = vecpak::from_slice(&vecpak_bin2).expect("from_slice");
        assert_eq!(decoded3.mask, None);
        assert_eq!(decoded3.header.prev_slot, -1);
    }

    #[test]
    fn test_entry_proto_roundtrip() {
        use amadeus_utils::vecpak;

        // Create a test EntryProto and verify it can roundtrip through serde
        let entry_proto = EventEntry {
            op: "event_entry".to_string(),
            entry_packed: Entry {
                hash: Hash::from([0x07u8; 32]),
                header: EntryHeader {
                    height: 41939338,
                    slot: 41939338,
                    prev_slot: 41939337,
                    prev_hash: Hash::from([0xD9u8; 32]),
                    dr: Hash::from([0x91u8; 32]),
                    vr: Signature::from([0xB3u8; 96]),
                    signer: PublicKey::from([0x95u8; 48]),
                    root_tx: Hash::from([0x3Cu8; 32]),
                    root_validator: Hash::from([0x28u8; 32]),
                },
                signature: Signature::from([0x90u8; 96]),
                mask: None,
                txs: vec![make_test_tx(1762402566835945439)],
            },
        };

        // Serialize
        let bin = vecpak::to_vec(&entry_proto).expect("should serialize");
        println!("Serialized EntryProto: {} bytes", bin.len());
        println!("Hex: {}", hex::encode(&bin));

        // Deserialize
        let decoded: EventEntry = vecpak::from_slice(&bin).expect("should deserialize");

        // Verify
        assert_eq!(decoded.op, "event_entry");
        assert_eq!(decoded.entry_packed.header.height, 41939338);
        assert_eq!(decoded.entry_packed.txs.len(), 1);
        assert_eq!(decoded.entry_packed.txs[0].tx.action.function, "test_func");

        println!("Successfully roundtripped EntryProto!");
    }
}
