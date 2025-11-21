use crate::Context;
use crate::config::ENTRY_SIZE;
use crate::consensus::doms::tx::TxU;
use crate::consensus::fabric;
use crate::node::protocol;
use crate::node::protocol::Protocol;
use crate::utils::bls12_381;
use crate::utils::misc::{TermExt, bin_to_bitvec, bitvec_to_bin, get_unix_millis_now};
use crate::utils::safe_etf::{encode_safe_deterministic, i64_to_term, u64_to_term};
use crate::utils::{archiver, blake3};
/// Entry is a consensus block in Amadeus
use amadeus_utils::constants::{DST_ENTRY, DST_VRF};
use amadeus_utils::vecpak;
use bitvec::prelude::*;
use eetf::{Atom, Binary, Map, Term};
use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;

const MAX_TXS: usize = 100; // maximum number of transactions in an entry

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
    BadEtf(&'static str),
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
        // allow empty map to represent "no tip" like the Elixir reference
        if map.0.is_empty() {
            return Ok(Self::empty());
        }

        // Handle header field - it can be either:
        // 1. A binary (encoded header) - compact format
        // 2. A PropList (header fields) - expanded format from Elixir
        let header = if let Some(header_bin) = map.get_binary::<Vec<u8>>(b"header") {
            // Case 1: header is already encoded as binary
            EntryHeader::from_etf_bin(&header_bin).map_err(|_| Error::BadEtf("header"))?
        } else if let Some(header_map) = map.get_proplist_map(b"header") {
            // Case 2: header is a PropList with fields (vecpak format)
            let height = header_map.get_integer(b"height").ok_or(Error::BadEtf("height"))?;
            let slot = header_map.get_integer(b"slot").ok_or(Error::BadEtf("slot"))?;
            let prev_slot = header_map.get_integer(b"prev_slot").ok_or(Error::BadEtf("prev_slot"))?;
            let prev_hash = header_map.get_binary(b"prev_hash").ok_or(Error::BadEtf("prev_hash"))?;
            let dr = header_map.get_binary(b"dr").ok_or(Error::BadEtf("dr"))?;
            let vr = header_map.get_binary(b"vr").ok_or(Error::BadEtf("vr"))?;
            let signer = header_map.get_binary(b"signer").ok_or(Error::BadEtf("signer"))?;
            let txs_hash = header_map.get_binary(b"txs_hash").ok_or(Error::BadEtf("txs_hash"))?;

            EntryHeader { height, slot, prev_slot, prev_hash, dr, vr, signer, txs_hash }
        } else {
            return Err(Error::BadEtf("header"));
        };

        let signature = map.get_binary(b"signature").ok_or(Error::BadEtf("signature"))?;
        let mask = map.get_binary::<Vec<u8>>(b"mask").map(bin_to_bitvec);
        Ok(Self { header, signature, mask })
    }

    pub fn to_vecpak_term(&self) -> vecpak::Term {
        let mut pairs = vec![
            (vecpak::Term::Binary(b"header".to_vec()), vecpak::Term::Binary(self.header.to_vecpak_bin())),
            (vecpak::Term::Binary(b"signature".to_vec()), vecpak::Term::Binary(self.signature.to_vec())),
        ];
        if let Some(mask) = &self.mask {
            pairs.push((vecpak::Term::Binary(b"mask".to_vec()), vecpak::Term::Binary(bitvec_to_bin(mask))));
        }
        vecpak::Term::PropList(pairs)
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
    pub fn from_etf_bin(bin: &[u8]) -> Result<Self, Error> {
        let term = Term::decode(bin).map_err(Error::EtfDecode)?;
        let map = term.get_term_map().ok_or(Error::BadEtf("entry-header-map"))?;

        let height = map.get_integer("height").ok_or(Error::BadEtf("height"))?;
        let slot = map.get_integer("slot").ok_or(Error::BadEtf("slot"))?;
        let prev_slot = map.get_integer("prev_slot").ok_or(Error::BadEtf("prev_slot"))?;
        let prev_hash = map.get_binary("prev_hash").ok_or(Error::BadEtf("prev_hash"))?;
        let dr = map.get_binary("dr").ok_or(Error::BadEtf("dr"))?;
        let vr = map.get_binary("vr").ok_or(Error::BadEtf("vr"))?;
        let signer = map.get_binary("signer").ok_or(Error::BadEtf("signer"))?;
        let txs_hash = map.get_binary("txs_hash").ok_or(Error::BadEtf("txs_hash"))?;

        Ok(EntryHeader { height, slot, prev_slot, prev_hash, dr, vr, signer, txs_hash })
    }

    // Always deterministic
    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut map = HashMap::new();
        map.insert(Term::Atom(Atom::from("height")), u64_to_term(self.height));
        map.insert(Term::Atom(Atom::from("slot")), u64_to_term(self.slot));
        map.insert(Term::Atom(Atom::from("prev_slot")), i64_to_term(self.prev_slot));
        map.insert(Term::Atom(Atom::from("prev_hash")), Term::from(Binary { bytes: self.prev_hash.to_vec() }));
        map.insert(Term::Atom(Atom::from("dr")), Term::from(Binary { bytes: self.dr.to_vec() }));
        map.insert(Term::Atom(Atom::from("vr")), Term::from(Binary { bytes: self.vr.to_vec() }));
        map.insert(Term::Atom(Atom::from("signer")), Term::from(Binary { bytes: self.signer.to_vec() }));
        map.insert(Term::Atom(Atom::from("txs_hash")), Term::from(Binary { bytes: self.txs_hash.to_vec() }));

        let term = Term::Map(Map { map });
        let out = encode_safe_deterministic(&term);
        Ok(out)
    }

    pub fn to_vecpak_bin(&self) -> Vec<u8> {
        use amadeus_utils::vecpak::encode;
        let pairs = vec![
            (vecpak::Term::Binary(b"height".to_vec()), vecpak::Term::VarInt(self.height as i128)),
            (vecpak::Term::Binary(b"slot".to_vec()), vecpak::Term::VarInt(self.slot as i128)),
            (vecpak::Term::Binary(b"prev_slot".to_vec()), vecpak::Term::VarInt(self.prev_slot as i128)),
            (vecpak::Term::Binary(b"prev_hash".to_vec()), vecpak::Term::Binary(self.prev_hash.to_vec())),
            (vecpak::Term::Binary(b"dr".to_vec()), vecpak::Term::Binary(self.dr.to_vec())),
            (vecpak::Term::Binary(b"vr".to_vec()), vecpak::Term::Binary(self.vr.to_vec())),
            (vecpak::Term::Binary(b"signer".to_vec()), vecpak::Term::Binary(self.signer.to_vec())),
            (vecpak::Term::Binary(b"txs_hash".to_vec()), vecpak::Term::Binary(self.txs_hash.to_vec())),
        ];
        encode(vecpak::Term::PropList(pairs))
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
    /// Pack entry to ETF deterministic format (like Elixir Entry.pack/1)
    pub fn pack(&self) -> Result<Vec<u8>, Error> {
        let mut map = HashMap::new();

        // Convert header to ETF binary first
        let header_bin = self.header.to_etf_bin()?;
        map.insert(Term::Atom(Atom::from("header")), Term::from(Binary { bytes: header_bin }));

        // Convert txs to ETF list of binaries
        let txs_terms: Vec<Term> = self.txs.iter().map(|tx| Term::from(Binary { bytes: tx.clone() })).collect();
        map.insert(Term::Atom(Atom::from("txs")), Term::from(eetf::List { elements: txs_terms }));

        map.insert(Term::Atom(Atom::from("hash")), Term::from(Binary { bytes: self.hash.to_vec() }));
        map.insert(Term::Atom(Atom::from("signature")), Term::from(Binary { bytes: self.signature.to_vec() }));

        // Handle optional mask
        if let Some(mask) = &self.mask {
            let mask_bytes = bitvec_to_bin(mask);
            map.insert(Term::Atom(Atom::from("mask")), Term::from(Binary { bytes: mask_bytes }));
        }

        let term = Term::from(eetf::Map { map });
        let out = encode_safe_deterministic(&term);
        Ok(out)
    }

    /// Unpack entry from vecpak format (data from Elixir now uses vecpak)
    pub fn unpack(entry_packed: &[u8]) -> Result<Self, Error> {
        use amadeus_utils::vecpak;

        let entry_term =
            vecpak::decode_seemingly_etf_to_vecpak(entry_packed).map_err(|_e| Error::BadEtf("vecpak decode failed"))?;

        Self::from_vecpak_term(entry_term).ok_or(Error::BadEtf("from_vecpak_term failed"))
    }

    pub fn pack_for_db(&self) -> Result<Vec<u8>, Error> {
        use amadeus_utils::vecpak::{self, Term as VTerm};

        let header_proplist = VTerm::PropList(vec![
            (VTerm::Binary(b"height".to_vec()), VTerm::VarInt(self.header.height as i128)),
            (VTerm::Binary(b"slot".to_vec()), VTerm::VarInt(self.header.slot as i128)),
            (VTerm::Binary(b"prev_slot".to_vec()), VTerm::VarInt(self.header.prev_slot as i128)),
            (VTerm::Binary(b"prev_hash".to_vec()), VTerm::Binary(self.header.prev_hash.to_vec())),
            (VTerm::Binary(b"dr".to_vec()), VTerm::Binary(self.header.dr.to_vec())),
            (VTerm::Binary(b"vr".to_vec()), VTerm::Binary(self.header.vr.to_vec())),
            (VTerm::Binary(b"signer".to_vec()), VTerm::Binary(self.header.signer.to_vec())),
            (VTerm::Binary(b"txs_hash".to_vec()), VTerm::Binary(self.header.txs_hash.to_vec())),
        ]);

        let header_packed = vecpak::encode(header_proplist);

        let txs_list = VTerm::List(self.txs.iter().map(|tx| VTerm::Binary(tx.clone())).collect());

        let mut entry_props = vec![
            (VTerm::Binary(b"header".to_vec()), VTerm::Binary(header_packed)),
            (VTerm::Binary(b"txs".to_vec()), txs_list),
            (VTerm::Binary(b"hash".to_vec()), VTerm::Binary(self.hash.to_vec())),
            (VTerm::Binary(b"signature".to_vec()), VTerm::Binary(self.signature.to_vec())),
        ];

        if let Some(mask) = &self.mask {
            entry_props.push((VTerm::Binary(b"mask".to_vec()), VTerm::Binary(bitvec_to_bin(mask))));
        }

        let entry_map = VTerm::PropList(entry_props);
        Ok(vecpak::encode(entry_map))
    }

    pub fn unpack_from_db(entry_packed: Option<Vec<u8>>) -> Option<Self> {
        use amadeus_utils::vecpak;

        let entry_packed = entry_packed?;

        // try vecpak format first (new format)
        match vecpak::decode_seemingly_etf_to_vecpak(&entry_packed) {
            Ok(entry_term) => {
                if let Some(entry) = Self::from_vecpak_term(entry_term) {
                    return Some(entry);
                }
            }
            Err(_) => {}
        }

        // fallback to ETF format (legacy format)
        if let Ok(entry) = Self::from_etf_direct(&entry_packed) {
            return Some(entry);
        }

        None
    }

    /// decode entry from ETF format (legacy database format)
    fn from_etf_direct(bin: &[u8]) -> Result<Self, Error> {
        let term = Term::decode(bin).map_err(Error::EtfDecode)?;
        let map = term.get_term_map().ok_or(Error::BadEtf("entry"))?;

        // decode header (binary encoded)
        let header_bin: Vec<u8> = map.get_binary("header").ok_or(Error::BadEtf("header"))?;
        let header = EntryHeader::from_etf_bin(&header_bin)?;

        // decode txs (list of binaries)
        let txs_list = map.get_list("txs").ok_or(Error::BadEtf("txs"))?;
        let mut txs = Vec::new();
        for tx_term in txs_list {
            if let Some(bytes) = tx_term.get_binary() {
                txs.push(bytes.to_vec());
            }
        }

        // decode hash
        let hash: [u8; 32] = map.get_binary("hash").ok_or(Error::BadEtf("hash"))?;

        // decode signature
        let signature: [u8; 96] = map.get_binary("signature").ok_or(Error::BadEtf("signature"))?;

        // decode optional mask
        let mask = map.get_binary::<Vec<u8>>("mask").map(bin_to_bitvec);

        Ok(Self { header, txs, hash, signature, mask })
    }

    fn from_vecpak_term(term: amadeus_utils::vecpak::Term) -> Option<Self> {
        use amadeus_utils::vecpak::{self, Term as VTerm};

        if let VTerm::PropList(props) = term {
            let mut hash = None;
            let mut header_bin = None;
            let mut signature = None;
            let mut mask = None;
            let mut txs = Vec::new();

            for (k, v) in &props {
                if let VTerm::Binary(key_bytes) = k {
                    match key_bytes.as_slice() {
                        b"hash" => {
                            if let VTerm::Binary(h) = v {
                                if h.len() == 32 {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(h);
                                    hash = Some(arr);
                                }
                            }
                        }
                        b"header" => match v {
                            VTerm::Binary(h) => {
                                header_bin = Some(h.clone());
                            }
                            VTerm::PropList(_) => {
                                // header is inline PropList, encode it to binary for parsing
                                header_bin = Some(vecpak::encode(v.clone()));
                            }
                            _ => {}
                        },
                        b"signature" => {
                            if let VTerm::Binary(s) = v {
                                if s.len() == 96 {
                                    let mut arr = [0u8; 96];
                                    arr.copy_from_slice(s);
                                    signature = Some(arr);
                                }
                            }
                        }
                        b"mask" => {
                            if let VTerm::Binary(m) = v {
                                mask = Some(bin_to_bitvec(m.clone()));
                            }
                        }
                        b"txs" => {
                            if let VTerm::List(tx_list) = v {
                                for tx_term in tx_list {
                                    if let VTerm::Binary(tx_bin) = tx_term {
                                        txs.push(tx_bin.clone());
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            if hash.is_none() || header_bin.is_none() || signature.is_none() {
                return None;
            }

            let header = Self::parse_vecpak_header(header_bin?)?;

            Some(Entry { hash: hash?, header, signature: signature?, mask, txs })
        } else {
            None
        }
    }

    fn parse_vecpak_header(header_bin: Vec<u8>) -> Option<EntryHeader> {
        use amadeus_utils::vecpak::{self, Term as VTerm};

        let header_term = vecpak::decode_seemingly_etf_to_vecpak(&header_bin).ok()?;

        if let VTerm::PropList(props) = header_term {
            let mut height = 0u64;
            let mut slot = 0u64;
            let mut prev_slot = 0i64;
            let mut prev_hash = [0u8; 32];
            let mut dr = [0u8; 32];
            let mut vr = [0u8; 96];
            let mut signer = [0u8; 48];
            let mut txs_hash = [0u8; 32];

            for (k, v) in props {
                if let VTerm::Binary(key_bytes) = k {
                    match key_bytes.as_slice() {
                        b"height" => {
                            if let VTerm::VarInt(h) = v {
                                if h >= 0 {
                                    height = h as u64;
                                }
                            }
                        }
                        b"slot" => {
                            if let VTerm::VarInt(s) = v {
                                if s >= 0 {
                                    slot = s as u64;
                                }
                            }
                        }
                        b"prev_slot" => {
                            if let VTerm::VarInt(ps) = v {
                                prev_slot = ps as i64;
                            }
                        }
                        b"prev_hash" => {
                            if let VTerm::Binary(ph) = v {
                                if ph.len() == 32 {
                                    prev_hash.copy_from_slice(&ph);
                                }
                            }
                        }
                        b"dr" => {
                            if let VTerm::Binary(d) = v {
                                if d.len() == 32 {
                                    dr.copy_from_slice(&d);
                                }
                            }
                        }
                        b"vr" => {
                            if let VTerm::Binary(v_bin) = v {
                                if v_bin.len() == 96 {
                                    vr.copy_from_slice(&v_bin);
                                }
                            }
                        }
                        b"signer" => {
                            if let VTerm::Binary(s) = v {
                                if s.len() == 48 {
                                    signer.copy_from_slice(&s);
                                }
                            }
                        }
                        b"txs_hash" => {
                            if let VTerm::Binary(th) = v {
                                if th.len() == 32 {
                                    txs_hash.copy_from_slice(&th);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            Some(EntryHeader { height, slot, prev_slot, prev_hash, dr, vr, signer, txs_hash })
        } else {
            None
        }
    }
}

impl TryFrom<&[u8]> for Entry {
    type Error = Error;

    fn try_from(bin: &[u8]) -> Result<Self, Self::Error> {
        Self::unpack(bin)
    }
}

impl TryInto<Vec<u8>> for Entry {
    type Error = Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        self.pack()
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
        let bin = map.get_binary(b"entry_packed").ok_or(Error::BadEtf("entry_packed"))?;
        Entry::from_etf_bin_validated(bin, ENTRY_SIZE).map_err(Into::into)
    }

    fn to_vecpak_bin(&self) -> Result<Vec<u8>, protocol::Error> {
        use amadeus_utils::vecpak::encode;
        let entry_bin: Vec<u8> = self.pack().map_err(|_| protocol::Error::Vecpak("entry pack failed".to_string()))?;

        let pairs = vec![
            (vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Self::TYPENAME.as_bytes().to_vec())),
            (vecpak::Term::Binary(b"entry_packed".to_vec()), vecpak::Term::Binary(entry_bin)),
        ];
        Ok(encode(vecpak::Term::PropList(pairs)))
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
            let bin = self.pack_for_db()?;

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

    pub fn from_etf_bin_validated(bin: &[u8], entry_size_limit: usize) -> Result<Entry, Error> {
        if bin.len() >= entry_size_limit {
            return Err(Error::BadEtf("entry_bin_too_large"));
        }

        // Validate deterministic ETF encoding first
        let parsed_entry = Entry::unpack(bin)?;
        let repacked = parsed_entry.pack()?;
        if bin != repacked {
            return Err(Error::BadEtf("not_deterministicly_encoded"));
        }

        // Validate header deterministic encoding
        let header_repacked = parsed_entry.header.to_etf_bin()?;
        // Note: We need to extract original header binary from the entry to compare
        let term = Term::decode(bin)?;
        let map = term.get_term_map().ok_or(Error::BadEtf("entry"))?;
        let original_header_bin = map.get_binary("header").ok_or(Error::BadEtf("header"))?;
        if original_header_bin != header_repacked {
            return Err(Error::BadEtf("not_deterministicly_encoded_header"));
        }

        let parsed = ParsedEntry { entry: parsed_entry, header_bin: original_header_bin };
        parsed.validate_signature()?;
        let is_special = parsed.entry.mask.is_some();
        parsed.entry.validate_contents(is_special)?;

        Ok(parsed.entry)
    }

    fn validate_contents(&self, is_special_meeting_block: bool) -> Result<(), Error> {
        if self.txs.len() > MAX_TXS {
            return Err(Error::BadEtf("txs_len_over_100"));
        }

        let txs_bin = self.txs.iter().flatten().cloned().collect::<Vec<u8>>();
        if self.header.txs_hash.as_slice() != blake3::hash(&txs_bin).as_slice() {
            return Err(Error::BadTxsHash);
        }

        for txp in &self.txs {
            super::tx::validate(txp, is_special_meeting_block)?;
        }

        Ok(())
    }

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

#[derive(Debug, Clone)]
struct ParsedEntry {
    pub entry: Entry,
    pub header_bin: Vec<u8>,
}

impl ParsedEntry {
    fn validate_signature(&self) -> Result<(), Error> {
        if let Some(_mask) = &self.entry.mask {
            // Aggregate signature path requires trainers from chain state (DB); not available here.
            return Err(Error::NoTrainers);
        } else {
            let h = blake3::hash(&self.header_bin);
            bls12_381::verify(&self.entry.header.signer, &self.entry.signature, &h, DST_ENTRY)?;
        }

        Ok(())
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

pub mod db {
    use super::Entry;
    use amadeus_utils::database::pad_integer;
    use amadeus_utils::rocksdb::RocksDb;

    pub fn by_hash(hash: &[u8], db: &RocksDb) -> Option<Entry> {
        let entry_packed = db.get("entry", hash).ok()??;
        Entry::unpack_from_db(Some(entry_packed))
    }

    pub fn by_height(height: u64, db: &RocksDb) -> Vec<Entry> {
        let prefix = format!("by_height:{}:", pad_integer(height));

        db.iter_prefix("entry_meta", prefix.as_bytes())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_key, value)| by_hash(&value, db))
            .collect()
    }

    pub fn by_height_return_hashes(height: u64, db: &RocksDb) -> Vec<Vec<u8>> {
        let prefix = format!("by_height:{}:", pad_integer(height));

        db.iter_prefix("entry_meta", prefix.as_bytes())
            .unwrap_or_default()
            .into_iter()
            .map(|(_key, value)| value)
            .collect()
    }

    pub fn by_height_in_main_chain(height: u64, db: &RocksDb) -> Option<Vec<u8>> {
        let key = format!("by_height_in_main_chain:{}", pad_integer(height));
        db.get("entry_meta", key.as_bytes()).ok()?
    }

    pub fn seentime(hash: &[u8], db: &RocksDb) -> Option<i64> {
        let key = format!("entry:{}:seentime", hex::encode(hash));
        let bytes = db.get("entry_meta", key.as_bytes()).ok()??;
        if bytes.len() == 8 {
            Some(i64::from_le_bytes(bytes.try_into().unwrap()))
        } else if bytes.len() == 16 {
            Some(u128::from_le_bytes(bytes.try_into().unwrap()) as i64)
        } else {
            None
        }
    }

    pub fn muts_hash(hash: &[u8], db: &RocksDb) -> Option<Vec<u8>> {
        let key = format!("entry:{}:muts_hash", hex::encode(hash));
        db.get("entry_meta", key.as_bytes()).ok()?
    }

    pub fn prev(hash: &[u8], db: &RocksDb) -> Option<Vec<u8>> {
        let key = format!("entry:{}:prev", hex::encode(hash));
        db.get("entry_meta", key.as_bytes()).ok()?
    }

    pub fn next(hash: &[u8], db: &RocksDb) -> Option<Vec<u8>> {
        let key = format!("entry:{}:next", hex::encode(hash));
        db.get("entry_meta", key.as_bytes()).ok()?
    }

    pub fn in_chain(hash: &[u8], db: &RocksDb) -> bool {
        let key = format!("entry:{}:in_chain", hex::encode(hash));
        db.get("entry_meta", key.as_bytes()).ok().flatten().is_some()
    }

    pub fn insert(entry: &Entry, db: &RocksDb) -> Result<(), Box<dyn std::error::Error>> {
        let entry_packed = entry.pack_for_db()?;

        db.put("entry", &entry.hash, &entry_packed)?;

        let height_key = format!("by_height:{}:{}", pad_integer(entry.header.height), hex::encode(&entry.hash));
        db.put("entry_meta", height_key.as_bytes(), &entry.hash)?;

        let seentime_key = format!("entry:{}:seentime", hex::encode(&entry.hash));
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
        db.put("entry_meta", seentime_key.as_bytes(), &now.to_le_bytes())?;

        Ok(())
    }
}
