/// Entry is a consensus block in Amadeus
use super::agg_sig::{DST_ENTRY, DST_VRF};
use crate::config::ENTRY_SIZE;
use crate::consensus::tx::TxU;
use crate::consensus::{fabric, tx};
use crate::node::protocol;
use crate::node::protocol::Protocol;
use crate::Context;
use crate::utils::bls12_381;
use crate::utils::misc::{TermExt, TermMap, bitvec_to_bools, bools_to_bitvec, get_unix_millis_now};
use crate::utils::{archiver, blake3};
use crate::{bic, consensus};
use eetf::{Atom, BigInteger, Binary, Map, Term};
use std::collections::HashMap;
use std::fmt;
// use tracing::{instrument, warn};

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
    Tx(#[from] tx::Error),
    #[error(transparent)]
    Bls(#[from] bls12_381::Error),
    #[error(transparent)]
    Fabric(#[from] fabric::Error),
    #[error(transparent)]
    Archiver(#[from] archiver::Error),
    #[error(transparent)]
    RocksDb(#[from] crate::utils::rocksdb::Error),
}

/// Shared summary of an entry’s tip.
#[derive(Debug)]
pub struct EntrySummary {
    pub header: EntryHeader,
    pub signature: [u8; 96],
    pub mask: Option<Vec<bool>>,
}

impl From<Entry> for EntrySummary {
    fn from(entry: Entry) -> Self {
        Self { header: entry.header, signature: entry.signature, mask: entry.mask }
    }
}

impl EntrySummary {
    /// Helper that reads an EntrySummary from an ETF term.
    pub fn from_etf_term(map: &TermMap) -> Result<Self, Error> {
        // allow empty map to represent "no tip" like the Elixir reference
        if map.0.is_empty() {
            return Ok(Self::empty());
        }
        let header_bin: Vec<u8> = map.get_binary("header").ok_or(Error::BadEtf("header"))?;
        let signature = map.get_binary("signature").ok_or(Error::BadEtf("signature"))?;
        let mask = map.get_binary("mask").map(bitvec_to_bools);
        let header = EntryHeader::from_etf_bin(&header_bin).map_err(|_| Error::BadEtf("header"))?;
        Ok(Self { header, signature, mask })
    }

    /// Convert EntrySummary to ETF term for encoding
    pub fn to_etf_term(&self) -> Result<Term, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("header")), Term::from(Binary { bytes: self.header.to_etf_bin()? }));
        m.insert(Term::Atom(Atom::from("signature")), Term::from(Binary { bytes: self.signature.to_vec() }));
        if let Some(mask) = &self.mask {
            m.insert(Term::Atom(Atom::from("mask")), Term::from(Binary { bytes: bools_to_bitvec(mask) }));
        }
        Ok(Term::from(Map { map: m }))
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

#[derive(bincode::Decode, bincode::Encode, Clone)]
pub struct EntryHeader {
    pub height: u64, // no need in u128 for next centuries
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

    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut map = HashMap::new();
        map.insert(Term::Atom(Atom::from("height")), Term::from(BigInteger { value: self.height.into() }));
        map.insert(Term::Atom(Atom::from("slot")), Term::from(BigInteger { value: self.slot.into() }));
        map.insert(Term::Atom(Atom::from("prev_slot")), Term::from(BigInteger { value: self.prev_slot.into() }));
        map.insert(Term::Atom(Atom::from("prev_hash")), Term::from(Binary { bytes: self.prev_hash.to_vec() }));
        map.insert(Term::Atom(Atom::from("dr")), Term::from(Binary { bytes: self.dr.to_vec() }));
        map.insert(Term::Atom(Atom::from("vr")), Term::from(Binary { bytes: self.vr.to_vec() }));
        map.insert(Term::Atom(Atom::from("signer")), Term::from(Binary { bytes: self.signer.to_vec() }));
        map.insert(Term::Atom(Atom::from("txs_hash")), Term::from(Binary { bytes: self.txs_hash.to_vec() }));

        let term = Term::Map(Map { map });
        let mut out = Vec::new();
        term.encode(&mut out)?;
        Ok(out)
    }
}

#[derive(bincode::Decode, bincode::Encode, Clone)]
pub struct Entry {
    pub hash: [u8; 32],
    pub header: EntryHeader,
    pub signature: [u8; 96],
    pub mask: Option<Vec<bool>>, // vec<bool> in rust is special - its a packed vec<u8>
    pub txs: Vec<Vec<u8>>,       // list of tx binaries that can be empty
}

impl TryFrom<&[u8]> for Entry {
    type Error = bincode::error::DecodeError;

    fn try_from(bin: &[u8]) -> Result<Self, Self::Error> {
        let config = bincode::config::standard();
        let (entry, len): (Self, usize) = bincode::decode_from_slice(bin, config)?;

        if len != bin.len() {
            return Err(bincode::error::DecodeError::Other("entry bin length mismatch"));
        }

        Ok(entry)
    }
}

impl TryInto<Vec<u8>> for Entry {
    type Error = bincode::error::EncodeError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let config = bincode::config::standard();
        bincode::encode_to_vec(&self, config).map_err(Into::into)
    }
}

impl crate::utils::misc::Typename for Entry {
    fn typename(&self) -> &'static str {
        Self::NAME
    }
}

#[async_trait::async_trait]
impl Protocol for Entry {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, protocol::Error> {
        let bin = map.get_binary("entry_packed").ok_or(Error::BadEtf("entry_packed"))?;
        Entry::from_etf_bin_validated(bin, ENTRY_SIZE).map_err(Into::into)
    }
    fn to_etf_bin(&self) -> Result<Vec<u8>, protocol::Error> {
        // encode entry as bincode first
        let entry_bin: Vec<u8> = self.clone().try_into().map_err(|_| protocol::Error::BadEtf("entry"))?;

        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("entry_packed")), Term::from(Binary { bytes: entry_bin }));

        let term = Term::from(Map { map: m });
        let mut out = Vec::new();
        term.encode(&mut out).map_err(protocol::Error::EtfEncode)?;
        Ok(out)
    }

    async fn handle_inner(&self, _ctx: &Context, _src: std::net::SocketAddr) -> Result<protocol::Instruction, protocol::Error> {
        self.handle_inner().await.map_err(Into::into)
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
    pub const NAME: &'static str = "entry";

    pub fn to_etf_bin(&self) -> Result<Vec<u8>, protocol::Error> {
        // encode entry as bincode first
        let entry_bin: Vec<u8> = self.clone().try_into().map_err(|_| protocol::Error::BadEtf("entry"))?;

        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("entry_packed")), Term::from(Binary { bytes: entry_bin }));

        let term = Term::from(Map { map: m });
        let mut out = Vec::new();
        term.encode(&mut out).map_err(protocol::Error::EtfEncode)?;
        Ok(out)
    }

    async fn handle_inner(&self) -> Result<protocol::Instruction, Error> {
        let height = self.header.height;

        // compute rooted_tip_height if possible
        let rooted_height = fabric::get_rooted_tip()
            .ok()
            .flatten()
            .map(TryInto::try_into)
            .and_then(|h| h.ok())
            .and_then(|h| fabric::get_entry_by_hash(&h))
            .map(|e| e.header.height)
            .unwrap_or(0);

        if height >= rooted_height {
            let hash = self.hash;
            let epoch = self.get_epoch();
            let slot = self.header.slot; // height is the same as slot in amadeus
            let bin: Vec<u8> = self.clone().try_into()?;

            fabric::insert_entry(&hash, height, slot, &bin, get_unix_millis_now())?;
            archiver::store(bin, format!("epoch-{}", epoch), format!("entry-{}", height)).await?;
        }

        Ok(protocol::Instruction::Noop)
    }

    pub fn from_etf_bin_validated(bin: &[u8], entry_size_limit: usize) -> Result<Entry, Error> {
        if bin.len() >= entry_size_limit {
            return Err(Error::BadEtf("entry_bin_too_large"));
        }

        let parsed = ParsedEntry::from_etf_bin(bin)?;
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
            tx::validate(txp, is_special_meeting_block)?;
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
    fn from_etf_bin(bin: &[u8]) -> Result<Self, Error> {
        let map = Term::decode(bin)?.get_term_map().ok_or(Error::BadEtf("entry"))?;
        let hash = map.get_binary("hash").ok_or(Error::BadEtf("hash"))?;
        let header_bin: Vec<u8> = map.get_binary("header").ok_or(Error::BadEtf("header"))?;
        let signature = map.get_binary("signature").ok_or(Error::BadEtf("signature"))?;
        let mask = map.get_binary("mask").map(bitvec_to_bools);
        let txs: Vec<Vec<u8>> =
            map.get_list("txs").unwrap_or_default().iter().filter_map(TermExt::get_binary).map(Into::into).collect();

        let header = EntryHeader::from_etf_bin(&header_bin)?;
        Ok(ParsedEntry { entry: Entry { hash, header, signature, mask, txs }, header_bin })
    }

    fn validate_signature(&self) -> Result<(), Error> {
        if let Some(mask) = &self.entry.mask {
            // resolve trainers for this height (chain state dependent)
            if let Some(trainers) = consensus::trainers_for_height(self.entry.header.height) {
                // unmask trainers who have signed using the provided bitmask
                let signed: Vec<[u8; 48]> = bic::epoch::unmask_trainers(&trainers, mask);
                if signed.is_empty() {
                    // no signers in mask -> invalid aggregate signature
                    return Err(Error::BadAggSignature);
                }
                // aggregate public keys
                let agg_pk = bls12_381::aggregate_public_keys(signed.iter())?;
                // verify aggregate signature over blake3(header_bin)
                let h = blake3::hash(&self.header_bin);
                bls12_381::verify(&agg_pk, &self.entry.signature, &h, DST_ENTRY)?;
            } else {
                return Err(Error::NoTrainers); // trainers unavailable
            }
        } else {
            let h = blake3::hash(&self.header_bin);
            bls12_381::verify(&self.entry.header.signer, &self.entry.signature, &h, DST_ENTRY)?;
        }

        Ok(())
    }
}
