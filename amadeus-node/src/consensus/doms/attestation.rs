use crate::Context;
use crate::node::protocol;
use crate::node::protocol::Protocol;
use crate::utils::bls12_381 as bls;
use crate::utils::bls12_381::Error as BlsError;
use crate::utils::misc::{TermExt, TermMap};
use crate::utils::safe_etf::encode_safe;
use amadeus_utils::constants::DST_ATT;
use eetf::DecodeError as EtfDecodeError;
use eetf::EncodeError as EtfEncodeError;
use eetf::{Atom, Binary, Term};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use tracing::{instrument, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong type: {0}")]
    WrongType(&'static str),
    #[error("missing field: {0}")]
    Missing(&'static str),
    #[error("attestation is not a binary")]
    AttestationNotBinary,
    #[error("too large")]
    TooLarge,
    #[error("not deterministically encoded")]
    NotDeterministic,
    #[error("invalid length: {0}")]
    InvalidLength(&'static str),
    #[error(transparent)]
    EtfDecode(#[from] EtfDecodeError),
    #[error(transparent)]
    EtfEncode(#[from] EtfEncodeError),
    #[error(transparent)]
    Bls(#[from] BlsError),
}

#[derive(Debug, Clone)]
pub struct EventAttestation {
    pub attestations: Vec<Attestation>,
}

#[derive(Clone)]
pub struct Attestation {
    pub entry_hash: [u8; 32],
    pub mutations_hash: [u8; 32],
    pub signer: [u8; 48],
    pub signature: [u8; 96],
}

impl Debug for Attestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attestation")
            .field("entry_hash", &bs58::encode(self.entry_hash).into_string())
            .field("mutations_hash", &bs58::encode(self.mutations_hash).into_string())
            .field("signer", &bs58::encode(self.signer).into_string())
            .finish()
    }
}

impl crate::utils::misc::Typename for EventAttestation {
    fn typename(&self) -> &'static str {
        Self::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for EventAttestation {
    #[instrument(skip(map), name = "EventAttestation::from_etf_map_validated")]
    fn from_etf_map_validated(map: TermMap) -> Result<Self, protocol::Error> {
        let attestations_list = map.get_list("attestations").ok_or(Error::Missing("attestations"))?;

        let mut attestations = Vec::new();

        for term in attestations_list.iter() {
            match term {
                Term::Map(att_map) => {
                    // The attestations come as unpacked maps from the Elixir node
                    let attestation = Attestation::from_etf_map(&att_map)?;
                    attestations.push(attestation);
                }
                Term::Binary(bin) => {
                    // Also support binary format for backwards compatibility
                    let attestation = Attestation::from_etf_bin(&bin.bytes)?;
                    attestations.push(attestation);
                }
                _ => return Err(Error::AttestationNotBinary.into()),
            }
        }

        Ok(Self { attestations })
    }

    fn to_etf_bin(&self) -> Result<Vec<u8>, protocol::Error> {
        let mut attestations_list = Vec::new();
        for attestation in &self.attestations {
            let attestation_bin = attestation.to_etf_bin()?;
            attestations_list.push(Term::from(Binary { bytes: attestation_bin }));
        }

        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::TYPENAME)));
        m.insert(Term::Atom(Atom::from("attestations")), Term::List(eetf::List { elements: attestations_list }));
        let term = Term::from(eetf::Map { map: m });
        let etf_data = encode_safe(&term);
        Ok(etf_data)
    }

    #[instrument(skip(self, _ctx), name = "EventAttestation::handle", err)]
    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<protocol::Instruction>, protocol::Error> {
        // TODO: handle the event_attestation
        Ok(vec![protocol::Instruction::Noop { why: "event_attestation handling not implemented".to_string() }])
    }
}

impl EventAttestation {
    pub const TYPENAME: &'static str = "event_attestation";
}

impl Attestation {
    #[instrument(skip(bin), name = "Attestation::from_etf_bin", err)]
    pub fn from_etf_bin(bin: &[u8]) -> Result<Self, Error> {
        let term = Term::decode(bin)?;

        let map = match term {
            Term::Map(m) => m,
            _ => return Err(Error::WrongType("attestation map")),
        };
        Self::from_etf_map(&map)
    }

    #[instrument(skip(map), name = "Attestation::from_etf_map", err)]
    pub fn from_etf_map(map: &eetf::Map) -> Result<Self, Error> {
        let entry_hash_v = map
            .map
            .get(&Term::Atom(Atom::from("entry_hash")))
            .and_then(|t| t.get_binary())
            .map(|b| b.to_vec())
            .ok_or_else(|| Error::Missing("entry_hash"))?;

        let mutations_hash_v = map
            .map
            .get(&Term::Atom(Atom::from("mutations_hash")))
            .and_then(|t| t.get_binary())
            .map(|b| b.to_vec())
            .ok_or_else(|| Error::Missing("mutations_hash"))?;

        let signer_v = map
            .map
            .get(&Term::Atom(Atom::from("signer")))
            .and_then(|t| t.get_binary())
            .map(|b| b.to_vec())
            .ok_or_else(|| Error::Missing("signer"))?;

        let signature_v = map
            .map
            .get(&Term::Atom(Atom::from("signature")))
            .and_then(|t| t.get_binary())
            .map(|b| b.to_vec())
            .ok_or_else(|| Error::Missing("signature"))?;

        Ok(Attestation {
            entry_hash: entry_hash_v.try_into().map_err(|_| Error::InvalidLength("entry_hash"))?,
            mutations_hash: mutations_hash_v.try_into().map_err(|_| Error::InvalidLength("mutations_hash"))?,
            signer: signer_v.try_into().map_err(|_| Error::InvalidLength("signer"))?,
            signature: signature_v.try_into().map_err(|_| Error::InvalidLength("signature"))?,
        })
    }
    /// Encode into an ETF map with deterministic field set
    #[instrument(skip(self), name = "Attestation::to_etf_bin", err)]
    pub fn to_etf_bin(&self) -> Result<Vec<u8>, Error> {
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("entry_hash")), Term::from(Binary { bytes: self.entry_hash.to_vec() }));
        m.insert(Term::Atom(Atom::from("mutations_hash")), Term::from(Binary { bytes: self.mutations_hash.to_vec() }));
        m.insert(Term::Atom(Atom::from("signer")), Term::from(Binary { bytes: self.signer.to_vec() }));
        m.insert(Term::Atom(Atom::from("signature")), Term::from(Binary { bytes: self.signature.to_vec() }));
        let term = Term::from(eetf::Map { map: m });
        let out = encode_safe(&term);
        Ok(out)
    }

    /// Validate sizes and signature with DST_ATT
    #[instrument(skip(self), name = "Attestation::validate", err)]
    pub fn validate(&self) -> Result<(), Error> {
        let mut to_sign = [0u8; 64];
        to_sign[..32].copy_from_slice(&self.entry_hash);
        to_sign[32..].copy_from_slice(&self.mutations_hash);
        bls::verify(&self.signer, &self.signature, &to_sign, DST_ATT)?;
        Ok(())
    }

    /// Verify this attestation against an allowed set of trainers (public keys)
    /// Returns Ok(()) only if signer is present in `trainers` and signature is valid
    pub fn validate_vs_trainers<TPk>(&self, trainers: &[TPk]) -> Result<(), Error>
    where
        TPk: AsRef<[u8]>,
    {
        let is_allowed = trainers.iter().any(|pk| pk.as_ref() == self.signer);
        if !is_allowed {
            return Err(Error::WrongType("signer_not_trainer"));
        }
        self.validate()
    }

    /// Create an attestation from provided public/secret material
    /// NOTE: we intentionally do not read global env here, caller supplies keys
    pub fn sign_with(
        pk_g1_48: &[u8],
        trainer_sk: &[u8],
        entry_hash: &[u8; 32],
        mutations_hash: &[u8; 32],
    ) -> Result<Self, Error> {
        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(entry_hash);
        msg[32..].copy_from_slice(mutations_hash);
        let signature = bls::sign(trainer_sk, &msg, DST_ATT)?;
        let signer: [u8; 48] = pk_g1_48.try_into().map_err(|_| Error::InvalidLength("signer"))?;
        let signature: [u8; 96] = signature.as_slice().try_into().map_err(|_| Error::InvalidLength("signature"))?;
        Ok(Self { entry_hash: *entry_hash, mutations_hash: *mutations_hash, signer, signature })
    }

    pub fn pack_for_db(&self) -> Vec<u8> {
        use amadeus_utils::vecpak::{self, Term as VTerm};

        let proplist = VTerm::PropList(vec![
            (VTerm::Binary(b"entry_hash".to_vec()), VTerm::Binary(self.entry_hash.to_vec())),
            (VTerm::Binary(b"mutations_hash".to_vec()), VTerm::Binary(self.mutations_hash.to_vec())),
            (VTerm::Binary(b"signer".to_vec()), VTerm::Binary(self.signer.to_vec())),
            (VTerm::Binary(b"signature".to_vec()), VTerm::Binary(self.signature.to_vec())),
        ]);

        vecpak::encode(proplist)
    }

    pub fn unpack_from_db(data: &[u8]) -> Option<Self> {
        use amadeus_utils::vecpak::{self, Term as VTerm};

        let term = vecpak::decode(data).ok()?;

        if let VTerm::PropList(props) = term {
            let mut entry_hash = None;
            let mut mutations_hash = None;
            let mut signer = None;
            let mut signature = None;

            for (k, v) in props {
                if let VTerm::Binary(key_bytes) = k {
                    match key_bytes.as_slice() {
                        b"entry_hash" => {
                            if let VTerm::Binary(h) = v {
                                if h.len() == 32 {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&h);
                                    entry_hash = Some(arr);
                                }
                            }
                        }
                        b"mutations_hash" => {
                            if let VTerm::Binary(m) = v {
                                if m.len() == 32 {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&m);
                                    mutations_hash = Some(arr);
                                }
                            }
                        }
                        b"signer" => {
                            if let VTerm::Binary(s) = v {
                                if s.len() == 48 {
                                    let mut arr = [0u8; 48];
                                    arr.copy_from_slice(&s);
                                    signer = Some(arr);
                                }
                            }
                        }
                        b"signature" => {
                            if let VTerm::Binary(s) = v {
                                if s.len() == 96 {
                                    let mut arr = [0u8; 96];
                                    arr.copy_from_slice(&s);
                                    signature = Some(arr);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            Some(Self {
                entry_hash: entry_hash?,
                mutations_hash: mutations_hash?,
                signer: signer?,
                signature: signature?,
            })
        } else {
            None
        }
    }
}

pub mod db {
    use super::Attestation;
    use amadeus_utils::database::pad_integer;
    use amadeus_utils::rocksdb::RocksDb;

    pub fn by_height(height: u64, db: &RocksDb) -> Vec<Attestation> {
        let prefix = format!("attestation:{}:", pad_integer(height));

        db.iter_prefix("attestation", prefix.as_bytes())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_key, value)| Attestation::unpack_from_db(&value))
            .collect()
    }

    pub fn put(attestation: &Attestation, height: u64, db: &RocksDb) -> Result<(), amadeus_utils::rocksdb::Error> {
        let key = format!(
            "attestation:{}:{}:{}:{}",
            pad_integer(height),
            hex::encode(&attestation.entry_hash),
            hex::encode(&attestation.signer),
            hex::encode(&attestation.mutations_hash)
        );
        let value = attestation.pack_for_db();
        db.put("attestation", key.as_bytes(), &value)?;
        Ok(())
    }
}
