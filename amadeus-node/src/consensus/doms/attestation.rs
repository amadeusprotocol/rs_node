use crate::Context;
use crate::consensus::agg_sig::DST_ATT;
use crate::node::protocol;
use crate::node::protocol::Protocol;
use crate::utils::bls12_381 as bls;
use crate::utils::bls12_381::Error as BlsError;
use crate::utils::misc::{TermExt, TermMap};
use crate::utils::safe_etf::encode_safe;
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
    pub attestation: Attestation,
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
        let bin = map.get_binary("attestation_packed").ok_or(Error::Missing("attestations_packed"))?;
        let attestation = Attestation::from_etf_bin(bin)?;

        Ok(Self { attestation })
    }

    fn to_etf_bin(&self) -> Result<Vec<u8>, protocol::Error> {
        let attestation = self.attestation.to_etf_bin()?;
        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::TYPENAME)));
        m.insert(Term::Atom(Atom::from("attestation_packed")), Term::from(Binary { bytes: attestation }));
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
            Term::Map(m) => m.map,
            _ => return Err(Error::WrongType("attestation map")),
        };
        let entry_hash_v = map
            .get(&Term::Atom(Atom::from("entry_hash")))
            .and_then(|t| t.get_binary())
            .map(|b| b.to_vec())
            .ok_or(Error::Missing("entry_hash"))?;
        let mutations_hash_v = map
            .get(&Term::Atom(Atom::from("mutations_hash")))
            .and_then(|t| t.get_binary())
            .map(|b| b.to_vec())
            .ok_or(Error::Missing("mutations_hash"))?;
        let signer_v = map
            .get(&Term::Atom(Atom::from("signer")))
            .and_then(|t| t.get_binary())
            .map(|b| b.to_vec())
            .ok_or(Error::Missing("signer"))?;
        let signature_v = map
            .get(&Term::Atom(Atom::from("signature")))
            .and_then(|t| t.get_binary())
            .map(|b| b.to_vec())
            .ok_or(Error::Missing("signature"))?;

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
}
