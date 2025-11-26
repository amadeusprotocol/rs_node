use crate::Context;
use crate::node::protocol;
use crate::node::protocol::Protocol;
use crate::utils::bls12_381 as bls;
use crate::utils::bls12_381::Error as BlsError;
use crate::utils::{Hash, PublicKey, Signature};
use amadeus_utils::constants::DST_ATT;
use amadeus_utils::vecpak::{Term, VecpakExt, decode, encode};
use std::fmt::Debug;
use std::net::Ipv4Addr;
use tracing::{instrument, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong type: {0}")]
    WrongType(&'static str),
    #[error("missing field: {0}")]
    Missing(&'static str),
    #[error("attestation is not vecpak")]
    AttestationNotVecpak,
    #[error("invalid length: {0}")]
    InvalidLength(&'static str),
    #[error(transparent)]
    Bls(#[from] BlsError),
}

#[derive(Debug, Clone)]
pub struct EventAttestation {
    pub attestations: Vec<Attestation>,
}

#[derive(Clone)]
pub struct Attestation {
    pub entry_hash: Hash,
    pub mutations_hash: Hash,
    pub signer: PublicKey,
    pub signature: Signature,
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
    #[instrument(skip(map), name = "EventAttestation::from_vecpak_map_validated")]
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, protocol::Error> {
        use amadeus_utils::vecpak::{Term, VecpakExt};

        let attestations_list = map.get_list(b"attestations").ok_or(Error::Missing("attestations"))?;

        let mut attestations = Vec::new();
        for term in attestations_list.iter() {
            match term {
                Term::PropList(_) => {
                    let att_map = term.get_proplist_map().ok_or(Error::AttestationNotVecpak)?;
                    let attestation = Attestation::from_vecpak_map(&att_map)?;
                    attestations.push(attestation);
                }
                _ => return Err(Error::AttestationNotVecpak.into()),
            }
        }

        Ok(Self { attestations })
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, protocol::Error> {
        use amadeus_utils::vecpak::{self, encode};

        let attestations_list: Vec<vecpak::Term> = self
            .attestations
            .iter()
            .map(|attestation| Ok(attestation.to_vecpak_term()))
            .collect::<Result<Vec<_>, protocol::Error>>()?;

        let pairs = vec![
            (vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Self::TYPENAME.as_bytes().to_vec())),
            (vecpak::Term::Binary(b"attestations".to_vec()), vecpak::Term::List(attestations_list)),
        ];
        Ok(encode(vecpak::Term::PropList(pairs)))
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
    /// Parse from vecpak PropListMap (primary format)
    #[instrument(skip(map), name = "Attestation::from_vecpak_map", err)]
    pub fn from_vecpak_map(map: &amadeus_utils::vecpak::PropListMap) -> Result<Self, Error> {
        let entry_hash_v = map.get_binary::<Vec<u8>>(b"entry_hash").ok_or(Error::Missing("entry_hash"))?;
        let mutations_hash_v = map.get_binary::<Vec<u8>>(b"mutations_hash").ok_or(Error::Missing("mutations_hash"))?;
        let signer_v = map.get_binary::<Vec<u8>>(b"signer").ok_or(Error::Missing("signer"))?;
        let signature_v = map.get_binary::<Vec<u8>>(b"signature").ok_or(Error::Missing("signature"))?;

        Ok(Attestation {
            entry_hash: entry_hash_v.try_into().map_err(|_| Error::InvalidLength("entry_hash"))?,
            mutations_hash: mutations_hash_v.try_into().map_err(|_| Error::InvalidLength("mutations_hash"))?,
            signer: signer_v.try_into().map_err(|_| Error::InvalidLength("signer"))?,
            signature: signature_v.try_into().map_err(|_| Error::InvalidLength("signature"))?,
        })
    }

    /// Validate sizes and signature with DST_ATT
    #[instrument(skip(self), name = "Attestation::validate", err)]
    pub fn validate(&self) -> Result<(), Error> {
        let mut to_sign = [0u8; 64];
        to_sign[..32].copy_from_slice(self.entry_hash.as_ref());
        to_sign[32..].copy_from_slice(self.mutations_hash.as_ref());
        bls::verify(&self.signer, &self.signature, &to_sign, DST_ATT)?;
        Ok(())
    }

    /// Verify this attestation against an allowed set of trainers (public keys)
    /// Returns Ok(()) only if signer is present in `trainers` and signature is valid
    pub fn validate_vs_trainers<TPk>(&self, trainers: &[TPk]) -> Result<(), Error>
    where
        TPk: AsRef<[u8]>,
    {
        let is_allowed = trainers.iter().any(|pk| pk.as_ref() == self.signer.as_ref() as &[u8]);
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
        entry_hash: &Hash,
        mutations_hash: &Hash,
    ) -> Result<Self, Error> {
        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(entry_hash.as_ref());
        msg[32..].copy_from_slice(mutations_hash.as_ref());
        let signature = bls::sign(trainer_sk, &msg, DST_ATT)?;
        let signer: PublicKey = pk_g1_48.try_into().map_err(|_| Error::InvalidLength("signer"))?;
        let signature: Signature = signature.as_slice().try_into().map_err(|_| Error::InvalidLength("signature"))?;
        Ok(Self { entry_hash: *entry_hash, mutations_hash: *mutations_hash, signer, signature })
    }

    pub fn to_vecpak_bin(&self) -> Vec<u8> {
        encode(self.to_vecpak_term())
    }

    pub fn from_vecpak_bin(data: &[u8]) -> Option<Self> {
        let term = decode(data).ok()?.get_proplist_map()?;
        Self::from_vecpak_map(&term).ok()
    }

    pub fn to_vecpak_term(&self) -> Term {
        Term::PropList(vec![
            (Term::Binary(b"entry_hash".to_vec()), Term::Binary(self.entry_hash.to_vec())),
            (Term::Binary(b"mutations_hash".to_vec()), Term::Binary(self.mutations_hash.to_vec())),
            (Term::Binary(b"signer".to_vec()), Term::Binary(self.signer.to_vec())),
            (Term::Binary(b"signature".to_vec()), Term::Binary(self.signature.to_vec())),
        ])
    }
}
