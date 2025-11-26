use crate::Context;
use crate::node::protocol::{self, Protocol};
use crate::utils::misc::Typename;
use amadeus_runtime::consensus::bic::sol::SOL_SIZE;
use amadeus_utils::vecpak;
use std::convert::TryInto;
use std::net::Ipv4Addr;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("invalid sol seed size")]
    InvalidSolSeedSize,
    #[error("invalid sol format: too short")]
    TooShort,
    #[error("missing field: {0}")]
    Missing(&'static str),
}

/// Enum wrapper for versioned solutions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Solution {
    V2(SolV2),
    V1(SolV1),
    V0(SolV0),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolV2 {
    pub epoch: u64,
    pub segment_vr_hash: [u8; 32],
    pub pk: [u8; 48],
    pub pop: [u8; 96],
    pub computor: [u8; 48],
    pub nonce: [u8; 12],
    pub tensor_c: [u8; 1024],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolV1 {
    pub epoch: u64,
    pub pk: [u8; 48],
    pub pop: [u8; 96],
    pub computor: [u8; 48],
    pub segment_vr: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolV0 {
    pub epoch: u64,
    pub pk: [u8; 48],
    pub pop: [u8; 96],
    pub computor: [u8; 48],
}

impl Solution {
    pub const TYPENAME: &'static str = "sol";

    pub fn from_bin(bin: &[u8]) -> std::result::Result<Self, Error> {
        if bin.len() >= SOL_SIZE {
            // V2 solution
            let sol = amadeus_runtime::consensus::bic::sol::unpack(bin[..SOL_SIZE].try_into().unwrap());
            Ok(Solution::V2(SolV2 {
                epoch: sol.epoch,
                segment_vr_hash: sol.segment_vr_hash,
                pk: sol.pk,
                pop: sol.pop,
                computor: sol.computor,
                nonce: sol.nonce,
                tensor_c: sol.tensor_c,
            }))
        } else if bin.len() >= 320 {
            // V1 solution
            Ok(Solution::V1(SolV1 {
                epoch: u32::from_le_bytes(bin[0..4].try_into().unwrap()) as u64,
                pk: bin[4..52].try_into().unwrap(),
                pop: bin[52..148].try_into().unwrap(),
                computor: bin[148..196].try_into().unwrap(),
                segment_vr: bin[196..228].try_into().unwrap(),
            }))
        } else if bin.len() >= 256 {
            // V0 solution
            Ok(Solution::V0(SolV0 {
                epoch: u32::from_le_bytes(bin[0..4].try_into().unwrap()) as u64,
                pk: bin[4..52].try_into().unwrap(),
                pop: bin[52..148].try_into().unwrap(),
                computor: bin[148..196].try_into().unwrap(),
            }))
        } else {
            Err(Error::TooShort)
        }
    }
}

impl Typename for Solution {
    fn typename(&self) -> &'static str {
        Solution::TYPENAME
    }
}

#[async_trait::async_trait]
impl Protocol for Solution {
    fn from_vecpak_map_validated(map: amadeus_utils::vecpak::PropListMap) -> Result<Self, protocol::Error> {
        let bin = map.get_binary(b"sol").ok_or(protocol::Error::Other("sol not found".to_string()))?;
        Solution::from_bin(bin).map_err(|_| protocol::Error::Other("sol parse failed".to_string()))
    }

    fn to_vecpak_packet_bin(&self) -> Result<Vec<u8>, protocol::Error> {
        use amadeus_utils::vecpak::encode;
        let sol_bin = match self {
            Solution::V2(v2) => {
                let mut buf = Vec::with_capacity(SOL_SIZE);
                buf.extend_from_slice(&v2.epoch.to_le_bytes());
                buf.extend_from_slice(&v2.segment_vr_hash);
                buf.extend_from_slice(&v2.pk);
                buf.extend_from_slice(&v2.pop);
                buf.extend_from_slice(&v2.computor);
                buf.extend_from_slice(&v2.nonce);
                buf.extend_from_slice(&v2.tensor_c);
                buf
            }
            Solution::V1(v1) => {
                let mut buf = Vec::with_capacity(320);
                buf.extend_from_slice(&v1.epoch.to_le_bytes());
                buf.extend_from_slice(&v1.pk);
                buf.extend_from_slice(&v1.pop);
                buf.extend_from_slice(&v1.computor);
                buf.extend_from_slice(&v1.segment_vr);
                buf.resize(320, 0);
                buf
            }
            Solution::V0(v0) => {
                let mut buf = Vec::with_capacity(256);
                buf.extend_from_slice(&v0.epoch.to_le_bytes());
                buf.extend_from_slice(&v0.pk);
                buf.extend_from_slice(&v0.pop);
                buf.extend_from_slice(&v0.computor);
                buf.resize(256, 0);
                buf
            }
        };

        let pairs = vec![
            (vecpak::Term::Binary(b"op".to_vec()), vecpak::Term::Binary(Solution::TYPENAME.as_bytes().to_vec())),
            (vecpak::Term::Binary(b"sol".to_vec()), vecpak::Term::Binary(sol_bin)),
        ];
        Ok(encode(vecpak::Term::PropList(pairs)))
    }

    async fn handle(&self, _ctx: &Context, _src: Ipv4Addr) -> Result<Vec<protocol::Instruction>, protocol::Error> {
        Ok(vec![protocol::Instruction::ReceivedSol { sol: self.clone() }])
    }
}
