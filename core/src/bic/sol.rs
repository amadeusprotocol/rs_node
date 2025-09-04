use crate::Context;
use crate::node::protocol;
use crate::node::protocol::Protocol;
use crate::utils::blake3;
use crate::utils::misc::TermMap;
use crate::utils::safe_etf::encode_safe;
use eetf::{Atom, Term};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Mutex;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("invalid sol seed size")]
    InvalidSolSeedSize,
    #[error("invalid sol format: too short")]
    TooShort,
    #[error("missing field: {0}")]
    Missing(&'static str),
}

pub const PREAMBLE_SIZE: usize = 240;
pub const MATRIX_SIZE: usize = 1024;
pub const SOL_SIZE: usize = PREAMBLE_SIZE + MATRIX_SIZE; // 1264

pub fn size() -> usize {
    SOL_SIZE
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolV2 {
    pub epoch: u32,
    pub segment_vr_hash: [u8; 32],
    pub pk: [u8; 48],
    pub pop: [u8; 96],
    pub computor: [u8; 48],
    pub tensor_c: [u8; 1024],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolV1 {
    pub epoch: u32,
    pub pk: [u8; 48],
    pub pop: [u8; 96],
    pub computor: [u8; 48],
    pub segment_vr: [u8; 96],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolV0 {
    pub epoch: u32,
    pub pk: [u8; 48],
    pub pop: [u8; 96],
    pub computor: [u8; 48],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Solution {
    V2(SolV2), // epoch >= 156
    V1(SolV1), // 1 <= epoch < 156
    V0(SolV0), // epoch < 1
}

impl crate::utils::misc::Typename for Solution {
    fn typename(&self) -> &'static str {
        Self::NAME
    }
}

#[async_trait::async_trait]
impl Protocol for Solution {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, protocol::Error> {
        let bin = map.get_binary("sol").ok_or(Error::Missing("sol"))?;
        Solution::from_etf_validated(bin).map_err(Into::into)
    }
    fn to_etf_bin(&self) -> Result<Vec<u8>, protocol::Error> {
        // convert solution back to binary format
        let sol_bin = match self {
            Solution::V2(v2) => {
                let mut buf = Vec::with_capacity(SOL_SIZE);
                buf.extend_from_slice(&v2.epoch.to_le_bytes());
                buf.extend_from_slice(&v2.segment_vr_hash);
                buf.extend_from_slice(&v2.pk);
                buf.extend_from_slice(&v2.pop);
                buf.extend_from_slice(&v2.computor);
                buf.extend_from_slice(&[0u8; 12]); // nonce placeholder
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
                // pad to expected size
                buf.resize(320, 0);
                buf
            }
            Solution::V0(v0) => {
                let mut buf = Vec::with_capacity(256);
                buf.extend_from_slice(&v0.epoch.to_le_bytes());
                buf.extend_from_slice(&v0.pk);
                buf.extend_from_slice(&v0.pop);
                buf.extend_from_slice(&v0.computor);
                // pad to expected size
                buf.resize(256, 0);
                buf
            }
        };

        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("sol")), Term::from(eetf::Binary { bytes: sol_bin }));

        let term = Term::from(eetf::Map { map: m });
        let out = encode_safe(&term);
        Ok(out)
    }

    async fn handle(
        &self,
        _ctx: &Context,
        _src: std::net::SocketAddr,
    ) -> Result<protocol::Instruction, protocol::Error> {
        // cache the solution
        Ok(protocol::Instruction::Noop { why: "solution handling not implemented".to_string() })
    }
}

impl Solution {
    pub const NAME: &'static str = "sol";

    pub fn to_etf_bin(&self) -> Result<Vec<u8>, protocol::Error> {
        // convert solution back to binary format
        let sol_bin = match self {
            Solution::V2(v2) => {
                let mut buf = Vec::with_capacity(SOL_SIZE);
                buf.extend_from_slice(&v2.epoch.to_le_bytes());
                buf.extend_from_slice(&v2.segment_vr_hash);
                buf.extend_from_slice(&v2.pk);
                buf.extend_from_slice(&v2.pop);
                buf.extend_from_slice(&v2.computor);
                buf.extend_from_slice(&[0u8; 12]); // nonce placeholder
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
                // pad to expected size
                buf.resize(320, 0);
                buf
            }
            Solution::V0(v0) => {
                let mut buf = Vec::with_capacity(256);
                buf.extend_from_slice(&v0.epoch.to_le_bytes());
                buf.extend_from_slice(&v0.pk);
                buf.extend_from_slice(&v0.pop);
                buf.extend_from_slice(&v0.computor);
                // pad to expected size
                buf.resize(256, 0);
                buf
            }
        };

        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from(Self::NAME)));
        m.insert(Term::Atom(Atom::from("sol")), Term::from(eetf::Binary { bytes: sol_bin }));

        let term = Term::from(eetf::Map { map: m });
        let out = encode_safe(&term);
        Ok(out)
    }

    pub fn from_etf_validated(bin: &[u8]) -> Result<Self, Error> {
        if Self::validate(bin)? { Self::unpack(bin) } else { Err(Error::InvalidSolSeedSize) }
    }

    pub fn unpack(sol: &[u8]) -> Result<Self, Error> {
        if sol.len() < 4 {
            return Err(Error::TooShort);
        }
        let epoch = u32::from_le_bytes(sol[0..4].try_into().unwrap());

        if epoch >= 156 {
            // <<epoch::32-little, segment_vr_hash::32-binary, sol_pk::48-binary, pop::96-binary, computor_pk::48-binary, nonce::12-binary, tensor_c::1024-binary>>
            if sol.len() < 4 + 32 + 48 + 96 + 48 + 12 + 1024 {
                return Err(Error::TooShort);
            }
            let segment_vr_hash: [u8; 32] = sol[4..36].try_into().unwrap();
            let pk: [u8; 48] = sol[36..84].try_into().unwrap();
            let pop: [u8; 96] = sol[84..180].try_into().unwrap();
            let computor: [u8; 48] = sol[180..228].try_into().unwrap();
            // skip nonce (12 bytes)
            let tensor_c: [u8; 1024] = sol[240..(240 + 1024)].try_into().unwrap();
            Ok(Solution::V2(SolV2 { epoch, segment_vr_hash, pk, pop, computor, tensor_c }))
        } else if epoch >= 1 {
            // <<epoch::32-little, sol_pk::48-binary, pop::96-binary, computor_pk::48-binary, segment_vr::96-binary, _::binary>>
            if sol.len() < 4 + 48 + 96 + 48 + 96 {
                return Err(Error::TooShort);
            }
            let pk: [u8; 48] = sol[4..52].try_into().unwrap();
            let pop: [u8; 96] = sol[52..148].try_into().unwrap();
            let computor: [u8; 48] = sol[148..196].try_into().unwrap();
            let segment_vr: [u8; 96] = sol[196..292].try_into().unwrap();
            Ok(Solution::V1(SolV1 { epoch, pk, pop, computor, segment_vr }))
        } else {
            // <<epoch::32-little, sol_pk::48-binary, pop::96-binary, computor_pk::48-binary, _::binary>>
            if sol.len() < 4 + 48 + 96 + 48 {
                return Err(Error::TooShort);
            }
            let pk: [u8; 48] = sol[4..52].try_into().unwrap();
            let pop: [u8; 96] = sol[52..148].try_into().unwrap();
            let computor: [u8; 48] = sol[148..196].try_into().unwrap();
            Ok(Solution::V0(SolV0 { epoch, pk, pop, computor }))
        }
    }

    pub fn validate(sol: &[u8]) -> Result<bool, Error> {
        if sol.len() < 4 {
            return Err(Error::TooShort);
        }
        let epoch = u32::from_le_bytes(sol[0..4].try_into().unwrap());
        if epoch >= 260 {
            if sol.len() != SOL_SIZE {
                return Err(Error::InvalidSolSeedSize);
            }
            let hash = blake3::hash(sol);
            let vr_b3 = vr_b3_stub();
            Ok(verify_hash(epoch, &hash) && blake3::freivalds_e260(sol, &vr_b3))
        } else if epoch >= 156 {
            if sol.len() != SOL_SIZE {
                return Err(Error::InvalidSolSeedSize);
            }
            let hash = blake3::hash(sol);
            Ok(verify_hash(epoch, &hash) && blake3::freivalds(sol))
        } else if epoch >= 1 {
            if sol.len() != 320 {
                return Err(Error::InvalidSolSeedSize);
            }
            Ok(verify_cache(epoch, sol, true))
        } else {
            if sol.len() != 256 {
                return Err(Error::InvalidSolSeedSize);
            }
            Ok(verify_cache(epoch, sol, false))
        }
    }
}

pub fn verify_hash(epoch: u32, hash: &[u8; 32]) -> bool {
    if epoch >= 244 {
        hash[0] == 0 && hash[1] == 0 && hash[2] == 0
    } else if epoch >= 1 {
        // there may be separate case for 156
        hash[0] == 0 && hash[1] == 0
    } else {
        hash[0] == 0
    }
}

fn vr_b3_stub() -> [u8; 32] {
    // TODO: provide cryptographically strong random 32 bytes if available
    // stubbed to zeros to avoid introducing external dependencies
    [0u8; 32]
}

// minimalistic global cache emulating SOLVerifyCache ETS behavior
static SOL_VERIFY_CACHE: Lazy<Mutex<HashMap<Vec<u8>, bool>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn cache_mark_valid(sol: &[u8]) {
    let mut m = SOL_VERIFY_CACHE.lock().unwrap();
    m.insert(sol.to_vec(), true);
}

fn verify_cache(epoch: u32, sol: &[u8], _use_upow1: bool) -> bool {
    if let Some(is_valid) = SOL_VERIFY_CACHE.lock().unwrap().get(sol).copied()
        && is_valid
    {
        // delete like :ets.delete
        SOL_VERIFY_CACHE.lock().unwrap().remove(sol);
        return true;
    }
    // module.calculate(sol) placeholder: use blake3 hash
    let hash: [u8; 32] = blake3::hash(sol);
    verify_hash(epoch, &hash)
}

pub fn verify_with_hash(sol: &[u8], hash: &[u8; 32]) -> Result<bool, Error> {
    if sol.len() < 4 {
        return Err(Error::TooShort);
    }
    let epoch = u32::from_le_bytes(sol[0..4].try_into().unwrap());
    if epoch >= 260 {
        if sol.len() != SOL_SIZE {
            return Err(Error::InvalidSolSeedSize);
        }
        let vr_b3 = vr_b3_stub();
        Ok(verify_hash(epoch, hash) && blake3::freivalds_e260(sol, &vr_b3))
    } else if epoch >= 156 {
        if sol.len() != SOL_SIZE {
            return Err(Error::InvalidSolSeedSize);
        }
        Ok(verify_hash(epoch, hash) && blake3::freivalds(sol))
    } else if epoch >= 1 {
        if sol.len() != 320 {
            return Err(Error::InvalidSolSeedSize);
        }
        Ok(verify_cache(epoch, sol, true))
    } else {
        if sol.len() != 256 {
            return Err(Error::InvalidSolSeedSize);
        }
        Ok(verify_cache(epoch, sol, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match() {
        assert_eq!(size(), 1264);
        assert_eq!(SOL_SIZE, 1264);
    }

    #[test]
    fn verify_hash_rules() {
        let mut h = [0u8; 32];
        assert!(verify_hash(0, &h));
        assert!(verify_hash(1, &h));
        assert!(verify_hash(156, &h));
        assert!(verify_hash(244, &h));
        h[0] = 1;
        assert!(!verify_hash(0, &h));
        assert!(!verify_hash(1, &h));
        h[0] = 0;
        h[1] = 1;
        assert!(!verify_hash(1, &h));
        assert!(!verify_hash(156, &h));
        h[1] = 0;
        h[2] = 1;
        assert!(verify_hash(156, &h));
        assert!(!verify_hash(244, &h));
    }

    #[test]
    fn unpack_v2() {
        // build minimal V2 buffer
        let epoch: u32 = 200;
        let mut buf = vec![];
        buf.extend_from_slice(&epoch.to_le_bytes());
        buf.extend_from_slice(&[0u8; 32]); // segment_vr_hash
        buf.extend_from_slice(&[1u8; 48]); // pk
        buf.extend_from_slice(&[2u8; 96]); // pop
        buf.extend_from_slice(&[3u8; 48]); // computor
        buf.extend_from_slice(&[4u8; 12]); // nonce
        buf.extend_from_slice(&[5u8; 1024]); // tensor_c
        match Solution::unpack(&buf).unwrap() {
            Solution::V2(v2) => {
                assert_eq!(v2.epoch, epoch);
                assert_eq!(v2.segment_vr_hash, [0u8; 32]);
                assert_eq!(v2.pk, [1u8; 48]);
                assert_eq!(v2.pop, [2u8; 96]);
                assert_eq!(v2.computor, [3u8; 48]);
                assert_eq!(v2.tensor_c, [5u8; 1024]);
            }
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn parse_well_known_sol() {
        // solution was taken from here https://explorer.ama.one/network/tx/7q8WZu9a2YNcEwhbLGSrJt3aCWefHRMm8nC66sg9YzGd
        let b58 = "9tvLYXHJMkJ9jFW42R8mZxzEtNmAm8J6gRVUHW2Rubxf5FoY8J8FXd2kaKd338B4uy57Tn3akZ4y6gaYe1Y1tCATcyR6w3rJGeFzL5aebmmExAGsdLPmzYK2CD5pYTTqbVhsQRGwMj2JxjpQHyppt3TY7XZVd1SuafinFKHe1hCXkxRWEAQnxXsBgzZmTDr7S9fnxBpVuBHxvgNefGGDVieD44cSA4LrCmeWA4WaUQby54g9jGhf53QdiQVCMWtaFwDUNnKTMZ1GG2cmNCHDDQqhpRQAqczzL4XqYmnzRF9TVZBEhPFgUnhAHu27FMhnCv8zqeg3ujrXvnX1SyGaBL7sJqG9FEcJbYLpisgnuwpYinUbDcg5tYgPZeBw28NYUvbc1xr9bnfSznxkHH5npZ2cA8uXq753FybTd5wd67FBHTKe7dW76JB2chxHK3Q2UGRf67oTb7wZC7SQtZt7bg9CWnLGe7bfYFKwR1U5dSzKroqkZ9Taunh4VswZCnEAhZJyFt5rw5fB8SnHQJgtnDomCdxbJUxByY9ekE4Jvr3DDhwtzf2YZuHMniE67TcNNoKTLsJxhJFGo1ct2mJv6iMPQXEYHqioQ7uzrLw42tzEQF6DQ9a6972duwfymfW98mueJpwNjsK8m52BdH7cEYqzAFj4nusZmm9vmjjKUy6aPD2MgMccyW18Dy8bpKrTCH9KTzGzeXHgHbNha44WPcCkGxqbMVWHdHVwSVPD9mJqwJGvrKAba15EobNQAnCJGJy4McGaGsChMrQXXrzakLjTtKjkrmWSbPxcjwLiBzf7dvhWUmzFZuxSdMbDRj2zFqsMqLDgZTTFMGoqBrwiwEyj8pQHy9DCiSRQWbycT4DdsFTKVrfgFNvA1XvUaptjSXozLASYS9SgXdjBTNsmCUsHrkdwHVVzFN6MNUAhjv7yF6X8yCmUMwrG1DQgmmJ4ADrzSP73xA5wMEVy2TWqy3ms69rLdjC4cgqKYsUwZVUkvamLoppLBsVh95yVPJuutmdsYHqiTxs8dQ4ymdu8uKZ5tcdnRL2HfRU6Xdjo99ws4Bwe8Pmx1WHWRgg83YV9E2nsWfreaSYrW8UTz7bNsPsQtmxzvdKq1RdnfTJWgAv5EPN2ZL3jBdE7pfGgEzw98W8EpLZGWDZSFUrht8GFTzUrUVR75WXVqWJdRk5hpetE3H67MCS3ujMvr4W1cNzmheJoCDh5SbFXj49S2ftUYcD4BVdfX451sKkRwuEeofKJoGBL4p3rdo3izFyBdJvMY8GrLMxYrS9adAqXjiLt16KBm5xYo6BdXygsrZfs54dWJUhzVVturAuXLPKecn5SJCxKhUy9KYxCNZaLcqCBWYX76EFZoBt9uAPbPNUNUWWQc9JA4yTveJ7J1uUpv2Qfam57ozbPuF5JkteymMpwWLHbC3UsY35orLeHRVhpj15dqTPDkF1ASjDPXXDJgwmtBCzJ1j8UXYwnxojNTsXLkBMRx8PX2phef88SznTnZhKVyMujpczgbPCafRGBXYpmAisQ39tyreT6n1pveg5LoFjWr9jDDEdRwQCoiyzg3ZSSzrfgnqfBYSK1f6ktA5Xceg1fp3FFpV4Yc3uvnKXdgRnvtm6ZV5mDqHQUUr73r1HoiK4y52THc6NvqpkosrZJsiAKf1eXHF8Rbjz6MD1ZxN7mAVnc4YYyPJgKrhuijF8WTrHx9WdNFzZBSJLC2J";
        let bin = bs58::decode(b58).into_vec().unwrap();
        let sol = Solution::from_etf_validated(&bin).unwrap();
        assert!(matches!(sol, Solution::V2(SolV2 { epoch: 274, .. })));
        println!("{:?}", sol);
    }
}
