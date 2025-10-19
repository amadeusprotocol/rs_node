// Protocol implementation for Solution from runtime
use crate::node::protocol::{self, Protocol};
use crate::utils::misc::TermMap;
use crate::utils::safe_etf::encode_safe;
use crate::Context;
use amadeus_runtime::bic::sol::{Solution, Error, SOL_SIZE};
use eetf::{Atom, Term};
use std::collections::HashMap;

// Wrapper type to implement Protocol for Solution
#[derive(Debug, Clone)]
pub struct SolutionProto(pub Solution);

impl crate::utils::misc::Typename for SolutionProto {
    fn typename(&self) -> &'static str {
        "sol"
    }
}

#[async_trait::async_trait]
impl Protocol for SolutionProto {
    fn from_etf_map_validated(map: TermMap) -> Result<Self, protocol::Error> {
        let bin = map.get_binary("sol").ok_or(Error::Missing("sol"))?;
        Solution::from_etf_validated(bin).map(SolutionProto).map_err(Into::into)
    }

    fn to_etf_bin(&self) -> Result<Vec<u8>, protocol::Error> {
        // convert solution back to binary format
        let sol_bin = match &self.0 {
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

        let mut m = HashMap::new();
        m.insert(Term::Atom(Atom::from("op")), Term::Atom(Atom::from("sol")));
        m.insert(Term::Atom(Atom::from("sol")), Term::from(eetf::Binary { bytes: sol_bin }));

        let term = Term::from(eetf::Map { map: m });
        let out = encode_safe(&term);
        Ok(out)
    }

    async fn handle(
        &self,
        _ctx: &Context,
        _src: std::net::Ipv4Addr,
    ) -> Result<Vec<protocol::Instruction>, protocol::Error> {
        // cache the solution
        Ok(vec![protocol::Instruction::Noop { why: "solution handling not implemented".to_string() }])
    }
}
