//! Vecpak term utilities similar to eetf TermExt

pub use ::vecpak::{Term, decode_term, encode, encode_term};

use crate::vecpak_compat;
use std::collections::HashMap;
use tracing::warn;

/// Decode binary data as vecpak Term (auto-detects legacy ETF and converts to vecpak)
/// Returns vecpak::Term - the primary format for all protocol messages
pub fn decode_seemingly_etf_to_vecpak(bin: &[u8]) -> Result<Term, &'static str> {
    if vecpak_compat::is_bin_vecpak(bin) {
        // Already vecpak - decode directly
        let mut offset = 0;
        decode_term(bin, &mut offset).map_err(|_| "vecpak decode failed")
    } else {
        // Legacy ETF format - convert to vecpak
        let etf_term = eetf::Term::decode(bin).map_err(|_| "etf decode failed")?;
        Ok(vecpak_compat::from_etf_term(&etf_term))
    }
}

pub trait VecpakExt {
    fn get_varint(&self) -> Option<i128>;
    fn get_binary(&self) -> Option<&[u8]>;
    fn get_list(&self) -> Option<&[Term]>;
    fn get_string(&self) -> Option<String>;
    fn get_proplist_map(&self) -> Option<PropListMap>;
    fn parse_list<T, E>(&self, parser: impl Fn(&[u8]) -> Result<T, E>) -> Vec<T>
    where
        E: std::fmt::Display;
}

impl VecpakExt for Term {
    fn get_varint(&self) -> Option<i128> {
        match self {
            Term::VarInt(v) => Some(*v),
            _ => None,
        }
    }

    fn get_binary(&self) -> Option<&[u8]> {
        match self {
            Term::Binary(bytes) => Some(bytes.as_slice()),
            _ => None,
        }
    }

    fn get_list(&self) -> Option<&[Term]> {
        match self {
            Term::List(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    fn get_string(&self) -> Option<String> {
        self.get_binary().and_then(|b| std::str::from_utf8(b).ok().map(|s| s.to_owned()))
    }

    fn get_proplist_map(&self) -> Option<PropListMap> {
        match self {
            Term::PropList(pairs) => Some(PropListMap(pairs.clone())),
            _ => None,
        }
    }

    fn parse_list<T, E>(&self, parser: impl Fn(&[u8]) -> Result<T, E>) -> Vec<T>
    where
        E: std::fmt::Display,
    {
        self.get_list().map(|list| parse_list(list, parser)).unwrap_or_default()
    }
}

#[derive(Default, Clone, Debug)]
pub struct PropListMap(pub Vec<(Term, Term)>);

impl PropListMap {
    pub fn get_by_key(&self, key: &[u8]) -> Option<&Term> {
        self.0.iter().find_map(|(k, v)| k.get_binary().filter(|&b| b == key).map(|_| v))
    }

    pub fn get_binary<'a, A>(&'a self, key: &[u8]) -> Option<A>
    where
        A: TryFrom<&'a [u8]>,
    {
        self.get_by_key(key).and_then(VecpakExt::get_binary).and_then(|b| A::try_from(b).ok())
    }

    pub fn get_varint<I>(&self, key: &[u8]) -> Option<I>
    where
        I: TryFrom<i128>,
    {
        self.get_by_key(key).and_then(VecpakExt::get_varint).and_then(|v| I::try_from(v).ok())
    }

    /// Alias for get_varint for consistency with old TermMap API
    pub fn get_integer<I>(&self, key: &[u8]) -> Option<I>
    where
        I: TryFrom<i128>,
    {
        self.get_varint(key)
    }

    pub fn get_list(&self, key: &[u8]) -> Option<&[Term]> {
        self.get_by_key(key).and_then(VecpakExt::get_list)
    }

    pub fn get_string(&self, key: &[u8]) -> Option<String> {
        self.get_by_key(key).and_then(VecpakExt::get_string)
    }

    /// Get a nested PropListMap from a key
    pub fn get_proplist_map(&self, key: &[u8]) -> Option<PropListMap> {
        self.get_by_key(key).and_then(VecpakExt::get_proplist_map)
    }

    pub fn parse_list<T, E>(&self, key: &[u8], parser: impl Fn(&[u8]) -> Result<T, E>) -> Vec<T>
    where
        E: std::fmt::Display,
    {
        self.get_by_key(key).map(|term| term.parse_list(parser)).unwrap_or_default()
    }

    pub fn into_term(self) -> Term {
        Term::PropList(self.0)
    }

    pub fn to_map(&self) -> HashMap<Vec<u8>, Term> {
        self.0.iter().filter_map(|(k, v)| k.get_binary().map(|b| (b.to_vec(), v.clone()))).collect()
    }
}

pub fn parse_list<T, E>(list: &[Term], parser: impl Fn(&[u8]) -> Result<T, E>) -> Vec<T>
where
    E: std::fmt::Display,
{
    list.iter()
        .filter_map(|term| {
            term.get_binary().and_then(|bytes| parser(bytes).map_err(|e| warn!("parse failed: {}", e)).ok())
        })
        .collect()
}

pub fn serialize_list<T, E>(items: &[T], serializer: impl Fn(&T) -> Result<Vec<u8>, E>) -> Option<Term>
where
    E: std::fmt::Display,
{
    let terms: Result<Vec<_>, _> = items.iter().map(|item| serializer(item).map(Term::Binary)).collect();
    terms.ok().map(Term::List)
}
