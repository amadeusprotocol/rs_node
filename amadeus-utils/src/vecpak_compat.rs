//! **DEPRECATED**: Vecpak to ETF compatibility layer
//!
//! **This module is legacy code kept for backwards compatibility only.**
//! The primary format is now vecpak (see vecpak.rs). ETF (Erlang Term Format) is legacy.
//! Use `vecpak::decode_seemingly_etf_to_vecpak()` to auto-detect and convert ETF if needed.
//!
//! Provides conversion from vecpak::Term to eetf::Term for protocol parsing

use eetf::{Atom, Binary, List, Map};
use num_traits::ToPrimitive;
use std::collections::HashMap;

/// Convert vecpak Term to eetf Term for compatibility with existing Protocol parsing
pub fn to_etf_term(term: &vecpak::Term) -> eetf::Term {
    match term {
        vecpak::Term::Nil() => eetf::Term::Atom(Atom::from("nil")),
        vecpak::Term::Bool(true) => eetf::Term::Atom(Atom::from("true")),
        vecpak::Term::Bool(false) => eetf::Term::Atom(Atom::from("false")),
        vecpak::Term::VarInt(v) => {
            if *v >= 0 && *v <= i32::MAX as i128 {
                eetf::Term::FixInteger(eetf::FixInteger { value: *v as i32 })
            } else {
                eetf::Term::BigInteger(eetf::BigInteger { value: (*v).into() })
            }
        }
        vecpak::Term::Binary(bytes) => eetf::Term::Binary(Binary { bytes: bytes.clone() }),
        vecpak::Term::List(items) => {
            let elements: Vec<eetf::Term> = items.iter().map(to_etf_term).collect();
            eetf::Term::List(List { elements })
        }
        vecpak::Term::PropList(pairs) => {
            let mut map = HashMap::new();
            for (k, v) in pairs {
                // in vecpak, keys are binaries like <<"op">>, but ETF uses atoms like :op
                let etf_key = match k {
                    vecpak::Term::Binary(bytes) => {
                        if let Ok(s) = String::from_utf8(bytes.clone()) {
                            eetf::Term::Atom(Atom::from(s.as_str()))
                        } else {
                            // fallback to binary if not valid UTF-8
                            eetf::Term::Binary(Binary { bytes: bytes.clone() })
                        }
                    }
                    _ => to_etf_term(k),
                };
                let etf_value = to_etf_term(v);
                map.insert(etf_key, etf_value);
            }
            eetf::Term::Map(Map { map })
        }
    }
}

/// Check if data might be vecpak format (starts with a valid vecpak tag)
#[inline]
pub fn is_bin_vecpak(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    // vecpak tags are 0-7, but most messages are maps (tag 7)
    // ETF version is 131, so if first byte is 0-7, it's likely vecpak
    matches!(data[0], 0..=7)
}

/// Parse vecpak binary into eetf Term
pub fn parse_vecpak_to_etf(data: &[u8]) -> Result<eetf::Term, String> {
    let mut offset = 0;
    let vecpak_term = vecpak::decode_term(data, &mut offset).map_err(|e| format!("vecpak decode error: {}", e))?;
    if offset != data.len() {
        return Err(format!("trailing bytes after vecpak term: {} remaining", data.len() - offset));
    }
    Ok(to_etf_term(&vecpak_term))
}

/// Convert eetf Term to vecpak Term for sending messages in vecpak format
pub fn from_etf_term(term: &eetf::Term) -> vecpak::Term {
    match term {
        eetf::Term::Atom(atom) => {
            // atoms are converted to binaries in vecpak (lowercase atom names)
            vecpak::Term::Binary(atom.name.as_bytes().to_vec())
        }
        eetf::Term::Binary(bin) => vecpak::Term::Binary(bin.bytes.clone()),
        eetf::Term::FixInteger(fix) => vecpak::Term::VarInt(fix.value as i128),
        eetf::Term::BigInteger(big) => {
            // try to convert to i128
            if let Some(val) = big.value.to_i128() {
                vecpak::Term::VarInt(val)
            } else {
                // fallback: encode as binary (shouldn't happen for typical use)
                vecpak::Term::VarInt(0)
            }
        }
        eetf::Term::Float(_) => {
            // vecpak doesn't support floats directly, this shouldn't be used in protocol
            vecpak::Term::Nil()
        }
        eetf::Term::List(list) => {
            let items: Vec<vecpak::Term> = list.elements.iter().map(from_etf_term).collect();
            vecpak::Term::List(items)
        }
        eetf::Term::Map(map) => {
            let pairs: Vec<(vecpak::Term, vecpak::Term)> =
                map.map.iter().map(|(k, v)| (from_etf_term(k), from_etf_term(v))).collect();
            vecpak::Term::PropList(pairs)
        }
        eetf::Term::Tuple(tuple) => {
            // tuples become lists in vecpak
            let items: Vec<vecpak::Term> = tuple.elements.iter().map(from_etf_term).collect();
            vecpak::Term::List(items)
        }
        _ => vecpak::Term::Nil(),
    }
}

/// Encode an eetf::Term into vecpak binary format
pub fn encode_etf_as_vecpak(term: &eetf::Term) -> Vec<u8> {
    let vecpak_term = from_etf_term(term);
    let mut buf = Vec::new();
    vecpak::encode_term(&mut buf, vecpak_term);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_vecpak() {
        assert!(is_bin_vecpak(&[7, 1, 2, 3])); // proplist
        assert!(is_bin_vecpak(&[0])); // nil
        assert!(is_bin_vecpak(&[6, 0])); // empty list
        assert!(!is_bin_vecpak(&[131, 104])); // ETF format
        assert!(!is_bin_vecpak(&[])); // empty
    }

    #[test]
    fn test_nil_conversion() {
        let vecpak_term = vecpak::Term::Nil();
        let etf_term = to_etf_term(&vecpak_term);
        assert!(matches!(etf_term, eetf::Term::Atom(_)));
    }

    #[test]
    fn test_bool_conversion() {
        let vecpak_term = vecpak::Term::Bool(true);
        let etf_term = to_etf_term(&vecpak_term);
        if let eetf::Term::Atom(atom) = etf_term {
            assert_eq!(atom.name, "true");
        } else {
            panic!("expected atom");
        }
    }

    #[test]
    fn test_varint_conversion() {
        let vecpak_term = vecpak::Term::VarInt(42);
        let etf_term = to_etf_term(&vecpak_term);
        if let eetf::Term::FixInteger(fix_int) = etf_term {
            assert_eq!(fix_int.value, 42);
        } else {
            panic!("expected fix integer");
        }
    }

    #[test]
    fn test_binary_conversion() {
        let data = vec![1, 2, 3, 4, 5];
        let vecpak_term = vecpak::Term::Binary(data.clone());
        let etf_term = to_etf_term(&vecpak_term);
        if let eetf::Term::Binary(bin) = etf_term {
            assert_eq!(bin.bytes, data);
        } else {
            panic!("expected binary");
        }
    }

    #[test]
    fn test_list_conversion() {
        let vecpak_term = vecpak::Term::List(vec![vecpak::Term::VarInt(1), vecpak::Term::VarInt(2)]);
        let etf_term = to_etf_term(&vecpak_term);
        if let eetf::Term::List(list) = etf_term {
            assert_eq!(list.elements.len(), 2);
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn test_proplist_conversion() {
        let vecpak_term =
            vecpak::Term::PropList(vec![(vecpak::Term::Binary(b"key".to_vec()), vecpak::Term::VarInt(100))]);
        let etf_term = to_etf_term(&vecpak_term);
        assert!(matches!(etf_term, eetf::Term::Map(_)));
    }
}
