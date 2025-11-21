//! **DEPRECATED**: Vecpak to ETF compatibility layer
//!
//! **This module is legacy code kept for backwards compatibility only.**
//! The primary format is now vecpak (see vecpak.rs). ETF (Erlang Term Format) is legacy.
//! Use `vecpak::decode_seemingly_etf_to_vecpak()` to auto-detect and convert ETF if needed.
//!
//! Provides conversion from vecpak::Term to eetf::Term for protocol parsing

use num_traits::ToPrimitive;

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
    fn test_from_etf_atom() {
        let etf_atom = eetf::Atom::from("test");
        let vecpak_term = from_etf_term(&eetf::Term::Atom(etf_atom));
        assert!(matches!(vecpak_term, vecpak::Term::Binary(_)));
    }

    #[test]
    fn test_from_etf_binary() {
        let data = vec![1, 2, 3, 4, 5];
        let etf_binary = eetf::Binary { bytes: data.clone() };
        let vecpak_term = from_etf_term(&eetf::Term::Binary(etf_binary));
        if let vecpak::Term::Binary(bin) = vecpak_term {
            assert_eq!(bin, data);
        } else {
            panic!("expected binary");
        }
    }

    #[test]
    fn test_from_etf_integer() {
        let etf_int = eetf::FixInteger { value: 42 };
        let vecpak_term = from_etf_term(&eetf::Term::FixInteger(etf_int));
        if let vecpak::Term::VarInt(v) = vecpak_term {
            assert_eq!(v, 42);
        } else {
            panic!("expected varint");
        }
    }
}
