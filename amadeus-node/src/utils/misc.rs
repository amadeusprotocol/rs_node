use eetf::convert::TryAsRef;
use eetf::{Atom, Binary, List, Term};
use num_traits::ToPrimitive;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

/// Trait for types that can provide their type name as a static string
pub trait Typename {
    /// Get the type name for this instance
    /// For enums, this can return different names based on the variant
    fn typename(&self) -> &'static str;
}

// FIXME: u32 is fine until early 2106, after that it will overflow
pub fn get_unix_secs_now() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).as_ref().map(Duration::as_secs).unwrap_or(0) as u32
}

pub fn get_unix_millis_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).as_ref().map(Duration::as_millis).unwrap_or(0) as u64
}

pub fn get_unix_nanos_now() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).as_ref().map(Duration::as_nanos).unwrap_or(0)
}

/// DEPRECATED: This function incorrectly uses base58 encoding
/// Elixir uses raw binary pubkeys in keys, not base58
/// Use build_key() or build_key_with_suffix() instead
#[deprecated(note = "Use raw binary keys instead of base58")]
pub fn pk_hex(pk: &[u8]) -> String {
    bs58::encode(pk).into_string()
}

/// Build a key with prefix and raw binary pubkey
/// Example: build_key(b"bic:base:nonce:", &pubkey) -> b"bic:base:nonce:<48_raw_bytes>"
pub fn build_key(prefix: &[u8], pk: &[u8]) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(pk);
    key
}

/// Build a key with prefix, pubkey, and suffix
/// Example: build_key_with_suffix(b"bic:coin:balance:", &pubkey, b":AMA")
pub fn build_key_with_suffix(prefix: &[u8], pk: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(pk);
    key.extend_from_slice(suffix);
    key
}

/// Produce a hex dump similar to `hexdump -C` for a binary slice.
pub fn hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let address = i * 16;
        // 8-digit upper-case hex address
        let offset_str = format!("{address:08X}");

        // hex bytes (2 hex chars per byte + 1 space => up to 48 chars)
        let mut hex_bytes = String::new();
        for b in chunk {
            hex_bytes.push_str(&format!("{:02X} ", b));
        }
        // pad to 48 characters to align ASCII column
        while hex_bytes.len() < 48 {
            hex_bytes.push(' ');
        }

        // ASCII representation (32..=126 printable)
        let ascii: String = chunk.iter().map(|&b| if (32..=126).contains(&b) { b as char } else { '.' }).collect();

        out.push_str(&format!("{offset_str}  {hex_bytes}  {ascii}\n"));
    }
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Keep only ASCII characters considered printable for our use-case.
pub fn ascii(input: &str) -> String {
    input
        .chars()
        .filter(|&c| {
            let code = c as u32;
            code == 32
                || (123..=126).contains(&code)
                || (('!' as u32)..=('@' as u32)).contains(&code)
                || (('[' as u32)..=('_' as u32)).contains(&code)
                || (('0' as u32)..=('9' as u32)).contains(&code)
                || (('A' as u32)..=('Z' as u32)).contains(&code)
                || (('a' as u32)..=('z' as u32)).contains(&code)
        })
        .collect()
}

pub fn is_ascii_clean(input: &str) -> bool {
    ascii(input) == input
}

pub fn alphanumeric(input: &str) -> String {
    input.chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}

pub fn is_alphanumeric(input: &str) -> bool {
    alphanumeric(input) == input
}

/// Trim trailing slash from url
pub fn url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

/// Trim trailing slash on base and append path verbatim
pub fn url_with(url: &str, path: &str) -> String {
    format!("{}{}", url, path)
}

/// Lightweight helpers so you can keep calling `.atom()`, `.integer()`, etc.
pub trait TermExt {
    fn as_atom(&self) -> Option<&Atom>;
    fn get_integer(&self) -> Option<i128>;
    fn get_binary(&self) -> Option<&[u8]>;
    fn get_list(&self) -> Option<&[Term]>;
    fn get_string(&self) -> Option<String>;
    fn get_term_map(&self) -> Option<TermMap>;
    fn parse_list<T, E>(&self, parser: impl Fn(&[u8]) -> Result<T, E>) -> Vec<T>
    where
        E: std::fmt::Display;
}

impl TermExt for Term {
    fn as_atom(&self) -> Option<&Atom> {
        TryAsRef::<Atom>::try_as_ref(self)
    }

    fn get_integer(&self) -> Option<i128> {
        match self {
            Term::FixInteger(i) => Some(i.value as i128),
            Term::BigInteger(bi) => bi.value.to_i128(),
            _ => None,
        }
    }

    fn get_binary(&self) -> Option<&[u8]> {
        TryAsRef::<Binary>::try_as_ref(self).map(|b| b.bytes.as_slice())
    }

    fn get_list(&self) -> Option<&[Term]> {
        TryAsRef::<List>::try_as_ref(self).map(|l| l.elements.as_slice())
    }

    fn get_string(&self) -> Option<String> {
        // Erlang strings come across either as ByteList or Binary
        if let Term::ByteList(bl) = self {
            std::str::from_utf8(&bl.bytes).ok().map(|s| s.to_owned())
        } else if let Term::Binary(b) = self {
            std::str::from_utf8(&b.bytes).ok().map(|s| s.to_owned())
        } else if let Term::Atom(a) = self {
            Some(a.name.clone())
        } else {
            None
        }
    }

    fn get_term_map(&self) -> Option<TermMap> {
        match self {
            Term::Map(m) => Some(TermMap(m.map.clone())),
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
pub struct TermMap(pub HashMap<Term, Term>);

impl Deref for TermMap {
    type Target = HashMap<Term, Term>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TermMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TermMap {
    pub fn get_term_map(&self, key: &str) -> Option<Self> {
        self.0.get(&Term::Atom(Atom::from(key))).and_then(TermExt::get_term_map)
    }

    pub fn get_binary<'a, A>(&'a self, key: &str) -> Option<A>
    where
        A: TryFrom<&'a [u8]>,
    {
        self.0.get(&Term::Atom(Atom::from(key))).and_then(TermExt::get_binary).and_then(|b| A::try_from(b).ok())
    }

    pub fn get_integer<I>(&self, key: &str) -> Option<I>
    where
        I: TryFrom<i128>,
    {
        self.0.get(&Term::Atom(Atom::from(key))).and_then(TermExt::get_integer).and_then(|b| I::try_from(b).ok())
    }

    pub fn get_list(&self, key: &str) -> Option<&[Term]> {
        self.0.get(&Term::Atom(Atom::from(key))).and_then(TermExt::get_list)
    }

    pub fn get_atom(&self, key: &str) -> Option<&Atom> {
        self.0.get(&Term::Atom(Atom::from(key))).and_then(TermExt::as_atom)
    }

    pub fn get_string(&self, key: &str) -> Option<String> {
        self.0.get(&Term::Atom(Atom::from(key))).and_then(TermExt::get_string)
    }

    pub fn parse_list<T, E>(&self, key: &str, parser: impl Fn(&[u8]) -> Result<T, E>) -> Vec<T>
    where
        E: std::fmt::Display,
    {
        self.0.get(&Term::Atom(Atom::from(key))).map(|term| term.parse_list(parser)).unwrap_or_default()
    }

    pub fn into_term(self) -> Term {
        Term::Map(eetf::Map { map: self.0 })
    }
}

pub fn bools_to_bitvec(mask: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; mask.len().div_ceil(8)];
    for (i, &b) in mask.iter().enumerate() {
        if b {
            out[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    out
}

pub fn bitvec_to_bools(bytes: Vec<u8>) -> Vec<bool> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for b in bytes {
        // TODO: double-check if this is MSB-first or LSB-first
        for i in (0..8).rev() {
            // MSB -> LSB; use 0..8 for LSB-first
            out.push(((b >> i) & 1) != 0);
        }
    }
    out
}
// fn bitvec_to_bools(bytes: &[u8]) -> Vec<bool> {
//     let mut out = Vec::with_capacity(bytes.len() * 8);
//     for (_, byte) in bytes.iter().enumerate() {
//         for bit in 0..8 {
//             let val = (byte >> (7 - bit)) & 1u8;
//             out.push(val == 1u8);
//         }
//     }
//     out
// }

/// Creates string representation as bytes, compatible with Erlang's :erlang.integer_to_binary/1

/// Format a duration into human-readable form following the requirements:
/// - seconds if less than a minute
/// - minutes plus seconds if less than hour
/// - hours and minutes if less than day
/// - days and hours if less than month
/// - months and days if less than year
/// - years, months and days if bigger than year
pub fn format_duration(total_seconds: u32) -> String {
    if total_seconds < 60 {
        return format!("{}s", total_seconds);
    }

    let minutes = total_seconds / 60;
    let seconds = total_seconds % 60;

    if minutes < 60 {
        return format!("{}m {}s", minutes, seconds);
    }

    let hours = minutes / 60;
    let minutes = minutes % 60;

    if hours < 24 {
        return format!("{}h {}m", hours, minutes);
    }

    let days = hours / 24;
    let hours = hours % 24;

    if days < 30 {
        return format!("{}d {}h", days, hours);
    }

    let months = days / 30; // Approximate months as 30 days
    let days = days % 30;

    if months < 12 {
        return format!("{}mo {}d", months, days);
    }

    let years = months / 12;
    let months = months % 12;

    format!("{}y {}mo {}d", years, months, days)
}

/// Parse a list of ETF terms into structured data using the provided parser
pub fn parse_list<T, E>(list: &[Term], parser: impl Fn(&[u8]) -> Result<T, E>) -> Vec<T>
where
    E: std::fmt::Display,
{
    list.iter()
        .filter_map(|term| {
            term.get_binary().and_then(|bytes| parser(bytes).map_err(|e| warn!("Failed to parse item: {}", e)).ok())
        })
        .collect()
}

/// Serialize a list of items into an ETF List term using the provided serializer
pub fn serialize_list<T, E>(items: &[T], serializer: impl Fn(&T) -> Result<Vec<u8>, E>) -> Option<Term>
where
    E: std::fmt::Display,
{
    let terms: Result<Vec<_>, _> =
        items.iter().map(|item| serializer(item).map(|bytes| Term::Binary(Binary::from(bytes)))).collect();
    terms.ok().map(|terms| Term::List(List::from(terms)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexdump_basic() {
        let s = hexdump(&[0x41, 0x00, 0x7F]);
        assert!(s.starts_with("00000000  "));
        assert!(s.contains("41 00 7F"));
        assert!(s.ends_with("A.."));
    }

    #[test]
    fn string_helpers() {
        assert!(is_ascii_clean("AZaz09_-!"));
        assert!(!is_ascii_clean("hi🙂"));
        assert_eq!(alphanumeric("Abc-123"), "Abc123");
        assert!(is_alphanumeric("abc123"));
        assert!(!is_alphanumeric("a_b"));
    }

    #[test]
    fn ext_and_urls() {
        assert_eq!(url("http://a/b/"), "http://a/b");
        assert_eq!(url("http://a/b"), "http://a/b");
        assert_eq!(url_with("http://a/b", "/c"), "http://a/b/c");
    }

    #[test]
    fn bitvec_roundtrip_prefix() {
        let mask = vec![true, false, true, true, false, false, false, true, true];
        let bytes = bools_to_bitvec(&mask);
        assert_eq!(bytes.len(), 2);
        let bools = bitvec_to_bools(bytes.clone());
        assert_eq!(&bools[..mask.len()], &mask[..]);
        for b in &bools[mask.len()..8 * bytes.len()] {
            assert!(!*b);
        }
    }
}
