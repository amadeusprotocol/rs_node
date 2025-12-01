use bitvec::prelude::*;
use eetf::convert::TryAsRef;
use eetf::{Atom, Binary, List, Term};
use num_traits::ToPrimitive;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::types::{Hash, PublicKey};

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
/// Use bcat() instead for building binary keys
#[deprecated(note = "Use bcat() for raw binary keys instead of base58")]
pub fn pk_hex(pk: &[u8]) -> String {
    bs58::encode(pk).into_string()
}

/// Decode base58 string to fixed-size byte array
/// Returns None if decoding fails or size doesn't match
pub fn decode_base58_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    bs58::decode(s).into_vec().ok().and_then(|bytes| bytes.try_into().ok())
}

/// Decode base58 string to 48-byte public key
pub fn decode_base58_pk(s: &str) -> Option<PublicKey> {
    decode_base58_array::<48>(s).map(PublicKey::from)
}

/// Decode base58 string to 32-byte hash
pub fn decode_base58_hash(s: &str) -> Option<Hash> {
    decode_base58_array::<32>(s).map(Hash::from)
}

/// Concatenate multiple byte slices into a single Vec<u8>
/// Example: bcat(&[b"bic:coin:balance:", pk, b":AMA"])
#[inline]
pub fn bcat(slices: &[&[u8]]) -> Vec<u8> {
    slices.iter().flat_map(|&s| s).copied().collect()
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

/// **DEPRECATED**: Lightweight helpers for ETF Term manipulation (legacy)
/// Use `vecpak::VecpakExt` trait instead for the primary vecpak format.
/// This trait is kept for backwards compatibility with legacy ETF code only.
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

/// **DEPRECATED**: ETF Term-based map wrapper (legacy)
/// Use `vecpak::PropListMap` instead for the primary vecpak format.
/// This struct is kept for backwards compatibility with legacy ETF code only.
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

/// Encode a list of binary values as ETF term
pub fn eetf_list_of_binaries(list_of_binaries: Vec<Vec<u8>>) -> Result<Vec<u8>, eetf::EncodeError> {
    let elements: Vec<Term> = list_of_binaries.into_iter().map(|bytes| Term::from(Binary { bytes })).collect();
    let term = Term::from(List::from(elements));
    let mut out = Vec::new();
    term.encode(&mut out)?;
    Ok(out)
}

pub fn list_of_binaries_to_vecpak(list_of_binaries: Vec<Vec<u8>>) -> Vec<u8> {
    use crate::vecpak::{Term as VecpakTerm, encode};
    let elements: Vec<VecpakTerm> = list_of_binaries.into_iter().map(VecpakTerm::Binary).collect();
    encode(VecpakTerm::List(elements))
}

pub fn bitvec_to_bin(mask: &BitVec<u8, Msb0>) -> Vec<u8> {
    mask.as_raw_slice().to_vec()
}

pub fn bin_to_bitvec(bytes: Vec<u8>) -> BitVec<u8, Msb0> {
    BitVec::from_vec(bytes)
}

/// Calculate percentage of true bits in a mask relative to total count
pub fn get_bits_percentage(mask: &BitVec<u8, Msb0>, total_count: usize) -> f64 {
    if total_count == 0 {
        return 0.0;
    }
    let true_bits = mask.count_ones();
    (true_bits as f64) / (total_count as f64)
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
        let mut mask = BitVec::<u8, Msb0>::new();
        mask.extend([true, false, true, true, false, false, false, true, true]);
        let bytes = bitvec_to_bin(&mask);
        assert_eq!(bytes.len(), 2);
        let bools = bin_to_bitvec(bytes.clone());
        assert_eq!(&bools[..mask.len()], &mask[..]);
        for i in mask.len()..8 * bytes.len() {
            assert!(!bools[i]);
        }
    }

    #[test]
    fn bcat_concatenates_slices() {
        let pk = [0x01, 0x02, 0x03];
        let result = bcat(&[b"prefix:", &pk, b":suffix"]);
        assert_eq!(result, b"prefix:\x01\x02\x03:suffix");
    }

    #[test]
    fn bcat_empty() {
        let result = bcat(&[]);
        assert_eq!(result, b"");
    }

    #[test]
    fn bcat_builds_keys() {
        let pk = [0xAA, 0xBB, 0xCC];
        let result = bcat(&[b"bic:coin:balance:", &pk, b":AMA"]);
        assert_eq!(result, b"bic:coin:balance:\xAA\xBB\xCC:AMA");
    }

    #[test]
    fn test_decode_base58_pk() {
        // Test valid 48-byte public key
        let test_pk = PublicKey::from([0u8; 48]);
        let encoded = bs58::encode(&test_pk).into_string();
        let decoded = decode_base58_pk(&encoded);
        assert_eq!(decoded, Some(test_pk));

        // Test invalid base58
        assert_eq!(decode_base58_pk("not-valid-base58!"), None);

        // Test wrong size (32 bytes instead of 48)
        let wrong_size = [0u8; 32];
        let encoded_wrong = bs58::encode(&wrong_size).into_string();
        assert_eq!(decode_base58_pk(&encoded_wrong), None);
    }

    #[test]
    fn test_decode_base58_hash() {
        // Test valid 32-byte hash
        let test_hash = Hash::from([0xFF; 32]);
        let encoded = bs58::encode(&test_hash).into_string();
        let decoded = decode_base58_hash(&encoded);
        assert_eq!(decoded, Some(test_hash));

        // Test wrong size (48 bytes instead of 32)
        let wrong_size = [0u8; 48];
        let encoded_wrong = bs58::encode(&wrong_size).into_string();
        assert_eq!(decode_base58_hash(&encoded_wrong), None);
    }

    #[test]
    fn test_decode_base58_array() {
        // Test arbitrary size array
        let test_bytes: [u8; 16] = [0x12; 16];
        let encoded = bs58::encode(&test_bytes).into_string();
        let decoded: Option<[u8; 16]> = decode_base58_array(&encoded);
        assert_eq!(decoded, Some(test_bytes));
    }
}
