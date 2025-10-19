/// Custom wire format for encoding transactions:
/// - 0 => nil
/// - 1 => true
/// - 2 => false
/// - 3 => integer: encode_varint
/// - 5 => binary/atom: encode_varint(len) + raw bytes
/// - 6 => list: encode_varint(len) + encoded elements
/// - 7 => map: encode_varint(len) + sorted (by key) [key, value] encoded pairs
///
/// Variant:
/// - 0 => single 0x00 byte
/// - otherwise: first byte has sign (MSB, 1 bit) and length in bytes (7 bits),
///   followed by that many big-endian magnitude bytes. sign=0 => positive, sign=1 => negative.
use std::cmp::Ordering;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Nil,
    Bool(bool),
    Int(i128),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Map(BTreeMap<Value, Value>),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("invalid type tag: {0}")]
    InvalidType(u8),
    #[error("invalid variant encoding")]
    InvalidVarInt,
    #[error("integer overflow (requires bigint)")]
    Overflow,
    #[error("trailing data after full decode")]
    TrailingData,
}

impl Value {
    /// Deterministic comparator roughly analogous to term ordering for common types used as keys
    fn cmp_keys(a: &Value, b: &Value) -> Ordering {
        use Value::*;
        let tag_order = |v: &Value| -> u8 {
            match v {
                Nil => 0,
                Bool(false) => 1,
                Bool(true) => 2,
                Int(_) => 3,
                Bytes(_) => 5,
                List(_) => 6,
                Map(_) => 7,
            }
        };
        let ta = tag_order(a);
        let tb = tag_order(b);
        if ta != tb {
            return ta.cmp(&tb);
        }
        match (a, b) {
            (Nil, Nil) => Ordering::Equal,
            (Bool(x), Bool(y)) => x.cmp(y), // false < true
            (Int(x), Int(y)) => x.cmp(y),
            (Bytes(x), Bytes(y)) => x.as_slice().cmp(y.as_slice()),
            (List(x), List(y)) => {
                let min_len = x.len().min(y.len());
                for i in 0..min_len {
                    let c = Value::cmp_keys(&x[i], &y[i]);
                    if c != Ordering::Equal {
                        return c;
                    }
                }
                x.len().cmp(&y.len())
            }
            (Map(x), Map(y)) => {
                // Compare by iterating BTreeMap entries (already sorted by key)
                let mut xi = x.iter();
                let mut yi = y.iter();
                loop {
                    match (xi.next(), yi.next()) {
                        (None, None) => return Ordering::Equal,
                        (None, Some(_)) => return Ordering::Less,
                        (Some(_), None) => return Ordering::Greater,
                        (Some((kxa, vxa)), Some((kxb, vxb))) => {
                            let c = Value::cmp_keys(kxa, kxb);
                            if c != Ordering::Equal {
                                return c;
                            }
                            let c2 = Value::cmp_keys(vxa, vxb);
                            if c2 != Ordering::Equal {
                                return c2;
                            }
                        }
                    }
                }
            }
            _ => Ordering::Equal, // same tag values are handled above; cross-tags handled by tag_order
        }
    }
}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> Ordering {
        Value::cmp_keys(self, other)
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

pub fn validate(bytes: &[u8]) -> Result<Value, Error> {
    let (term, rest) = decode(bytes)?;
    if !rest.is_empty() {
        return Err(Error::TrailingData);
    }
    let re = encode(&term);
    if re.as_slice() == bytes {
        Ok(term)
    } else {
        Err(Error::InvalidVarInt) // mismatch with Elixir roundtrip; keep simple error
    }
}

pub fn decode_all(bytes: &[u8]) -> Result<Value, Error> {
    let (v, rest) = decode(bytes)?;
    if rest.is_empty() { Ok(v) } else { Err(Error::TrailingData) }
}

pub fn decode(mut bytes: &[u8]) -> Result<(Value, &[u8]), Error> {
    if bytes.is_empty() {
        return Err(Error::UnexpectedEof);
    }
    let t = bytes[0];
    bytes = &bytes[1..];
    match t {
        0 => Ok((Value::Nil, bytes)),
        1 => Ok((Value::Bool(true), bytes)),
        2 => Ok((Value::Bool(false), bytes)),
        3 => {
            let (i, rest) = decode_varint(bytes)?;
            Ok((Value::Int(i), rest))
        }
        5 => {
            let (len_i, rest) = decode_varint(bytes)?;
            let len: usize = len_i.try_into().map_err(|_| Error::InvalidVarInt)?;
            let rest_len = rest.len();
            if rest_len < len {
                return Err(Error::UnexpectedEof);
            }
            let payload = rest[..len].to_vec();
            let rest2 = &rest[len..];
            Ok((Value::Bytes(payload), rest2))
        }
        6 => {
            let (len_i, mut rest) = decode_varint(bytes)?;
            let len: usize = len_i.try_into().map_err(|_| Error::InvalidVarInt)?;
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                let (v, r) = decode(rest)?;
                items.push(v);
                rest = r;
            }
            Ok((Value::List(items), rest))
        }
        7 => {
            let (len_i, mut rest) = decode_varint(bytes)?;
            let len: usize = len_i.try_into().map_err(|_| Error::InvalidVarInt)?;
            let mut map: BTreeMap<Value, Value> = BTreeMap::new();
            for _ in 0..len {
                let (k, r1) = decode(rest)?;
                let (v, r2) = decode(r1)?;
                map.insert(k, v);
                rest = r2;
            }
            Ok((Value::Map(map), rest))
        }
        other => Err(Error::InvalidType(other)),
    }
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    use Value::*;
    match value {
        Nil => out.push(0),
        Bool(true) => out.push(1),
        Bool(false) => out.push(2),
        Int(i) => {
            out.push(3);
            encode_varint(*i, out);
        }
        Bytes(b) => {
            out.push(5);
            encode_varint(b.len() as i128, out);
            out.extend_from_slice(b);
        }
        List(items) => {
            out.push(6);
            encode_varint(items.len() as i128, out);
            for it in items {
                encode_into(it, out);
            }
        }
        Map(kvs) => {
            out.push(7);
            encode_varint(kvs.len() as i128, out);
            for (k, v) in kvs.iter() {
                encode_into(k, out);
                encode_into(v, out);
            }
        }
    }
}

fn encode_varint(n: i128, out: &mut Vec<u8>) {
    if n == 0 {
        out.push(0);
        return;
    }
    let sign_bit: u8 = if n >= 0 { 0 } else { 1 };
    let mag = magnitude_u128(n);
    let be = mag.to_be_bytes();
    // strip leading zeros
    let first_nz = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    let bytes = &be[first_nz..];
    let len = bytes.len();
    assert!(len <= 127, "varint magnitude too large to encode length in 7 bits");
    out.push((sign_bit << 7) | (len as u8));
    out.extend_from_slice(bytes);
}

fn decode_varint(input: &[u8]) -> Result<(i128, &[u8]), Error> {
    if input.is_empty() {
        return Err(Error::UnexpectedEof);
    }
    let b0 = input[0];
    if b0 == 0 {
        return Ok((0, &input[1..]));
    }
    let sign = (b0 & 0b1000_0000) >> 7;
    let len = (b0 & 0b0111_1111) as usize;
    let rest = &input[1..];
    if rest.len() < len {
        return Err(Error::UnexpectedEof);
    }
    let payload = &rest[..len];
    let rest2 = &rest[len..];
    let mut mag: u128 = 0;
    for &byte in payload {
        mag = (mag << 8) | (byte as u128);
    }
    if sign == 0 {
        if mag > i128::MAX as u128 {
            return Err(Error::Overflow);
        }
        Ok((mag as i128, rest2))
    } else {
        // negative: -mag, but ensure mag fits into i128::MAX + 1
        if mag > (i128::MAX as u128) + 1 {
            return Err(Error::Overflow);
        }
        if mag == 0 {
            // -0 should still be 0, but Elixir encode won't produce sign=1 with mag=0
            return Ok((0, rest2));
        }
        let val = if mag == (i128::MAX as u128) + 1 { i128::MIN } else { -(mag as i128) };
        Ok((val, rest2))
    }
}

#[inline]
fn magnitude_u128(n: i128) -> u128 {
    if n >= 0 { n as u128 } else { (!(n as u128)).wrapping_add(1) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_primitives() {
        let cases = vec![
            Value::Nil,
            Value::Bool(true),
            Value::Bool(false),
            Value::Int(0),
            Value::Int(1),
            Value::Int(-1),
            Value::Int(255),
            Value::Int(256),
            Value::Bytes(vec![]),
            Value::Bytes(b"abc".to_vec()),
        ];
        for v in cases {
            let enc = encode(&v);
            let dec = decode_all(&enc).unwrap();
            assert_eq!(v, dec);
        }
    }

    #[test]
    fn roundtrip_lists_and_maps() {
        let list = Value::List(vec![Value::Int(1), Value::Bool(false), Value::Bytes(b"x".to_vec())]);
        let mut bm = BTreeMap::new();
        bm.insert(Value::Bytes(b"b".to_vec()), Value::Int(2));
        bm.insert(Value::Bytes(b"a".to_vec()), Value::Int(1));
        let map = Value::Map(bm);
        let v = Value::List(vec![list, map]);
        let enc = encode(&v);
        let dec = decode_all(&enc).unwrap();
        assert_eq!(v, dec);
    }

    #[test]
    fn varint_sign_and_length() {
        for &n in &[0i128, 1, -1, 127, 128, -128, 255, 256, i128::MIN + 1] {
            let mut buf = Vec::new();
            encode_varint(n, &mut buf);
            let (m, rest) = decode_varint(&buf).unwrap();
            assert_eq!(n, m);
            assert!(rest.is_empty());
        }
        // i128::MIN is representable
        let mut buf = Vec::new();
        encode_varint(i128::MIN, &mut buf);
        let (m, rest) = decode_varint(&buf).unwrap();
        assert_eq!(i128::MIN, m);
        assert!(rest.is_empty());
    }
}
