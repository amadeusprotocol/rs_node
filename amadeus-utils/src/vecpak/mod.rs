use serde::{Serialize, Deserialize};

mod error;
mod ser;
mod de;
mod ext;

pub use error::Error;
pub use ser::to_vec;
pub use de::from_slice;
pub use ext::{VecpakExt, PropListMap, parse_list};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Term {
    Nil(),
    Bool(bool),
    VarInt(i128),
    Binary(Vec<u8>),
    List(Vec<Term>),
    PropList(Vec<(Term,Term)>),
    //Map(HashMap<Term,Term>),
}

//TODO: varint should support any size not limited to RUST i128
#[inline(always)]
pub fn encode_varint(buf: &mut Vec<u8>, v: i128) {
    if v == 0 {
        buf.push(0);
        return;
    }

    let sign = (v < 0) as u8;
    let mag = v.unsigned_abs();
    let lz = mag.leading_zeros() as usize; //bitsize (128 for i128)
    let first = lz / 8;
    let len = 16 - first;
    buf.push((sign << 7) | (len as u8));
    let be = mag.to_be_bytes();
    buf.extend_from_slice(&be[first..]);
}

#[inline(always)]
pub fn decode_varint(buf: &[u8], i: &mut usize) -> Result<i128, &'static str> {
    if *i >= buf.len() { return Err("eof"); }
    let b0 = buf[*i]; *i += 1;
    if b0 == 0 {
        return Ok(0);
    }
    if b0 == 0x80 { return Err("noncanonical_zero"); }

    let sign = (b0 & 0x80) != 0;
    let len  = (b0 & 0x7F) as usize;
    if len == 0 || len > 16 { return Err("bad_varint_length"); }
    if buf.len().saturating_sub(*i) < len { return Err("eof"); }

    if buf[*i] == 0 { return Err("varint_leading_zero"); }

    // read big-endian magnitude
    let mut be = [0u8; 16];
    be[16 - len..].copy_from_slice(&buf[*i..*i + len]);
    *i += len;

    let mag = u128::from_be_bytes(be);
    if mag > i128::MAX as u128 { return Err("varint_underflow"); }

    if sign {
        Ok(-(mag as i128))
    } else {
        Ok(mag as i128)
    }
}

#[inline]
fn decode_varint_gte_zero(buf: &[u8], i: &mut usize) -> Result<usize, &'static str> {
    let n = decode_varint(buf, i)?;
    if n < 0 { return Err("length_is_negative"); }
    usize::try_from(n).map_err(|_| "length_overflow")
}

pub fn encode_term(buf: &mut Vec<u8>, term: Term) {
    match term {
        Term::Nil() => { buf.push(0); }
        Term::Bool(true) => { buf.push(1); }
        Term::Bool(false) => { buf.push(2); }
        Term::VarInt(varint) => {
            buf.push(3);
            encode_varint(buf, varint);
        }
        Term::Binary(bin) => {
            buf.push(5);
            encode_varint(buf, bin.len() as i128);
            buf.extend_from_slice(bin.as_slice());
        }
        Term::List(list) => {
            buf.push(6);
            encode_varint(buf, list.len() as i128);
            for member in list {
                encode_term(buf, member);
            }
        }
        Term::PropList(proplist) => {
            buf.push(7);
            encode_varint(buf, proplist.len() as i128);

            let mut keyed: Vec<(Vec<u8>, Term)> = Vec::with_capacity(proplist.len());
            for (k, v) in proplist {
                let mut kbytes = Vec::with_capacity(64);
                encode_term(&mut kbytes, k);
                keyed.push((kbytes, v));
            }
            keyed.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            for (kbytes, v) in keyed {
                buf.extend_from_slice(&kbytes);
                encode_term(buf, v);
            }
        }
        /*Term::Map(map) => {
            buf.push(7);
            encode_varint(buf, map.len() as i128);

            let mut keyed: Vec<(Vec<u8>, Term)> = Vec::with_capacity(map.len());
            for (k, v) in map {
                let mut kbytes = Vec::with_capacity(64);
                encode_term(&mut kbytes, k);
                keyed.push((kbytes, v));
            }
            keyed.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            for (kbytes, v) in keyed {
                buf.extend_from_slice(&kbytes);
                encode_term(buf, v);
            }
        }*/
    }
}

pub fn encode(term: Term) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);
    encode_term(&mut buf, term);
    buf
}

#[inline]
fn read_u8(buf: &[u8], i: &mut usize) -> Result<u8, &'static str> {
    if *i >= buf.len() { return Err("eof"); }
    let b = buf[*i];
    *i += 1;
    Ok(b)
}

#[inline]
fn read_exact<'a>(buf: &'a [u8], i: &mut usize, n: usize) -> Result<&'a [u8], &'static str> {
    if buf.len().saturating_sub(*i) < n { return Err("eof"); }
    let s = &buf[*i..*i + n];
    *i += n;
    Ok(s)
}

pub fn decode_term(buf: &[u8], i: &mut usize) -> Result<Term, &'static str> {
    let tag = read_u8(buf, i)?;
    match tag {
        0 => { Ok(Term::Nil()) }
        1 => { Ok(Term::Bool(true)) }
        2 => { Ok(Term::Bool(false)) }
        3 => {
            let v = decode_varint(buf, i)?;
            Ok(Term::VarInt(v))
        }
        5 => {
            let len = decode_varint_gte_zero(buf, i)?;
            let bytes = read_exact(buf, i, len as usize)?.to_vec();
            Ok(Term::Binary(bytes))
        }
        6 => {
            let count = decode_varint_gte_zero(buf, i)?;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(decode_term(buf, i)?);
            }
            Ok(Term::List(items))
        }
        7 => {
            let count = decode_varint_gte_zero(buf, i)?;
            let mut pairs = Vec::with_capacity(count);

            //Canonical check
            let mut prev_key_bytes: Option<&[u8]> = None;

            for _ in 0..count {
                let k_start = *i;
                let k = decode_term(buf, i)?;
                let k_bytes = &buf[k_start..*i];

                if let Some(prev) = prev_key_bytes {
                    if k_bytes <= prev { return Err("map_not_canonical"); }
                }
                prev_key_bytes = Some(k_bytes);

                let v = decode_term(buf, i)?;
                pairs.push((k, v));
            }
            Ok(Term::PropList(pairs))
        }
        _ => Err("unknown_tag"),
    }
}

pub fn decode(buf: &[u8]) -> Result<Term, &'static str> {
    let mut i = 0;
    let term = decode_term(buf, &mut i)?;
    if i != buf.len() { return Err("trailing_bytes"); }
    Ok(term)
}
