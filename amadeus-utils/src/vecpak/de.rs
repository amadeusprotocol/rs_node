use super::{
    decode_varint,
    error::{Error, Result},
};
use serde::de::{
    self, Deserialize, DeserializeSeed, IntoDeserializer, MapAccess, SeqAccess, Visitor,
};

/// The vecpak format uses snake_case for enum variants on the wire
/// Serde's derive macros expect PascalCase for Rust enum variants
/// This function converts snake_case to PascalCase to bridge the two
fn to_pascal_case(s: &str) -> String {
    let mut result = String::new();
    let mut cap_next = true;
    for c in s.chars() {
        if c == '_' {
            cap_next = true;
        } else if cap_next {
            result.push(c.to_ascii_uppercase());
            cap_next = false;
        } else {
            result.push(c);
        }
    }
    result
}

pub struct Deserializer<'de> {
    input: &'de [u8],
    pos: usize,
}

pub fn from_slice<'a, T: Deserialize<'a>>(input: &'a [u8]) -> Result<T> {
    let mut deserializer = Deserializer { input, pos: 0 };
    let value = T::deserialize(&mut deserializer)?;
    if deserializer.pos != input.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(value)
}

impl<'de> Deserializer<'de> {
    fn read_byte(&mut self) -> Result<u8> {
        if self.pos >= self.input.len() {
            return Err(Error::Eof);
        }
        let byte = self.input[self.pos];
        self.pos += 1;
        Ok(byte)
    }

    fn read_bytes(&mut self, count: usize) -> Result<&'de [u8]> {
        if self.input.len().saturating_sub(self.pos) < count {
            return Err(Error::Eof);
        }
        let slice = &self.input[self.pos..self.pos + count];
        self.pos += count;
        Ok(slice)
    }

    fn read_varint(&mut self) -> Result<i128> {
        decode_varint(self.input, &mut self.pos).map_err(|e| Error::Message(e.into()))
    }

    fn read_length(&mut self) -> Result<usize> {
        let num = self.read_varint()?;
        if num < 0 {
            return Err(Error::InvalidLength);
        }
        let len = usize::try_from(num).map_err(|_| Error::InvalidLength)?;
        if len > self.input.len() - self.pos {
            return Err(Error::InvalidLength);
        }
        Ok(len)
    }

    fn skip_value(&mut self) -> Result<()> {
        match self.read_byte()? {
            0 | 1 | 2 => Ok(()),
            3 => {
                self.read_varint()?;
                Ok(())
            }
            5 => {
                let len = self.read_length()?;
                self.pos += len;
                Ok(())
            }
            6 => {
                let len = self.read_length()?;
                for _ in 0..len {
                    self.skip_value()?;
                }
                Ok(())
            }
            7 => {
                let len = self.read_length()?;
                for _ in 0..len {
                    self.skip_value()?;
                    self.skip_value()?;
                }
                Ok(())
            }
            _ => Err(Error::InvalidTag),
        }
    }
}

impl<'de, 'a> de::Deserializer<'de> for &'a mut Deserializer<'de> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let tag = self.read_byte()?;
        match tag {
            0 => visitor.visit_unit(),
            1 => visitor.visit_bool(true),
            2 => visitor.visit_bool(false),
            3 => visitor.visit_i128(self.read_varint()?),
            5 => {
                let len = self.read_length()?;
                let bytes = self.read_bytes(len)?;
                visitor.visit_borrowed_bytes(bytes)
            }
            6 => {
                let len = self.read_length()?;
                visitor.visit_seq(SequenceDeserializer {
                    de: self,
                    remaining: len,
                })
            }
            7 => {
                let len = self.read_length()?;
                visitor.visit_map(MapDeserializer {
                    de: self,
                    remaining: len,
                })
            }
            _ => Err(Error::InvalidTag),
        }
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.read_byte()? {
            1 => visitor.visit_bool(true),
            2 => visitor.visit_bool(false),
            _ => Err(Error::InvalidTag),
        }
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 3 {
            return Err(Error::InvalidTag);
        }
        visitor.visit_i8(self.read_varint()? as i8)
    }

    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 3 {
            return Err(Error::InvalidTag);
        }
        visitor.visit_i16(self.read_varint()? as i16)
    }

    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 3 {
            return Err(Error::InvalidTag);
        }
        visitor.visit_i32(self.read_varint()? as i32)
    }

    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 3 {
            return Err(Error::InvalidTag);
        }
        visitor.visit_i64(self.read_varint()? as i64)
    }

    fn deserialize_i128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 3 {
            return Err(Error::InvalidTag);
        }
        visitor.visit_i128(self.read_varint()?)
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 3 {
            return Err(Error::InvalidTag);
        }
        visitor.visit_u8(self.read_varint()? as u8)
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 3 {
            return Err(Error::InvalidTag);
        }
        visitor.visit_u16(self.read_varint()? as u16)
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 3 {
            return Err(Error::InvalidTag);
        }
        visitor.visit_u32(self.read_varint()? as u32)
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 3 {
            return Err(Error::InvalidTag);
        }
        visitor.visit_u64(self.read_varint()? as u64)
    }

    fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 3 {
            return Err(Error::InvalidTag);
        }
        visitor.visit_u128(self.read_varint()? as u128)
    }

    fn deserialize_f32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("floats not supported".into()))
    }

    fn deserialize_f64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("floats not supported".into()))
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 5 {
            return Err(Error::InvalidTag);
        }
        let len = self.read_length()?;
        let bytes = self.read_bytes(len)?;
        let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
        visitor.visit_borrowed_str(text)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 5 {
            return Err(Error::InvalidTag);
        }
        let len = self.read_length()?;
        let bytes = self.read_bytes(len)?;
        visitor.visit_borrowed_bytes(bytes)
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.input.get(self.pos) == Some(&0) {
            self.pos += 1;
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 0 {
            return Err(Error::InvalidTag);
        }
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 6 {
            return Err(Error::InvalidTag);
        }
        let len = self.read_length()?;
        visitor.visit_seq(SequenceDeserializer {
            de: self,
            remaining: len,
        })
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.read_byte()? != 7 {
            return Err(Error::InvalidTag);
        }
        let len = self.read_length()?;
        visitor.visit_map(MapDeserializer {
            de: self,
            remaining: len,
        })
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_enum(EnumDeserializer {
            de: self,
            entries: Vec::new(),
        })
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_any(visitor)
    }
}

struct SequenceDeserializer<'a, 'de: 'a> {
    de: &'a mut Deserializer<'de>,
    remaining: usize,
}

impl<'de, 'a> SeqAccess<'de> for SequenceDeserializer<'a, 'de> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }
}

struct MapDeserializer<'a, 'de: 'a> {
    de: &'a mut Deserializer<'de>,
    remaining: usize,
}

impl<'de, 'a> MapAccess<'de> for MapDeserializer<'a, 'de> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        seed.deserialize(&mut *self.de)
    }
}

struct EnumDeserializer<'a, 'de: 'a> {
    de: &'a mut Deserializer<'de>,
    entries: Vec<(usize, usize, usize, usize)>,
}

impl<'de, 'a> de::EnumAccess<'de> for EnumDeserializer<'a, 'de> {
    type Error = Error;
    type Variant = Self;

    /// Enums can be encoded in two ways:
    /// 1. A simple string (tag 5) for unit variants, e.g., `"my_variant"`
    /// 2. A proplist (tag 7) for variants with data. This proplist must contain a
    ///    special `op` key whose value is the variant name. Other key-value pairs
    ///    are the fields of the struct. For example:
    ///    `[{op, "my_struct_variant"}, {"field1", 123}, {"field2", "abc"}]`
    ///
    /// This function handles both cases. For proplists, it extracts the `op` value
    /// to identify the variant and buffers the remaining key-value pairs to be
    /// deserialized later as the struct's fields.
    fn variant_seed<V: DeserializeSeed<'de>>(
        mut self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant)> {
        let tag = self.de.read_byte()?;
        if tag == 5 {
            // Case 1: Unit variant (e.g., MyEnum::Variant) is encoded as a simple string.
            let len = self.de.read_length()?;
            let bytes = self.de.read_bytes(len)?;
            let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
            let pascal = to_pascal_case(text);
            let val = seed.deserialize(pascal.into_deserializer())?;
            Ok((val, self))
        } else if tag == 7 {
            let count = self.de.read_length()?;
            let mut variant: Option<String> = None;
            for _ in 0..count {
                let ks = self.de.pos;
                if self.de.read_byte()? != 5 {
                    return Err(Error::InvalidTag);
                }
                let klen = self.de.read_length()?;
                let key = self.de.read_bytes(klen)?;
                let ke = self.de.pos;
                let vs = self.de.pos;
                if key == b"op" {
                    if self.de.read_byte()? != 5 {
                        return Err(Error::InvalidTag);
                    }
                    let vlen = self.de.read_length()?;
                    let text = std::str::from_utf8(self.de.read_bytes(vlen)?)
                        .map_err(|_| Error::InvalidUtf8)?;
                    variant = Some(to_pascal_case(text));
                } else {
                    self.de.skip_value()?;
                    self.entries.push((ks, ke, vs, self.de.pos));
                }
            }
            let var = variant.ok_or_else(|| Error::Message("missing op field".into()))?;
            let val = seed.deserialize(var.into_deserializer())?;
            Ok((val, self))
        } else {
            Err(Error::InvalidTag)
        }
    }
}

impl<'de, 'a> de::VariantAccess<'de> for EnumDeserializer<'a, 'de> {
    type Error = Error;

    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value> {
        // If we have buffered entries from a proplist, use them as the struct fields
        // This handles newtype variants like Protocol::NewPhoneWhoDis(NewPhoneWhoDis {})
        // where the wire format is [{op, "new_phone_who_dis"}, ...struct_fields...]
        if !self.entries.is_empty() || self.de.pos >= self.de.input.len() {
            // Use BufferedMapDeserializer to reconstruct the inner struct from buffered entries
            let mut buf_de = BufferedMapDeserializer {
                input: self.de.input,
                entries: self.entries,
            };
            seed.deserialize(&mut buf_de)
        } else {
            seed.deserialize(self.de)
        }
    }

    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value> {
        de::Deserializer::deserialize_seq(self.de, visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_map(BufferedMapAccess {
            input: self.de.input,
            entries: self.entries,
            idx: 0,
        })
    }
}

struct BufferedMapAccess<'de> {
    input: &'de [u8],
    entries: Vec<(usize, usize, usize, usize)>,
    idx: usize,
}

impl<'de> MapAccess<'de> for BufferedMapAccess<'de> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>> {
        if self.idx >= self.entries.len() {
            return Ok(None);
        }
        let (ks, ke, _, _) = self.entries[self.idx];
        let mut de = Deserializer {
            input: &self.input[ks..ke],
            pos: 0,
        };
        seed.deserialize(&mut de).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        let (_, _, vs, ve) = self.entries[self.idx];
        self.idx += 1;
        let mut de = Deserializer {
            input: &self.input[vs..ve],
            pos: 0,
        };
        seed.deserialize(&mut de)
    }
}

/// A deserializer that reconstructs a struct from buffered proplist entries
/// Used for newtype variants where the inner struct fields are merged with "op"
struct BufferedMapDeserializer<'de> {
    input: &'de [u8],
    entries: Vec<(usize, usize, usize, usize)>,
}

impl<'de, 'a> de::Deserializer<'de> for &'a mut BufferedMapDeserializer<'de> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        // Treat as a map/struct
        self.deserialize_map(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_map(BufferedMapAccess {
            input: self.input,
            entries: std::mem::take(&mut self.entries),
            idx: 0,
        })
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_map(visitor)
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_unit()
    }

    // Forward other methods - these shouldn't be called for struct deserialization
    fn deserialize_bool<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message(
            "unexpected bool in buffered deserializer".into(),
        ))
    }
    fn deserialize_i8<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected i8".into()))
    }
    fn deserialize_i16<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected i16".into()))
    }
    fn deserialize_i32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected i32".into()))
    }
    fn deserialize_i64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected i64".into()))
    }
    fn deserialize_i128<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected i128".into()))
    }
    fn deserialize_u8<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected u8".into()))
    }
    fn deserialize_u16<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected u16".into()))
    }
    fn deserialize_u32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected u32".into()))
    }
    fn deserialize_u64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected u64".into()))
    }
    fn deserialize_u128<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected u128".into()))
    }
    fn deserialize_f32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("floats not supported".into()))
    }
    fn deserialize_f64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("floats not supported".into()))
    }
    fn deserialize_char<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected char".into()))
    }
    fn deserialize_str<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected str".into()))
    }
    fn deserialize_string<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected string".into()))
    }
    fn deserialize_bytes<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected bytes".into()))
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected byte_buf".into()))
    }
    fn deserialize_option<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected option".into()))
    }
    fn deserialize_seq<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected seq".into()))
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, _len: usize, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected tuple".into()))
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value> {
        Err(Error::Message("unexpected tuple_struct".into()))
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_newtype_struct(self)
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value> {
        Err(Error::Message("unexpected enum".into()))
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
        Err(Error::Message("unexpected identifier".into()))
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_any(visitor)
    }
}
