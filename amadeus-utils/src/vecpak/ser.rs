use super::{
    decode_varint, encode_varint,
    error::{Error, Result},
};
use serde::{ser, Serialize};

/// Skip over a value in the byte buffer and return the new position
fn skip_value_bytes(buf: &[u8], mut pos: usize) -> Result<usize> {
    if pos >= buf.len() {
        return Err(Error::Message("eof in skip_value_bytes".into()));
    }
    let tag = buf[pos];
    pos += 1;
    match tag {
        0 | 1 | 2 => Ok(pos), // nil, true, false
        3 => {
            // varint
            let (_, bytes_read) =
                decode_varint_with_len(&buf[pos..]).map_err(|e| Error::Message(e.into()))?;
            Ok(pos + bytes_read)
        }
        5 => {
            // binary
            let (len, bytes_read) =
                decode_varint_with_len(&buf[pos..]).map_err(|e| Error::Message(e.into()))?;
            Ok(pos + bytes_read + len as usize)
        }
        6 => {
            // list
            let (count, bytes_read) =
                decode_varint_with_len(&buf[pos..]).map_err(|e| Error::Message(e.into()))?;
            pos += bytes_read;
            for _ in 0..count {
                pos = skip_value_bytes(buf, pos)?;
            }
            Ok(pos)
        }
        7 => {
            // proplist
            let (count, bytes_read) =
                decode_varint_with_len(&buf[pos..]).map_err(|e| Error::Message(e.into()))?;
            pos += bytes_read;
            for _ in 0..count {
                pos = skip_value_bytes(buf, pos)?; // key
                pos = skip_value_bytes(buf, pos)?; // value
            }
            Ok(pos)
        }
        _ => Err(Error::Message(format!(
            "unknown tag {} in skip_value_bytes",
            tag
        ))),
    }
}

fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.push(c.to_ascii_lowercase());
        } else {
            result.push(c);
        }
    }
    result
}

pub struct Serializer {
    output: Vec<u8>,
}

pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut serializer = Serializer { output: Vec::new() };
    value.serialize(&mut serializer)?;
    Ok(serializer.output)
}

impl<'a> ser::Serializer for &'a mut Serializer {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = MapSerializer<'a>;
    type SerializeStruct = MapSerializer<'a>;
    type SerializeStructVariant = StructVariantSerializer<'a>;

    fn serialize_bool(self, v: bool) -> Result<()> {
        self.output.push(if v { 1 } else { 2 });
        Ok(())
    }

    fn serialize_i8(self, v: i8) -> Result<()> {
        self.serialize_i128(v as i128)
    }
    fn serialize_i16(self, v: i16) -> Result<()> {
        self.serialize_i128(v as i128)
    }
    fn serialize_i32(self, v: i32) -> Result<()> {
        self.serialize_i128(v as i128)
    }
    fn serialize_i64(self, v: i64) -> Result<()> {
        self.serialize_i128(v as i128)
    }
    fn serialize_i128(self, v: i128) -> Result<()> {
        self.output.push(3);
        encode_varint(&mut self.output, v);
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> Result<()> {
        self.serialize_i128(v as i128)
    }
    fn serialize_u16(self, v: u16) -> Result<()> {
        self.serialize_i128(v as i128)
    }
    fn serialize_u32(self, v: u32) -> Result<()> {
        self.serialize_i128(v as i128)
    }
    fn serialize_u64(self, v: u64) -> Result<()> {
        self.serialize_i128(v as i128)
    }
    fn serialize_u128(self, v: u128) -> Result<()> {
        if v > i128::MAX as u128 {
            return Err(Error::Message("u128 too large".into()));
        }
        self.serialize_i128(v as i128)
    }

    fn serialize_f32(self, _v: f32) -> Result<()> {
        Err(Error::Message("floats not supported".into()))
    }
    fn serialize_f64(self, _v: f64) -> Result<()> {
        Err(Error::Message("floats not supported".into()))
    }

    fn serialize_char(self, v: char) -> Result<()> {
        self.serialize_str(&v.to_string())
    }

    fn serialize_str(self, v: &str) -> Result<()> {
        self.output.push(5);
        encode_varint(&mut self.output, v.len() as i128);
        self.output.extend_from_slice(v.as_bytes());
        Ok(())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        self.output.push(5);
        encode_varint(&mut self.output, v.len() as i128);
        self.output.extend_from_slice(v);
        Ok(())
    }

    fn serialize_none(self) -> Result<()> {
        self.output.push(0);
        Ok(())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<()> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<()> {
        self.output.push(0);
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        self.serialize_unit()
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
    ) -> Result<()> {
        self.serialize_str(&to_snake_case(variant))
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<()> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<()> {
        // Serialize inner value to a buffer first
        let mut inner_serializer = Serializer { output: Vec::new() };
        value.serialize(&mut inner_serializer)?;
        let inner_bytes = inner_serializer.output;

        // Build the "op" key-value pair
        let snake = to_snake_case(variant);
        let mut op_key = vec![5];
        encode_varint(&mut op_key, 2);
        op_key.extend_from_slice(b"op");
        let mut op_value = vec![5];
        encode_varint(&mut op_value, snake.len() as i128);
        op_value.extend_from_slice(snake.as_bytes());

        // If inner value is a proplist (tag 7), merge fields with "op"
        if inner_bytes.first() == Some(&7) {
            // Parse the inner proplist to get entry count
            let mut pos = 1;
            let (inner_count, bytes_read) = decode_varint_with_len(&inner_bytes[pos..])
                .map_err(|e| Error::Message(e.into()))?;
            pos += bytes_read;

            // Write merged proplist: op + inner fields
            self.output.push(7);
            encode_varint(&mut self.output, inner_count + 1);

            // Collect all entries for sorting
            let mut entries: Vec<(Vec<u8>, Vec<u8>)> = vec![(op_key, op_value)];

            // Parse and collect inner entries
            let mut inner_pos = pos;
            for _ in 0..inner_count {
                let key_start = inner_pos;
                // Skip key
                if inner_bytes.get(inner_pos) != Some(&5) {
                    return Err(Error::Message("expected binary key".into()));
                }
                inner_pos += 1;
                let (key_len, bytes_read) = decode_varint_with_len(&inner_bytes[inner_pos..])
                    .map_err(|e| Error::Message(e.into()))?;
                inner_pos += bytes_read + key_len as usize;
                let key_end = inner_pos;

                let value_start = inner_pos;
                // Skip value
                inner_pos = skip_value_bytes(&inner_bytes, inner_pos)?;
                let value_end = inner_pos;

                entries.push((
                    inner_bytes[key_start..key_end].to_vec(),
                    inner_bytes[value_start..value_end].to_vec(),
                ));
            }

            // Sort entries by key and write
            entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            for (key_bytes, value_bytes) in entries {
                self.output.extend_from_slice(&key_bytes);
                self.output.extend_from_slice(&value_bytes);
            }
        } else {
            // Inner value is not a proplist - just emit op field only
            // (for unit-like structs that serialize to something other than proplist)
            self.output.push(7);
            encode_varint(&mut self.output, 1);
            self.output.extend_from_slice(&op_key);
            self.output.extend_from_slice(&op_value);
        }
        Ok(())
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        self.output.push(6);
        encode_varint(&mut self.output, len.unwrap_or(0) as i128);
        Ok(self)
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        self.output.push(7);
        encode_varint(&mut self.output, 1);
        self.serialize_str(&to_snake_case(variant))?;
        self.serialize_seq(Some(len))?;
        Ok(self)
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        Ok(MapSerializer::new(self))
    }

    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct> {
        Ok(MapSerializer::new(self))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        let snake = to_snake_case(variant);
        let mut variant_bytes = Vec::new();
        variant_bytes.push(5);
        encode_varint(&mut variant_bytes, snake.len() as i128);
        variant_bytes.extend_from_slice(snake.as_bytes());
        Ok(StructVariantSerializer {
            ser: self,
            variant_bytes,
            entries: Vec::new(),
        })
    }
}

impl<'a> ser::SerializeSeq for &'a mut Serializer {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<'a> ser::SerializeTuple for &'a mut Serializer {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<'a> ser::SerializeTupleStruct for &'a mut Serializer {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<'a> ser::SerializeTupleVariant for &'a mut Serializer {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(&mut **self)
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}

pub struct StructVariantSerializer<'a> {
    ser: &'a mut Serializer,
    variant_bytes: Vec<u8>,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl<'a> ser::SerializeStructVariant for StructVariantSerializer<'a> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        if key == "op" {
            return Err(Error::Message(
                "field 'op' conflicts with enum variant tag".into(),
            ));
        }
        let mut key_serializer = Serializer { output: Vec::new() };
        key.serialize(&mut key_serializer)?;
        let mut value_serializer = Serializer { output: Vec::new() };
        value.serialize(&mut value_serializer)?;
        self.entries
            .push((key_serializer.output, value_serializer.output));
        Ok(())
    }

    fn end(self) -> Result<()> {
        let mut entries = self.entries;
        let mut op_key = vec![5];
        encode_varint(&mut op_key, 2);
        op_key.extend_from_slice(b"op");
        entries.push((op_key, self.variant_bytes));
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        self.ser.output.push(7);
        encode_varint(&mut self.ser.output, entries.len() as i128);
        for (key_bytes, value_bytes) in entries {
            self.ser.output.extend_from_slice(&key_bytes);
            self.ser.output.extend_from_slice(&value_bytes);
        }
        Ok(())
    }
}

pub struct MapSerializer<'a> {
    ser: &'a mut Serializer,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

impl<'a> MapSerializer<'a> {
    fn new(ser: &'a mut Serializer) -> Self {
        MapSerializer {
            ser,
            entries: Vec::new(),
        }
    }

    fn end_map(self) -> Result<()> {
        let mut entries = self.entries;
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        self.ser.output.push(7);
        encode_varint(&mut self.ser.output, entries.len() as i128);
        for (key_bytes, value_bytes) in entries {
            self.ser.output.extend_from_slice(&key_bytes);
            self.ser.output.extend_from_slice(&value_bytes);
        }
        Ok(())
    }
}

impl<'a> ser::SerializeMap for MapSerializer<'a> {
    type Ok = ();
    type Error = Error;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<()> {
        let mut key_serializer = Serializer { output: Vec::new() };
        key.serialize(&mut key_serializer)?;
        self.entries.push((key_serializer.output, Vec::new()));
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        let mut value_serializer = Serializer { output: Vec::new() };
        value.serialize(&mut value_serializer)?;
        self.entries.last_mut().unwrap().1 = value_serializer.output;
        Ok(())
    }

    fn end(self) -> Result<()> {
        self.end_map()
    }
}

impl<'a> ser::SerializeStruct for MapSerializer<'a> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        ser::SerializeMap::serialize_key(self, key)?;
        ser::SerializeMap::serialize_value(self, value)
    }

    fn end(self) -> Result<()> {
        self.end_map()
    }
}

/// Convenience function to decode a varint and return the value and its length
#[inline]
pub fn decode_varint_with_len(buf: &[u8]) -> std::result::Result<(i128, usize), &'static str> {
    let mut i = 0;
    let val = decode_varint(buf, &mut i)?;
    Ok((val, i))
}
