use std::collections::BTreeSet;

use serde::{Serialize, ser};

use super::{MAX_DEPTH, MessageError};

pub(super) fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, MessageError> {
    encode_at(value, 0)
}

struct Serializer {
    depth: usize,
}

macro_rules! serialize_primitives {
    ($($method:ident($ty:ty)),* $(,)?) => {
        $(fn $method(self, value: $ty) -> Result<Self::Ok, Self::Error> {
            primitive(&value)
        })*
    };
}

impl ser::Serializer for Serializer {
    type Ok = Vec<u8>;
    type Error = MessageError;
    type SerializeSeq = Sequence;
    type SerializeTuple = Sequence;
    type SerializeTupleStruct = Sequence;
    type SerializeTupleVariant = TupleVariant;
    type SerializeMap = Map;
    type SerializeStruct = Map;
    type SerializeStructVariant = Map;

    serialize_primitives! {
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_char(char),
        serialize_str(&str),
    }

    fn serialize_i128(self, value: i128) -> Result<Self::Ok, Self::Error> {
        let encoded = primitive(&value)?;
        if encoded[0] >> 5 == 6 {
            check_depth(self.depth + 1)?;
        }
        Ok(encoded)
    }

    fn serialize_u128(self, value: u128) -> Result<Self::Ok, Self::Error> {
        let encoded = primitive(&value)?;
        if encoded[0] >> 5 == 6 {
            check_depth(self.depth + 1)?;
        }
        Ok(encoded)
    }

    fn serialize_f32(self, value: f32) -> Result<Self::Ok, Self::Error> {
        if value.is_nan() {
            let bits = value.to_bits();
            let sign = u64::from(bits & 0x8000_0000) << 32;
            let significand = u64::from(bits & 0x007f_ffff) << 29;
            return Ok(encode_nan(sign | 0x7ff0_0000_0000_0000 | significand));
        }
        primitive(&value)
    }

    fn serialize_f64(self, value: f64) -> Result<Self::Ok, Self::Error> {
        if value.is_nan() {
            return Ok(encode_nan(value.to_bits()));
        }
        primitive(&value)
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<Self::Ok, Self::Error> {
        let mut encoded = header(2, value.len())?;
        encoded.extend_from_slice(value);
        Ok(encoded)
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        primitive(&())
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        primitive(&())
    }

    fn serialize_unit_struct(self, _: &'static str) -> Result<Self::Ok, Self::Error> {
        self.serialize_unit()
    }

    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        primitive(&variant)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        _: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        if name == "@@TAG@@" && variant == "@@UNTAGGED@@" {
            return value.serialize(self);
        }
        let mut encoded = variant_prefix(variant)?;
        encoded.extend(encode_at(value, self.depth + 1)?);
        Ok(encoded)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(Sequence::new(self.depth + 1, len, Vec::new()))
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        name: &'static str,
        _: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        if name == "@@TAG@@" && variant == "@@TAGGED@@" {
            if len != 2 {
                return Err(MessageError::Encoding("tag requires a number and content"));
            }
            return Ok(TupleVariant::Tag {
                depth: self.depth + 1,
                fields: Vec::new(),
            });
        }
        check_depth(self.depth + 1)?;
        Ok(TupleVariant::Array(Sequence::new(
            self.depth + 2,
            Some(len),
            variant_prefix(variant)?,
        )))
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(Map::new(self.depth + 1, len, Vec::new()))
    }

    fn serialize_struct(
        self,
        _: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        check_depth(self.depth + 1)?;
        Ok(Map::new(
            self.depth + 2,
            Some(len),
            variant_prefix(variant)?,
        ))
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

struct Sequence {
    depth: usize,
    expected_len: Option<usize>,
    len: usize,
    prefix: Vec<u8>,
    contents: Vec<u8>,
}

impl Sequence {
    const fn new(depth: usize, expected_len: Option<usize>, prefix: Vec<u8>) -> Self {
        Self {
            depth,
            expected_len,
            len: 0,
            prefix,
            contents: Vec::new(),
        }
    }

    fn element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), MessageError> {
        self.contents.extend(encode_at(value, self.depth)?);
        self.len += 1;
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>, MessageError> {
        check_len(self.expected_len, self.len)?;
        self.prefix.extend(header(4, self.len)?);
        self.prefix.extend(self.contents);
        Ok(self.prefix)
    }
}

impl ser::SerializeSeq for Sequence {
    type Ok = Vec<u8>;
    type Error = MessageError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.element(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

impl ser::SerializeTuple for Sequence {
    type Ok = Vec<u8>;
    type Error = MessageError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.element(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

impl ser::SerializeTupleStruct for Sequence {
    type Ok = Vec<u8>;
    type Error = MessageError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.element(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

enum TupleVariant {
    Array(Sequence),
    Tag { depth: usize, fields: Vec<Vec<u8>> },
}

impl ser::SerializeTupleVariant for TupleVariant {
    type Ok = Vec<u8>;
    type Error = MessageError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        match self {
            Self::Array(sequence) => sequence.element(value),
            Self::Tag { depth, fields } => {
                if fields.len() >= 2 {
                    return Err(MessageError::Encoding("tag requires a number and content"));
                }
                let encoded = encode_at(
                    value,
                    if fields.is_empty() {
                        *depth - 1
                    } else {
                        *depth
                    },
                )?;
                if fields.is_empty() && encoded[0] >> 5 != 0 {
                    return Err(MessageError::Encoding(
                        "tag number must be an unsigned integer",
                    ));
                }
                fields.push(encoded);
                Ok(())
            }
        }
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        match self {
            Self::Array(sequence) => sequence.finish(),
            Self::Tag { fields, .. } => {
                let [mut tag, content]: [Vec<u8>; 2] = fields
                    .try_into()
                    .map_err(|_| MessageError::Encoding("tag requires a number and content"))?;
                if matches!(tag.as_slice(), [2] | [3]) {
                    check_bignum(&content)?;
                }
                tag[0] |= 6 << 5;
                tag.extend(content);
                Ok(tag)
            }
        }
    }
}

struct Map {
    depth: usize,
    expected_len: Option<usize>,
    prefix: Vec<u8>,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    pending_key: Option<Vec<u8>>,
}

impl Map {
    const fn new(depth: usize, expected_len: Option<usize>, prefix: Vec<u8>) -> Self {
        Self {
            depth,
            expected_len,
            prefix,
            entries: Vec::new(),
            pending_key: None,
        }
    }

    fn field<T: Serialize + ?Sized>(&mut self, key: &str, value: &T) -> Result<(), MessageError> {
        self.entries
            .push((encode_at(key, self.depth)?, encode_at(value, self.depth)?));
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>, MessageError> {
        if self.pending_key.is_some() {
            return Err(MessageError::Encoding("map key has no value"));
        }
        check_len(self.expected_len, self.entries.len())?;
        self.entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut keys = BTreeSet::new();
        for (key, _) in &self.entries {
            if !keys.insert(super::de::key_fingerprint(key)?) {
                return Err(MessageError::Encoding("duplicate equivalent map key"));
            }
        }
        self.prefix.extend(header(5, self.entries.len())?);
        for (key, value) in self.entries {
            self.prefix.extend(key);
            self.prefix.extend(value);
        }
        Ok(self.prefix)
    }
}

impl ser::SerializeMap for Map {
    type Ok = Vec<u8>;
    type Error = MessageError;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Self::Error> {
        if self.pending_key.is_some() {
            return Err(MessageError::Encoding("map key has no value"));
        }
        self.pending_key = Some(encode_at(key, self.depth)?);
        Ok(())
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        let key = self
            .pending_key
            .take()
            .ok_or(MessageError::Encoding("map value has no key"))?;
        self.entries.push((key, encode_at(value, self.depth)?));
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

impl ser::SerializeStruct for Map {
    type Ok = Vec<u8>;
    type Error = MessageError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.field(key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

impl ser::SerializeStructVariant for Map {
    type Ok = Vec<u8>;
    type Error = MessageError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.field(key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

impl ser::Error for MessageError {
    fn custom<T: std::fmt::Display>(message: T) -> Self {
        Self::Payload(ciborium::value::Error::Custom(message.to_string()))
    }
}

fn encode_at<T: Serialize + ?Sized>(value: &T, depth: usize) -> Result<Vec<u8>, MessageError> {
    check_depth(depth)?;
    value.serialize(Serializer { depth })
}

const fn check_depth(depth: usize) -> Result<(), MessageError> {
    if depth > MAX_DEPTH {
        return Err(MessageError::Encoding("nesting depth exceeded"));
    }
    Ok(())
}

fn check_len(expected: Option<usize>, actual: usize) -> Result<(), MessageError> {
    if expected.is_some_and(|expected| expected != actual) {
        return Err(MessageError::Encoding(
            "container length does not match its contents",
        ));
    }
    Ok(())
}

fn primitive<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, MessageError> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded).map_err(<MessageError as ser::Error>::custom)?;
    Ok(encoded)
}

// Float casts can quiet signaling NaNs, so narrow their sign and significand as integer bits.
fn encode_nan(bits: u64) -> Vec<u8> {
    let significand = bits & 0x000f_ffff_ffff_ffff;
    if significand & ((1 << 42) - 1) == 0 {
        let narrowed = ((bits >> 48) as u16 & 0x8000) | 0x7c00 | (significand >> 42) as u16;
        let mut encoded = vec![0xf9];
        encoded.extend(narrowed.to_be_bytes());
        return encoded;
    }
    if significand & ((1 << 29) - 1) == 0 {
        let narrowed =
            ((bits >> 32) as u32 & 0x8000_0000) | 0x7f80_0000 | (significand >> 29) as u32;
        let mut encoded = vec![0xfa];
        encoded.extend(narrowed.to_be_bytes());
        return encoded;
    }
    let mut encoded = vec![0xfb];
    encoded.extend(bits.to_be_bytes());
    encoded
}

fn header(major: u8, argument: usize) -> Result<Vec<u8>, MessageError> {
    let argument =
        u64::try_from(argument).map_err(|_| MessageError::Encoding("container length overflow"))?;
    let mut encoded = primitive(&argument)?;
    encoded[0] |= major << 5;
    Ok(encoded)
}

fn variant_prefix(variant: &str) -> Result<Vec<u8>, MessageError> {
    let mut encoded = header(5, 1)?;
    encoded.extend(primitive(&variant)?);
    Ok(encoded)
}

fn check_bignum(content: &[u8]) -> Result<(), MessageError> {
    if content[0] >> 5 != 2 {
        return Err(MessageError::Encoding("bignum content must be bytes"));
    }
    let header_len = match content[0] & 31 {
        0..=23 => 1,
        24 => 2,
        25 => 3,
        26 => 5,
        27 => 9,
        _ => return Err(MessageError::Encoding("bignum must have a definite length")),
    };
    let magnitude = &content[header_len..];
    if magnitude.len() <= 8 || magnitude[0] == 0 {
        return Err(MessageError::Encoding("non-preferred bignum"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;
    use serde::ser::{SerializeMap as _, SerializeSeq as _};

    #[test]
    fn scalars_use_ciborium_encoding() {
        for value in [i128::MIN, -1, 0, i128::MAX] {
            assert_eq!(encode(&value).unwrap(), primitive(&value).unwrap());
        }
        assert_eq!(encode(&u128::MAX).unwrap(), primitive(&u128::MAX).unwrap());
        for value in [0.0, -0.0, 1.5, f64::INFINITY, f64::NAN] {
            assert_eq!(encode(&value).unwrap(), primitive(&value).unwrap());
        }
    }

    #[test]
    fn nan_encoding_preserves_signaling_bits_at_the_smallest_width() {
        for (bits, expected) in [
            (0x7ff0_0400_0000_0000, vec![0xf9, 0x7c, 1]),
            (0xfff8_0400_0000_0000, vec![0xf9, 0xfe, 1]),
            (0x7ff0_0000_2000_0000, vec![0xfa, 0x7f, 0x80, 0, 1]),
            (
                0x7ff0_0000_0000_0001,
                vec![0xfb, 0x7f, 0xf0, 0, 0, 0, 0, 0, 1],
            ),
        ] {
            assert_eq!(encode(&f64::from_bits(bits)).unwrap(), expected);
        }
        assert_eq!(
            encode(&f32::from_bits(0x7f80_2000)).unwrap(),
            [0xf9, 0x7c, 1]
        );
        assert_eq!(
            encode(&f32::from_bits(0xff80_0001)).unwrap(),
            [0xfa, 0xff, 0x80, 0, 1]
        );
    }

    #[test]
    fn signaling_and_quiet_nan_map_keys_remain_distinct() {
        let map = Value::Map(vec![
            (
                Value::Float(f64::from_bits(0x7ff8_0400_0000_0000)),
                Value::Null,
            ),
            (
                Value::Float(f64::from_bits(0x7ff0_0400_0000_0000)),
                Value::Null,
            ),
        ]);
        assert_eq!(
            encode(&map).unwrap(),
            [0xa2, 0xf9, 0x7c, 1, 0xf6, 0xf9, 0x7e, 1, 0xf6]
        );
    }

    #[test]
    fn unknown_sequence_lengths_are_encoded_definitely() {
        struct Items;
        impl Serialize for Items {
            fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut sequence = serializer.serialize_seq(None)?;
                sequence.serialize_element(&1)?;
                sequence.serialize_element(&2)?;
                sequence.end()
            }
        }
        assert_eq!(encode(&Items).unwrap(), [0x82, 1, 2]);
    }

    #[test]
    fn unknown_map_lengths_are_encoded_definitely_with_sorted_keys() {
        struct Entries;
        impl Serialize for Entries {
            fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry(&-1, &())?;
                map.serialize_entry(&24, &())?;
                map.end()
            }
        }
        assert_eq!(
            encode(&Entries).unwrap(),
            [0xa2, 0x18, 24, 0xf6, 0x20, 0xf6]
        );
    }

    #[test]
    fn tags_preserve_nested_map_ordering_and_reject_invalid_bignums() {
        let value = Value::Tag(
            100,
            Box::new(Value::Map(vec![
                (Value::Integer((-1).into()), Value::Null),
                (Value::Integer(24.into()), Value::Null),
            ])),
        );
        assert_eq!(
            encode(&value).unwrap(),
            [0xd8, 100, 0xa2, 0x18, 24, 0xf6, 0x20, 0xf6]
        );
        for tag in [2, 3] {
            for bytes in [vec![], vec![1], vec![0; 9]] {
                assert!(encode(&Value::Tag(tag, Box::new(Value::Bytes(bytes)))).is_err());
            }
            assert!(encode(&Value::Tag(tag, Box::new(Value::Bytes(vec![1; 9])))).is_ok());
        }
    }

    #[test]
    fn enum_variants_and_struct_fields_use_cbor_representation() {
        #[derive(Serialize)]
        enum Example {
            Unit,
            Newtype(Option<u32>),
            Tuple(u32, bool),
            Struct { z: bool, a: u32 },
        }
        for value in [
            Example::Unit,
            Example::Newtype(Some(1)),
            Example::Tuple(1, true),
        ] {
            assert_eq!(encode(&value).unwrap(), primitive(&value).unwrap());
        }
        let bytes = encode(&Example::Struct { z: true, a: 1 }).unwrap();
        assert_eq!(&bytes[8..], [0xa2, 0x61, b'a', 1, 0x61, b'z', 0xf5]);
    }

    #[test]
    fn rejects_excessive_nesting_before_serializing_children() {
        let mut value = Value::Null;
        for _ in 0..MAX_DEPTH {
            value = Value::Array(vec![value]);
        }
        assert!(encode(&value).is_ok());
        assert!(encode(&Value::Array(vec![value])).is_err());
    }
}
