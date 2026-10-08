//! Bounded CBOR decoding with generic map-key equivalence.

use std::collections::BTreeSet;

use ciborium_ll::{Decoder, Header};

use super::{MAX_DEPTH, MessageError};
use crate::authenticator_message::Value;

pub(super) fn decode(bytes: &[u8]) -> Result<Value, MessageError> {
    read_document(bytes).map(|(value, _)| value)
}

pub(super) fn key_fingerprint(bytes: &[u8]) -> Result<Vec<u8>, MessageError> {
    read_document(bytes).map(|(_, fingerprint)| fingerprint)
}

fn read_document(bytes: &[u8]) -> Result<(Value, Vec<u8>), MessageError> {
    let mut remaining = bytes;
    let value = read_value(&mut remaining, 0)?;
    if !remaining.is_empty() {
        return Err(MessageError::Encoding("trailing bytes"));
    }
    Ok(value)
}

fn read_value(bytes: &mut &[u8], depth: usize) -> Result<(Value, Vec<u8>), MessageError> {
    if depth > MAX_DEPTH {
        return Err(MessageError::Encoding("nesting depth exceeded"));
    }
    let before = *bytes;
    let header = Decoder::from(&mut *bytes)
        .pull()
        .map_err(|_| MessageError::Encoding("truncated or invalid CBOR header"))?;
    let encoded_header = &before[..before.len() - bytes.len()];
    if encoded_header[0] == 0xf8 && encoded_header[1] < 32 {
        return Err(MessageError::Encoding("invalid simple value encoding"));
    }
    let mut payload = Vec::new();
    let (kind, value) = match header {
        Header::Positive(number) => {
            payload.extend_from_slice(&number.to_be_bytes());
            (0, Value::Integer(number.into()))
        }
        Header::Negative(number) => {
            payload.extend_from_slice(&number.to_be_bytes());
            (
                1,
                Value::Integer(
                    (-1 - i128::from(number))
                        .try_into()
                        .expect("CBOR negative integer fits"),
                ),
            )
        }
        Header::Bytes(Some(length)) | Header::Text(Some(length)) => {
            let data = take(bytes, length)?;
            payload.extend_from_slice(data);
            if matches!(header, Header::Bytes(_)) {
                (2, Value::Bytes(data.to_vec()))
            } else {
                let text = std::str::from_utf8(data)
                    .map_err(|_| MessageError::Encoding("invalid UTF-8"))?;
                (3, Value::Text(text.into()))
            }
        }
        Header::Array(Some(length)) => {
            check_length(length, bytes.len())?;
            let mut items = Vec::new();
            for _ in 0..length {
                let (item, fingerprint) = read_value(bytes, depth + 1)?;
                items.push(item);
                payload.extend(fingerprint);
            }
            (4, Value::Array(items))
        }
        Header::Map(Some(length)) => {
            check_length(length, bytes.len() / 2)?;
            let mut entries = Vec::new();
            let mut keys = BTreeSet::new();
            let mut pairs = Vec::new();
            for _ in 0..length {
                let (key, key_fingerprint) = read_value(bytes, depth + 1)?;
                if !keys.insert(key_fingerprint.clone()) {
                    return Err(MessageError::Encoding("duplicate equivalent map key"));
                }
                let (value, value_fingerprint) = read_value(bytes, depth + 1)?;
                entries.push((key, value));
                pairs.push((key_fingerprint, value_fingerprint));
            }
            pairs.sort_unstable();
            for (key, value) in pairs {
                payload.extend(key);
                payload.extend(value);
            }
            (5, Value::Map(entries))
        }
        Header::Tag(tag) => {
            let (value, fingerprint) = read_value(bytes, depth + 1)?;
            if matches!(tag, 2 | 3) {
                let Value::Bytes(magnitude) = &value else {
                    return Err(MessageError::Encoding("bignum content must be bytes"));
                };
                let start = magnitude
                    .iter()
                    .position(|byte| *byte != 0)
                    .unwrap_or(magnitude.len());
                let magnitude = &magnitude[start..];
                if magnitude.len() <= 8 {
                    let number = magnitude
                        .iter()
                        .fold(0u64, |number, byte| (number << 8) | u64::from(*byte));
                    return Ok((
                        Value::Tag(tag, Box::new(value)),
                        frame((tag - 2) as u8, &number.to_be_bytes()),
                    ));
                }
                payload.extend_from_slice(&tag.to_be_bytes());
                payload.extend(frame(2, magnitude));
            } else {
                payload.extend_from_slice(&tag.to_be_bytes());
                payload.extend(fingerprint);
            }
            (6, Value::Tag(tag, Box::new(value)))
        }
        Header::Simple(20) => (7, Value::Bool(false)),
        Header::Simple(21) => (7, Value::Bool(true)),
        Header::Simple(22) => (7, Value::Null),
        Header::Simple(_) => return Err(MessageError::Encoding("unsupported CBOR simple value")),
        Header::Float(mut number) => {
            if number.is_nan() {
                payload.push(1);
                let (bits, width) = match encoded_header[0] {
                    0xf9 => (
                        u64::from(u16::from_be_bytes(
                            encoded_header[1..].try_into().expect("half float header"),
                        )),
                        10,
                    ),
                    0xfa => (
                        u64::from(u32::from_be_bytes(
                            encoded_header[1..].try_into().expect("single float header"),
                        )),
                        23,
                    ),
                    _ => (
                        u64::from_be_bytes(
                            encoded_header[1..].try_into().expect("double float header"),
                        ),
                        52,
                    ),
                };
                let significand = bits & ((1u64 << width) - 1);
                payload.extend_from_slice(&(significand << (64 - width)).to_be_bytes());
                // Floating-point casts quiet signaling NaNs; preserve their wire significand.
                number = f64::from_bits(
                    (number.to_bits() & (1u64 << 63))
                        | (0x7ffu64 << 52)
                        | (significand << (52 - width)),
                );
            } else {
                payload.push(0);
                payload.extend_from_slice(
                    &(if number == 0.0 { 0 } else { number.to_bits() }).to_be_bytes(),
                );
            }
            (8, Value::Float(number))
        }
        Header::Bytes(None) | Header::Text(None) | Header::Array(None) | Header::Map(None) => {
            return Err(MessageError::Encoding("indefinite lengths are unsupported"));
        }
        Header::Break => return Err(MessageError::Encoding("unexpected break")),
    };
    if let Header::Simple(simple) = header {
        payload.push(simple);
    }
    Ok((value, frame(kind, &payload)))
}

fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut fingerprint = vec![kind];
    fingerprint.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    fingerprint.extend_from_slice(payload);
    fingerprint
}

const fn check_length(length: usize, remaining: usize) -> Result<(), MessageError> {
    if length > remaining {
        return Err(MessageError::Encoding(
            "container length exceeds remaining bytes",
        ));
    }
    Ok(())
}

const fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], MessageError> {
    if length > bytes.len() {
        return Err(MessageError::Encoding("truncated item or invalid length"));
    }
    let (item, remaining) = bytes.split_at(length);
    *bytes = remaining;
    Ok(item)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_nonpreferred_widths_and_unsorted_maps() {
        assert_eq!(decode(&[0x18, 0x01]).unwrap(), Value::Integer(1.into()));
        assert!(decode(&[0xa2, 0x02, 0xf6, 0x01, 0xf6]).is_ok());
        assert_eq!(
            key_fingerprint(&[0x01]).unwrap(),
            key_fingerprint(&[0x18, 0x01]).unwrap()
        );
    }

    #[test]
    fn rejects_equivalent_keys_including_bignum_aliases() {
        for bytes in [
            vec![0xa2, 0x01, 0xf6, 0x18, 0x01, 0xf6],
            vec![0xa2, 0x01, 0xf6, 0xc2, 0x42, 0x00, 0x01, 0xf6],
            vec![0xa2, 0xf9, 0x00, 0x00, 0xf6, 0xf9, 0x80, 0x00, 0xf6],
            vec![
                0xa2, 0xf9, 0x7e, 0x00, 0xf6, 0xfa, 0xff, 0xc0, 0x00, 0x00, 0xf6,
            ],
        ] {
            assert!(matches!(
                decode(&bytes),
                Err(MessageError::Encoding("duplicate equivalent map key"))
            ));
        }
    }

    #[test]
    fn compares_nested_keys_by_value_and_keeps_distinct_nan_payloads() {
        let ordered = [0xa2, 0x01, 0xf6, 0x02, 0xf5];
        let reversed = [0xa2, 0x02, 0xf5, 0x01, 0xf6];
        assert_eq!(
            key_fingerprint(&ordered).unwrap(),
            key_fingerprint(&reversed).unwrap()
        );
        assert_eq!(
            key_fingerprint(&[0x81, 0xd8, 0x64, 0xf9, 0x00, 0x00]).unwrap(),
            key_fingerprint(&[0x81, 0xd8, 0x64, 0xf9, 0x80, 0x00]).unwrap(),
        );
        assert_ne!(
            key_fingerprint(&[0xf9, 0x7c, 0x01]).unwrap(),
            key_fingerprint(&[0xf9, 0x7e, 0x01]).unwrap()
        );
        assert_ne!(
            key_fingerprint(&[0x01]).unwrap(),
            key_fingerprint(&[0xf9, 0x3c, 0x00]).unwrap()
        );
    }

    #[test]
    fn rejects_malformed_or_unsupported_data() {
        for bytes in [
            vec![0xf8, 0x16],
            vec![0xf7],
            vec![0xc2, 0x01],
            vec![0xf6, 0xf6],
            vec![0x9f, 0xff],
            vec![0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert!(decode(&bytes).is_err());
        }
    }
}
