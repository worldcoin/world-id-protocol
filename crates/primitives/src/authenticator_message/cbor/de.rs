//! Bounded CBOR decoding with generic map-key equivalence.

use std::collections::BTreeSet;

use ciborium_ll::{Decoder, Header};

use super::{MAX_DEPTH, MessageError};
use crate::authenticator_message::Value;

/// Decodes one complete document, rejecting trailing bytes and duplicate keys.
pub(super) fn decode(bytes: &[u8]) -> Result<Value, MessageError> {
    read_document(bytes).map(|(value, _)| value)
}

fn read_document(bytes: &[u8]) -> Result<(Value, Vec<u8>), MessageError> {
    let mut remaining = bytes;
    let value = read_value(&mut remaining, 0)?;
    if !remaining.is_empty() {
        return Err(MessageError::Encoding("trailing bytes"));
    }
    Ok(value)
}

/// Consumes one bounded value and builds its identity alongside it. Computing both together
/// preserves wire distinctions, such as NaN payload bits, that native value conversion can erase.
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
        Header::Bytes(length) | Header::Text(length) => {
            let is_text = matches!(header, Header::Text(_));
            let data = read_string(bytes, length, is_text)?;
            payload.extend_from_slice(&data);
            if is_text {
                let text =
                    String::from_utf8(data).map_err(|_| MessageError::Encoding("invalid UTF-8"))?;
                (3, Value::Text(text))
            } else {
                (2, Value::Bytes(data))
            }
        }
        Header::Array(mut length) => {
            if let Some(length) = length {
                check_length(length, bytes.len())?;
            }
            let mut items = Vec::new();
            while has_next(bytes, &mut length)? {
                let (item, fingerprint) = read_value(bytes, depth + 1)?;
                items.push(item);
                payload.extend(fingerprint);
            }
            (4, Value::Array(items))
        }
        Header::Map(mut length) => {
            if let Some(length) = length {
                check_length(length, bytes.len() / 2)?;
            }
            let mut entries = Vec::new();
            let mut keys = BTreeSet::new();
            let mut pairs = Vec::new();
            while has_next(bytes, &mut length)? {
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
        Header::Break => return Err(MessageError::Encoding("unexpected break")),
    };
    if let Header::Simple(simple) = header {
        payload.push(simple);
    }
    Ok((value, frame(kind, &payload)))
}

/// Reads definite chunks directly; indefinite strings may contain only definite chunks of the
/// same string type. Text chunks must each contain complete UTF-8 code points.
fn read_string(
    bytes: &mut &[u8],
    length: Option<usize>,
    is_text: bool,
) -> Result<Vec<u8>, MessageError> {
    if let Some(length) = length {
        return Ok(read_string_chunk(bytes, length, is_text)?.to_vec());
    }
    let mut data = Vec::new();
    while has_next(bytes, &mut None)? {
        let header = Decoder::from(&mut *bytes)
            .pull()
            .map_err(|_| MessageError::Encoding("truncated or invalid string chunk header"))?;
        let length = match (is_text, header) {
            (false, Header::Bytes(Some(length))) | (true, Header::Text(Some(length))) => length,
            _ => return Err(MessageError::Encoding("invalid indefinite string chunk")),
        };
        data.extend_from_slice(read_string_chunk(bytes, length, is_text)?);
    }
    Ok(data)
}

fn read_string_chunk<'a>(
    bytes: &mut &'a [u8],
    length: usize,
    is_text: bool,
) -> Result<&'a [u8], MessageError> {
    let chunk = take(bytes, length)?;
    if is_text && std::str::from_utf8(chunk).is_err() {
        return Err(MessageError::Encoding("invalid UTF-8"));
    }
    Ok(chunk)
}

/// Consumes a definite entry count or the terminating break of an indefinite container.
fn has_next(bytes: &mut &[u8], remaining: &mut Option<usize>) -> Result<bool, MessageError> {
    if let Some(remaining) = remaining {
        if *remaining == 0 {
            return Ok(false);
        }
        *remaining -= 1;
        return Ok(true);
    }
    match bytes.first() {
        Some(0xff) => {
            *bytes = &bytes[1..];
            Ok(false)
        }
        Some(_) => Ok(true),
        None => Err(MessageError::Encoding("unterminated indefinite container")),
    }
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
    use test_case::test_case;

    fn key_fingerprint(bytes: &[u8]) -> Result<Vec<u8>, MessageError> {
        read_document(bytes).map(|(_, fingerprint)| fingerprint)
    }

    #[test]
    fn accepts_nonpreferred_widths_and_unsorted_maps() {
        assert_eq!(decode(&[0x18, 0x01]).unwrap(), Value::Integer(1.into()));
        assert!(decode(&[0xa2, 0x02, 0xf6, 0x01, 0xf6]).is_ok());
        assert_eq!(
            key_fingerprint(&[0x01]).unwrap(),
            key_fingerprint(&[0x18, 0x01]).unwrap()
        );
    }

    #[test_case(&[0xa2, 0x01, 0xf6, 0x18, 0x01, 0xf6]; "integer widths")]
    #[test_case(&[0xa2, 0x01, 0xf6, 0xc2, 0x42, 0x00, 0x01, 0xf6]; "bignum alias")]
    #[test_case(&[0xa2, 0xf9, 0x00, 0x00, 0xf6, 0xf9, 0x80, 0x00, 0xf6]; "signed zero")]
    #[test_case(&[0xa2, 0xf9, 0x7e, 0x00, 0xf6, 0xfa, 0xff, 0xc0, 0x00, 0x00, 0xf6]; "nan width and sign")]
    fn rejects_equivalent_keys_including_bignum_aliases(bytes: &[u8]) {
        assert!(matches!(
            decode(bytes),
            Err(MessageError::Encoding("duplicate equivalent map key"))
        ));
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

    #[test_case(&[0x5f, 0x42, 1, 2, 0x41, 3, 0xff], Value::Bytes(vec![1, 2, 3]); "byte chunks")]
    #[test_case(&[0x5f, 0xff], Value::Bytes(vec![]); "empty bytes")]
    #[test_case(&[0x7f, 0x61, b'a', 0x62, 0xc3, 0xa9, 0xff], Value::Text("aé".into()); "text chunks")]
    #[test_case(&[0x7f, 0xff], Value::Text(String::new()); "empty text")]
    #[test_case(&[0x9f, 1, 2, 0xff], Value::Array(vec![1.into(), 2.into()]); "array")]
    #[test_case(&[0x9f, 0xff], Value::Array(vec![]); "empty array")]
    #[test_case(&[0xbf, 1, 2, 0xff], Value::Map(vec![(1.into(), 2.into())]); "map")]
    #[test_case(&[0xbf, 0xff], Value::Map(vec![]); "empty map")]
    fn accepts_indefinite_items(bytes: &[u8], expected: Value) {
        assert_eq!(decode(bytes).unwrap(), expected);
    }

    #[test_case(&[0x41, 1], &[0x5f, 0x41, 1, 0xff]; "bytes")]
    #[test_case(&[0x61, b'a'], &[0x7f, 0x61, b'a', 0xff]; "text")]
    #[test_case(&[0x81, 1], &[0x9f, 1, 0xff]; "array")]
    #[test_case(&[0xa1, 1, 2], &[0xbf, 1, 2, 0xff]; "map")]
    fn rejects_equivalent_definite_and_indefinite_keys(definite: &[u8], indefinite: &[u8]) {
        let mut bytes = vec![0xbf];
        bytes.extend_from_slice(definite);
        bytes.push(0xf6);
        bytes.extend_from_slice(indefinite);
        bytes.extend([0xf6, 0xff]);
        assert!(matches!(
            decode(&bytes),
            Err(MessageError::Encoding("duplicate equivalent map key"))
        ));
    }

    #[test_case(&[0xff]; "top level break")]
    #[test_case(&[0x81, 0xff]; "break in definite array")]
    #[test_case(&[0xbf, 1, 0xff]; "odd map")]
    #[test_case(&[0x9f, 1]; "unterminated array")]
    #[test_case(&[0xbf, 1, 2]; "unterminated map")]
    #[test_case(&[0x5f, 0x41, 1]; "unterminated bytes")]
    #[test_case(&[0x7f, 0x61, b'a']; "unterminated text")]
    #[test_case(&[0x5f, 0x5f, 0xff, 0xff]; "nested indefinite chunk")]
    #[test_case(&[0x5f, 0x61, b'a', 0xff]; "text inside bytes")]
    #[test_case(&[0x7f, 0x41, b'a', 0xff]; "bytes inside text")]
    #[test_case(&[0x7f, 0x61, 0xc3, 0x61, 0xa9, 0xff]; "split utf8 codepoint")]
    #[test_case(&[0x5f, 0x42, 1]; "truncated chunk")]
    #[test_case(&[0x9f, 0xff, 0xff]; "trailing break")]
    fn rejects_malformed_indefinite_items(bytes: &[u8]) {
        assert!(decode(bytes).is_err());
    }

    #[test]
    fn indefinite_containers_obey_nesting_bound() {
        let mut bytes = vec![0x9f; MAX_DEPTH];
        bytes.push(0xf6);
        bytes.extend(vec![0xff; MAX_DEPTH]);
        assert!(decode(&bytes).is_ok());
        bytes.insert(0, 0x9f);
        bytes.push(0xff);
        assert!(matches!(
            decode(&bytes),
            Err(MessageError::Encoding("nesting depth exceeded"))
        ));
    }

    #[test_case(&[0xf8, 0x16]; "invalid simple value width")]
    #[test_case(&[0xf7]; "undefined")]
    #[test_case(&[0xc2, 0x01]; "invalid bignum content")]
    #[test_case(&[0xf6, 0xf6]; "trailing bytes")]
    #[test_case(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]; "oversized byte string")]
    fn rejects_malformed_or_unsupported_data(bytes: &[u8]) {
        assert!(decode(bytes).is_err());
    }
}
