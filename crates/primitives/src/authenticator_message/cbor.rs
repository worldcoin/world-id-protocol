use std::collections::BTreeSet;

use serde::{Serialize, de::DeserializeOwned};

use super::{MethodName, Value};

const MAX_DEPTH: usize = 32;

/// Encodes an envelope using RFC 8949 core deterministic encoding.
///
/// Map keys are sorted by their encoded bytes, recursively. Duplicate keys, invalid envelopes,
/// and values nested more than 32 levels are rejected. Transports must enforce their own encoded
/// size limit before sending. Binary payload types must serialize as bytes, not integer arrays.
pub fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>, MessageError> {
    let mut value = Value::serialized(message)?;
    validate_envelope(&value)?;
    sort_maps(&mut value, 0)?;
    let bytes = serialize_value(&value)?;
    validate_encoding(&bytes)?;
    Ok(bytes)
}

/// Decodes exactly one message after validating the entire encoding and envelope.
///
/// `max_size` is the transport's maximum encoded message size. Lengths and nesting (at most 32
/// levels) are checked before allocating payload containers. Unknown envelope and error fields
/// are ignored, but their encodings are still checked. Method-specific schemas are checked by
/// `T`; callers must not execute a request until this function succeeds.
///
/// The Serde value model supports integers, floats, bytes, text, arrays, maps, tags, booleans and
/// null. CBOR `undefined` and unassigned simple values are rejected instead of being silently
/// converted to null. Methods using these values need a codec with a richer value model.
pub fn decode<T: DeserializeOwned>(bytes: &[u8], max_size: usize) -> Result<T, MessageError> {
    if bytes.len() > max_size {
        return Err(MessageError::TooLarge);
    }
    validate_encoding(bytes)?;
    let value: Value = ciborium::from_reader(bytes)
        .map_err(|_| MessageError::Encoding("unsupported or invalid CBOR value"))?;
    validate_envelope(&value)?;
    Ok(value.deserialized()?)
}

/// A message failed its transport size bound, CBOR encoding rules, envelope, or payload schema.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    /// The transport's encoded message limit was exceeded.
    #[error("authenticator message exceeds transport size limit")]
    TooLarge,
    /// The message violates the CBOR encoding rules.
    #[error("invalid authenticator CBOR: {0}")]
    Encoding(&'static str),
    /// The CBOR is valid, but the WIP-105 envelope is not.
    #[error("invalid authenticator envelope: {0}")]
    Envelope(&'static str),
    /// Serialization or the method-specific payload schema failed.
    #[error("authenticator payload serialization failed: {0}")]
    Payload(#[from] ciborium::value::Error),
}

fn validate_envelope(value: &Value) -> Result<(), MessageError> {
    let Value::Map(fields) = value else {
        return Err(MessageError::Envelope("message must be a map"));
    };
    if fields.iter().any(|(key, _)| !matches!(key, Value::Text(_))) {
        return Err(MessageError::Envelope("envelope keys must be text"));
    }
    let get = |name: &str| {
        fields
            .iter()
            .find_map(|(key, value)| (key.as_text() == Some(name)).then_some(value))
    };
    if get("version").and_then(Value::as_text) != Some("1.0") {
        return Err(MessageError::Envelope("unsupported or missing version"));
    }
    let valid_id = |id: &Value| matches!(id, Value::Integer(_) | Value::Text(_));
    if let Some(method) = get("method") {
        if method
            .as_text()
            .and_then(|m| m.parse::<MethodName>().ok())
            .is_none()
        {
            return Err(MessageError::Envelope("invalid method name"));
        }
        if get("result").is_some() || get("error").is_some() {
            return Err(MessageError::Envelope("request contains response fields"));
        }
        if get("id").is_some_and(|id| !valid_id(id)) {
            return Err(MessageError::Envelope("request ID must be text or integer"));
        }
        if get("params").is_some_and(|params| !matches!(params, Value::Array(_) | Value::Map(_))) {
            return Err(MessageError::Envelope("parameters must be an array or map"));
        }
        return Ok(());
    }
    if get("params").is_some() {
        return Err(MessageError::Envelope("response contains parameters"));
    }
    let id = get("id").ok_or(MessageError::Envelope("response ID is missing"))?;
    match (get("result"), get("error")) {
        (Some(_), None) if valid_id(id) => Ok(()),
        (None, Some(Value::Map(error))) if valid_id(id) || matches!(id, Value::Null) => {
            if error.iter().any(|(key, _)| !matches!(key, Value::Text(_))) {
                return Err(MessageError::Envelope("error keys must be text"));
            }
            for required in ["code", "message"] {
                if !error.iter().any(|(key, value)| {
                    key.as_text() == Some(required) && matches!(value, Value::Text(_))
                }) {
                    return Err(MessageError::Envelope(
                        "error requires text code and message",
                    ));
                }
            }
            Ok(())
        }
        _ => Err(MessageError::Envelope(
            "response requires a valid ID and exactly one result or error",
        )),
    }
}

fn sort_maps(value: &mut Value, depth: usize) -> Result<(), MessageError> {
    if depth > MAX_DEPTH {
        return Err(MessageError::Encoding("nesting depth exceeded"));
    }
    match value {
        Value::Array(items) => {
            for item in items {
                sort_maps(item, depth + 1)?;
            }
        }
        Value::Map(entries) => {
            let mut sorted = Vec::with_capacity(entries.len());
            for (mut key, mut value) in std::mem::take(entries) {
                sort_maps(&mut key, depth + 1)?;
                sort_maps(&mut value, depth + 1)?;
                sorted.push((serialize_value(&key)?, key, value));
            }
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            *entries = sorted
                .into_iter()
                .map(|(_, key, value)| (key, value))
                .collect();
        }
        Value::Tag(_, value) => sort_maps(value, depth + 1)?,
        _ => {}
    }
    Ok(())
}

fn serialize_value(value: &Value) -> Result<Vec<u8>, MessageError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|_| MessageError::Encoding("value cannot be encoded"))?;
    Ok(bytes)
}

fn validate_encoding(bytes: &[u8]) -> Result<(), MessageError> {
    let mut remaining = bytes;
    scan(&mut remaining, 0)?;
    if !remaining.is_empty() {
        return Err(MessageError::Encoding("trailing bytes"));
    }
    Ok(())
}

// The fingerprint frames each item by type and length. Floating-point signed zeros and NaN signs
// are normalized, and map pairs sorted, to implement RFC 8949 §5.6.1 key equivalence.
fn scan(bytes: &mut &[u8], depth: usize) -> Result<Vec<u8>, MessageError> {
    if depth > MAX_DEPTH {
        return Err(MessageError::Encoding("nesting depth exceeded"));
    }
    let start = *bytes;
    let initial = take(bytes, 1)?[0];
    let major = initial >> 5;
    let additional = initial & 31;
    let argument = match additional {
        0..=23 => u64::from(additional),
        24..=27 => {
            let size = 1 << (additional - 24);
            let raw = take(bytes, size)?;
            let value = raw
                .iter()
                .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
            if major != 7 && (value < 24 || (size > 1 && value < (1u64 << (size / 2 * 8)))) {
                return Err(MessageError::Encoding("non-preferred integer or length"));
            }
            value
        }
        _ => return Err(MessageError::Encoding("indefinite or reserved item")),
    };
    let mut payload = Vec::new();
    match major {
        0 | 1 => payload.extend_from_slice(&argument.to_be_bytes()),
        2 | 3 => {
            let length =
                usize::try_from(argument).map_err(|_| MessageError::Encoding("length overflow"))?;
            let data = take(bytes, length)?;
            if major == 3 && std::str::from_utf8(data).is_err() {
                return Err(MessageError::Encoding("invalid UTF-8"));
            }
            payload.extend_from_slice(data);
        }
        4 | 5 => {
            let length =
                usize::try_from(argument).map_err(|_| MessageError::Encoding("length overflow"))?;
            let items_per_entry = if major == 5 { 2 } else { 1 };
            if length > bytes.len() / items_per_entry {
                return Err(MessageError::Encoding(
                    "container length exceeds remaining bytes",
                ));
            }
            let mut previous_key: Option<&[u8]> = None;
            let mut keys = BTreeSet::new();
            let mut pairs = Vec::new();
            for _ in 0..length {
                let before = *bytes;
                let key = scan(bytes, depth + 1)?;
                if major == 4 {
                    payload.extend(key);
                    continue;
                }
                let encoded_key = &before[..before.len() - bytes.len()];
                if previous_key.is_some_and(|previous| previous >= encoded_key) {
                    return Err(MessageError::Encoding(
                        "map keys are duplicated or out of order",
                    ));
                }
                previous_key = Some(encoded_key);
                if !keys.insert(key.clone()) {
                    return Err(MessageError::Encoding("duplicate equivalent map key"));
                }
                let value = scan(bytes, depth + 1)?;
                pairs.push((key, value));
            }
            pairs.sort_unstable();
            for (key, value) in pairs {
                payload.extend(key);
                payload.extend(value);
            }
        }
        6 => {
            let content = scan(bytes, depth + 1)?;
            if matches!(argument, 2 | 3) {
                if content[0] != 2 {
                    return Err(MessageError::Encoding("bignum content must be bytes"));
                }
                // Byte-string fingerprints have a type byte and an eight-byte length prefix.
                let magnitude = &content[9..];
                if magnitude.len() <= 8 || magnitude[0] == 0 {
                    return Err(MessageError::Encoding("non-preferred bignum"));
                }
            }
            payload.extend_from_slice(&argument.to_be_bytes());
            payload.extend(content);
        }
        7 if additional <= 24 => {
            if !(20..=22).contains(&argument) {
                return Err(MessageError::Encoding("unsupported CBOR simple value"));
            }
            if additional == 24 && argument < 32 {
                return Err(MessageError::Encoding(
                    "invalid or non-preferred simple value",
                ));
            }
            payload.push(argument as u8);
        }
        7 => {
            let raw = &start[..start.len() - bytes.len()];
            let value: f64 =
                ciborium::from_reader(raw).map_err(|_| MessageError::Encoding("invalid float"))?;
            let significand_bits = match additional {
                25 => 10,
                26 => 23,
                _ => 52,
            };
            if value.is_nan() {
                payload.push(1);
                let significand = argument & ((1 << significand_bits) - 1);
                if (additional == 26 && significand & ((1 << 13) - 1) == 0)
                    || (additional == 27 && significand & ((1 << 29) - 1) == 0)
                {
                    return Err(MessageError::Encoding("non-preferred NaN"));
                }
                payload.extend_from_slice(&(significand << (64 - significand_bits)).to_be_bytes());
            } else {
                payload.push(0);
                let preferred = serialize_value(&Value::Float(value))?;
                if preferred != raw {
                    return Err(MessageError::Encoding("non-preferred float"));
                }
                payload.extend_from_slice(
                    &(if value == 0.0 { 0 } else { value.to_bits() }).to_be_bytes(),
                );
            }
        }
        _ => unreachable!(),
    }
    let mut fingerprint = vec![if major == 7 && additional >= 25 {
        8
    } else {
        major
    }];
    fingerprint.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    fingerprint.extend(payload);
    Ok(fingerprint)
}

const fn take<'a>(bytes: &mut &'a [u8], len: usize) -> Result<&'a [u8], MessageError> {
    if len > bytes.len() {
        return Err(MessageError::Encoding("truncated item or invalid length"));
    }
    let (item, remaining) = bytes.split_at(len);
    *bytes = remaining;
    Ok(item)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator_message::{ErrorObject, Id, Notification, Request, Response};

    fn map(fields: &[(&str, Value)]) -> Value {
        Value::Map(
            fields
                .iter()
                .map(|(key, value)| (Value::Text((*key).into()), value.clone()))
                .collect(),
        )
    }

    fn response(result: Value) -> Value {
        map(&[
            ("version", "1.0".into()),
            ("id", 1.into()),
            ("result", result),
        ])
    }

    fn raw(value: &Value) -> Vec<u8> {
        let mut value = value.clone();
        sort_maps(&mut value, 0).unwrap();
        serialize_value(&value).unwrap()
    }

    #[test]
    fn round_trips_native_binary_and_integer_ids() {
        for id in [
            Id::Number(i128::from(u64::MAX)),
            Id::Number(-1 - i128::from(u64::MAX)),
            Id::String("1".into()),
        ] {
            let request = Request::new(
                id,
                MethodName::from_static("worldid_auth_v1_register"),
                map(&[("key", Value::Bytes(vec![0, 255]))]),
            );
            let bytes = encode(&request).unwrap();
            let decoded: Request<Value> = decode(&bytes, bytes.len()).unwrap();
            assert_eq!(decoded, request);
        }
    }

    #[test]
    fn emits_core_deterministic_order_not_length_first_order() {
        let value = response(Value::Map(vec![
            (Value::Integer((-1).into()), Value::Null),
            (Value::Integer(24.into()), Value::Null),
        ]));
        let encoded = encode(&value).unwrap();
        assert!(
            encoded
                .windows(6)
                .any(|bytes| bytes == [0xa2, 0x18, 0x18, 0xf6, 0x20, 0xf6])
        );
        assert_eq!(
            encode(&decode::<Value>(&encoded, 1024).unwrap()).unwrap(),
            encoded
        );
    }

    #[test]
    fn notifications_and_absent_arguments_round_trip() {
        let notification =
            Notification::<Value>::without_params(MethodName::from_static("worldid_ping"));
        let bytes = encode(&notification).unwrap();
        assert_eq!(
            decode::<Notification<Value>>(&bytes, 1024).unwrap(),
            notification
        );
        assert!(decode::<Request<Value>>(&bytes, 1024).is_err());
        let request =
            Request::<Value>::without_params(1.into(), MethodName::from_static("worldid_ping"));
        assert_eq!(
            decode::<Request<Value>>(&encode(&request).unwrap(), 1024).unwrap(),
            request
        );
    }

    #[test]
    fn responses_preserve_null_results_and_error_data() {
        let success: Response<Value> = Response {
            id: Some(1.into()),
            outcome: Ok(Value::Null),
        };
        assert_eq!(
            decode::<Response<Value>>(&encode(&success).unwrap(), 1024).unwrap(),
            success
        );
        let error: Response<Value> = Response {
            id: None,
            outcome: Err(ErrorObject {
                code: "parse_error".into(),
                message: "Malformed message".into(),
                data: Some(Value::Null),
            }),
        };
        assert_eq!(
            decode::<Response<Value>>(&encode(&error).unwrap(), 1024).unwrap(),
            error
        );
        let request =
            Request::<Value>::without_params(1.into(), MethodName::from_static("worldid_ping"));
        assert!(decode::<Notification<Value>>(&encode(&request).unwrap(), 1024).is_err());
        let invalid: Response<Value> = Response {
            id: None,
            outcome: Ok(Value::Null),
        };
        assert!(encode(&invalid).is_err());
    }

    #[test]
    fn ignores_unknown_envelope_and_error_fields() {
        let envelope = map(&[
            ("version", "1.0".into()),
            ("id", Value::Null),
            ("extra", Value::Bytes(vec![1])),
            (
                "error",
                map(&[
                    ("code", "parse_error".into()),
                    ("message", "bad".into()),
                    ("extra", true.into()),
                ]),
            ),
        ]);
        let decoded: Response<Value> = decode(&encode(&envelope).unwrap(), 1024).unwrap();
        assert_eq!(decoded.outcome.unwrap_err().code, "parse_error");
    }

    #[test]
    fn rejects_invalid_envelopes() {
        let request = map(&[
            ("version", "1.0".into()),
            ("id", 1.into()),
            ("method", "worldid_ping".into()),
        ]);
        for (field, value) in [
            ("params", Value::Null),
            ("params", true.into()),
            ("id", Value::Null),
            ("id", Value::Float(1.0)),
            ("method", "other_ping".into()),
            ("version", "2.0".into()),
            ("result", Value::Null),
            ("error", Value::Null),
        ] {
            let mut modified = request.clone();
            let fields = modified.as_map_mut().unwrap();
            fields.retain(|(key, _)| key.as_text() != Some(field));
            fields.push((field.into(), value));
            assert!(
                matches!(
                    decode::<Value>(&raw(&modified), 1024),
                    Err(MessageError::Envelope(_))
                ),
                "{field}"
            );
        }
        for invalid in [
            map(&[("version", "1.0".into()), ("id", 1.into())]),
            map(&[("version", "1.0".into()), ("result", Value::Null)]),
            map(&[
                ("version", "1.0".into()),
                ("id", Value::Null),
                ("result", Value::Null),
            ]),
            map(&[
                ("version", "1.0".into()),
                ("id", 1.into()),
                ("result", Value::Null),
                ("error", Value::Null),
            ]),
        ] {
            assert!(decode::<Value>(&raw(&invalid), 1024).is_err());
        }
    }

    #[test]
    fn rejects_malformed_or_non_deterministic_encoding_before_payload_decode() {
        for invalid in [
            vec![0xbf, 0xff],
            vec![0xa0, 0x00],
            vec![0xb8, 0x00],
            vec![0xa1, 0x61, 0xff, 0],
            vec![0xa1, 0x61, b'x', 0x9f, 0xff],
            vec![0xa1, 0x61, b'x', 0x1b, 0, 0, 0, 0, 0, 0, 0, 1],
            vec![0xa2, 0x61, b'b', 0, 0x61, b'a', 0],
            vec![0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            vec![0xa1, 0, 0xfa, 0x3f, 0x80, 0, 0],
        ] {
            assert!(
                matches!(
                    decode::<Value>(&invalid, 1024),
                    Err(MessageError::Encoding(_))
                ),
                "{invalid:x?}"
            );
        }
    }

    #[test]
    fn rejects_duplicate_nested_keys_including_equivalent_signed_zeros() {
        for keys in [
            vec![Value::Text("x".into()), Value::Text("x".into())],
            vec![Value::Float(0.0), Value::Float(-0.0)],
            vec![
                Value::Array(vec![Value::Float(0.0)]),
                Value::Array(vec![Value::Float(-0.0)]),
            ],
            vec![
                Value::Tag(100, Box::new(Value::Float(0.0))),
                Value::Tag(100, Box::new(Value::Float(-0.0))),
            ],
        ] {
            let result = Value::Map(keys.into_iter().map(|key| (key, Value::Null)).collect());
            assert!(matches!(
                decode::<Value>(&raw(&response(result)), 1024),
                Err(MessageError::Encoding(_))
            ));
        }
        let distinct = response(Value::Map(vec![
            (1.into(), Value::Null),
            (Value::Float(1.0), Value::Null),
        ]));
        assert!(decode::<Value>(&encode(&distinct).unwrap(), 1024).is_ok());
    }

    #[test]
    fn rejects_nonpreferred_and_invalid_bignums_before_payload_decode() {
        for tag in [2, 3] {
            for content in [
                Value::Bytes(vec![]),
                Value::Bytes(vec![1]),
                Value::Bytes(vec![255; 8]),
                Value::Bytes(vec![0; 9]),
                Value::Bytes([vec![0], vec![1; 9]].concat()),
                Value::Text("1".into()),
            ] {
                let encoded = raw(&response(Value::Tag(tag, Box::new(content))));
                assert!(matches!(
                    decode::<Response<Value>>(&encoded, 1024),
                    Err(MessageError::Encoding(_))
                ));
            }
        }
    }

    #[test]
    fn preferred_bignums_round_trip_without_changing_map_keys() {
        for tag in [2, 3] {
            for length in [9, 16, 17] {
                let key = Value::Tag(tag, Box::new(Value::Bytes(vec![1; length])));
                let message = response(Value::Map(vec![(key, Value::Null)]));
                let encoded = encode(&message).unwrap();
                let decoded: Response<Value> = decode(&encoded, 1024).unwrap();
                assert_eq!(encode(&decoded).unwrap(), encoded);
            }
        }
    }

    #[test]
    fn never_converts_undefined_to_null() {
        let mut encoded = encode(&response(Value::Null)).unwrap();
        let null = encoded.iter().position(|byte| *byte == 0xf6).unwrap();
        encoded[null] = 0xf7;
        assert!(matches!(
            decode::<Response<Value>>(&encoded, 1024),
            Err(MessageError::Encoding("unsupported CBOR simple value"))
        ));
    }

    #[test]
    fn enforces_size_and_depth_limits() {
        let encoded = encode(&response(Value::Null)).unwrap();
        assert!(matches!(
            decode::<Value>(&encoded, encoded.len() - 1),
            Err(MessageError::TooLarge)
        ));
        let mut nested = vec![0x81; MAX_DEPTH + 2];
        nested.push(0);
        assert!(matches!(
            decode::<Value>(&nested, 1024),
            Err(MessageError::Encoding("nesting depth exceeded"))
        ));
    }
}
