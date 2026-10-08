//! Deterministic CBOR output and bounded decoding of definite-length CBOR values.

use serde::{Serialize, de::DeserializeOwned};

mod de;
mod ser;

const MAX_DEPTH: usize = 32;

/// Encodes a value using RFC 8949 core deterministic encoding.
///
/// Maps are buffered and sorted by their encoded keys, recursively. Duplicate keys and values
/// nested more than 32 levels are rejected. Transports must enforce their own encoded size limit.
/// Binary payload types must serialize as bytes, not integer arrays.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, MessageError> {
    ser::encode(value)
}

/// Decodes exactly one value, rejecting duplicate keys and enforcing size and nesting bounds.
///
/// Map ordering and non-minimal integer, length and floating-point encodings are accepted.
/// Indefinite-length items are rejected. Lengths are checked against the remaining input before
/// allocating containers; nesting is limited to 32 levels. The schema is determined by `T`.
///
/// The Serde value model supports integers, floats, bytes, text, arrays, maps, tags, booleans and
/// null. CBOR `undefined` and unassigned simple values are rejected rather than converted to null.
pub fn decode<T: DeserializeOwned>(bytes: &[u8], max_size: usize) -> Result<T, MessageError> {
    if bytes.len() > max_size {
        return Err(MessageError::TooLarge);
    }
    Ok(de::decode(bytes)?.deserialized()?)
}

/// A value failed its transport size bound, CBOR encoding rules, or payload schema.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    /// The transport's encoded message limit was exceeded.
    #[error("CBOR value exceeds transport size limit")]
    TooLarge,
    /// The message violates the CBOR encoding rules.
    #[error("invalid CBOR: {0}")]
    Encoding(&'static str),
    /// Serialization or the method-specific payload schema failed.
    #[error("CBOR payload serialization failed: {0}")]
    Payload(#[from] ciborium::value::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator_message::{
        ErrorObject, Id, MethodName, Request, Response, Value, Version,
    };

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
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn round_trips_native_binary_and_integer_ids() {
        for id in [
            Id::Number(i128::from(u64::MAX)),
            Id::Number(-1 - i128::from(u64::MAX)),
            Id::String("1".into()),
        ] {
            let request = Request::new(
                Some(id),
                MethodName::from_static("worldid_auth_v1_register"),
                map(&[("key", Value::Bytes(vec![0, 255]))]),
            );
            let bytes = encode(&request).unwrap();
            let decoded: Request<Value> = decode(&bytes, bytes.len()).unwrap();
            assert_eq!(decoded, request);
        }
    }

    #[test]
    fn typed_ids_reject_integers_outside_the_basic_cbor_range() {
        for number in [i128::from(u64::MAX) + 1, -2 - i128::from(u64::MAX)] {
            let request = Request::<Value>::without_params(
                Some(Id::Number(number)),
                MethodName::from_static("worldid_ping"),
            );
            assert!(encode(&request).is_err());
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
            Request::<Value>::without_params(None, MethodName::from_static("worldid_ping"));
        let bytes = encode(&notification).unwrap();
        assert_eq!(
            decode::<Request<Value>>(&bytes, 1024).unwrap(),
            notification
        );
        let request = Request::<Value>::without_params(
            Some(1.into()),
            MethodName::from_static("worldid_ping"),
        );
        assert_eq!(
            decode::<Request<Value>>(&encode(&request).unwrap(), 1024).unwrap(),
            request
        );
    }

    #[test]
    fn responses_preserve_null_results_and_error_data() {
        let success: Response<Value> = Response {
            version: Version::V1,
            id: Some(1.into()),
            outcome: Ok(Value::Null),
        };
        assert_eq!(
            decode::<Response<Value>>(&encode(&success).unwrap(), 1024).unwrap(),
            success
        );
        let error: Response<Value> = Response {
            version: Version::V1,
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
        let invalid: Response<Value> = Response {
            version: Version::V1,
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
    fn generic_codec_accepts_arbitrary_payloads() {
        for value in [
            Value::Null,
            Value::Bool(true),
            Value::Bytes(vec![1, 2]),
            map(&[("x", 1.into())]),
        ] {
            assert_eq!(
                decode::<Value>(&encode(&value).unwrap(), 1024).unwrap(),
                value
            );
        }
        let request = Request::new(None, MethodName::from_static("worldid_ping"), true);
        assert_eq!(
            decode::<Request<bool>>(&encode(&request).unwrap(), 1024).unwrap(),
            request
        );
    }

    #[test]
    fn typed_envelopes_reject_invalid_fields() {
        let request = map(&[
            ("version", "1.0".into()),
            ("id", 1.into()),
            ("method", "worldid_ping".into()),
        ]);
        for (field, value) in [
            ("id", Value::Null),
            ("id", Value::Float(1.0)),
            ("method", "other_ping".into()),
            ("version", "2.0".into()),
        ] {
            let mut modified = request.clone();
            let fields = modified.as_map_mut().unwrap();
            fields.retain(|(key, _)| key.as_text() != Some(field));
            fields.push((field.into(), value));
            assert!(
                matches!(
                    decode::<Request<Value>>(&raw(&modified), 1024),
                    Err(MessageError::Payload(_))
                ),
                "{field}"
            );
        }
        let error = map(&[("code", "failed".into()), ("message", "failed".into())]);
        for invalid in [
            map(&[("id", 1.into()), ("result", Value::Null)]),
            map(&[
                ("version", "2.0".into()),
                ("id", 1.into()),
                ("result", Value::Null),
            ]),
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
                ("error", error),
            ]),
        ] {
            assert!(decode::<Response<Value>>(&raw(&invalid), 1024).is_err());
        }
    }

    #[test]
    fn rejects_malformed_and_indefinite_encoding_before_payload_decode() {
        for invalid in [
            vec![0xbf, 0xff],
            vec![0xa0, 0x00],
            vec![0xa1, 0x61, 0xff, 0],
            vec![0xa1, 0x61, b'x', 0x9f, 0xff],
            vec![0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
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
    fn accepts_non_deterministic_input_but_emits_deterministic_output() {
        for (input, expected) in [
            (vec![0xb8, 0], vec![0xa0]),
            (vec![0x1b, 0, 0, 0, 0, 0, 0, 0, 1], vec![1]),
            (
                vec![0xa2, 0x61, b'b', 0, 0x61, b'a', 0],
                vec![0xa2, 0x61, b'a', 0, 0x61, b'b', 0],
            ),
            (vec![0xfa, 0x3f, 0x80, 0, 0], vec![0xf9, 0x3c, 0]),
        ] {
            let decoded: Value = decode(&input, 1024).unwrap();
            assert_eq!(encode(&decoded).unwrap(), expected);
        }
    }

    #[test]
    fn rejects_equivalent_keys_with_different_encodings() {
        for input in [
            vec![0xa2, 1, 0, 0x18, 1, 0],
            vec![0xa2, 1, 0, 0xc2, 0x42, 0, 1, 0],
            vec![0xa2, 0x20, 0, 0xc3, 0x40, 0],
            vec![0xa2, 0xf9, 0, 0, 0, 0xfa, 0x80, 0, 0, 0, 0],
        ] {
            assert!(decode::<Value>(&input, 1024).is_err(), "{input:x?}");
        }
        let first = map(&[("a", 1.into()), ("b", 2.into())]);
        let second = map(&[("b", 2.into()), ("a", 1.into())]);
        let duplicate = Value::Map(vec![(first, Value::Null), (second, Value::Null)]);
        assert!(decode::<Value>(&raw(&duplicate), 1024).is_err());
        assert!(encode(&duplicate).is_err());
    }

    #[test]
    fn accepts_nonpreferred_bignums_but_rejects_invalid_contents() {
        for tag in [2, 3] {
            for magnitude in [
                vec![],
                vec![1],
                vec![255; 8],
                vec![0; 9],
                [vec![0], vec![1; 9]].concat(),
            ] {
                let encoded = raw(&Value::Tag(tag, Box::new(Value::Bytes(magnitude))));
                assert!(decode::<Value>(&encoded, 1024).is_ok());
            }
            let invalid = raw(&Value::Tag(tag, Box::new(Value::Text("1".into()))));
            assert!(decode::<Value>(&invalid, 1024).is_err());
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
    fn preserves_distinct_signaling_and_quiet_nan_keys() {
        let encoded = [0xa2, 0xf9, 0x7c, 0x01, 0, 0xf9, 0x7e, 0x01, 0];
        let decoded: Value = decode(&encoded, 1024).unwrap();
        let keys = decoded.as_map().unwrap();
        assert_eq!(
            keys[0].0.as_float().unwrap().to_bits(),
            0x7ff0_0400_0000_0000
        );
        assert_eq!(
            keys[1].0.as_float().unwrap().to_bits(),
            0x7ff8_0400_0000_0000
        );
        assert_eq!(encode(&decoded).unwrap(), encoded);
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
