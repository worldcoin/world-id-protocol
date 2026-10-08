//! CBOR serialization and bounded decoding.

use serde::{Serialize, de::DeserializeOwned};

mod de;

const MAX_DEPTH: usize = 32;

/// Serializes a value as CBOR using Ciborium.
///
/// Map entries retain the order supplied by `Serialize`. Containers with unknown lengths use
/// indefinite-length encoding. Binary payloads must serialize as bytes, not integer arrays.
/// Transports enforce their own encoded size limits; this function does not validate the schema,
/// reject duplicate keys, or limit nesting.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, MessageError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

/// Decodes exactly one value, rejecting duplicate keys and enforcing size and nesting bounds.
///
/// Map ordering and non-minimal integer, length and floating-point encodings are accepted.
/// Definite and indefinite lengths are supported. Lengths are checked against the remaining
/// input before allocating containers; nesting is limited to 32 levels. The schema is determined
/// by `T`.
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
    /// The value could not be serialized as CBOR.
    #[error("CBOR serialization failed: {0}")]
    Serialize(#[from] ciborium::ser::Error<std::io::Error>),
    /// The method-specific payload schema failed.
    #[error("CBOR payload serialization failed: {0}")]
    Payload(#[from] ciborium::value::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator_message::{
        ErrorObject, Id, MethodName, Request, Response, Value, Version,
    };
    use test_case::test_case;

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

    #[test_case(Id::Number(i128::from(u64::MAX)); "maximum_positive")]
    #[test_case(Id::Number(-1 - i128::from(u64::MAX)); "minimum_negative")]
    #[test_case(Id::String("1".into()); "string")]
    fn round_trips_native_binary_and_integer_ids(id: Id) {
        let request = Request::new(
            Some(id),
            MethodName::from_static("worldid_auth_v1_register"),
            map(&[("key", Value::Bytes(vec![0, 255]))]),
        );
        let bytes = encode(&request).unwrap();
        let decoded: Request<Value> = decode(&bytes, bytes.len()).unwrap();
        assert_eq!(decoded, request);
    }

    #[test_case(i128::from(u64::MAX) + 1; "above_maximum")]
    #[test_case(-2 - i128::from(u64::MAX); "below_minimum")]
    fn typed_ids_reject_integers_outside_the_basic_cbor_range(number: i128) {
        let request = Request::<Value>::without_params(
            Some(Id::Number(number)),
            MethodName::from_static("worldid_ping"),
        );
        assert!(encode(&request).is_err());
    }

    #[test]
    fn preserves_map_entry_order() {
        let value = Value::Map(vec![
            (Value::Integer((-1).into()), Value::Null),
            (Value::Integer(24.into()), Value::Null),
        ]);
        let encoded = encode(&value).unwrap();
        assert_eq!(encoded, [0xa2, 0x20, 0xf6, 0x18, 0x18, 0xf6]);
        assert_eq!(decode::<Value>(&encoded, 1024).unwrap(), value);
    }

    #[test]
    fn unknown_sequence_lengths_round_trip() {
        use serde::ser::SerializeSeq as _;

        struct UnknownLength;
        impl Serialize for UnknownLength {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut sequence = serializer.serialize_seq(None)?;
                sequence.serialize_element(&1)?;
                sequence.end()
            }
        }
        let encoded = encode(&UnknownLength).unwrap();
        assert_eq!(encoded, [0x9f, 1, 0xff]);
        assert_eq!(decode::<Vec<u8>>(&encoded, 1024).unwrap(), vec![1]);
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

    #[test_case(Value::Null; "null")]
    #[test_case(Value::Bool(true); "boolean")]
    #[test_case(Value::Bytes(vec![1, 2]); "bytes")]
    #[test_case(map(&[("x", 1.into())]); "map_payload")]
    fn generic_codec_accepts_arbitrary_payloads(value: Value) {
        assert_eq!(
            decode::<Value>(&encode(&value).unwrap(), 1024).unwrap(),
            value
        );
    }

    #[test_case(None; "absent")]
    #[test_case(Some(Value::Null); "present null")]
    #[test_case(Some(map(&[("x", 1.into())])); "present map")]
    fn request_params_preserve_presence(params: Option<Value>) {
        let request = Request {
            version: Version::V1,
            id: Some(1.into()),
            method: MethodName::from_static("worldid_ping"),
            params,
        };
        assert_eq!(
            decode::<Request<Value>>(&encode(&request).unwrap(), 1024).unwrap(),
            request
        );
    }

    #[test_case(None, true; "absent")]
    #[test_case(Some(Value::Null), false; "present null")]
    #[test_case(Some(map(&[("x", 1.into())])), true; "present map")]
    fn typed_request_params_reject_null(params: Option<Value>, accepted: bool) {
        let request = Request {
            version: Version::V1,
            id: Some(1.into()),
            method: MethodName::from_static("worldid_ping"),
            params,
        };
        let bytes = encode(&request).unwrap();
        assert_eq!(
            decode::<Request<std::collections::BTreeMap<String, u64>>>(&bytes, 1024).is_ok(),
            accepted
        );
    }

    #[test]
    fn requests_accept_boolean_params() {
        let request = Request::new(None, MethodName::from_static("worldid_ping"), true);
        assert_eq!(
            decode::<Request<bool>>(&encode(&request).unwrap(), 1024).unwrap(),
            request
        );
    }

    #[test_case("id", Value::Null; "null_id")]
    #[test_case("id", Value::Float(1.0); "float_id")]
    #[test_case("method", "other_ping".into(); "invalid_method")]
    #[test_case("version", "2.0".into(); "unsupported_version")]
    fn typed_envelopes_reject_invalid_fields(field: &str, value: Value) {
        let mut modified = map(&[
            ("version", "1.0".into()),
            ("id", 1.into()),
            ("method", "worldid_ping".into()),
        ]);
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

    #[test_case(map(&[("id", 1.into()), ("result", Value::Null)]); "missing_version")]
    #[test_case(map(&[
        ("version", "2.0".into()),
        ("id", 1.into()),
        ("result", Value::Null),
    ]); "unsupported_version")]
    #[test_case(map(&[("version", "1.0".into()), ("id", 1.into())]); "missing_outcome")]
    #[test_case(map(&[("version", "1.0".into()), ("result", Value::Null)]); "missing_id")]
    #[test_case(map(&[
        ("version", "1.0".into()),
        ("id", Value::Null),
        ("result", Value::Null),
    ]); "null_success_id")]
    #[test_case(map(&[
        ("version", "1.0".into()),
        ("id", 1.into()),
        ("result", Value::Null),
        ("error", map(&[("code", "failed".into()), ("message", "failed".into())])),
    ]); "both_outcomes")]
    fn typed_responses_reject_invalid_fields(invalid: Value) {
        assert!(decode::<Response<Value>>(&raw(&invalid), 1024).is_err());
    }

    #[test_case(vec![0xa0, 0x00]; "trailing_data")]
    #[test_case(vec![0xa1, 0x61, 0xff, 0]; "invalid_utf8")]
    #[test_case(vec![0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]; "excessive_length")]
    fn rejects_malformed_encoding_before_payload_decode(invalid: Vec<u8>) {
        assert!(
            matches!(
                decode::<Value>(&invalid, 1024),
                Err(MessageError::Encoding(_))
            ),
            "{invalid:x?}"
        );
    }

    #[test_case(vec![Value::Text("x".into()), Value::Text("x".into())]; "text")]
    #[test_case(vec![Value::Float(0.0), Value::Float(-0.0)]; "signed_zero")]
    #[test_case(vec![
        Value::Array(vec![Value::Float(0.0)]),
        Value::Array(vec![Value::Float(-0.0)]),
    ]; "array_signed_zero")]
    #[test_case(vec![
        Value::Tag(100, Box::new(Value::Float(0.0))),
        Value::Tag(100, Box::new(Value::Float(-0.0))),
    ]; "tag_signed_zero")]
    fn rejects_duplicate_nested_keys_including_equivalent_signed_zeros(keys: Vec<Value>) {
        let result = Value::Map(keys.into_iter().map(|key| (key, Value::Null)).collect());
        assert!(matches!(
            decode::<Value>(&raw(&response(result)), 1024),
            Err(MessageError::Encoding(_))
        ));
    }

    #[test]
    fn integer_and_float_keys_are_distinct() {
        let distinct = response(Value::Map(vec![
            (1.into(), Value::Null),
            (Value::Float(1.0), Value::Null),
        ]));
        assert!(decode::<Value>(&encode(&distinct).unwrap(), 1024).is_ok());
    }

    #[test_case(vec![0xb8, 0], Value::Map(vec![]); "wide_map_length")]
    #[test_case(vec![0x1b, 0, 0, 0, 0, 0, 0, 0, 1], Value::Integer(1.into()); "wide_integer")]
    #[test_case(vec![0xa2, 0x61, b'b', 0, 0x61, b'a', 0],
                map(&[("b", 0.into()), ("a", 0.into())]); "unsorted_map")]
    #[test_case(vec![0xfa, 0x3f, 0x80, 0, 0], Value::Float(1.0); "wide_float")]
    fn accepts_map_order_and_nonpreferred_widths(input: Vec<u8>, expected: Value) {
        assert_eq!(decode::<Value>(&input, 1024).unwrap(), expected);
    }

    #[test_case(vec![0xa2, 1, 0, 0x18, 1, 0]; "integer_width")]
    #[test_case(vec![0xa2, 1, 0, 0xc2, 0x42, 0, 1, 0]; "positive_bignum")]
    #[test_case(vec![0xa2, 0x20, 0, 0xc3, 0x40, 0]; "negative_bignum")]
    #[test_case(vec![0xa2, 0xf9, 0, 0, 0, 0xfa, 0x80, 0, 0, 0, 0]; "float_width")]
    fn rejects_equivalent_keys_with_different_encodings(input: Vec<u8>) {
        assert!(decode::<Value>(&input, 1024).is_err(), "{input:x?}");
    }

    #[test]
    fn rejects_equivalent_map_keys_in_different_orders() {
        let first = map(&[("a", 1.into()), ("b", 2.into())]);
        let second = map(&[("b", 2.into()), ("a", 1.into())]);
        let duplicate = Value::Map(vec![(first, Value::Null), (second, Value::Null)]);
        assert!(decode::<Value>(&raw(&duplicate), 1024).is_err());
    }

    #[test_case(2, vec![]; "positive_empty")]
    #[test_case(2, vec![1]; "positive_small")]
    #[test_case(2, vec![255; 8]; "positive_eight_bytes")]
    #[test_case(2, vec![0; 9]; "positive_zero")]
    #[test_case(2, [vec![0], vec![1; 9]].concat(); "positive_leading_zero")]
    #[test_case(3, vec![]; "negative_empty")]
    #[test_case(3, vec![1]; "negative_small")]
    #[test_case(3, vec![255; 8]; "negative_eight_bytes")]
    #[test_case(3, vec![0; 9]; "negative_zero")]
    #[test_case(3, [vec![0], vec![1; 9]].concat(); "negative_leading_zero")]
    fn accepts_nonpreferred_bignums(tag: u64, magnitude: Vec<u8>) {
        let encoded = raw(&Value::Tag(tag, Box::new(Value::Bytes(magnitude))));
        assert!(decode::<Value>(&encoded, 1024).is_ok());
    }

    #[test_case(2; "positive")]
    #[test_case(3; "negative")]
    fn rejects_invalid_bignum_contents(tag: u64) {
        let invalid = raw(&Value::Tag(tag, Box::new(Value::Text("1".into()))));
        assert!(decode::<Value>(&invalid, 1024).is_err());
    }

    #[test_case(2, 9; "positive_9_bytes")]
    #[test_case(2, 16; "positive_16_bytes")]
    #[test_case(2, 17; "positive_17_bytes")]
    #[test_case(3, 9; "negative_9_bytes")]
    #[test_case(3, 16; "negative_16_bytes")]
    #[test_case(3, 17; "negative_17_bytes")]
    fn preferred_bignums_round_trip_without_changing_map_keys(tag: u64, length: usize) {
        let key = Value::Tag(tag, Box::new(Value::Bytes(vec![1; length])));
        let message = response(Value::Map(vec![(key, Value::Null)]));
        let encoded = encode(&message).unwrap();
        let decoded: Response<Value> = decode(&encoded, 1024).unwrap();
        assert_eq!(encode(&decoded).unwrap(), encoded);
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
