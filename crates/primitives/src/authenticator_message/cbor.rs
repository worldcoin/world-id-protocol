//! CBOR serialization and bounded decoding.

use serde::{Serialize, de::DeserializeOwned};

const RECURSION_LIMIT: usize = 32;

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

/// Decodes exactly one CBOR value using Ciborium, with a byte-size and recursion limit.
///
/// `T` determines the schema and duplicate-field behavior. Ciborium's standard value semantics
/// apply, including support for indefinite lengths and conversion of `undefined` to null.
/// The decoder uses a recursion limit of 32 and rejects any trailing bytes.
pub fn decode<T: DeserializeOwned>(bytes: &[u8], max_size: usize) -> Result<T, MessageError> {
    if bytes.len() > max_size {
        return Err(MessageError::TooLarge);
    }
    let mut remaining = bytes;
    let value = ciborium::de::from_reader_with_recursion_limit(&mut remaining, RECURSION_LIMIT)?;
    if !remaining.is_empty() {
        return Err(MessageError::TrailingData);
    }
    Ok(value)
}

/// A value failed its transport size bound, CBOR encoding rules, or payload schema.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    /// The transport's encoded message limit was exceeded.
    #[error("CBOR value exceeds transport size limit")]
    TooLarge,
    /// More bytes remain after decoding one value.
    #[error("trailing bytes after CBOR value")]
    TrailingData,
    /// The value could not be serialized as CBOR.
    #[error("CBOR serialization failed: {0}")]
    Serialize(#[from] ciborium::ser::Error<std::io::Error>),
    /// The CBOR input or requested schema could not be decoded.
    #[error("CBOR deserialization failed: {0}")]
    Deserialize(#[from] ciborium::de::Error<std::io::Error>),
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

    #[test_case(Some(1.into()), None; "absent_params")]
    #[test_case(Some(1.into()), Some(Value::Null); "null_params")]
    #[test_case(Some(1.into()), Some(map(&[("x", 1.into())])); "map_params")]
    #[test_case(None, None; "notification")]
    fn requests_preserve_absent_and_null_fields(id: Option<Id>, params: Option<Value>) {
        let request = Request {
            version: Version::V1,
            id,
            method: MethodName::from_static("worldid_ping"),
            params,
        };
        assert_eq!(
            decode::<Request<Value>>(&encode(&request).unwrap(), 1024).unwrap(),
            request
        );
    }

    #[test]
    fn typed_request_params_reject_null() {
        let request = Request::new(
            Some(1.into()),
            MethodName::from_static("worldid_ping"),
            Value::Null,
        );
        let bytes = encode(&request).unwrap();
        assert!(decode::<Request<std::collections::BTreeMap<String, u64>>>(&bytes, 1024).is_err());
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

    #[test_case("id", Value::Null; "null_id")]
    #[test_case("id", Value::Float(1.0); "float_id")]
    #[test_case("version", "2.0".into(); "unsupported_version")]
    fn typed_requests_reject_invalid_fields(field: &str, value: Value) {
        let mut modified = map(&[
            ("version", "1.0".into()),
            ("id", 1.into()),
            ("method", "worldid_ping".into()),
        ]);
        let fields = modified.as_map_mut().unwrap();
        fields.retain(|(key, _)| key.as_text() != Some(field));
        fields.push((field.into(), value));
        assert!(matches!(
            decode::<Request<Value>>(&encode(&modified).unwrap(), 1024),
            Err(MessageError::Deserialize(_))
        ));
    }

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
        assert!(decode::<Response<Value>>(&encode(&invalid).unwrap(), 1024).is_err());
    }

    #[test]
    fn typed_requests_reject_duplicate_fields() {
        let duplicate = map(&[
            ("version", "1.0".into()),
            ("version", "1.0".into()),
            ("method", "worldid_ping".into()),
        ]);
        assert!(decode::<Request<Value>>(&encode(&duplicate).unwrap(), 1024).is_err());
    }

    #[test]
    fn rejects_trailing_data() {
        assert!(matches!(
            decode::<Value>(&[0xa0, 0], 1024),
            Err(MessageError::TrailingData)
        ));
    }

    #[test]
    fn enforces_size_and_depth_limits() {
        let encoded = encode(&map(&[("version", "1.0".into())])).unwrap();
        assert!(matches!(
            decode::<Value>(&encoded, encoded.len() - 1),
            Err(MessageError::TooLarge)
        ));
        let mut nested = vec![0x81; RECURSION_LIMIT + 2];
        nested.push(0);
        assert!(matches!(
            decode::<Value>(&nested, 1024),
            Err(MessageError::Deserialize(
                ciborium::de::Error::RecursionLimitExceeded
            ))
        ));
    }
}
