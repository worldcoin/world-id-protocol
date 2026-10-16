//! Authenticator message encoding tests, with fixtures in CBOR diagnostic notation. Valid
//! fixtures follow the structs' field order; receivers accept other map orders as well.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use test_case::test_case;
use world_id_primitives::authenticator_message::{
    ErrorObject, MessageError, MethodName, Request, Response, Value, Version,
};

const PING: MethodName = MethodName::from_static("worldid_ping");

/// Parses a fixture in CBOR diagnostic notation.
fn fixture(diagnostic: &str) -> Vec<u8> {
    cbor_diag::parse_diag(diagnostic).unwrap().to_bytes()
}

fn decode_request<P: DeserializeOwned>(diagnostic: &str) -> Result<Request<P>, MessageError> {
    let bytes = fixture(diagnostic);
    Request::decode(&bytes, bytes.len())
}

fn decode_response<R: DeserializeOwned, D: DeserializeOwned>(
    diagnostic: &str,
) -> Result<Response<R, D>, MessageError> {
    let bytes = fixture(diagnostic);
    Response::decode(&bytes, bytes.len())
}

#[test_case(
    Request::new(Some("ping-1".into()), PING, Some(Value::Map(vec![(Value::Text("nonce".into()), Value::Bytes(vec![0, 255]))]))),
    r#"{"version": "1.0", "id": "ping-1", "method": "worldid_ping", "params": {"nonce": h'00ff'}}"#;
    "request with binary payload"
)]
#[test_case(
    Request::new(Some("ping-1".into()), PING, None),
    r#"{"version": "1.0", "id": "ping-1", "method": "worldid_ping"}"#;
    "request without params"
)]
#[test_case(
    Request::new(None, PING, Some(Value::Array(vec![]))),
    r#"{"version": "1.0", "method": "worldid_ping", "params": []}"#;
    "notification"
)]
fn request_wire_example(request: Request<Value>, diagnostic: &str) {
    assert_eq!(request.encode().unwrap(), fixture(diagnostic));
    assert_eq!(decode_request::<Value>(diagnostic).unwrap(), request);
}

#[test_case(
    Response::success("ping-1".into(), Value::Bytes(vec![0, 255])),
    r#"{"version": "1.0", "id": "ping-1", "result": h'00ff'}"#;
    "binary result"
)]
#[test_case(
    Response::success("ping-1".into(), Value::Null),
    r#"{"version": "1.0", "id": "ping-1", "result": null}"#;
    "present null result"
)]
#[test_case(
    Response::error(Some("ping-1".into()), ErrorObject::new("invalid_params", "Invalid params", None)),
    r#"{"version": "1.0", "id": "ping-1", "error": {"code": "invalid_params", "message": "Invalid params"}}"#;
    "correlated error without data"
)]
#[test_case(
    Response::error(None, ErrorObject::new("parse_error", "Invalid message", Some(Value::Null))),
    r#"{"version": "1.0", "id": null, "error": {"code": "parse_error", "message": "Invalid message", "data": null}}"#;
    "uncorrelated error with present null data"
)]
fn response_wire_example(response: Response<Value>, diagnostic: &str) {
    assert_eq!(response.encode().unwrap(), fixture(diagnostic));
    assert_eq!(
        decode_response::<Value, Value>(diagnostic).unwrap(),
        response
    );
}

#[test]
fn ignores_unknown_error_fields() {
    let response = decode_response::<Value, Value>(
        r#"{"version": "1.0", "id": null,
            "error": {"code": "parse_error", "message": "bad", "extra": true}}"#,
    )
    .unwrap();
    assert_eq!(
        response,
        Response::error(None, ErrorObject::new("parse_error", "bad", None))
    );
}

#[test_case(r#"{"version": "1.0", "id": null, "method": "worldid_ping"}"#; "null id")]
#[test_case(r#"{"version": "1.0", "id": 1.0, "method": "worldid_ping"}"#; "float id")]
#[test_case(r#"{"version": "2.0", "id": "ping-1", "method": "worldid_ping"}"#; "unsupported version")]
#[test_case(r#"{"version": "1.0", "id": "ping-1", "method": "worldid_Ping"}"#; "invalid method")]
#[test_case(
    r#"{"version": "1.0", "version": "1.0", "method": "worldid_ping"}"#;
    "duplicate field"
)]
#[test_case(r#"{"version": "1.0", "method": "worldid_ping", "result": null}"#; "result field")]
#[test_case(r#"{"version": "1.0", "method": "worldid_ping", "error": null}"#; "error field")]
#[test_case(r#"{"version": "1.0", "method": "worldid_ping", "extra": null}"#; "unknown field")]
#[test_case(r#"{"version": "1.0", "method": "worldid_ping", "id": "ping-1", "id": "ping-2"}"#; "duplicate id")]
#[test_case(r#"{"version": "1.0", "method": "worldid_ping", "params": null, "params": null}"#; "duplicate params")]
fn rejects_invalid_request(diagnostic: &str) {
    assert!(matches!(
        decode_request::<Value>(diagnostic),
        Err(MessageError::Deserialize(_))
    ));
}

#[test]
fn typed_params_reject_null() {
    let decoded = decode_request::<BTreeMap<String, u64>>(
        r#"{"version": "1.0", "id": "ping-1", "method": "worldid_ping", "params": null}"#,
    );
    assert!(matches!(decoded, Err(MessageError::Deserialize(_))));
}

#[test]
fn nullable_result_is_required_and_preserved() {
    let response = decode_response::<Option<u64>, Value>(
        r#"{"version": "1.0", "id": "ping-1", "result": null}"#,
    )
    .unwrap();
    assert_eq!(response, Response::success("ping-1".into(), None));
    assert!(
        decode_response::<Option<u64>, Value>(r#"{"version": "1.0", "id": "ping-1"}"#).is_err()
    );
}

#[test]
fn nullable_error_data_distinguishes_absent_and_null() {
    let error_data = |data: &str| {
        let response = decode_response::<Value, Option<u64>>(&format!(
            r#"{{"version": "1.0", "id": null, "error": {{"code": "failed", "message": "bad"{data}}}}}"#
        )).unwrap();
        let Response::Error {
            version: Version::V1,
            error,
            ..
        } = response
        else {
            panic!("expected error")
        };
        error.data
    };
    assert_eq!(error_data(""), None);
    assert_eq!(error_data(r#", "data": null"#), Some(None));
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictPayload {
    #[serde(rename = "nonce")]
    _nonce: u64,
}

#[test_case(r#"{"nonce": 1, "extra": true}"#; "unknown field")]
#[test_case(r#"{"nonce": 1, "nonce": 2}"#; "duplicate field")]
#[test_case("null"; "null")]
fn typed_payloads_enforce_their_schema(payload: &str) {
    assert!(
        decode_request::<StrictPayload>(&format!(
            r#"{{"version": "1.0", "method": "worldid_ping", "params": {payload}}}"#
        ))
        .is_err(),
        "request params accepted an invalid payload"
    );
    assert!(
        decode_response::<StrictPayload, Value>(&format!(
            r#"{{"version": "1.0", "id": "ping-1", "result": {payload}}}"#
        ))
        .is_err(),
        "success result accepted an invalid payload"
    );
    let error_message = format!(
        r#"{{"version": "1.0",
            "id": null, "error": {{"code": "failed", "message": "bad", "data": {payload}}}
        }}"#
    );
    assert!(
        decode_response::<Value, StrictPayload>(&error_message).is_err(),
        "error data accepted an invalid payload"
    );
}

#[test_case("null", Value::Null; "null")]
#[test_case("1", 1.into(); "integer")]
#[test_case("\"text\"", "text".into(); "text")]
#[test_case("h'01'", Value::Bytes(vec![1]); "bytes")]
#[test_case("true", true.into(); "boolean")]
#[test_case("1.5", Value::Float(1.5); "float")]
fn request_parameters_are_defined_by_the_method(wire: &str, params: Value) {
    let request = decode_request::<Value>(&format!(
        r#"{{"version": "1.0", "method": "worldid_ping", "params": {wire}}}"#
    ))
    .unwrap();
    assert_eq!(request, Request::new(None, PING, Some(params)));
}

#[test]
fn typed_params_decode_at_the_envelope_boundary() {
    let request = decode_request::<BTreeMap<String, u64>>(
        r#"{"version": "1.0", "method": "worldid_ping", "params": {"nonce": 42}}"#,
    )
    .unwrap();
    assert_eq!(request.params, Some(BTreeMap::from([("nonce".into(), 42)])));
    let request = decode_request::<Vec<u64>>(
        r#"{"version": "1.0", "method": "worldid_ping", "params": [1, 2]}"#,
    )
    .unwrap();
    assert_eq!(request.params, Some(vec![1, 2]));
}

#[test]
fn typed_params_reject_duplicate_schema_fields() {
    #[derive(serde::Deserialize)]
    struct Params {
        #[serde(rename = "nonce")]
        _nonce: u64,
    }

    assert!(matches!(
        decode_request::<Params>(
            r#"{"version": "1.0", "method": "worldid_ping", "params": {"nonce": 1, "nonce": 2}}"#,
        ),
        Err(MessageError::Deserialize(_))
    ));
}

#[test]
fn nullable_params_distinguish_absent_and_null() {
    let absent =
        decode_request::<Option<u64>>(r#"{"version": "1.0", "method": "worldid_ping"}"#).unwrap();
    let present = decode_request::<Option<u64>>(
        r#"{"version": "1.0", "method": "worldid_ping", "params": null}"#,
    )
    .unwrap();
    assert_eq!(absent.params, None);
    assert_eq!(present.params, Some(None));
}

#[test]
fn response_accepts_reordered_and_indefinite_maps() {
    let response =
        decode_response::<Value, Value>(r#"{_ "result": null, "id": "ping-1", "version": "1.0"}"#)
            .unwrap();
    assert_eq!(response, Response::success("ping-1".into(), Value::Null));
}

#[test_case("1"; "positive")]
#[test_case("-1"; "negative")]
#[test_case("18446744073709551615"; "maximum")]
#[test_case("1.0"; "float")]
#[test_case("2(h'01')"; "bignum")]
fn numeric_ids_are_rejected(id: &str) {
    assert!(
        decode_request::<Value>(&format!(
            r#"{{"version": "1.0", "id": {id}, "method": "worldid_ping"}}"#
        ))
        .is_err()
    );
    assert!(
        decode_response::<Value, Value>(&format!(
            r#"{{"version": "1.0", "id": {id}, "result": null}}"#
        ))
        .is_err()
    );
    assert!(
        decode_response::<Value, Value>(&format!(
            r#"{{"version": "1.0", "id": {id}, "error": {{"code": "failed", "message": "bad"}}}}"#
        ))
        .is_err()
    );
}

#[test]
fn typed_codecs_enforce_bounds_and_framing() {
    let request = Request::<Value>::new(None, PING, None).encode().unwrap();
    let response = Response::<Value>::success("ping-1".into(), Value::Null)
        .encode()
        .unwrap();
    assert!(matches!(
        Request::<Value>::decode(&request, request.len() - 1),
        Err(MessageError::TooLarge)
    ));
    assert!(matches!(
        Response::<Value>::decode(&response, response.len() - 1),
        Err(MessageError::TooLarge)
    ));
    let mut request = request;
    request.push(0);
    let mut response = response;
    response.push(0);
    assert!(matches!(
        Request::<Value>::decode(&request, request.len()),
        Err(MessageError::TrailingData)
    ));
    assert!(matches!(
        Response::<Value>::decode(&response, response.len()),
        Err(MessageError::TrailingData)
    ));
    let nested = format!("{}0{}", "[".repeat(34), "]".repeat(34));
    let request = fixture(&format!(
        r#"{{"version": "1.0", "method": "worldid_ping", "params": {nested}}}"#
    ));
    let response = fixture(&format!(
        r#"{{"version": "1.0", "id": "ping-1", "result": {nested}}}"#
    ));
    assert!(matches!(
        Request::<Value>::decode(&request, request.len()),
        Err(MessageError::Deserialize(
            ciborium::de::Error::RecursionLimitExceeded
        ))
    ));
    assert!(matches!(
        Response::<Value>::decode(&response, response.len()),
        Err(MessageError::Deserialize(
            ciborium::de::Error::RecursionLimitExceeded
        ))
    ));
}

#[test_case(r#"{"id": "ping-1", "result": null}"#; "missing version")]
#[test_case(r#"{"version": "2.0", "id": "ping-1", "result": null}"#; "unsupported version")]
#[test_case(r#"{"version": "1.0", "result": null}"#; "missing success id")]
#[test_case(r#"{"version": "1.0", "id": null, "result": null}"#; "null success id")]
#[test_case(r#"{"version": "1.0", "error": {"code": "failed", "message": "bad"}}"#; "missing error id")]
#[test_case(r#"{"version": "1.0", "id": null, "error": null}"#; "null error")]
#[test_case(r#"{"version": "1.0", "id": "ping-1"}"#; "neither result nor error")]
#[test_case(r#"{_ "version": "1.0", "id": "ping-1", "result": null, "error": {"code": "failed", "message": "bad"}}"#; "both result and error")]
#[test_case(r#"{"version": "1.0", "version": "1.0", "id": "ping-1", "result": null}"#; "duplicate version")]
#[test_case(r#"{"version": "1.0", "id": null, "id": "ping-1", "error": {"code": "failed", "message": "bad"}}"#; "duplicate nullable id")]
#[test_case(r#"{_ "version": "1.0", "id": "ping-1", "result": null, "result": null}"#; "duplicate nullable result")]
#[test_case(r#"{_ "version": "1.0", "id": null, "error": {"code": "failed", "message": "bad"}, "error": {"code": "failed", "message": "bad"}}"#; "duplicate error")]
#[test_case(r#"{"version": "1.0", "id": null, "error": {"code": "failed", "code": "failed", "message": "bad"}}"#; "duplicate error code")]
#[test_case(r#"{"version": "1.0", "id": "ping-1", "result": null, "extra": true}"#; "unknown envelope")]
#[test_case(r#"{"version": "1.0", "id": "ping-1", "result": null, "method": "worldid_ping"}"#; "response method")]
#[test_case(r#"{"version": "1.0", "id": "ping-1", "result": null, "params": {}}"#; "response params")]
#[test_case(r#"{h'76657273696f6e': "1.0", "id": "ping-1", "result": null}"#; "byte string version key")]
#[test_case(r#"{"version": "1.0", h'6964': "ping-1", "result": null}"#; "byte string id key")]
#[test_case(r#"{"version": "1.0", "id": "ping-1", h'726573756c74': null}"#; "byte string result key")]
#[test_case(r#"{"version": "1.0", "id": null, h'6572726f72': {"code": "failed", "message": "bad"}}"#; "byte string error key")]
#[test_case(r#"{"version": "1.0", "id": null, "error": {"code": "failed", "message": "bad", "message": "bad"}}"#; "duplicate error message")]
fn rejects_invalid_response(diagnostic: &str) {
    assert!(matches!(
        decode_response::<Value, Value>(diagnostic),
        Err(MessageError::Deserialize(_))
    ));
}

#[test_case(r#"{"version": "1.0", "id": "ping-1", "result": null}"#; "definite success")]
#[test_case(r#"{_ "version": "1.0", "id": "ping-1", "result": null}"#; "indefinite success")]
#[test_case(r#"{"version": "1.0", "id": null, "error": {"code": "failed", "message": "bad"}}"#; "definite error")]
#[test_case(r#"{_ "version": "1.0", "id": null, "error": {_ "code": "failed", "message": "bad"}}"#; "indefinite error")]
fn response_accepts_both_length_encodings(diagnostic: &str) {
    let response = decode_response::<Value, Value>(diagnostic).unwrap();
    assert_eq!(
        Response::<Value>::decode(&response.encode().unwrap(), 1024).unwrap(),
        response
    );
}

#[test_case("0(7)"; "generic tag")]
#[test_case("2(h'07')"; "generic bignum")]
fn generic_payloads_decode_directly(diagnostic: &str) {
    let response = decode_response::<Value, Value>(&format!(
        r#"{{"version": "1.0", "id": "ping-1", "result": {diagnostic}}}"#
    ))
    .unwrap();
    let Response::Success { result, .. } = response else {
        panic!("expected success")
    };
    let expected: Value = ciborium::from_reader(fixture(diagnostic).as_slice()).unwrap();
    assert_eq!(result, expected);
}

#[test]
fn large_byte_string_reaches_payload_as_owned_bytes() {
    struct OwnedBytes(Vec<u8>);

    impl<'de> serde::Deserialize<'de> for OwnedBytes {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct OwnedBytesVisitor;

            impl<'de> serde::de::Visitor<'de> for OwnedBytesVisitor {
                type Value = OwnedBytes;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str("an owned byte string")
                }

                fn visit_byte_buf<E: serde::de::Error>(
                    self,
                    bytes: Vec<u8>,
                ) -> Result<Self::Value, E> {
                    Ok(OwnedBytes(bytes))
                }
            }

            deserializer.deserialize_any(OwnedBytesVisitor)
        }
    }

    let bytes = vec![7; 8192];
    let response = Response::<Value>::success("ping-1".into(), Value::Bytes(bytes.clone()));
    let encoded = response.encode().unwrap();
    let decoded = Response::<OwnedBytes>::decode(&encoded, encoded.len()).unwrap();
    let Response::Success { result, .. } = decoded else {
        panic!("expected success");
    };
    assert_eq!(result.0, bytes);
}
