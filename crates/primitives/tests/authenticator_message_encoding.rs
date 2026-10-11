//! Authenticator message encoding tests, with fixtures in CBOR diagnostic notation. Valid
//! fixtures follow the structs' field order; receivers accept other map orders as well.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use test_case::test_case;
use world_id_primitives::authenticator_message::{
    ErrorObject, Id, MessageError, MethodName, Request, Response, Value, cbor,
};

const PING: MethodName = MethodName::from_static("worldid_ping");

/// Parses a fixture in CBOR diagnostic notation.
fn fixture(diagnostic: &str) -> Vec<u8> {
    cbor_diag::parse_diag(diagnostic).unwrap().to_bytes()
}

/// Decodes a fixture in CBOR diagnostic notation.
fn decode<T: DeserializeOwned>(diagnostic: &str) -> Result<T, MessageError> {
    let bytes = fixture(diagnostic);
    cbor::decode(&bytes, bytes.len())
}

#[test_case(
    Request::builder()
        .id(1)
        .method(PING)
        .params(Value::Map(vec![(Value::Text("nonce".into()), Value::Bytes(vec![0, 255]))]))
        .build(),
    r#"{"version": "1.0", "id": 1, "method": "worldid_ping", "params": {"nonce": h'00ff'}}"#;
    "request with binary payload"
)]
#[test_case(
    Request::builder().id("ping-1".to_owned()).method(PING).build(),
    r#"{"version": "1.0", "id": "ping-1", "method": "worldid_ping"}"#;
    "request without params"
)]
#[test_case(
    Request::builder().id(1).method(PING).params(Value::Null).build(),
    r#"{"version": "1.0", "id": 1, "method": "worldid_ping", "params": null}"#;
    "request with present null params"
)]
#[test_case(
    Request::builder().method(PING).params(Value::Array(vec![])).build(),
    r#"{"version": "1.0", "method": "worldid_ping", "params": []}"#;
    "notification"
)]
#[test_case(
    Request::builder().id(Id::Number(u64::MAX.into())).method(PING).build(),
    r#"{"version": "1.0", "id": 18446744073709551615, "method": "worldid_ping"}"#;
    "maximum integer id"
)]
#[test_case(
    Request::builder().id(Id::Number(-1 - i128::from(u64::MAX))).method(PING).build(),
    r#"{"version": "1.0", "id": -18446744073709551616, "method": "worldid_ping"}"#;
    "minimum integer id"
)]
fn request_wire_example(request: Request<Value>, diagnostic: &str) {
    assert_eq!(cbor::encode(&request).unwrap(), fixture(diagnostic));
    assert_eq!(decode::<Request<Value>>(diagnostic).unwrap(), request);
}

#[test_case(
    Response::builder().id(1).outcome(Ok(Value::Bytes(vec![0, 255]))).build(),
    r#"{"version": "1.0", "id": 1, "result": h'00ff'}"#;
    "binary result"
)]
#[test_case(
    Response::builder().id("ping-1".to_owned()).outcome(Ok(Value::Null)).build(),
    r#"{"version": "1.0", "id": "ping-1", "result": null}"#;
    "present null result"
)]
#[test_case(
    Response::builder()
        .id(1)
        .outcome(Err(ErrorObject::builder()
            .code("invalid_params")
            .message("Invalid params")
            .build()))
        .build(),
    r#"{"version": "1.0", "id": 1, "error": {"code": "invalid_params", "message": "Invalid params"}}"#;
    "correlated error without data"
)]
#[test_case(
    Response::builder()
        .outcome(Err(ErrorObject::builder()
            .code("parse_error")
            .message("Invalid message")
            .data(Value::Null)
            .build()))
        .build(),
    r#"{"version": "1.0", "id": null, "error": {"code": "parse_error", "message": "Invalid message", "data": null}}"#;
    "uncorrelated error with present null data"
)]
fn response_wire_example(response: Response<Value>, diagnostic: &str) {
    assert_eq!(cbor::encode(&response).unwrap(), fixture(diagnostic));
    assert_eq!(decode::<Response<Value>>(diagnostic).unwrap(), response);
}

#[test_case(i128::from(u64::MAX) + 1; "above maximum")]
#[test_case(-2 - i128::from(u64::MAX); "below minimum")]
fn integer_ids_outside_the_cbor_range_fail_to_encode(number: i128) {
    let request = Request::<Value>::builder()
        .id(Id::Number(number))
        .method(PING)
        .build();
    assert!(cbor::encode(&request).is_err());
}

#[test]
fn success_without_id_fails_to_encode() {
    let response = Response::<Value>::builder()
        .outcome(Ok(Value::Null))
        .build();
    assert!(cbor::encode(&response).is_err());
}

#[test]
fn ignores_unknown_envelope_and_error_fields() {
    let decoded = decode::<Response<Value>>(
        r#"{"version": "1.0", "id": null, "extra": h'01',
            "error": {"code": "parse_error", "message": "bad", "extra": true}}"#,
    );
    assert_eq!(
        decoded.unwrap(),
        Response::builder()
            .outcome(Err(ErrorObject::builder()
                .code("parse_error")
                .message("bad")
                .build()))
            .build()
    );
}

#[test_case(r#"{"version": "1.0", "id": null, "method": "worldid_ping"}"#; "null id")]
#[test_case(r#"{"version": "1.0", "id": 1.0, "method": "worldid_ping"}"#; "float id")]
#[test_case(r#"{"version": "2.0", "id": 1, "method": "worldid_ping"}"#; "unsupported version")]
#[test_case(
    r#"{"version": "1.0", "version": "1.0", "method": "worldid_ping"}"#;
    "duplicate field"
)]
fn rejects_invalid_request(diagnostic: &str) {
    assert!(matches!(
        decode::<Request<Value>>(diagnostic),
        Err(MessageError::Deserialize(_))
    ));
}

#[test]
fn typed_params_reject_null() {
    let decoded = decode::<Request<BTreeMap<String, u64>>>(
        r#"{"version": "1.0", "id": 1, "method": "worldid_ping", "params": null}"#,
    );
    assert!(matches!(decoded, Err(MessageError::Deserialize(_))));
}

#[test_case(r#"{"version": "1.0", "id": 1}"#; "missing outcome")]
#[test_case(r#"{"version": "1.0", "result": null}"#; "missing id")]
#[test_case(r#"{"version": "1.0", "id": null, "result": null}"#; "success with null id")]
#[test_case(
    r#"{"version": "1.0", "id": 1, "result": null,
        "error": {"code": "failed", "message": "failed"}}"#;
    "both outcomes"
)]
fn rejects_invalid_response(diagnostic: &str) {
    assert!(matches!(
        decode::<Response<Value>>(diagnostic),
        Err(MessageError::Deserialize(_))
    ));
}
