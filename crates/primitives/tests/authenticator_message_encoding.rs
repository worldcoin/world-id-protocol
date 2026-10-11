//! Authenticator message encoding tests, with fixtures in CBOR diagnostic notation. Valid
//! fixtures follow the structs' field order; receivers accept other map orders as well.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use test_case::test_case;
use world_id_primitives::authenticator_message::{
    ErrorObject, Id, MessageError, MethodName, Request, Response, Value, Version, cbor,
};

/// A `worldid_ping` request. Unset fields are absent on the wire.
#[bon::builder(finish_fn = build)]
fn ping(#[builder(into)] id: Option<Id>, params: Option<Value>) -> Request<Value> {
    Request {
        version: Version::V1,
        id,
        method: MethodName::from_static("worldid_ping"),
        params,
    }
}

/// A response with `outcome`. An unset ID is encoded as null.
#[bon::builder(finish_fn = build)]
fn response(
    #[builder(start_fn)] outcome: Result<Value, ErrorObject>,
    #[builder(into)] id: Option<Id>,
) -> Response<Value> {
    Response {
        version: Version::V1,
        id,
        outcome,
    }
}

#[bon::builder(finish_fn = build)]
fn error(
    #[builder(start_fn, into)] code: String,
    #[builder(start_fn, into)] message: String,
    data: Option<Value>,
) -> ErrorObject {
    ErrorObject {
        code,
        message,
        data,
    }
}

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
    ping()
        .id(1)
        .params(Value::Map(vec![(Value::Text("nonce".into()), Value::Bytes(vec![0, 255]))]))
        .build(),
    r#"{"version": "1.0", "id": 1, "method": "worldid_ping", "params": {"nonce": h'00ff'}}"#;
    "request with binary payload"
)]
#[test_case(
    ping().id("ping-1".to_owned()).build(),
    r#"{"version": "1.0", "id": "ping-1", "method": "worldid_ping"}"#;
    "request without params"
)]
#[test_case(
    ping().id(1).params(Value::Null).build(),
    r#"{"version": "1.0", "id": 1, "method": "worldid_ping", "params": null}"#;
    "request with present null params"
)]
#[test_case(
    ping().params(Value::Array(vec![])).build(),
    r#"{"version": "1.0", "method": "worldid_ping", "params": []}"#;
    "notification"
)]
#[test_case(
    ping().id(Id::Number(u64::MAX.into())).build(),
    r#"{"version": "1.0", "id": 18446744073709551615, "method": "worldid_ping"}"#;
    "maximum integer id"
)]
#[test_case(
    ping().id(Id::Number(-1 - i128::from(u64::MAX))).build(),
    r#"{"version": "1.0", "id": -18446744073709551616, "method": "worldid_ping"}"#;
    "minimum integer id"
)]
fn request_wire_example(request: Request<Value>, diagnostic: &str) {
    assert_eq!(cbor::encode(&request).unwrap(), fixture(diagnostic));
    assert_eq!(decode::<Request<Value>>(diagnostic).unwrap(), request);
}

#[test_case(
    response(Ok(Value::Bytes(vec![0, 255]))).id(1).build(),
    r#"{"version": "1.0", "id": 1, "result": h'00ff'}"#;
    "binary result"
)]
#[test_case(
    response(Ok(Value::Null)).id("ping-1".to_owned()).build(),
    r#"{"version": "1.0", "id": "ping-1", "result": null}"#;
    "present null result"
)]
#[test_case(
    response(Err(error("invalid_params", "Invalid params").build())).id(1).build(),
    r#"{"version": "1.0", "id": 1, "error": {"code": "invalid_params", "message": "Invalid params"}}"#;
    "correlated error without data"
)]
#[test_case(
    response(Err(error("parse_error", "Invalid message").data(Value::Null).build())).build(),
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
    assert!(cbor::encode(&ping().id(Id::Number(number)).build()).is_err());
}

#[test]
fn success_without_id_fails_to_encode() {
    assert!(cbor::encode(&response(Ok(Value::Null)).build()).is_err());
}

#[test]
fn ignores_unknown_envelope_and_error_fields() {
    let decoded = decode::<Response<Value>>(
        r#"{"version": "1.0", "id": null, "extra": h'01',
            "error": {"code": "parse_error", "message": "bad", "extra": true}}"#,
    );
    assert_eq!(
        decoded.unwrap(),
        response(Err(error("parse_error", "bad").build())).build()
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
