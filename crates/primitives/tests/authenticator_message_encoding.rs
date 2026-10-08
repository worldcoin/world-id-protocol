//! Wire examples in CBOR diagnostic notation. Map entries are written in their
//! expected deterministic order so these fixtures also check exact output bytes.

use test_case::test_case;
use world_id_primitives::authenticator_message::{
    ErrorObject, Id, MethodName, Request, Response, Value, Version, cbor,
};

#[test_case(
    Some(Id::Number(1)), Some(Value::Map(vec![(Value::Text("nonce".into()), Value::Bytes(vec![0, 255]))])),
    r#"{"id": 1, "method": "worldid_ping", "params": {"nonce": h'00ff'}, "version": "1.0"}"#;
    "request with binary payload"
)]
#[test_case(
    Some(Id::String("ping-1".into())), None,
    r#"{"id": "ping-1", "method": "worldid_ping", "version": "1.0"}"#;
    "request without params"
)]
#[test_case(
    None, Some(Value::Array(vec![])),
    r#"{"method": "worldid_ping", "params": [], "version": "1.0"}"#;
    "notification"
)]
fn request_wire_example(id: Option<Id>, params: Option<Value>, diagnostic: &str) {
    let request = Request {
        version: Version::V1,
        id,
        method: MethodName::from_static("worldid_ping"),
        params,
    };
    let expected = cbor_diag::parse_diag(diagnostic).unwrap().to_bytes();
    assert_eq!(cbor::encode(&request).unwrap(), expected);
    assert_eq!(
        cbor::decode::<Request<Value>>(&expected, expected.len()).unwrap(),
        request
    );
}

#[test_case(
    Ok(Value::Bytes(vec![0, 255])), Some(Id::Number(1)),
    r#"{"id": 1, "result": h'00ff', "version": "1.0"}"#;
    "binary result"
)]
#[test_case(
    Ok(Value::Null), Some(Id::String("ping-1".into())),
    r#"{"id": "ping-1", "result": null, "version": "1.0"}"#;
    "present null result"
)]
#[test_case(
    Err(ErrorObject { code: "invalid_params".into(), message: "Invalid params".into(), data: None }),
    Some(Id::Number(1)),
    r#"{"id": 1, "error": {"code": "invalid_params", "message": "Invalid params"}, "version": "1.0"}"#;
    "correlated error without data"
)]
#[test_case(
    Err(ErrorObject { code: "parse_error".into(), message: "Invalid message".into(), data: Some(Value::Null) }),
    None,
    r#"{"id": null, "error": {"code": "parse_error", "data": null, "message": "Invalid message"}, "version": "1.0"}"#;
    "uncorrelated error with present null data"
)]
fn response_wire_example(outcome: Result<Value, ErrorObject>, id: Option<Id>, diagnostic: &str) {
    let response = Response {
        version: Version::V1,
        id,
        outcome,
    };
    let expected = cbor_diag::parse_diag(diagnostic).unwrap().to_bytes();
    assert_eq!(cbor::encode(&response).unwrap(), expected);
    assert_eq!(
        cbor::decode::<Response<Value>>(&expected, expected.len()).unwrap(),
        response
    );
}
