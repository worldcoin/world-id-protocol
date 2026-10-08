//! Wire examples in CBOR diagnostic notation. Fixtures follow the structs' field order;
//! receivers accept other map orders as well.

use test_case::test_case;
use world_id_primitives::authenticator_message::{
    ErrorObject, Id, MethodName, Request, Response, Value, Version, cbor,
};

#[test_case(
    Some(Id::Number(1)), Some(Value::Map(vec![(Value::Text("nonce".into()), Value::Bytes(vec![0, 255]))])),
    r#"{"version": "1.0", "id": 1, "method": "worldid_ping", "params": {"nonce": h'00ff'}}"#;
    "request with binary payload"
)]
#[test_case(
    Some(Id::String("ping-1".into())), None,
    r#"{"version": "1.0", "id": "ping-1", "method": "worldid_ping"}"#;
    "request without params"
)]
#[test_case(
    None, Some(Value::Array(vec![])),
    r#"{"version": "1.0", "method": "worldid_ping", "params": []}"#;
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
    r#"{"version": "1.0", "id": 1, "result": h'00ff'}"#;
    "binary result"
)]
#[test_case(
    Ok(Value::Null), Some(Id::String("ping-1".into())),
    r#"{"version": "1.0", "id": "ping-1", "result": null}"#;
    "present null result"
)]
#[test_case(
    Err(ErrorObject { code: "invalid_params".into(), message: "Invalid params".into(), data: None }),
    Some(Id::Number(1)),
    r#"{"version": "1.0", "id": 1, "error": {"code": "invalid_params", "message": "Invalid params"}}"#;
    "correlated error without data"
)]
#[test_case(
    Err(ErrorObject { code: "parse_error".into(), message: "Invalid message".into(), data: Some(Value::Null) }),
    None,
    r#"{"version": "1.0", "id": null, "error": {"code": "parse_error", "message": "Invalid message", "data": null}}"#;
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

#[test]
fn decodes_request_with_indefinite_containers() {
    let bytes = cbor_diag::parse_diag(
        r#"{_ "version": "1.0", "id": 1, "method": "worldid_ping",
             "params": {_ "nonce": (_ h'00', h'ff'), "items": [_ 1, 2]}}"#,
    )
    .unwrap()
    .to_bytes();
    let expected = Request::new(
        Some(Id::Number(1)),
        MethodName::from_static("worldid_ping"),
        Value::Map(vec![
            (Value::Text("nonce".into()), Value::Bytes(vec![0, 255])),
            (
                Value::Text("items".into()),
                Value::Array(vec![1.into(), 2.into()]),
            ),
        ]),
    );
    assert_eq!(
        cbor::decode::<Request<Value>>(&bytes, bytes.len()).unwrap(),
        expected
    );
}

#[test]
fn decodes_response_with_indefinite_text() {
    let bytes =
        cbor_diag::parse_diag(r#"{_ "version": "1.0", "id": 1, "result": (_ "hel", "lo")}"#)
            .unwrap()
            .to_bytes();
    let expected: Response<Value> = Response {
        version: Version::V1,
        id: Some(Id::Number(1)),
        outcome: Ok(Value::Text("hello".into())),
    };
    assert_eq!(
        cbor::decode::<Response<Value>>(&bytes, bytes.len()).unwrap(),
        expected
    );
}
