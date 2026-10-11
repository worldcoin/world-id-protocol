//! Wire examples in CBOR diagnostic notation. Fixtures follow the structs' field order;
//! receivers accept other map orders as well.

use test_case::test_case;
use world_id_primitives::authenticator_message::{
    ErrorObject, Id, MethodName, Request, Response, Value, Version, cbor,
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
    ping().params(Value::Array(vec![])).build(),
    r#"{"version": "1.0", "method": "worldid_ping", "params": []}"#;
    "notification"
)]
fn request_wire_example(request: Request<Value>, diagnostic: &str) {
    let expected = cbor_diag::parse_diag(diagnostic).unwrap().to_bytes();
    assert_eq!(cbor::encode(&request).unwrap(), expected);
    assert_eq!(
        cbor::decode::<Request<Value>>(&expected, expected.len()).unwrap(),
        request
    );
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
    let expected = cbor_diag::parse_diag(diagnostic).unwrap().to_bytes();
    assert_eq!(cbor::encode(&response).unwrap(), expected);
    assert_eq!(
        cbor::decode::<Response<Value>>(&expected, expected.len()).unwrap(),
        response
    );
}
