//! Authenticator message encoding tests, with fixtures in CBOR diagnostic notation. Valid
//! fixtures follow the structs' field order; receivers accept other map orders as well.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use test_case::test_case;
use world_id_primitives::authenticator_message::{
    ErrorObject, Id, MessageError, MethodName, Outcome, Request, Response, Value, cbor,
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
    Outcome::Success { id: Id::Number(1), result: Value::Bytes(vec![0, 255]) },
    r#"{"version": "1.0", "outcome": {"success": {"id": 1, "result": h'00ff'}}}"#;
    "binary result"
)]
#[test_case(
    Outcome::Success { id: Id::String("ping-1".into()), result: Value::Null },
    r#"{"version": "1.0", "outcome": {"success": {"id": "ping-1", "result": null}}}"#;
    "present null result"
)]
#[test_case(
    Outcome::Error { id: Some(Id::Number(1)), error: ErrorObject::builder().code("invalid_params").message("Invalid params").build() },
    r#"{"version": "1.0", "outcome": {"error": {"id": 1, "error": {"code": "invalid_params", "message": "Invalid params"}}}}"#;
    "correlated error without data"
)]
#[test_case(
    Outcome::Error { id: None, error: ErrorObject::builder().code("parse_error").message("Invalid message").data(Value::Null).build() },
    r#"{"version": "1.0", "outcome": {"error": {"id": null, "error": {"code": "parse_error", "message": "Invalid message", "data": null}}}}"#;
    "uncorrelated error with present null data"
)]
fn response_wire_example(outcome: Outcome<Value>, diagnostic: &str) {
    let response = Response::builder().outcome(outcome).build();
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
fn ignores_unknown_error_fields() {
    let response = decode::<Response<Value>>(
        r#"{"version": "1.0", "outcome": {"error": {"id": null,
            "error": {"code": "parse_error", "message": "bad", "extra": true}}}}"#,
    )
    .unwrap();
    assert_eq!(
        response.outcome,
        Outcome::Error {
            id: None,
            error: ErrorObject::builder()
                .code("parse_error")
                .message("bad")
                .build(),
        }
    );
}

#[test_case(r#"{"version": "1.0", "id": null, "method": "worldid_ping"}"#; "null id")]
#[test_case(r#"{"version": "1.0", "id": 1.0, "method": "worldid_ping"}"#; "float id")]
#[test_case(r#"{"version": "2.0", "id": 1, "method": "worldid_ping"}"#; "unsupported version")]
#[test_case(r#"{"version": "1.0", "id": 1, "method": "worldid_Ping"}"#; "invalid method")]
#[test_case(
    r#"{"version": "1.0", "version": "1.0", "method": "worldid_ping"}"#;
    "duplicate field"
)]
#[test_case(r#"{"version": "1.0", "method": "worldid_ping", "result": null}"#; "result field")]
#[test_case(r#"{"version": "1.0", "method": "worldid_ping", "error": null}"#; "error field")]
#[test_case(r#"{"version": "1.0", "method": "worldid_ping", "extra": null}"#; "unknown field")]
#[test_case(r#"{"version": "1.0", "method": "worldid_ping", "id": 1, "id": 2}"#; "duplicate id")]
#[test_case(r#"{"version": "1.0", "method": "worldid_ping", "params": null, "params": null}"#; "duplicate params")]
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

#[test_case(r#"{"version": "1.0"}"#; "missing outcome")]
#[test_case(r#"{"version": "1.0", "outcome": {}}"#; "empty outcome")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"result": null}}}"#; "missing success id")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": null, "result": null}}}"#; "null success id")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": 1}}}"#; "missing result")]
#[test_case(r#"{"version": "1.0", "outcome": {"error": {"error": {"code": "failed", "message": "bad"}}}}"#; "missing error id")]
#[test_case(r#"{"version": "1.0", "outcome": {"error": {"id": null}}}"#; "missing error payload")]
#[test_case(r#"{"version": "1.0", "outcome": {"error": {"id": null, "error": null}}}"#; "null error payload")]
#[test_case(r#"{"version": "1.0", "outcome": {"other": null}}"#; "unknown outcome")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": 1, "result": null}, "error": {"id": null, "error": {"code": "failed", "message": "bad"}}}}"#; "both outcomes")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": 1, "result": null}, "success": {"id": 1, "result": null}}}"#; "duplicate variant")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": 1, "result": null}}, "outcome": {"success": {"id": 1, "result": null}}}"#; "duplicate outcome")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": 1, "id": 2, "result": null}}}"#; "duplicate success id")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": 1, "result": null, "result": null}}}"#; "duplicate result")]
#[test_case(r#"{"version": "1.0", "outcome": {"error": {"id": null, "id": 1, "error": {"code": "failed", "message": "bad"}}}}"#; "duplicate error id")]
#[test_case(r#"{"version": "1.0", "outcome": {"error": {"id": null, "error": {}, "error": {}}}}"#; "duplicate error payload")]
#[test_case(r#"{"version": "1.0", "outcome": {"error": {"id": null, "error": {"code": "failed", "code": "failed", "message": "bad"}}}}"#; "duplicate error code")]
#[test_case(r#"{"version": "1.0", "extra": true, "outcome": {"success": {"id": 1, "result": null}}}"#; "unknown envelope")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": 1, "result": null, "extra": true}}}"#; "unknown success field")]
#[test_case(r#"{"version": "1.0", "outcome": {"error": {"id": null, "error": {"code": "failed", "message": "bad"}, "extra": true}}}"#; "unknown error field")]
#[test_case(r#"{"version": "1.0", "id": 1, "outcome": {"success": {"id": 1, "result": null}}}"#; "legacy top level id")]
#[test_case(r#"{"version": "1.0", "outcome": {_ "success": {"id": 1, "result": null}}}"#; "indefinite outcome wrapper")]
#[test_case(r#"{"version": "2.0", "outcome": {"success": {"id": 1, "result": null}}}"#; "unsupported response version")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": 1, "result": null}}, "method": "worldid_ping"}"#; "response method")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": 1, "result": null}}, "params": {}}"#; "response params")]
fn rejects_invalid_response(diagnostic: &str) {
    assert!(matches!(
        decode::<Response<Value>>(diagnostic),
        Err(MessageError::Deserialize(_))
    ));
}

#[test]
fn nullable_result_is_required_and_preserved() {
    let response = decode::<Response<Option<u64>>>(
        r#"{"version": "1.0", "outcome": {"success": {"id": 1, "result": null}}}"#,
    )
    .unwrap();
    assert_eq!(
        response.outcome,
        Outcome::Success {
            id: Id::Number(1),
            result: None
        }
    );
    assert!(
        decode::<Response<Option<u64>>>(r#"{"version": "1.0", "outcome": {"success": {"id": 1}}}"#)
            .is_err()
    );
}

#[test]
fn nullable_error_data_distinguishes_absent_and_null() {
    let absent =
        decode::<ErrorObject<Option<u64>>>(r#"{"code": "failed", "message": "bad"}"#).unwrap();
    let present =
        decode::<ErrorObject<Option<u64>>>(r#"{"code": "failed", "message": "bad", "data": null}"#)
            .unwrap();
    assert_eq!(absent.data, None);
    assert_eq!(present.data, Some(None));
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
        decode::<Request<StrictPayload>>(&format!(
            r#"{{"version": "1.0", "method": "worldid_ping", "params": {payload}}}"#
        ))
        .is_err()
    );
    assert!(
        decode::<Response<StrictPayload>>(&format!(
            r#"{{"version": "1.0", "outcome": {{"success": {{"id": 1, "result": {payload}}}}}}}"#
        ))
        .is_err()
    );
    assert!(decode::<Response<Value, StrictPayload>>(&format!(r#"{{"version": "1.0", "outcome": {{"error": {{"id": null, "error": {{"code": "failed", "message": "bad", "data": {payload}}}}}}}}}"#)).is_err());
}

#[test_case("null", Value::Null; "null")]
#[test_case("1", 1.into(); "integer")]
#[test_case("\"text\"", "text".into(); "text")]
#[test_case("h'01'", Value::Bytes(vec![1]); "bytes")]
#[test_case("true", true.into(); "boolean")]
#[test_case("1.5", Value::Float(1.5); "float")]
fn request_parameters_are_defined_by_the_method(wire: &str, params: Value) {
    let request = decode::<Request<Value>>(&format!(
        r#"{{"version": "1.0", "method": "worldid_ping", "params": {wire}}}"#
    ))
    .unwrap();
    assert_eq!(
        request,
        Request::builder().method(PING).params(params).build()
    );
}

#[test]
fn typed_params_decode_at_the_envelope_boundary() {
    let request = decode::<Request<BTreeMap<String, u64>>>(
        r#"{"version": "1.0", "method": "worldid_ping", "params": {"nonce": 42}}"#,
    )
    .unwrap();
    assert_eq!(request.params, Some(BTreeMap::from([("nonce".into(), 42)])));
    let request = decode::<Request<Vec<u64>>>(
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
        decode::<Request<Params>>(
            r#"{"version": "1.0", "method": "worldid_ping", "params": {"nonce": 1, "nonce": 2}}"#,
        ),
        Err(MessageError::Deserialize(_))
    ));
}

#[test]
fn nullable_params_distinguish_absent_and_null() {
    let absent =
        decode::<Request<Option<u64>>>(r#"{"version": "1.0", "method": "worldid_ping"}"#).unwrap();
    let present = decode::<Request<Option<u64>>>(
        r#"{"version": "1.0", "method": "worldid_ping", "params": null}"#,
    )
    .unwrap();
    assert_eq!(absent.params, None);
    assert_eq!(present.params, Some(None));
}

#[test]
fn response_accepts_reordered_and_indefinite_maps_outside_the_outcome_wrapper() {
    let response = decode::<Response<Value>>(
        r#"{_ "outcome": {"success": {_ "result": null, "id": 1}}, "version": "1.0"}"#,
    )
    .unwrap();
    assert_eq!(
        response.outcome,
        Outcome::Success {
            id: Id::Number(1),
            result: Value::Null
        }
    );
}
