//! Authenticator message encoding tests, with fixtures in CBOR diagnostic notation. Valid
//! fixtures follow the structs' field order; receivers accept other map orders as well.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use test_case::test_case;
use world_id_primitives::authenticator_message::{
    ErrorObject, MessageError, MethodName, Outcome, Request, Response, Value,
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
    Outcome::Success { id: "ping-1".into(), result: Value::Bytes(vec![0, 255]) },
    r#"{"version": "1.0", "outcome": {"success": {"id": "ping-1", "result": h'00ff'}}}"#;
    "binary result"
)]
#[test_case(
    Outcome::Success { id: "ping-1".into(), result: Value::Null },
    r#"{"version": "1.0", "outcome": {"success": {"id": "ping-1", "result": null}}}"#;
    "present null result"
)]
#[test_case(
    Outcome::Error { id: Some("ping-1".into()), error: ErrorObject::new("invalid_params", "Invalid params", None) },
    r#"{"version": "1.0", "outcome": {"error": {"id": "ping-1", "error": {"code": "invalid_params", "message": "Invalid params"}}}}"#;
    "correlated error without data"
)]
#[test_case(
    Outcome::Error { id: None, error: ErrorObject::new("parse_error", "Invalid message", Some(Value::Null)) },
    r#"{"version": "1.0", "outcome": {"error": {"id": null, "error": {"code": "parse_error", "message": "Invalid message", "data": null}}}}"#;
    "uncorrelated error with present null data"
)]
fn response_wire_example(outcome: Outcome<Value>, diagnostic: &str) {
    let response = Response::new(outcome);
    assert_eq!(response.encode().unwrap(), fixture(diagnostic));
    assert_eq!(
        decode_response::<Value, Value>(diagnostic).unwrap(),
        response
    );
}

#[test]
fn ignores_unknown_error_fields() {
    let response = decode_response::<Value, Value>(
        r#"{"version": "1.0", "outcome": {"error": {"id": null,
            "error": {"code": "parse_error", "message": "bad", "extra": true}}}}"#,
    )
    .unwrap();
    assert_eq!(
        response.outcome,
        Outcome::Error {
            id: None,
            error: ErrorObject::new("parse_error", "bad", None),
        }
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

#[test_case(r#"{"version": "1.0"}"#; "missing outcome")]
#[test_case(r#"{"version": "1.0", "outcome": {}}"#; "empty outcome")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"result": null}}}"#; "missing success id")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": null, "result": null}}}"#; "null success id")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": "ping-1"}}}"#; "missing result")]
#[test_case(r#"{"version": "1.0", "outcome": {"error": {"error": {"code": "failed", "message": "bad"}}}}"#; "missing error id")]
#[test_case(r#"{"version": "1.0", "outcome": {"error": {"id": null}}}"#; "missing error payload")]
#[test_case(r#"{"version": "1.0", "outcome": {"error": {"id": null, "error": null}}}"#; "null error payload")]
#[test_case(r#"{"version": "1.0", "outcome": {"other": null}}"#; "unknown outcome")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": "ping-1", "result": null}, "error": {"id": null, "error": {"code": "failed", "message": "bad"}}}}"#; "both outcomes")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": "ping-1", "result": null}, "success": {"id": "ping-1", "result": null}}}"#; "duplicate variant")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": "ping-1", "result": null}}, "outcome": {"success": {"id": "ping-1", "result": null}}}"#; "duplicate outcome")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": "ping-1", "id": "ping-2", "result": null}}}"#; "duplicate success id")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": "ping-1", "result": null, "result": null}}}"#; "duplicate result")]
#[test_case(r#"{"version": "1.0", "outcome": {"error": {"id": null, "id": "ping-1", "error": {"code": "failed", "message": "bad"}}}}"#; "duplicate error id")]
#[test_case(r#"{"version": "1.0", "outcome": {"error": {"id": null, "error": {}, "error": {}}}}"#; "duplicate error payload")]
#[test_case(r#"{"version": "1.0", "outcome": {"error": {"id": null, "error": {"code": "failed", "code": "failed", "message": "bad"}}}}"#; "duplicate error code")]
#[test_case(r#"{"version": "1.0", "extra": true, "outcome": {"success": {"id": "ping-1", "result": null}}}"#; "unknown envelope")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": "ping-1", "result": null, "extra": true}}}"#; "unknown success field")]
#[test_case(r#"{"version": "1.0", "outcome": {"error": {"id": null, "error": {"code": "failed", "message": "bad"}, "extra": true}}}"#; "unknown error field")]
#[test_case(r#"{"version": "1.0", "id": "ping-1", "outcome": {"success": {"id": "ping-1", "result": null}}}"#; "legacy top level id")]
#[test_case(r#"{"version": "2.0", "outcome": {"success": {"id": "ping-1", "result": null}}}"#; "unsupported response version")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": "ping-1", "result": null}}, "method": "worldid_ping"}"#; "response method")]
#[test_case(r#"{"version": "1.0", "outcome": {"success": {"id": "ping-1", "result": null}}, "params": {}}"#; "response params")]
fn rejects_invalid_response(diagnostic: &str) {
    assert!(matches!(
        decode_response::<Value, Value>(diagnostic),
        Err(MessageError::Deserialize(_))
    ));
}

#[test_case(r#"{"success": ["ping-1", null]}"#; "success")]
#[test_case(r#"{"error": [null, {"code": "failed", "message": "bad"}]}"#; "error")]
fn rejects_outcome_with_positional_body(outcome: &str) {
    assert!(
        decode_response::<Value, Value>(&format!(r#"{{"version": "1.0", "outcome": {outcome}}}"#))
            .is_err()
    );
}

#[test_case("success", r#"{"id": "ping-1", "result": null}"#; "success")]
#[test_case("error", r#"{"id": null, "error": {"code": "failed", "message": "bad"}}"#; "error")]
fn rejects_outcome_body_in_a_second_cbor_item(variant: &str, body: &str) {
    let mut bytes = fixture(&format!(r#"{{"version": "1.0", "outcome": "{variant}"}}"#));
    bytes.extend(fixture(body));
    assert!(Response::<Value>::decode(&bytes, bytes.len()).is_err());
}

#[test]
fn nullable_result_is_required_and_preserved() {
    let response = decode_response::<Option<u64>, Value>(
        r#"{"version": "1.0", "outcome": {"success": {"id": "ping-1", "result": null}}}"#,
    )
    .unwrap();
    assert_eq!(
        response.outcome,
        Outcome::Success {
            id: "ping-1".into(),
            result: None
        }
    );
    assert!(
        decode_response::<Option<u64>, Value>(
            r#"{"version": "1.0", "outcome": {"success": {"id": "ping-1"}}}"#
        )
        .is_err()
    );
}

#[test]
fn nullable_error_data_distinguishes_absent_and_null() {
    let error_data = |data: &str| {
        let response = decode_response::<Value, Option<u64>>(&format!(
            r#"{{"version": "1.0", "outcome": {{"error": {{"id": null, "error": {{"code": "failed", "message": "bad"{data}}}}}}}}}"#
        )).unwrap();
        let Outcome::Error { error, .. } = response.outcome else {
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
            r#"{{"version": "1.0", "outcome": {{"success": {{"id": "ping-1", "result": {payload}}}}}}}"#
        ))
        .is_err(),
        "success result accepted an invalid payload"
    );
    let error_message = format!(
        r#"{{"version": "1.0", "outcome": {{"error": {{
            "id": null, "error": {{"code": "failed", "message": "bad", "data": {payload}}}
        }}}}}}"#
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
    let response = decode_response::<Value, Value>(
        r#"{_ "outcome": {"success": {_ "result": null, "id": "ping-1"}}, "version": "1.0"}"#,
    )
    .unwrap();
    assert_eq!(
        response.outcome,
        Outcome::Success {
            id: "ping-1".into(),
            result: Value::Null
        }
    );
}

#[test_case("1"; "positive")]
#[test_case("-1"; "negative")]
#[test_case("18446744073709551615"; "maximum")]
fn numeric_ids_are_rejected(id: &str) {
    assert!(
        decode_request::<Value>(&format!(
            r#"{{"version": "1.0", "id": {id}, "method": "worldid_ping"}}"#
        ))
        .is_err()
    );
    assert!(
        decode_response::<Value, Value>(&format!(
            r#"{{"version": "1.0", "outcome": {{"success": {{"id": {id}, "result": null}}}}}}"#
        ))
        .is_err()
    );
    assert!(decode_response::<Value, Value>(&format!(r#"{{"version": "1.0", "outcome": {{"error": {{"id": {id}, "error": {{"code": "failed", "message": "bad"}}}}}}}}"#)).is_err());
}

#[test]
fn typed_codecs_enforce_bounds_and_framing() {
    let request = Request::<Value>::new(None, PING, None).encode().unwrap();
    let response = Response::<Value>::new(Outcome::Success {
        id: "ping-1".into(),
        result: Value::Null,
    })
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
        r#"{{"version": "1.0", "outcome": {{"success": {{"id": "ping-1", "result": {nested}}}}}}}"#
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

#[test_case(r#"{"success": {"id": "ping-1", "result": null}}"#; "definite success")]
#[test_case(r#"{_ "success": {"id": "ping-1", "result": null}}"#; "indefinite success")]
#[test_case(r#"{"error": {"id": null, "error": {"code": "failed", "message": "bad"}}}"#; "definite error")]
#[test_case(r#"{_ "error": {"id": null, "error": {"code": "failed", "message": "bad"}}}"#; "indefinite error")]
fn outcome_maps_accept_both_length_encodings(outcome: &str) {
    let response =
        decode_response::<Value, Value>(&format!(r#"{{"version": "1.0", "outcome": {outcome}}}"#))
            .unwrap();
    assert_eq!(
        Response::<Value>::decode(&response.encode().unwrap(), 1024).unwrap(),
        response
    );
}

#[test_case(r#"{_}"#; "empty map")]
#[test_case(r#"{_ "other": null}"#; "unknown variant")]
#[test_case(r#"{_ "success": {"id": "ping-1", "result": null}, "error": {"id": null, "error": {"code": "failed", "message": "bad"}}}"#; "both variants")]
#[test_case(r#"{_ "success": {"id": "ping-1", "result": null}, "success": {"id": "ping-1", "result": null}}"#; "duplicate success")]
#[test_case(r#"{_ "error": {"id": null, "error": {"code": "failed", "message": "bad"}}, "error": {"id": null, "error": {"code": "failed", "message": "bad"}}}"#; "duplicate error")]
fn indefinite_outcome_rejects_invalid_entries(outcome: &str) {
    assert!(
        decode_response::<Value, Value>(&format!(r#"{{"version": "1.0", "outcome": {outcome}}}"#))
            .is_err()
    );
}
