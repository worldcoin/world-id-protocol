use idkit_core::{
    AuthenticatorRequest, AuthenticatorResponse, ConstraintExpr, ConstraintNode, ResponseItem,
    WorldIdAction,
};
use time::macros::datetime;

#[test]
fn action_roundtrip_and_hash_bytes() {
    let action = WorldIdAction {
        expires_at: 1_700_000_000,
        data: b"hello".to_vec(),
        description: "Test".to_string(),
    };
    let enc = action.encode();
    assert!(enc.starts_with("act_"));
    let dec = WorldIdAction::decode(&enc).unwrap();
    assert_eq!(dec, action);
    let bytes = WorldIdAction::hash_input_bytes(&enc).unwrap();
    // Should equal raw JSON bytes
    let expected = serde_json::to_vec(&action).unwrap();
    assert_eq!(bytes, expected);
}

#[test]
fn constraints_all_any_nested() {
    // Build a response that has orb and passport successful, gov-id missing
    let response = AuthenticatorResponse {
        id: "req_123".into(),
        version: 1,
        responses: vec![
            ResponseItem {
                credential_type: "orb".into(),
                proof: Some("0x0".into()),
                nullifier: Some("nil_1".into()),
                session_id: None,
                error: None,
            },
            ResponseItem {
                credential_type: "passport".into(),
                proof: Some("0x0".into()),
                nullifier: Some("nil_2".into()),
                session_id: None,
                error: None,
            },
            ResponseItem {
                credential_type: "gov-id".into(),
                proof: None,
                nullifier: None,
                session_id: None,
                error: Some("credential_not_available".into()),
            },
        ],
    };

    // all: ["orb", any: ["passport", "national-id"]]
    let expr = ConstraintExpr::All {
        all: vec![
            ConstraintNode::Type("orb".into()),
            ConstraintNode::Expr(ConstraintExpr::Any {
                any: vec![
                    ConstraintNode::Type("passport".into()),
                    ConstraintNode::Type("national-id".into()),
                ],
            }),
        ],
    };

    assert!(response.constraints_satisfied(Some(&expr)));

    // all: ["orb", "gov-id"] should fail due to gov-id error
    let fail_expr = ConstraintExpr::All {
        all: vec![
            ConstraintNode::Type("orb".into()),
            ConstraintNode::Type("gov-id".into()),
        ],
    };
    assert!(!response.constraints_satisfied(Some(&fail_expr)));
}

#[test]
fn request_validate_response_none_constraints_means_all() {
    let request = AuthenticatorRequest {
        id: "req_1".into(),
        version: 1,
        created_at: None,
        expires_at: datetime!(2025-01-01 00:00:00 UTC),
        rp_id: "rp_1".into(),
        app_id: "app_1".into(),
        encoded_action: "act_...".into(),
        requests: vec![
            idkit_core::model::CredentialRequest {
                credential_type: "orb".into(),
                signal: None,
            },
            idkit_core::model::CredentialRequest {
                credential_type: "passport".into(),
                signal: None,
            },
        ],
        constraints: None,
    };

    let ok = AuthenticatorResponse {
        id: "req_1".into(),
        version: 1,
        responses: vec![
            ResponseItem {
                credential_type: "orb".into(),
                proof: Some("0x".into()),
                nullifier: None,
                session_id: None,
                error: None,
            },
            ResponseItem {
                credential_type: "passport".into(),
                proof: Some("0x".into()),
                nullifier: None,
                session_id: None,
                error: None,
            },
        ],
    };
    assert!(request.validate_response(&ok).is_ok());

    let missing = AuthenticatorResponse {
        id: "req_1".into(),
        version: 1,
        responses: vec![ResponseItem {
            credential_type: "orb".into(),
            proof: Some("0x".into()),
            nullifier: None,
            session_id: None,
            error: None,
        }],
    };
    let err = request.validate_response(&missing).unwrap_err();
    assert!(matches!(
        err,
        idkit_core::model::ValidationError::MissingCredential(_)
    ));
}

#[test]
fn constraint_depth_enforced() {
    // Root all -> nested any -> nested all (depth 3) should be rejected
    let deep = ConstraintExpr::All {
        all: vec![ConstraintNode::Expr(ConstraintExpr::Any {
            any: vec![ConstraintNode::Expr(ConstraintExpr::All {
                all: vec![ConstraintNode::Type("orb".into())],
            })],
        })],
    };

    let request = AuthenticatorRequest {
        id: "req_2".into(),
        version: 1,
        created_at: None,
        expires_at: datetime!(2025-01-01 00:00:00 UTC),
        rp_id: "rp_1".into(),
        app_id: "app_1".into(),
        encoded_action: "act_...".into(),
        requests: vec![idkit_core::model::CredentialRequest {
            credential_type: "orb".into(),
            signal: None,
        }],
        constraints: Some(deep),
    };

    let response = AuthenticatorResponse {
        id: "req_2".into(),
        version: 1,
        responses: vec![ResponseItem {
            credential_type: "orb".into(),
            proof: Some("0x".into()),
            nullifier: None,
            session_id: None,
            error: None,
        }],
    };

    let err = request.validate_response(&response).unwrap_err();
    assert!(matches!(
        err,
        idkit_core::model::ValidationError::ConstraintTooDeep
    ));
}

#[test]
fn request_single_credential_parse_and_validate() {
    let json = r#"{
  "id": "req_18c0f7f03e7d",
  "version": 1,
  "created_at": "2025-09-03T17:33:12Z",
  "expires_at": "2025-09-03T17:38:12Z",
  "rp_id": "rp_0000000000000000000000000000000000001",
  "app_id": "app_123",
  "encoded_action": "act_0000000000000000000000000000000000001",
  "requests": [
    { "type": "gov-id", "signal": "abcd-efgh-ijkl" }
  ]
}"#;

    let req = AuthenticatorRequest::from_json(json).unwrap();
    assert_eq!(req.id, "req_18c0f7f03e7d");
    assert_eq!(req.requests.len(), 1);
    assert_eq!(req.requests[0].credential_type, "gov-id");

    // Build matching successful response
    let resp = AuthenticatorResponse {
        id: req.id.clone(),
        version: 1,
        responses: vec![ResponseItem {
            credential_type: "gov-id".into(),
            proof: Some("0x".into()),
            nullifier: Some("nil_1".into()),
            session_id: None,
            error: None,
        }],
    };
    assert!(req.validate_response(&resp).is_ok());
}

#[test]
fn request_multiple_credentials_all_constraint_and_failure() {
    let json = r#"{
  "id": "req_18c0f7f03e7d",
  "version": 1,
  "created_at": "2025-09-03T17:33:12Z",
  "expires_at": "2025-09-03T17:38:12Z",
  "rp_id": "rp_0000000000000000000000000000000000001",
  "app_id": "app_123",
  "encoded_action": "act_0000000000000000000000000000000000001",
  "requests": [
    { "type": "gov-id", "signal": "abcd-efgh-ijkl" },
    { "type": "orb", "signal": "abcd-efgh-ijkl" }
  ],
  "constraints": { "all": ["gov-id", "orb"] }
}"#;

    let req = AuthenticatorRequest::from_json(json).unwrap();

    // Build response that fails constraints (gov-id error)
    let resp = AuthenticatorResponse {
        id: req.id.clone(),
        version: 1,
        responses: vec![
            ResponseItem {
                credential_type: "orb".into(),
                proof: Some("0x".into()),
                nullifier: Some("nil_1".into()),
                session_id: None,
                error: None,
            },
            ResponseItem {
                credential_type: "gov-id".into(),
                proof: None,
                nullifier: None,
                session_id: None,
                error: Some("credential_not_available".into()),
            },
        ],
    };

    let err = req.validate_response(&resp).unwrap_err();
    assert!(matches!(
        err,
        idkit_core::model::ValidationError::ConstraintNotSatisfied
    ));
}

#[test]
fn request_more_complex_constraints_nested_success() {
    let json = r#"{
  "id": "req_18c0f7f03e7d",
  "version": 1,
  "created_at": "2025-09-03T17:33:12Z",
  "expires_at": "2025-09-03T17:38:12Z",
  "rp_id": "rp_0000000000000000000000000000000000001",
  "app_id": "app_123",
  "encoded_action": "act_0000000000000000000000000000000000001",
  "requests": [
    { "type": "passport", "signal": "abcd-efgh-ijkl" },
    { "type": "my-number-card", "signal": "mnop-qrst-uvwx" },
    { "type": "orb", "signal": "abcd-efgh-ijkl" }
  ],
  "constraints": {
    "all": [
      "orb",
      { "any": ["passport", "my-number-card"] }
    ]
  }
}"#;

    let req = AuthenticatorRequest::from_json(json).unwrap();

    // Satisfy nested any with passport + orb
    let resp = AuthenticatorResponse {
        id: req.id.clone(),
        version: 1,
        responses: vec![
            ResponseItem {
                credential_type: "orb".into(),
                proof: Some("0x".into()),
                nullifier: Some("nil_1".into()),
                session_id: None,
                error: None,
            },
            ResponseItem {
                credential_type: "passport".into(),
                proof: Some("0x".into()),
                nullifier: Some("nil_2".into()),
                session_id: None,
                error: None,
            },
        ],
    };

    assert!(req.validate_response(&resp).is_ok());
}

#[test]
fn response_success_and_with_session_and_failure_parse() {
    // Success OK
    let ok_json = r#"{
  "id": "req_18c0f7f03e7d",
  "version": 1,
  "responses": [
    {
      "type": "orb",
      "proof": "0x0",
      "nullifier": "nil_000...001"
    }
  ]
}"#;
    let ok = AuthenticatorResponse::from_json(ok_json).unwrap();
    assert_eq!(ok.successful_credentials(), vec!["orb"]);

    // Failure (constraints not satisfied) shape parsing
    let fail_json = r#"{
  "id": "req_18c0f7f03e7d",
  "version": 1,
  "responses": [
    { "type": "orb", "proof": "0x0", "nullifier": "nil_000...001" },
    { "type": "gov-id", "error": "credential_not_available" }
  ]
}"#;
    let fail = AuthenticatorResponse::from_json(fail_json).unwrap();
    assert_eq!(fail.successful_credentials(), vec!["orb"]);

    // Success with Session
    let sess_json = r#"{
  "id": "req_18c0f7f03e7d",
  "version": 1,
  "responses": [
    {
      "type": "orb",
      "proof": "0x0",
      "nullifier": "nil_000...001",
      "session_id": "psub_0fff...002"
    }
  ]
}"#;
    let sess = AuthenticatorResponse::from_json(sess_json).unwrap();
    assert_eq!(sess.successful_credentials(), vec!["orb"]);
    assert!(sess.responses[0].session_id.is_some());
}
