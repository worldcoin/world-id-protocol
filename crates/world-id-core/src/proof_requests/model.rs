use crate::proof_requests::constraints::{ConstraintExpr, ConstraintNode};
use alloy::primitives::U256;
use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::collections::HashSet;
use time::OffsetDateTime;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
pub enum Version {
    V1 = 1,
}

/// Authenticator request
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorRequest {
    /// Unique identifier for this request
    pub id: String,
    /// Version of the request
    pub version: Version,
    /// ISO8601 timestamp when created
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub created_at: Option<OffsetDateTime>,
    /// ISO8601 timestamp when request expires
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Registered RP id
    pub rp_id: U256,
    /// App id
    pub app_id: String,
    /// Encoded action string (act_...)
    pub encoded_action: String,
    /// Credential proof_requests
    pub requests: Vec<CredentialRequest>,
    /// Constraint expression (all/any) optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<ConstraintExpr<'static>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRequest {
    /// Credential type
    #[serde(rename = "type")]
    pub credential_type: String,
    /// Optional signal
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

/// Authenticator response per docs spec
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorResponse {
    /// Response id references request id
    pub id: String,
    /// Version corresponding to request version
    pub version: Version,
    /// Per-credential results
    pub responses: Vec<ResponseItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseItem {
    /// Credential type string this item refers to
    #[serde(rename = "type")]
    pub credential_type: String,
    /// Proof payload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// Computed nullifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullifier: Option<String>,
    /// Session identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Present if credential not provided
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AuthenticatorResponse {
    /// Determine if constraints are satisfied given a constraint expression.
    pub fn constraints_satisfied(&self, constraints: &ConstraintExpr<'_>) -> bool {
        let provided: HashSet<&str> = self
            .responses
            .iter()
            .filter(|item| item.error.is_none())
            .map(|item| item.credential_type.as_str())
            .collect();
        constraints.evaluate(&|t| provided.contains(t))
    }
}

impl AuthenticatorRequest {
    /// Determine which requested credentials to prove given available credentials.
    /// Returns None if constraints (or lack thereof) cannot be satisfied with the available set.
    pub fn credentials_to_prove(
        &self,
        available: &HashSet<&str>,
    ) -> Option<Vec<&CredentialRequest>> {
        use std::collections::HashSet as Set;

        // Build set of requested types
        let requested: Set<&str> = self
            .requests
            .iter()
            .map(|r| r.credential_type.as_str())
            .collect();

        // Predicate: only select if both available and requested
        let is_selectable = |t: &str| available.contains(t) && requested.contains(t);

        // Recursive selection helpers
        fn select_node<'a>(
            node: &'a ConstraintNode<'a>,
            pred: &impl Fn(&str) -> bool,
        ) -> Option<Vec<&'a str>> {
            match node {
                ConstraintNode::Type(t) => pred(t.as_ref()).then(|| vec![t.as_ref()]),
                ConstraintNode::Expr(e) => select_expr(e, pred),
            }
        }

        fn select_expr<'a>(
            expr: &'a ConstraintExpr<'a>,
            pred: &impl Fn(&str) -> bool,
        ) -> Option<Vec<&'a str>> {
            match expr {
                ConstraintExpr::All { all } => {
                    let mut seen: Set<&'a str> = Set::new();
                    let mut out: Vec<&'a str> = Vec::new();
                    for n in all {
                        let sub = select_node(n, pred)?;
                        for s in sub {
                            if seen.insert(s) {
                                out.push(s);
                            }
                        }
                    }
                    Some(out)
                }
                ConstraintExpr::Any { any } => any.iter().find_map(|n| select_node(n, pred)),
            }
        }

        // If no explicit constraints: require all requested be available
        if self.constraints.is_none() {
            return if self
                .requests
                .iter()
                .all(|r| available.contains(r.credential_type.as_str()))
            {
                Some(self.requests.iter().collect())
            } else {
                None
            };
        }

        // Compute selected types using the constraint expression
        let selected_types = select_expr(self.constraints.as_ref().unwrap(), &is_selectable)?;
        let selected_set: Set<&str> = selected_types.into_iter().collect();

        // Return proof_requests in original order filtered by selected types
        let result: Vec<&CredentialRequest> = self
            .requests
            .iter()
            .filter(|r| selected_set.contains(r.credential_type.as_str()))
            .collect();
        Some(result)
    }
    /// Returns true if the request is expired relative to now
    #[must_use]
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now > self.expires_at
    }

    /// Validate that a response satisfies this request: id match and constraints semantics.
    pub fn validate_response(
        &self,
        response: &AuthenticatorResponse,
    ) -> Result<(), ValidationError> {
        // Validate id and version match
        if self.id != response.id {
            return Err(ValidationError::RequestIdMismatch);
        }
        if self.version != response.version {
            return Err(ValidationError::VersionMismatch);
        }

        // Build set of successful credentials
        let provided: HashSet<&str> = response
            .responses
            .iter()
            .filter(|r| r.error.is_none())
            .map(|r| r.credential_type.as_str())
            .collect();

        match &self.constraints {
            // None => all requested credential types are required
            None => {
                for req in &self.requests {
                    if !provided.contains(req.credential_type.as_str()) {
                        return Err(ValidationError::MissingCredential(
                            req.credential_type.clone(),
                        ));
                    }
                }
                Ok(())
            }
            Some(expr) => {
                if !expr.validate_max_depth(2) {
                    return Err(ValidationError::ConstraintTooDeep);
                }
                if expr.evaluate(&|t| provided.contains(t)) {
                    Ok(())
                } else {
                    Err(ValidationError::ConstraintNotSatisfied)
                }
            }
        }
    }

    /// Parse from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let v: Self = serde_json::from_str(json)?;
        // Enforce unique credential types within a single request
        let mut seen: HashSet<&str> = HashSet::new();
        for r in &v.requests {
            let t = r.credential_type.as_str();
            if !seen.insert(t) {
                return Err(serde_json::Error::custom(format!(
                    "duplicate credential type: {}",
                    r.credential_type
                )));
            }
        }
        Ok(v)
    }

    /// Serialize to pretty JSON
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl AuthenticatorResponse {
    /// Parse from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to pretty JSON
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Return the list of successful credential types (no error)
    #[must_use]
    pub fn successful_credentials(&self) -> Vec<&str> {
        self.responses
            .iter()
            .filter(|r| r.error.is_none())
            .map(|r| r.credential_type.as_str())
            .collect()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("Request ID mismatch")]
    RequestIdMismatch,
    #[error("Version mismatch")]
    VersionMismatch,
    #[error("Missing required credential: {0}")]
    MissingCredential(String),
    #[error("Constraints not satisfied")]
    ConstraintNotSatisfied,
    #[error("Constraints nesting exceeds maximum allowed depth")]
    ConstraintTooDeep,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_requests::{ConstraintExpr, ConstraintNode};
    use time::macros::datetime;

    #[test]
    fn constraints_all_any_nested() {
        // Build a response that has orb and passport successful, gov-id missing
        let response = AuthenticatorResponse {
            id: "req_123".into(),
            version: Version::V1,
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

        assert!(response.constraints_satisfied(&expr));

        // all: ["orb", "gov-id"] should fail due to gov-id error
        let fail_expr = ConstraintExpr::All {
            all: vec![
                ConstraintNode::Type("orb".into()),
                ConstraintNode::Type("gov-id".into()),
            ],
        };
        assert!(!response.constraints_satisfied(&fail_expr));
    }

    #[test]
    fn request_validate_response_none_constraints_means_all() {
        let request = AuthenticatorRequest {
            id: "req_1".into(),
            version: Version::V1,
            created_at: None,
            expires_at: datetime!(2025-01-01 00:00:00 UTC),
            rp_id: U256::from(1u64),
            app_id: "app_1".into(),
            encoded_action: "act_...".into(),
            requests: vec![
                CredentialRequest {
                    credential_type: "orb".into(),
                    signal: None,
                },
                CredentialRequest {
                    credential_type: "passport".into(),
                    signal: None,
                },
            ],
            constraints: None,
        };

        let ok = AuthenticatorResponse {
            id: "req_1".into(),
            version: Version::V1,
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
            version: Version::V1,
            responses: vec![ResponseItem {
                credential_type: "orb".into(),
                proof: Some("0x".into()),
                nullifier: None,
                session_id: None,
                error: None,
            }],
        };
        let err = request.validate_response(&missing).unwrap_err();
        assert!(matches!(err, ValidationError::MissingCredential(_)));
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
            version: Version::V1,
            created_at: None,
            expires_at: datetime!(2025-01-01 00:00:00 UTC),
            rp_id: U256::from(1u64),
            app_id: "app_1".into(),
            encoded_action: "act_...".into(),
            requests: vec![CredentialRequest {
                credential_type: "orb".into(),
                signal: None,
            }],
            constraints: Some(deep),
        };

        let response = AuthenticatorResponse {
            id: "req_2".into(),
            version: Version::V1,
            responses: vec![ResponseItem {
                credential_type: "orb".into(),
                proof: Some("0x".into()),
                nullifier: None,
                session_id: None,
                error: None,
            }],
        };

        let err = request.validate_response(&response).unwrap_err();
        assert!(matches!(err, ValidationError::ConstraintTooDeep));
    }

    #[test]
    fn request_single_credential_parse_and_validate() {
        let json = r#"{
  "id": "req_18c0f7f03e7d",
  "version": 1,
  "created_at": "2025-09-03T17:33:12Z",
  "expires_at": "2025-09-03T17:38:12Z",
  "rp_id": "1",
  "app_id": "app_123",
  "encoded_action": "act_0000000000000000000000000000000000001",
  "proof_requests": [
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
            version: Version::V1,
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
  "rp_id": "1",
  "app_id": "app_123",
  "encoded_action": "act_0000000000000000000000000000000000001",
  "proof_requests": [
    { "type": "gov-id", "signal": "abcd-efgh-ijkl" },
    { "type": "orb", "signal": "abcd-efgh-ijkl" }
  ],
  "constraints": { "all": ["gov-id", "orb"] }
}"#;

        let req = AuthenticatorRequest::from_json(json).unwrap();

        // Build response that fails constraints (gov-id error)
        let resp = AuthenticatorResponse {
            id: req.id.clone(),
            version: Version::V1,
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
        assert!(matches!(err, ValidationError::ConstraintNotSatisfied));
    }

    #[test]
    fn request_more_complex_constraints_nested_success() {
        let json = r#"{
  "id": "req_18c0f7f03e7d",
  "version": 1,
  "created_at": "2025-09-03T17:33:12Z",
  "expires_at": "2025-09-03T17:38:12Z",
  "rp_id": "1",
  "app_id": "app_123",
  "encoded_action": "act_0000000000000000000000000000000000001",
  "proof_requests": [
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
            version: Version::V1,
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

    #[test]
    fn request_rejects_duplicate_credential_types_on_parse() {
        let json = r#"{
  "id": "req_dup",
  "version": 1,
  "created_at": "2025-09-03T17:33:12Z",
  "expires_at": "2025-09-03T17:38:12Z",
  "rp_id": "1",
  "app_id": "app_123",
  "encoded_action": "act_0000000000000000000000000000000000001",
  "proof_requests": [
    { "type": "orb" },
    { "type": "orb" }
  ]
}"#;

        let err = AuthenticatorRequest::from_json(json).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("duplicate credential type"));
    }

    #[test]
    fn credentials_to_prove_none_constraints_requires_all_and_drops_if_missing() {
        let req = AuthenticatorRequest {
            id: "req".into(),
            version: Version::V1,
            created_at: None,
            expires_at: datetime!(2025-01-01 00:00:00 UTC),
            rp_id: U256::from(1u64),
            app_id: "app".into(),
            encoded_action: "act".into(),
            requests: vec![
                CredentialRequest {
                    credential_type: "orb".into(),
                    signal: None,
                },
                CredentialRequest {
                    credential_type: "passport".into(),
                    signal: None,
                },
            ],
            constraints: None,
        };

        let available_ok: std::collections::HashSet<&str> =
            ["orb", "passport"].into_iter().collect();
        let sel_ok = req.credentials_to_prove(&available_ok).unwrap();
        assert_eq!(sel_ok.len(), 2);
        assert_eq!(sel_ok[0].credential_type, "orb");
        assert_eq!(sel_ok[1].credential_type, "passport");

        let available_missing: std::collections::HashSet<&str> = ["orb"].into_iter().collect();
        assert!(req.credentials_to_prove(&available_missing).is_none());
    }

    #[test]
    fn credentials_to_prove_with_constraints_all_and_any() {
        // proof_requests: orb, passport, national-id
        let req = AuthenticatorRequest {
            id: "req".into(),
            version: Version::V1,
            created_at: None,
            expires_at: datetime!(2025-01-01 00:00:00 UTC),
            rp_id: U256::from(1u64),
            app_id: "app".into(),
            encoded_action: "act".into(),
            requests: vec![
                CredentialRequest {
                    credential_type: "orb".into(),
                    signal: None,
                },
                CredentialRequest {
                    credential_type: "passport".into(),
                    signal: None,
                },
                CredentialRequest {
                    credential_type: "national-id".into(),
                    signal: None,
                },
            ],
            constraints: Some(ConstraintExpr::All {
                all: vec![
                    ConstraintNode::Type("orb".into()),
                    ConstraintNode::Expr(ConstraintExpr::Any {
                        any: vec![
                            ConstraintNode::Type("passport".into()),
                            ConstraintNode::Type("national-id".into()),
                        ],
                    }),
                ],
            }),
        };

        // Available has orb + passport → should pick [orb, passport]
        let available1: std::collections::HashSet<&str> = ["orb", "passport"].into_iter().collect();
        let sel1 = req.credentials_to_prove(&available1).unwrap();
        assert_eq!(sel1.len(), 2);
        assert_eq!(sel1[0].credential_type, "orb");
        assert_eq!(sel1[1].credential_type, "passport");

        // Available has orb + national-id → should pick [orb, national-id]
        let available2: std::collections::HashSet<&str> =
            ["orb", "national-id"].into_iter().collect();
        let sel2 = req.credentials_to_prove(&available2).unwrap();
        assert_eq!(sel2.len(), 2);
        assert_eq!(sel2[0].credential_type, "orb");
        assert_eq!(sel2[1].credential_type, "national-id");

        // Missing orb → cannot satisfy "all" → None
        let available3: std::collections::HashSet<&str> = ["passport"].into_iter().collect();
        assert!(req.credentials_to_prove(&available3).is_none());
    }
}
