//! Module containing all the functionality to handle requests from Relying Parties (RPs) to Authenticators.
//!
//! Enables an RP to create a Proof request or a Session Proof request, and provides base functionality
//! for Authneticators to handle such requests.

mod constraints;
pub use constraints::{ConstraintExpr, ConstraintKind, ConstraintNode, MAX_CONSTRAINT_NODES};

use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use world_id_primitives::rp::{RpId, RpNullifierKey};
use world_id_primitives::{FieldElement, PrimitiveError, WorldIdProof};

/// Protocol schema version for proof requests and responses.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestVersion {
    /// Version 1
    V1 = 1,
}

impl serde::Serialize for RequestVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let v = *self as u8;
        serializer.serialize_u8(v)
    }
}

impl<'de> serde::Deserialize<'de> for RequestVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u8::deserialize(deserializer)?;
        match v {
            1 => Ok(Self::V1),
            _ => Err(serde::de::Error::custom("unsupported version")),
        }
    }
}

/// A proof request from a relying party for an authenticator
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofRequest {
    /// Unique identifier for this request
    pub id: String,
    /// Version of the request
    pub version: RequestVersion,
    /// Unix timestamp (seconds since epoch) when the request was created
    pub created_at: u64,
    /// Unix timestamp (seconds since epoch) when request expires
    pub expires_at: u64,
    /// Registered RP id
    pub rp_id: RpId,
    /// The raw representation of the action. This must be already a field element.
    ///
    /// When dealing with strings or bytes, such value can be hashed e.g. with a byte-friendly
    /// hash function like keccak256 or SHA256 and then reduced to a field element.
    pub action: FieldElement,
    /// The nullifier key of the RP
    pub rp_nullifier_key: RpNullifierKey,
    /// The RP's ECDSA signature over the request
    pub signature: k256::ecdsa::Signature,
    /// Unique nonce for this request (serialized as hex string)
    pub nonce: FieldElement,
    /// Specific credential requests. This defines which credentials to ask for.
    #[serde(rename = "proof_requests")]
    pub requests: Vec<RequestItem>,
    /// Constraint expression (all/any) optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<ConstraintExpr<'static>>,
}

/// Per-credential request payload
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestItem {
    /// The specific credential being requested as registered in the `CredentialIssuerSchemaRegistry`.
    /// Serialized as hex string in JSON.
    pub issuer_schema_id: FieldElement,
    /// Optional signal (TODO: improve documentation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

impl RequestItem {
    /// Create a new request item with the given issuer schema ID and optional signal.
    #[must_use]
    pub const fn new(issuer_schema_id: FieldElement, signal: Option<String>) -> Self {
        Self {
            issuer_schema_id,
            signal,
        }
    }

    /// Get the signal hash for the request item.
    #[must_use]
    pub fn signal_hash(&self) -> FieldElement {
        if let Some(signal) = &self.signal {
            FieldElement::from_arbitrary_raw_bytes(signal.as_bytes())
        } else {
            FieldElement::ZERO
        }
    }
}

/// Overall response from the Authenticator to the RP
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofResponse {
    /// The response id references request id
    pub id: String,
    /// Version corresponding to request version
    pub version: RequestVersion,
    /// Per-credential results
    pub responses: Vec<ResponseItem>,
}

/// Per-credential response item
///
/// TODO: Improve documentation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseItem {
    /// Issuer schema id this item refers to (serialized as hex string)
    pub issuer_schema_id: FieldElement,
    /// Proof payload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<WorldIdProof>,
    /// Computed nullifier
    ///
    /// /// TODO: Correct type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullifier: Option<String>,
    /// Session identifier
    ///
    /// TODO: Correct type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Present if credential not provided
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ProofResponse {
    /// Determine if constraints are satisfied given a constraint expression.
    #[must_use]
    pub fn constraints_satisfied(&self, constraints: &ConstraintExpr<'_>) -> bool {
        let provided: HashSet<String> = self
            .responses
            .iter()
            .filter(|item| item.error.is_none())
            .map(|item| item.issuer_schema_id.to_string())
            .collect();
        constraints.evaluate(&|t| provided.contains(t))
    }
}

impl ProofRequest {
    /// Determine which requested credentials to prove given available credentials.
    /// Returns None if constraints (or lack thereof) cannot be satisfied with the available set.
    /// Determine which requested credentials to prove given available credentials.
    ///
    /// # Panics
    /// Panics if constraints are present but invalid according to the type invariants
    /// (this should not occur as constraints are provided by trusted request issuer).
    #[must_use]
    pub fn credentials_to_prove(
        &self,
        available: &HashSet<FieldElement>,
    ) -> Option<Vec<&RequestItem>> {
        // Build set of requested types
        let requested: std::collections::HashSet<FieldElement> =
            self.requests.iter().map(|r| r.issuer_schema_id).collect();

        // FIXME @decentralgabe: proper comparison of issuer_schema_id

        // Convert to string sets for constraint evaluation (constraints use string types)
        let available_strings: HashSet<String> =
            available.iter().map(ToString::to_string).collect();
        let requested_strings: HashSet<String> =
            requested.iter().map(ToString::to_string).collect();

        // Predicate: only select if both available and requested
        let is_selectable =
            |t: &str| available_strings.contains(t) && requested_strings.contains(t);

        // If no explicit constraints: require all requested be available
        if self.constraints.is_none() {
            return if self
                .requests
                .iter()
                .all(|r| available.contains(&r.issuer_schema_id))
            {
                Some(self.requests.iter().collect())
            } else {
                None
            };
        }

        // Compute selected types using the constraint expression
        let selected_types = select_expr(self.constraints.as_ref().unwrap(), &is_selectable)?;
        let selected_set: std::collections::HashSet<&str> = selected_types.into_iter().collect();

        // Return proof_requests in original order filtered by selected types
        let result: Vec<&RequestItem> = self
            .requests
            .iter()
            .filter(|r| selected_set.contains(r.issuer_schema_id.to_string().as_str()))
            .collect();
        Some(result)
    }

    /// Find a request item by issuer schema ID if available
    #[must_use]
    pub fn find_request_by_issuer_schema_id(
        &self,
        issuer_schema_id: FieldElement,
    ) -> Option<&RequestItem> {
        self.requests
            .iter()
            .find(|r| r.issuer_schema_id == issuer_schema_id)
    }

    /// Returns true if the request is expired relative to now (unix timestamp in seconds)
    #[must_use]
    pub const fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at
    }

    /// Compute the digest hash of this request that should be signed by the RP, which right now
    /// includes the `nonce` and the timestamp of the request.
    ///
    /// # Returns
    /// A 32-byte hash that represents this request and should be signed by the RP.
    ///
    /// # Errors
    /// Returns a `PrimitiveError` if `FieldElement` serialization fails (which should never occur in practice).
    pub fn digest_hash(&self) -> Result<[u8; 32], PrimitiveError> {
        use k256::sha2::{Digest, Sha256};

        let mut writer = Vec::new();
        let mut hasher = Sha256::new();
        self.nonce.serialize_as_bytes(&mut writer)?;
        hasher.update(&writer);
        hasher.update(self.created_at.to_be_bytes());
        Ok(hasher.finalize().into())
    }

    /// Validate that a response satisfies this request: id match and constraints semantics.
    ///
    /// # Errors
    /// Returns a `ValidationError` if the response does not correspond to this request or
    /// does not satisfy the declared constraints.
    pub fn validate_response(&self, response: &ProofResponse) -> Result<(), ValidationError> {
        // Validate id and version match
        if self.id != response.id {
            return Err(ValidationError::RequestIdMismatch);
        }
        if self.version != response.version {
            return Err(ValidationError::VersionMismatch);
        }

        // Build set of successful credentials
        let provided: HashSet<String> = response
            .responses
            .iter()
            .filter(|r| r.error.is_none())
            .map(|r| r.issuer_schema_id.to_string())
            .collect();

        match &self.constraints {
            // None => all requested credential (via issuer_schema_id) are required
            None => {
                for req in &self.requests {
                    if !provided.contains(&req.issuer_schema_id.to_string()) {
                        return Err(ValidationError::MissingCredential(
                            req.issuer_schema_id.to_string(),
                        ));
                    }
                }
                Ok(())
            }
            Some(expr) => {
                if !expr.validate_max_depth(2) {
                    return Err(ValidationError::ConstraintTooDeep);
                }
                if !expr.validate_max_nodes(MAX_CONSTRAINT_NODES) {
                    return Err(ValidationError::ConstraintTooLarge);
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
    ///
    /// # Errors
    /// Returns an error if the JSON is invalid or contains duplicate issuer schema ids.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let v: Self = serde_json::from_str(json)?;
        // Enforce unique issuer schema ids within a single request
        let mut seen: HashSet<String> = HashSet::new();
        for r in &v.requests {
            let t = r.issuer_schema_id.to_string();
            if !seen.insert(t.clone()) {
                return Err(serde_json::Error::custom(format!(
                    "duplicate issuer schema id: {t}"
                )));
            }
        }
        Ok(v)
    }

    /// Serialize to JSON
    ///
    /// # Errors
    /// Returns an error if serialization unexpectedly fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize to pretty JSON
    ///
    /// # Errors
    /// Returns an error if serialization unexpectedly fails.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl ProofResponse {
    /// Parse from JSON
    ///
    /// # Errors
    /// Returns an error if the JSON does not match the expected response shape.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to pretty JSON
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Return the list of successful issuer schema ids (no error)
    #[must_use]
    pub fn successful_credentials(&self) -> Vec<String> {
        self.responses
            .iter()
            .filter(|r| r.error.is_none())
            .map(|r| r.issuer_schema_id.to_string())
            .collect()
    }
}

/// Validation errors when checking a response against a request
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    /// The response `id` does not match the request `id`
    #[error("Request ID mismatch")]
    RequestIdMismatch,
    /// The response `version` does not match the request `version`
    #[error("Version mismatch")]
    VersionMismatch,
    /// A required credential was not provided
    #[error("Missing required credential: {0}")]
    MissingCredential(String),
    /// The provided credentials do not satisfy the request constraints
    #[error("Constraints not satisfied")]
    ConstraintNotSatisfied,
    /// The constraints expression exceeds the supported nesting depth
    #[error("Constraints nesting exceeds maximum allowed depth")]
    ConstraintTooDeep,
    /// The constraints expression exceeds the maximum allowed size/complexity
    #[error("Constraints exceed maximum allowed size")]
    ConstraintTooLarge,
}

// Helper selection functions for constraint evaluation
fn select_node<'a, F>(node: &'a ConstraintNode<'a>, pred: &F) -> Option<Vec<&'a str>>
where
    F: Fn(&str) -> bool,
{
    match node {
        ConstraintNode::Type(t) => pred(t.as_ref()).then(|| vec![t.as_ref()]),
        ConstraintNode::Expr(e) => select_expr(e, pred),
    }
}

fn select_expr<'a, F>(expr: &'a ConstraintExpr<'a>, pred: &F) -> Option<Vec<&'a str>>
where
    F: Fn(&str) -> bool,
{
    match expr {
        ConstraintExpr::All { all } => {
            let mut seen: std::collections::HashSet<&'a str> = std::collections::HashSet::new();
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

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{signature::Signer, SigningKey};

    // Test helpers
    fn test_signature() -> k256::ecdsa::Signature {
        let signing_key = SigningKey::from_bytes(&[1u8; 32].into()).unwrap();
        signing_key.sign(b"test")
    }

    fn test_rp_nullifier_key() -> RpNullifierKey {
        // Create a dummy point for testing
        use ark_ec::AffineRepr;
        RpNullifierKey::new(ark_babyjubjub::EdwardsAffine::generator())
    }

    fn test_nonce() -> FieldElement {
        FieldElement::from(1u64)
    }

    fn test_field_element(n: u64) -> FieldElement {
        FieldElement::from(n)
    }

    #[test]
    fn constraints_all_any_nested() {
        // Build a response that has orb and passport successful, gov-id missing
        let id1 = test_field_element(1);
        let id2 = test_field_element(2);
        let id3 = test_field_element(3);
        let id4 = test_field_element(4);

        let response = ProofResponse {
            id: "req_123".into(),
            version: RequestVersion::V1,
            responses: vec![
                ResponseItem {
                    issuer_schema_id: id1,
                    proof: Some(WorldIdProof::default()),
                    nullifier: Some("nil_1".into()),
                    session_id: None,
                    error: None,
                },
                ResponseItem {
                    issuer_schema_id: id2,
                    proof: Some(WorldIdProof::default()),
                    nullifier: Some("nil_2".into()),
                    session_id: None,
                    error: None,
                },
                ResponseItem {
                    issuer_schema_id: id3,
                    proof: None,
                    nullifier: None,
                    session_id: None,
                    error: Some("credential_not_available".into()),
                },
            ],
        };

        // all: [id1, any: [id2, id4]]
        let expr = ConstraintExpr::All {
            all: vec![
                ConstraintNode::Type(id1.to_string().into()),
                ConstraintNode::Expr(ConstraintExpr::Any {
                    any: vec![
                        ConstraintNode::Type(id2.to_string().into()),
                        ConstraintNode::Type(id4.to_string().into()),
                    ],
                }),
            ],
        };

        assert!(response.constraints_satisfied(&expr));

        // all: [id1, id3] should fail due to id3 error
        let fail_expr = ConstraintExpr::All {
            all: vec![
                ConstraintNode::Type(id1.to_string().into()),
                ConstraintNode::Type(id3.to_string().into()),
            ],
        };
        assert!(!response.constraints_satisfied(&fail_expr));
    }

    #[test]
    fn test_digest_hash() {
        let request = ProofRequest {
            id: "test_request".into(),
            version: RequestVersion::V1,
            created_at: 1_700_000_000,
            expires_at: 1_700_100_000,
            rp_id: RpId::from(1u128),
            action: FieldElement::ZERO,
            rp_nullifier_key: test_rp_nullifier_key(),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![RequestItem {
                issuer_schema_id: test_field_element(1),
                signal: Some("test_signal".into()),
            }],
            constraints: None,
        };

        let digest1 = request.digest_hash().unwrap();
        // Verify it returns a 32-byte hash
        assert_eq!(digest1.len(), 32);

        // Verify deterministic: same request produces same hash
        let digest2 = request.digest_hash().unwrap();
        assert_eq!(digest1, digest2);

        // Verify different request nonces produce different hashes
        let request2 = ProofRequest {
            nonce: test_field_element(3),
            ..request
        };
        let digest3 = request2.digest_hash().unwrap();
        assert_ne!(digest1, digest3);
    }

    #[test]
    fn request_validate_response_none_constraints_means_all() {
        let request = ProofRequest {
            id: "req_1".into(),
            version: RequestVersion::V1,
            created_at: 1_735_689_600,
            expires_at: 1_735_689_600, // 2025-01-01
            rp_id: RpId::from(1u128),
            action: FieldElement::ZERO,
            rp_nullifier_key: test_rp_nullifier_key(),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    issuer_schema_id: test_field_element(1),
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: test_field_element(2),
                    signal: None,
                },
            ],
            constraints: None,
        };

        let ok = ProofResponse {
            id: "req_1".into(),
            version: RequestVersion::V1,
            responses: vec![
                ResponseItem {
                    issuer_schema_id: test_field_element(1),
                    proof: Some(WorldIdProof::default()),
                    nullifier: None,
                    session_id: None,
                    error: None,
                },
                ResponseItem {
                    issuer_schema_id: test_field_element(2),
                    proof: Some(WorldIdProof::default()),
                    nullifier: None,
                    session_id: None,
                    error: None,
                },
            ],
        };
        assert!(request.validate_response(&ok).is_ok());

        let missing = ProofResponse {
            id: "req_1".into(),
            version: RequestVersion::V1,
            responses: vec![ResponseItem {
                issuer_schema_id: test_field_element(1),
                proof: Some(WorldIdProof::default()),
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

        let request = ProofRequest {
            id: "req_2".into(),
            version: RequestVersion::V1,
            created_at: 1_735_689_600,
            expires_at: 1_735_689_600,
            rp_id: RpId::from(1u128),
            action: test_field_element(1),
            rp_nullifier_key: test_rp_nullifier_key(),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![RequestItem {
                issuer_schema_id: test_field_element(1),
                signal: None,
            }],
            constraints: Some(deep),
        };

        let response = ProofResponse {
            id: "req_2".into(),
            version: RequestVersion::V1,
            responses: vec![ResponseItem {
                issuer_schema_id: test_field_element(1),
                proof: Some(WorldIdProof::default()),
                nullifier: None,
                session_id: None,
                error: None,
            }],
        };

        let err = request.validate_response(&response).unwrap_err();
        assert!(matches!(err, ValidationError::ConstraintTooDeep));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn constraint_node_limit_boundary_passes() {
        // Root All with: 1 Type + Any(4) + Any(4)
        // Node count = root(1) + type(1) + any(1+4) + any(1+4) = 12
        let id10 = test_field_element(10);
        let id11 = test_field_element(11);
        let id12 = test_field_element(12);
        let id13 = test_field_element(13);
        let id14 = test_field_element(14);
        let id15 = test_field_element(15);
        let id16 = test_field_element(16);
        let id17 = test_field_element(17);
        let id18 = test_field_element(18);

        let expr = ConstraintExpr::All {
            all: vec![
                ConstraintNode::Type(id10.to_string().into()),
                ConstraintNode::Expr(ConstraintExpr::Any {
                    any: vec![
                        ConstraintNode::Type(id11.to_string().into()),
                        ConstraintNode::Type(id12.to_string().into()),
                        ConstraintNode::Type(id13.to_string().into()),
                        ConstraintNode::Type(id14.to_string().into()),
                    ],
                }),
                ConstraintNode::Expr(ConstraintExpr::Any {
                    any: vec![
                        ConstraintNode::Type(id15.to_string().into()),
                        ConstraintNode::Type(id16.to_string().into()),
                        ConstraintNode::Type(id17.to_string().into()),
                        ConstraintNode::Type(id18.to_string().into()),
                    ],
                }),
            ],
        };

        let request = ProofRequest {
            id: "req_nodes_ok".into(),
            version: RequestVersion::V1,
            created_at: 1_735_689_600,
            expires_at: 1_735_689_600,
            rp_id: RpId::from(1u128),
            action: test_field_element(5),
            rp_nullifier_key: test_rp_nullifier_key(),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    issuer_schema_id: id10,
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: id11,
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: id12,
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: id13,
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: id14,
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: id15,
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: id16,
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: id17,
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: id18,
                    signal: None,
                },
            ],
            constraints: Some(expr),
        };

        // Provide just enough to satisfy both any-groups and the single type
        let response = ProofResponse {
            id: "req_nodes_ok".into(),
            version: RequestVersion::V1,
            responses: vec![
                ResponseItem {
                    issuer_schema_id: id10,
                    proof: Some(WorldIdProof::default()),
                    nullifier: None,
                    session_id: None,
                    error: None,
                },
                ResponseItem {
                    issuer_schema_id: id11,
                    proof: Some(WorldIdProof::default()),
                    nullifier: None,
                    session_id: None,
                    error: None,
                },
                ResponseItem {
                    issuer_schema_id: id15,
                    proof: Some(WorldIdProof::default()),
                    nullifier: None,
                    session_id: None,
                    error: None,
                },
            ],
        };

        // Should not exceed size and should validate OK
        assert!(request.validate_response(&response).is_ok());
    }

    #[test]
    fn constraint_node_limit_exceeded_fails() {
        // Root All with: 1 Type + Any(4) + Any(5)
        // Node count = root(1) + type(1) + any(1+4) + any(1+5) = 13 (> 12)
        let expr = ConstraintExpr::All {
            all: vec![
                ConstraintNode::Type("t0".into()),
                ConstraintNode::Expr(ConstraintExpr::Any {
                    any: vec![
                        ConstraintNode::Type("t1".into()),
                        ConstraintNode::Type("t2".into()),
                        ConstraintNode::Type("t3".into()),
                        ConstraintNode::Type("t4".into()),
                    ],
                }),
                ConstraintNode::Expr(ConstraintExpr::Any {
                    any: vec![
                        ConstraintNode::Type("t5".into()),
                        ConstraintNode::Type("t6".into()),
                        ConstraintNode::Type("t7".into()),
                        ConstraintNode::Type("t8".into()),
                        ConstraintNode::Type("t9".into()),
                    ],
                }),
            ],
        };

        let request = ProofRequest {
            id: "req_nodes_too_many".into(),
            version: RequestVersion::V1,
            created_at: 1_735_689_600,
            expires_at: 1_735_689_600,
            rp_id: RpId::from(1u128),
            action: test_field_element(1),
            rp_nullifier_key: test_rp_nullifier_key(),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    issuer_schema_id: test_field_element(20),
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: test_field_element(21),
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: test_field_element(22),
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: test_field_element(23),
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: test_field_element(24),
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: test_field_element(25),
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: test_field_element(26),
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: test_field_element(27),
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: test_field_element(28),
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: test_field_element(29),
                    signal: None,
                },
            ],
            constraints: Some(expr),
        };

        // Response content is irrelevant; validation should fail before evaluation due to size
        let response = ProofResponse {
            id: "req_nodes_too_many".into(),
            version: RequestVersion::V1,
            responses: vec![ResponseItem {
                issuer_schema_id: test_field_element(20),
                proof: Some(WorldIdProof::default()),
                nullifier: None,
                session_id: None,
                error: None,
            }],
        };

        let err = request.validate_response(&response).unwrap_err();
        assert!(matches!(err, ValidationError::ConstraintTooLarge));
    }

    #[test]
    fn request_single_credential_parse_and_validate() {
        let req = ProofRequest {
            id: "req_18c0f7f03e7d".into(),
            version: RequestVersion::V1,
            created_at: 1_725_381_192,
            expires_at: 1_725_381_492,
            rp_id: RpId::from(1u128),
            action: test_field_element(1),
            rp_nullifier_key: test_rp_nullifier_key(),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![RequestItem {
                issuer_schema_id: test_field_element(1),
                signal: Some("abcd-efgh-ijkl".into()),
            }],
            constraints: None,
        };

        assert_eq!(req.id, "req_18c0f7f03e7d");
        assert_eq!(req.requests.len(), 1);

        // Build matching successful response
        let resp = ProofResponse {
            id: req.id.clone(),
            version: RequestVersion::V1,
            responses: vec![ResponseItem {
                issuer_schema_id: test_field_element(1),
                proof: Some(WorldIdProof::default()),
                nullifier: Some("nil_1".into()),
                session_id: None,
                error: None,
            }],
        };
        assert!(req.validate_response(&resp).is_ok());
    }

    #[test]
    fn request_multiple_credentials_all_constraint_and_failure() {
        let req = ProofRequest {
            id: "req_18c0f7f03e7d".into(),
            version: RequestVersion::V1,
            created_at: 1_725_381_192,
            expires_at: 1_725_381_492,
            rp_id: RpId::from(1u128),
            action: test_field_element(1),
            rp_nullifier_key: test_rp_nullifier_key(),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    issuer_schema_id: test_field_element(1),
                    signal: Some("abcd-efgh-ijkl".into()),
                },
                RequestItem {
                    issuer_schema_id: test_field_element(2),
                    signal: Some("abcd-efgh-ijkl".into()),
                },
            ],
            constraints: Some(ConstraintExpr::All {
                all: vec![
                    ConstraintNode::Type(test_field_element(1).to_string().into()),
                    ConstraintNode::Type(test_field_element(2).to_string().into()),
                ],
            }),
        };

        // Build response that fails constraints (0x1 error)
        let resp = ProofResponse {
            id: req.id.clone(),
            version: RequestVersion::V1,
            responses: vec![
                ResponseItem {
                    issuer_schema_id: test_field_element(2),
                    proof: Some(WorldIdProof::default()),
                    nullifier: Some("nil_1".into()),
                    session_id: None,
                    error: None,
                },
                ResponseItem {
                    issuer_schema_id: test_field_element(1),
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
        let req = ProofRequest {
            id: "req_18c0f7f03e7d".into(),
            version: RequestVersion::V1,
            created_at: 1_725_381_192,
            expires_at: 1_725_381_492,
            rp_id: RpId::from(1u128),
            action: test_field_element(1),
            rp_nullifier_key: test_rp_nullifier_key(),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    issuer_schema_id: test_field_element(1),
                    signal: Some("abcd-efgh-ijkl".into()),
                },
                RequestItem {
                    issuer_schema_id: test_field_element(2),
                    signal: Some("mnop-qrst-uvwx".into()),
                },
                RequestItem {
                    issuer_schema_id: test_field_element(3),
                    signal: Some("abcd-efgh-ijkl".into()),
                },
            ],
            constraints: Some(ConstraintExpr::All {
                all: vec![
                    ConstraintNode::Type(test_field_element(3).to_string().into()),
                    ConstraintNode::Expr(ConstraintExpr::Any {
                        any: vec![
                            ConstraintNode::Type(test_field_element(1).to_string().into()),
                            ConstraintNode::Type(test_field_element(2).to_string().into()),
                        ],
                    }),
                ],
            }),
        };

        // Satisfy nested any with 0x1 + 0x3
        let resp = ProofResponse {
            id: req.id.clone(),
            version: RequestVersion::V1,
            responses: vec![
                ResponseItem {
                    issuer_schema_id: test_field_element(3),
                    proof: Some(WorldIdProof::default()),
                    nullifier: Some("nil_1".into()),
                    session_id: None,
                    error: None,
                },
                ResponseItem {
                    issuer_schema_id: test_field_element(1),
                    proof: Some(WorldIdProof::default()),
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
        // Success OK - using default proof (all zeros) in hex
        let orb_id_str = test_field_element(100).to_string();
        let gov_id_str = test_field_element(101).to_string();

        let ok_json = format!(
            r#"{{
  "id": "req_18c0f7f03e7d",
  "version": 1,
  "responses": [
    {{
      "issuer_schema_id": "{orb_id_str}",
      "proof": "00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000",
      "nullifier": "nil_000...001"
    }}
  ]
}}"#
        );
        let ok = ProofResponse::from_json(&ok_json).unwrap();
        assert_eq!(ok.successful_credentials(), vec![orb_id_str.clone()]);

        // Failure (constraints not satisfied) shape parsing
        let fail_json = format!(
            r#"{{
  "id": "req_18c0f7f03e7d",
  "version": 1,
  "responses": [
    {{ "issuer_schema_id": "{orb_id_str}", "proof": "00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000", "nullifier": "nil_000...001" }},
    {{ "issuer_schema_id": "{gov_id_str}", "error": "credential_not_available" }}
  ]
}}"#
        );
        let fail = ProofResponse::from_json(&fail_json).unwrap();
        assert_eq!(fail.successful_credentials(), vec![orb_id_str.clone()]);

        // Success with Session
        let sess_json = format!(
            r#"{{
  "id": "req_18c0f7f03e7d",
  "version": 1,
  "responses": [
    {{
      "issuer_schema_id": "{orb_id_str}",
      "proof": "00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000",
      "nullifier": "nil_000...001",
      "session_id": "psub_0fff...002"
    }}
  ]
}}"#
        );
        let sess = ProofResponse::from_json(&sess_json).unwrap();
        assert_eq!(sess.successful_credentials(), vec![orb_id_str]);
        assert!(sess.responses[0].session_id.is_some());
    }

    #[test]
    fn request_rejects_duplicate_issuer_schema_ids_on_parse() {
        // Test duplicate detection by creating a serialized ProofRequest with duplicates
        // and then trying to parse it with from_json which should detect the duplicates
        let id1 = test_field_element(1);
        let req = ProofRequest {
            id: "req_dup".into(),
            version: RequestVersion::V1,
            created_at: 1_725_381_192,
            expires_at: 1_725_381_492,
            rp_id: RpId::from(1u128),
            action: test_field_element(5),
            rp_nullifier_key: test_rp_nullifier_key(),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    issuer_schema_id: id1,
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: id1, // Duplicate!
                    signal: None,
                },
            ],
            constraints: None,
        };

        // Serialize then deserialize to trigger the duplicate check in from_json
        let json = req.to_json().unwrap();
        let err = ProofRequest::from_json(&json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate issuer schema id"),
            "Expected error message to contain 'duplicate issuer schema id', got: {msg}"
        );
    }

    #[test]
    fn credentials_to_prove_none_constraints_requires_all_and_drops_if_missing() {
        let orb_id = test_field_element(100);
        let passport_id = test_field_element(101);

        let req = ProofRequest {
            id: "req".into(),
            version: RequestVersion::V1,
            created_at: 1_735_689_600,
            expires_at: 1_735_689_600, // 2025-01-01 00:00:00 UTC
            rp_id: RpId::from(1u128),
            action: test_field_element(5),
            rp_nullifier_key: test_rp_nullifier_key(),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    issuer_schema_id: orb_id,
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: passport_id,
                    signal: None,
                },
            ],
            constraints: None,
        };

        let available_ok: HashSet<FieldElement> = [orb_id, passport_id].into_iter().collect();
        let sel_ok = req.credentials_to_prove(&available_ok).unwrap();
        assert_eq!(sel_ok.len(), 2);
        assert_eq!(sel_ok[0].issuer_schema_id, orb_id);
        assert_eq!(sel_ok[1].issuer_schema_id, passport_id);

        let available_missing: HashSet<FieldElement> = std::iter::once(orb_id).collect();
        assert!(req.credentials_to_prove(&available_missing).is_none());
    }

    #[test]
    fn credentials_to_prove_with_constraints_all_and_any() {
        // proof_requests: orb, passport, national-id
        let orb_id = test_field_element(100);
        let passport_id = test_field_element(101);
        let national_id_id = test_field_element(102);

        let req = ProofRequest {
            id: "req".into(),
            version: RequestVersion::V1,
            created_at: 1_735_689_600,
            expires_at: 1_735_689_600, // 2025-01-01 00:00:00 UTC
            rp_id: RpId::from(1u128),
            action: test_field_element(1),
            rp_nullifier_key: test_rp_nullifier_key(),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    issuer_schema_id: orb_id,
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: passport_id,
                    signal: None,
                },
                RequestItem {
                    issuer_schema_id: national_id_id,
                    signal: None,
                },
            ],
            constraints: Some(ConstraintExpr::All {
                all: vec![
                    ConstraintNode::Type(orb_id.to_string().into()),
                    ConstraintNode::Expr(ConstraintExpr::Any {
                        any: vec![
                            ConstraintNode::Type(passport_id.to_string().into()),
                            ConstraintNode::Type(national_id_id.to_string().into()),
                        ],
                    }),
                ],
            }),
        };

        // Available has orb + passport → should pick [orb, passport]
        let available1: HashSet<FieldElement> = [orb_id, passport_id].into_iter().collect();
        let sel1 = req.credentials_to_prove(&available1).unwrap();
        assert_eq!(sel1.len(), 2);
        assert_eq!(sel1[0].issuer_schema_id, orb_id);
        assert_eq!(sel1[1].issuer_schema_id, passport_id);

        // Available has orb + national-id → should pick [orb, national-id]
        let available2: HashSet<FieldElement> = [orb_id, national_id_id].into_iter().collect();
        let sel2 = req.credentials_to_prove(&available2).unwrap();
        assert_eq!(sel2.len(), 2);
        assert_eq!(sel2[0].issuer_schema_id, orb_id);
        assert_eq!(sel2[1].issuer_schema_id, national_id_id);

        // Missing orb → cannot satisfy "all" → None
        let available3: HashSet<FieldElement> = std::iter::once(passport_id).collect();
        assert!(req.credentials_to_prove(&available3).is_none());
    }
}
