//! Module containing all the functionality to handle requests from Relying Parties (RPs) to Authenticators.
//!
//! Enables an RP to create a Proof request or a Session Proof request, and provides base functionality
//! for Authenticators to handle such requests.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod constraints;
pub use constraints::{ConstraintExpr, ConstraintKind, ConstraintNode, MAX_CONSTRAINT_NODES};

use serde::{Deserialize, Serialize, de::Error as _};
use std::collections::HashSet;
use taceo_oprf::types::OprfKeyId;
use world_id_primitives::{FieldElement, PrimitiveError, ZeroKnowledgeProof, rp::RpId};

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

/// A proof request from a Relying Party (RP) for an Authenticator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofRequest {
    /// Unique identifier for this request.
    pub id: String,
    /// Version of the request.
    pub version: RequestVersion,
    /// Unix timestamp (seconds) when the request was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) when the request expires.
    pub expires_at: u64,
    /// Registered RP identifier from the `RpRegistry`.
    pub rp_id: RpId,
    /// `OprfKeyId` of the RP.
    pub oprf_key_id: OprfKeyId,
    /// Session identifier that links proofs for the same user/RP pair across requests.
    ///
    /// If provided, a Session Proof will be generated instead of a Uniqueness Proof.
    /// The proof will only be valid if the session ID is meant for this context and this
    /// particular World ID holder.
    pub session_id: Option<FieldElement>,
    /// An RP-defined context that scopes what the user is proving uniqueness on.
    ///
    /// This parameter expects a field element. When dealing with strings or bytes,
    /// hash with a byte-friendly hash function like keccak256 or SHA256 and reduce to the field.
    pub action: Option<FieldElement>,
    /// The RP's ECDSA signature over the request.
    pub signature: alloy::signers::Signature,
    /// Unique nonce for this request provided by the RP.
    pub nonce: FieldElement,
    /// Specific credential requests. This defines which credentials to ask for.
    #[serde(rename = "proof_requests")]
    pub requests: Vec<RequestItem>,
    /// Constraint expression (all/any) optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<ConstraintExpr<'static>>,
}

/// Per-credential request payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestItem {
    /// An RP-defined identifier for this request item used to match against constraints and responses.
    ///
    /// Example: `orb`, `document`.
    pub identifier: String,

    /// Unique identifier for the credential schema and issuer pair.
    ///
    /// Registered in the `CredentialSchemaIssuerRegistry`.
    pub issuer_schema_id: u64,

    /// Arbitrary data provided by the RP that gets cryptographically bound into the proof.
    ///
    /// When present, the Authenticator hashes this via `signal_hash` and commits it into the
    /// proof circuit so the RP can tie the proof to a particular context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,

    /// Minimum `genesis_issued_at` timestamp that the used Credential must meet.
    ///
    /// If present, the proof will include a constraint that the credential's genesis issued at timestamp
    /// is greater than or equal to this value. Can be set to 0 to skip.
    /// This is useful for migration from previous protocol versions.
    pub genesis_issued_at_min: Option<u64>,

    /// The minimum expiration required for the Credential used in the proof.
    ///
    /// If the constraint is not required, it should use the current time as the minimum expiration.
    /// The Authenticator will normally expose the effective input used in the proof.
    ///
    /// This is particularly useful to specify a minimum duration for a Credential proportional to the action
    /// being performed. For example, when claiming a benefit that is once every 6 months, the minimum duration
    /// can be set to 180 days to prevent double claiming in that period in case the Credential is set to expire earlier.
    ///
    /// It is an RP's responsibility to understand the issuer's policies regarding expiration to ensure the request
    /// can be fulfilled.
    ///
    /// If not provided, this will default to the [`ProofRequest::created_at`] attribute.
    pub expires_at_min: Option<u64>,
}

impl RequestItem {
    /// Create a new request item with the given identifier, issuer schema ID and optional signal.
    #[must_use]
    pub const fn new(
        identifier: String,
        issuer_schema_id: u64,
        signal: Option<String>,
        genesis_issued_at_min: Option<u64>,
        expires_at_min: Option<u64>,
    ) -> Self {
        Self {
            identifier,
            issuer_schema_id,
            signal,
            genesis_issued_at_min,
            expires_at_min,
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

    /// Get the effective minimum expiration timestamp for this request item.
    ///
    /// If `expires_at_min` is `Some`, returns that value.
    /// Otherwise, returns the `request_created_at` value (which should be the `ProofRequest::created_at` timestamp).
    #[must_use]
    pub const fn effective_expires_at_min(&self, request_created_at: u64) -> u64 {
        match self.expires_at_min {
            Some(value) => value,
            None => request_created_at,
        }
    }
}

/// Overall response from the Authenticator to the RP
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofResponse {
    /// The response id references request id
    pub id: String,
    /// Version corresponding to request version
    pub version: RequestVersion,
    /// RP session identifier that links multiple proofs for the same
    /// user/RP pair across requests.
    ///
    /// When session proofs are enabled, this is the hex-encoded field element
    /// emitted by the session circuit; otherwise it is omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<FieldElement>,
    /// Error message if the entire proof request failed.
    /// When present, the responses array will be empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Per-credential results (empty if error is present)
    pub responses: Vec<ResponseItem>,
}

/// Per-credential response item returned by the Authenticator.
///
/// Each entry corresponds to one requested credential with its proof material.
/// If any credential cannot be satisfied, the entire proof response will have
/// an error at the `ProofResponse` level with an empty `responses` array.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseItem {
    /// An RP-defined identifier for this request item used to match against constraints and responses.
    ///
    /// Example: `orb`, `document`.
    pub identifier: String,

    /// Unique identifier for the credential schema and issuer pair.
    pub issuer_schema_id: u64,

    /// Encoded World ID Proof. See [`ZeroKnowledgeProof`] for more details.
    pub proof: ZeroKnowledgeProof,

    /// A unique, one-time identifier derived from (user, rpId, action) that lets RPs detect
    /// duplicate actions without learning who the user is.
    ///
    /// Encoded as a hex string representation of the field element.
    pub nullifier: FieldElement,

    /// The minimum expiration required for the Credential used in the proof.
    ///
    /// This precise value must be used when verifying the proof on-chain.
    pub expires_at_min: u64,
}

impl ProofResponse {
    /// Determine if constraints are satisfied given a constraint expression.
    /// Returns false if the response has an error.
    #[must_use]
    pub fn constraints_satisfied(&self, constraints: &ConstraintExpr<'_>) -> bool {
        // If there's an error, constraints cannot be satisfied
        if self.error.is_some() {
            return false;
        }

        let provided: HashSet<&str> = self
            .responses
            .iter()
            .map(|item| item.identifier.as_str())
            .collect();

        constraints.evaluate(&|t| provided.contains(t))
    }
}

impl ResponseItem {
    /// Create a new response item for a fulfilled request.
    #[must_use]
    pub const fn new(
        identifier: String,
        issuer_schema_id: u64,
        proof: ZeroKnowledgeProof,
        nullifier: FieldElement,
        expires_at_min: u64,
    ) -> Self {
        Self {
            identifier,
            issuer_schema_id,
            proof,
            nullifier,
            expires_at_min,
        }
    }
}

impl ProofRequest {
    /// Determine which requested credentials to prove given available credentials.
    ///
    /// Returns `None` if constraints (or lack thereof) cannot be satisfied with the available set.
    ///
    /// # Panics
    /// Panics if constraints are present but invalid according to the type invariants
    /// (this should not occur as constraints are provided by trusted request issuer).
    #[must_use]
    pub fn credentials_to_prove(&self, available: &HashSet<String>) -> Option<Vec<&RequestItem>> {
        // Build set of requested identifiers
        let requested: HashSet<&str> = self
            .requests
            .iter()
            .map(|r| r.identifier.as_str())
            .collect();

        // Predicate: only select if both available and requested
        let is_selectable =
            |identifier: &str| available.contains(identifier) && requested.contains(identifier);

        // If no explicit constraints: require all requested be available
        if self.constraints.is_none() {
            return if self
                .requests
                .iter()
                .all(|r| available.contains(&r.identifier))
            {
                Some(self.requests.iter().collect())
            } else {
                None
            };
        }

        // Compute selected identifiers using the constraint expression
        let selected_identifiers = select_expr(self.constraints.as_ref().unwrap(), &is_selectable)?;
        let selected_set: HashSet<&str> = selected_identifiers.into_iter().collect();

        // Return proof_requests in original order filtered by selected identifiers
        let result: Vec<&RequestItem> = self
            .requests
            .iter()
            .filter(|r| selected_set.contains(r.identifier.as_str()))
            .collect();
        Some(result)
    }

    /// Find a request item by issuer schema ID if available
    #[must_use]
    pub fn find_request_by_issuer_schema_id(&self, issuer_schema_id: u64) -> Option<&RequestItem> {
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
    ///
    /// The digest is computed as: `SHA256(nonce || action || created_at || expires_at)`.
    /// This mirrors the RP signature message format from `rp::compute_rp_signature_msg`.
    /// Note: the timestamp is encoded as big-endian to mirror the RP-side signing
    /// performed in test fixtures and the OPRF stub.
    pub fn digest_hash(&self) -> Result<[u8; 32], PrimitiveError> {
        use k256::sha2::{Digest, Sha256};
        use world_id_primitives::rp::compute_rp_signature_msg;

        let msg = compute_rp_signature_msg(*self.nonce, self.created_at, self.expires_at);
        let mut hasher = Sha256::new();
        hasher.update(&msg);
        Ok(hasher.finalize().into())
    }

    /// Gets the action value to use in the proof.
    ///
    /// When an explicit action is provided, it is returned directly.
    /// For session proofs (action is `None`), a random action is generated.
    /// Callers must cache the result when the `None` branch may be hit,
    /// since each call produces a different random value.
    #[must_use]
    pub fn computed_action<R: rand::CryptoRng + rand::RngCore>(&self, rng: &mut R) -> FieldElement {
        match self.action {
            Some(action) => action,
            None => FieldElement::random(rng),
        }
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

        // If response has an error, it failed to satisfy constraints
        if let Some(error) = &response.error {
            return Err(ValidationError::ProofGenerationFailed(error.clone()));
        }

        // Validate that expires_at_min matches for each response item
        for response_item in &response.responses {
            // Find the corresponding request item
            if let Some(request_item) = self
                .requests
                .iter()
                .find(|r| r.identifier == response_item.identifier)
            {
                let expected_expires_at_min =
                    request_item.effective_expires_at_min(self.created_at);
                if response_item.expires_at_min != expected_expires_at_min {
                    return Err(ValidationError::ExpiresAtMinMismatch(
                        response_item.identifier.clone(),
                        expected_expires_at_min,
                        response_item.expires_at_min,
                    ));
                }
            }
        }

        // Build set of provided credentials by identifier
        let provided: HashSet<&str> = response
            .responses
            .iter()
            .map(|r| r.identifier.as_str())
            .collect();

        match &self.constraints {
            // None => all requested credentials (via identifier) are required
            None => {
                for req in &self.requests {
                    if !provided.contains(req.identifier.as_str()) {
                        return Err(ValidationError::MissingCredential(req.identifier.clone()));
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

    /// Return the list of successful `issuer_schema_id`s in the response.
    /// Returns an empty vec if the response has an error.
    #[must_use]
    pub fn successful_credentials(&self) -> Vec<u64> {
        if self.error.is_some() {
            return vec![];
        }
        self.responses.iter().map(|r| r.issuer_schema_id).collect()
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
    /// The proof generation failed (response contains an error)
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),
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
    /// The `expires_at_min` value in the response does not match the expected value from the request
    #[error("Invalid expires_at_min for credential '{0}': expected {1}, got {2}")]
    ExpiresAtMinMismatch(String, u64, u64),
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
    use alloy::{
        signers::{SignerSync, local::PrivateKeySigner},
        uint,
    };
    use k256::ecdsa::SigningKey;

    // Test helpers
    fn test_signature() -> alloy::signers::Signature {
        let signer =
            PrivateKeySigner::from_signing_key(SigningKey::from_bytes(&[1u8; 32].into()).unwrap());
        signer.sign_message_sync(b"test").expect("can sign")
    }

    fn test_nonce() -> FieldElement {
        FieldElement::from(1u64)
    }

    fn test_field_element(n: u64) -> FieldElement {
        FieldElement::from(n)
    }

    #[test]
    fn constraints_all_any_nested() {
        // Build a response that has test_req_1 and test_req_2 provided
        let response = ProofResponse {
            id: "req_123".into(),
            version: RequestVersion::V1,
            session_id: None,
            error: None,
            responses: vec![
                ResponseItem {
                    identifier: "test_req_1".into(),
                    issuer_schema_id: 1,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1001),
                    expires_at_min: 1_735_689_600,
                },
                ResponseItem {
                    identifier: "test_req_2".into(),
                    issuer_schema_id: 2,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1002),
                    expires_at_min: 1_735_689_600,
                },
            ],
        };

        // all: [test_req_1, any: [test_req_2, test_req_4]]
        let expr = ConstraintExpr::All {
            all: vec![
                ConstraintNode::Type("test_req_1".into()),
                ConstraintNode::Expr(ConstraintExpr::Any {
                    any: vec![
                        ConstraintNode::Type("test_req_2".into()),
                        ConstraintNode::Type("test_req_4".into()),
                    ],
                }),
            ],
        };

        assert!(response.constraints_satisfied(&expr));

        // all: [test_req_1, test_req_3] should fail because test_req_3 is not in response
        let fail_expr = ConstraintExpr::All {
            all: vec![
                ConstraintNode::Type("test_req_1".into()),
                ConstraintNode::Type("test_req_3".into()),
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
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: None,
            action: Some(FieldElement::ZERO),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![RequestItem {
                identifier: "orb".into(),
                issuer_schema_id: 1,
                signal: Some("test_signal".into()),
                genesis_issued_at_min: None,
                expires_at_min: None,
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
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: None,
            action: Some(FieldElement::ZERO),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    identifier: "orb".into(),
                    issuer_schema_id: 1,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "document".into(),
                    issuer_schema_id: 2,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
            ],
            constraints: None,
        };

        let ok = ProofResponse {
            id: "req_1".into(),
            version: RequestVersion::V1,
            session_id: None,
            error: None,
            responses: vec![
                ResponseItem {
                    identifier: "orb".into(),
                    issuer_schema_id: 1,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1001),
                    expires_at_min: 1_735_689_600,
                },
                ResponseItem {
                    identifier: "document".into(),
                    issuer_schema_id: 2,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1002),
                    expires_at_min: 1_735_689_600,
                },
            ],
        };
        assert!(request.validate_response(&ok).is_ok());

        let missing = ProofResponse {
            id: "req_1".into(),
            version: RequestVersion::V1,
            session_id: None,
            error: None,
            responses: vec![ResponseItem {
                identifier: "orb".into(),
                issuer_schema_id: 1,
                proof: ZeroKnowledgeProof::default(),
                nullifier: test_field_element(1001),
                expires_at_min: 1_735_689_600,
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
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: None,
            action: Some(test_field_element(1)),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![RequestItem {
                identifier: "orb".into(),
                issuer_schema_id: 1,
                signal: None,
                genesis_issued_at_min: None,
                expires_at_min: None,
            }],
            constraints: Some(deep),
        };

        let response = ProofResponse {
            id: "req_2".into(),
            version: RequestVersion::V1,
            session_id: None,
            error: None,
            responses: vec![ResponseItem {
                identifier: "orb".into(),
                issuer_schema_id: 1,
                proof: ZeroKnowledgeProof::default(),
                nullifier: test_field_element(1001),
                expires_at_min: 1_735_689_600,
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

        let expr = ConstraintExpr::All {
            all: vec![
                ConstraintNode::Type("test_req_10".into()),
                ConstraintNode::Expr(ConstraintExpr::Any {
                    any: vec![
                        ConstraintNode::Type("test_req_11".into()),
                        ConstraintNode::Type("test_req_12".into()),
                        ConstraintNode::Type("test_req_13".into()),
                        ConstraintNode::Type("test_req_14".into()),
                    ],
                }),
                ConstraintNode::Expr(ConstraintExpr::Any {
                    any: vec![
                        ConstraintNode::Type("test_req_15".into()),
                        ConstraintNode::Type("test_req_16".into()),
                        ConstraintNode::Type("test_req_17".into()),
                        ConstraintNode::Type("test_req_18".into()),
                    ],
                }),
            ],
        };

        let request = ProofRequest {
            id: "req_nodes_ok".into(),
            version: RequestVersion::V1,
            created_at: 1_735_689_600,
            expires_at: 1_735_689_600,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: None,
            action: Some(test_field_element(5)),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    identifier: "test_req_10".into(),
                    issuer_schema_id: 10,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_11".into(),
                    issuer_schema_id: 11,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_12".into(),
                    issuer_schema_id: 12,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_13".into(),
                    issuer_schema_id: 13,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_14".into(),
                    issuer_schema_id: 14,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_15".into(),
                    issuer_schema_id: 15,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_16".into(),
                    issuer_schema_id: 16,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_17".into(),
                    issuer_schema_id: 17,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_18".into(),
                    issuer_schema_id: 18,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
            ],
            constraints: Some(expr),
        };

        // Provide just enough to satisfy both any-groups and the single type
        let response = ProofResponse {
            id: "req_nodes_ok".into(),
            version: RequestVersion::V1,
            session_id: None,
            error: None,
            responses: vec![
                ResponseItem {
                    identifier: "test_req_10".into(),
                    issuer_schema_id: 10,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1010),
                    expires_at_min: 1_735_689_600,
                },
                ResponseItem {
                    identifier: "test_req_11".into(),
                    issuer_schema_id: 11,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1011),
                    expires_at_min: 1_735_689_600,
                },
                ResponseItem {
                    identifier: "test_req_15".into(),
                    issuer_schema_id: 15,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1015),
                    expires_at_min: 1_735_689_600,
                },
            ],
        };

        // Should not exceed size and should validate OK
        assert!(request.validate_response(&response).is_ok());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
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
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: None,
            action: Some(test_field_element(1)),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    identifier: "test_req_20".into(),
                    issuer_schema_id: 20,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_21".into(),
                    issuer_schema_id: 21,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_22".into(),
                    issuer_schema_id: 22,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_23".into(),
                    issuer_schema_id: 23,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_24".into(),
                    issuer_schema_id: 24,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_25".into(),
                    issuer_schema_id: 25,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_26".into(),
                    issuer_schema_id: 26,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_27".into(),
                    issuer_schema_id: 27,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_28".into(),
                    issuer_schema_id: 28,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_29".into(),
                    issuer_schema_id: 29,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
            ],
            constraints: Some(expr),
        };

        // Response content is irrelevant; validation should fail before evaluation due to size
        let response = ProofResponse {
            id: "req_nodes_too_many".into(),
            version: RequestVersion::V1,
            session_id: None,
            error: None,
            responses: vec![ResponseItem {
                identifier: "test_req_20".into(),
                issuer_schema_id: 20,
                proof: ZeroKnowledgeProof::default(),
                nullifier: test_field_element(1020),
                expires_at_min: 1_735_689_600,
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
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: Some(test_field_element(55)),
            action: Some(test_field_element(1)),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![RequestItem {
                identifier: "test_req_1".into(),
                issuer_schema_id: 1,
                signal: Some("abcd-efgh-ijkl".into()),
                genesis_issued_at_min: Some(1_725_381_192),
                expires_at_min: None,
            }],
            constraints: None,
        };

        assert_eq!(req.id, "req_18c0f7f03e7d");
        assert_eq!(req.requests.len(), 1);

        // Build matching successful response
        let resp = ProofResponse {
            id: req.id.clone(),
            version: RequestVersion::V1,
            session_id: None,
            error: None,
            responses: vec![ResponseItem {
                identifier: "test_req_1".into(),
                issuer_schema_id: 1,
                proof: ZeroKnowledgeProof::default(),
                nullifier: test_field_element(1001),
                expires_at_min: 1_725_381_192,
            }],
        };
        assert!(req.validate_response(&resp).is_ok());
    }

    #[test]
    fn request_multiple_credentials_all_constraint_and_missing() {
        let req = ProofRequest {
            id: "req_18c0f7f03e7d".into(),
            version: RequestVersion::V1,
            created_at: 1_725_381_192,
            expires_at: 1_725_381_492,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: None,
            action: Some(test_field_element(1)),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    identifier: "test_req_1".into(),
                    issuer_schema_id: 1,
                    signal: Some("abcd-efgh-ijkl".into()),
                    genesis_issued_at_min: Some(1_725_381_192),
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_2".into(),
                    issuer_schema_id: 2,
                    signal: Some("abcd-efgh-ijkl".into()),
                    genesis_issued_at_min: Some(1_725_381_192),
                    expires_at_min: None,
                },
            ],
            constraints: Some(ConstraintExpr::All {
                all: vec![
                    ConstraintNode::Type("test_req_1".into()),
                    ConstraintNode::Type("test_req_2".into()),
                ],
            }),
        };

        // Build response that fails constraints (test_req_1 is missing)
        let resp = ProofResponse {
            id: req.id.clone(),
            version: RequestVersion::V1,
            session_id: None,
            error: None,
            responses: vec![ResponseItem {
                identifier: "test_req_2".into(),
                issuer_schema_id: 2,
                proof: ZeroKnowledgeProof::default(),
                nullifier: test_field_element(1001),
                expires_at_min: 1_725_381_192,
            }],
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
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: None,
            action: Some(test_field_element(1)),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    identifier: "test_req_1".into(),
                    issuer_schema_id: 1,
                    signal: Some("abcd-efgh-ijkl".into()),
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_2".into(),
                    issuer_schema_id: 2,
                    signal: Some("mnop-qrst-uvwx".into()),
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_3".into(),
                    issuer_schema_id: 3,
                    signal: Some("abcd-efgh-ijkl".into()),
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
            ],
            constraints: Some(ConstraintExpr::All {
                all: vec![
                    ConstraintNode::Type("test_req_3".into()),
                    ConstraintNode::Expr(ConstraintExpr::Any {
                        any: vec![
                            ConstraintNode::Type("test_req_1".into()),
                            ConstraintNode::Type("test_req_2".into()),
                        ],
                    }),
                ],
            }),
        };

        // Satisfy nested any with 0x1 + 0x3
        let resp = ProofResponse {
            id: req.id.clone(),
            version: RequestVersion::V1,
            session_id: None,
            error: None,
            responses: vec![
                ResponseItem {
                    identifier: "test_req_3".into(),
                    issuer_schema_id: 3,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1001),
                    expires_at_min: 1_725_381_192,
                },
                ResponseItem {
                    identifier: "test_req_1".into(),
                    issuer_schema_id: 1,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1002),
                    expires_at_min: 1_725_381_192,
                },
            ],
        };

        assert!(req.validate_response(&resp).is_ok());
    }

    #[test]
    fn response_json_parse() {
        // Success OK - using default proof (all zeros) in hex
        let ok_json = r#"{
  "id": "req_18c0f7f03e7d",
  "version": 1,
  "responses": [
    {
      "identifier": "orb",
      "issuer_schema_id": 100,
      "proof": "00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000",
      "nullifier": "0x00000000000000000000000000000000000000000000000000000000000003e9",
      "expires_at_min": 1725381192
    }
  ]
}"#;

        let ok = ProofResponse::from_json(ok_json).unwrap();
        assert_eq!(ok.successful_credentials(), vec![100]);

        // Success with Session
        let sess_json = r#"{
  "id": "req_18c0f7f03e7d",
  "version": 1,
  "session_id": "0x00000000000000000000000000000000000000000000000000000000000003ea",
  "responses": [
    {
      "identifier": "orb",
      "issuer_schema_id": 100,
      "proof": "00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000",
      "nullifier": "0x00000000000000000000000000000000000000000000000000000000000003e9",
      "expires_at_min": 1725381192
    }
  ]
}"#;
        let sess = ProofResponse::from_json(sess_json).unwrap();
        assert_eq!(sess.successful_credentials(), vec![100]);
        assert!(sess.session_id.is_some());
    }

    /// Test duplicate detection by creating a serialized `ProofRequest` with duplicates
    /// and then trying to parse it with `from_json` which should detect the duplicates
    #[test]
    fn request_rejects_duplicate_issuer_schema_ids_on_parse() {
        let req = ProofRequest {
            id: "req_dup".into(),
            version: RequestVersion::V1,
            created_at: 1_725_381_192,
            expires_at: 1_725_381_492,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: None,
            action: Some(test_field_element(5)),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    identifier: "test_req_1".into(),
                    issuer_schema_id: 1,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "test_req_2".into(),
                    issuer_schema_id: 1, // Duplicate!
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
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
    fn response_with_error_has_empty_responses_and_fails_validation() {
        let request = ProofRequest {
            id: "req_error".into(),
            version: RequestVersion::V1,
            created_at: 1_735_689_600,
            expires_at: 1_735_689_600,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: None,
            action: Some(FieldElement::ZERO),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![RequestItem {
                identifier: "orb".into(),
                issuer_schema_id: 1,
                signal: None,
                genesis_issued_at_min: None,
                expires_at_min: None,
            }],
            constraints: None,
        };

        // Response with error should have empty responses array
        let error_response = ProofResponse {
            id: "req_error".into(),
            version: RequestVersion::V1,
            session_id: None,
            error: Some("credential_not_available".into()),
            responses: vec![], // Empty when error is present
        };

        // Validation should fail with ProofGenerationFailed
        let err = request.validate_response(&error_response).unwrap_err();
        assert!(matches!(err, ValidationError::ProofGenerationFailed(_)));
        if let ValidationError::ProofGenerationFailed(msg) = err {
            assert_eq!(msg, "credential_not_available");
        }

        // successful_credentials should return empty vec when error is present
        assert_eq!(error_response.successful_credentials(), Vec::<u64>::new());

        // constraints_satisfied should return false when error is present
        let expr = ConstraintExpr::All {
            all: vec![ConstraintNode::Type("orb".into())],
        };
        assert!(!error_response.constraints_satisfied(&expr));
    }

    #[test]
    fn response_error_json_parse() {
        // Error response JSON
        let error_json = r#"{
  "id": "req_error",
  "version": 1,
  "error": "credential_not_available",
  "responses": []
}"#;

        let error_resp = ProofResponse::from_json(error_json).unwrap();
        assert_eq!(error_resp.error, Some("credential_not_available".into()));
        assert_eq!(error_resp.responses.len(), 0);
        assert_eq!(error_resp.successful_credentials(), Vec::<u64>::new());
    }

    #[test]
    fn credentials_to_prove_none_constraints_requires_all_and_drops_if_missing() {
        let req = ProofRequest {
            id: "req".into(),
            version: RequestVersion::V1,
            created_at: 1_735_689_600,
            expires_at: 1_735_689_600, // 2025-01-01 00:00:00 UTC
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: None,
            action: Some(test_field_element(5)),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    identifier: "orb".into(),
                    issuer_schema_id: 100,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "passport".into(),
                    issuer_schema_id: 101,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
            ],
            constraints: None,
        };

        let available_ok: HashSet<String> = ["orb".to_string(), "passport".to_string()]
            .into_iter()
            .collect();
        let sel_ok = req.credentials_to_prove(&available_ok).unwrap();
        assert_eq!(sel_ok.len(), 2);
        assert_eq!(sel_ok[0].issuer_schema_id, 100);
        assert_eq!(sel_ok[1].issuer_schema_id, 101);

        let available_missing: HashSet<String> = std::iter::once("orb".to_string()).collect();
        assert!(req.credentials_to_prove(&available_missing).is_none());
    }

    #[test]
    fn credentials_to_prove_with_constraints_all_and_any() {
        // proof_requests: orb, passport, national-id
        let orb_id = 100;
        let passport_id = 101;
        let national_id_id = 102;

        let req = ProofRequest {
            id: "req".into(),
            version: RequestVersion::V1,
            created_at: 1_735_689_600,
            expires_at: 1_735_689_600, // 2025-01-01 00:00:00 UTC
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: None,
            action: Some(test_field_element(1)),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    identifier: "orb".into(),
                    issuer_schema_id: orb_id,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "passport".into(),
                    issuer_schema_id: passport_id,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
                RequestItem {
                    identifier: "national_id".into(),
                    issuer_schema_id: national_id_id,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None,
                },
            ],
            constraints: Some(ConstraintExpr::All {
                all: vec![
                    ConstraintNode::Type("orb".into()),
                    ConstraintNode::Expr(ConstraintExpr::Any {
                        any: vec![
                            ConstraintNode::Type("passport".into()),
                            ConstraintNode::Type("national_id".into()),
                        ],
                    }),
                ],
            }),
        };

        // Available has orb + passport → should pick [orb, passport]
        let available1: HashSet<String> = ["orb".to_string(), "passport".to_string()]
            .into_iter()
            .collect();
        let sel1 = req.credentials_to_prove(&available1).unwrap();
        assert_eq!(sel1.len(), 2);
        assert_eq!(sel1[0].issuer_schema_id, orb_id);
        assert_eq!(sel1[1].issuer_schema_id, passport_id);

        // Available has orb + national-id → should pick [orb, national-id]
        let available2: HashSet<String> = ["orb".to_string(), "national_id".to_string()]
            .into_iter()
            .collect();
        let sel2 = req.credentials_to_prove(&available2).unwrap();
        assert_eq!(sel2.len(), 2);
        assert_eq!(sel2[0].issuer_schema_id, orb_id);
        assert_eq!(sel2[1].issuer_schema_id, national_id_id);

        // Missing orb → cannot satisfy "all" → None
        let available3: HashSet<String> = std::iter::once("passport".to_string()).collect();
        assert!(req.credentials_to_prove(&available3).is_none());
    }

    #[test]
    fn request_item_effective_expires_at_min_defaults_to_created_at() {
        let request_created_at = 1_735_689_600; // 2025-01-01 00:00:00 UTC
        let custom_expires_at = 1_735_862_400; // 2025-01-03 00:00:00 UTC

        // When expires_at_min is None, should use request_created_at
        let item_with_none = RequestItem {
            identifier: "test".into(),
            issuer_schema_id: 100,
            signal: None,
            genesis_issued_at_min: None,
            expires_at_min: None,
        };
        assert_eq!(
            item_with_none.effective_expires_at_min(request_created_at),
            request_created_at,
            "When expires_at_min is None, should default to request created_at"
        );

        // When expires_at_min is Some, should use that value
        let item_with_custom = RequestItem {
            identifier: "test".into(),
            issuer_schema_id: 100,
            signal: None,
            genesis_issued_at_min: None,
            expires_at_min: Some(custom_expires_at),
        };
        assert_eq!(
            item_with_custom.effective_expires_at_min(request_created_at),
            custom_expires_at,
            "When expires_at_min is Some, should use that explicit value"
        );
    }

    #[test]
    fn validate_response_checks_expires_at_min_matches() {
        let request_created_at = 1_735_689_600; // 2025-01-01 00:00:00 UTC
        let custom_expires_at = 1_735_862_400; // 2025-01-03 00:00:00 UTC

        // Request with one item that has no explicit expires_at_min (defaults to created_at)
        // and one with an explicit expires_at_min
        let request = ProofRequest {
            id: "req_expires_test".into(),
            version: RequestVersion::V1,
            created_at: request_created_at,
            expires_at: request_created_at + 300,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: None,
            action: Some(test_field_element(1)),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![
                RequestItem {
                    identifier: "orb".into(),
                    issuer_schema_id: 100,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: None, // Should default to request_created_at
                },
                RequestItem {
                    identifier: "document".into(),
                    issuer_schema_id: 101,
                    signal: None,
                    genesis_issued_at_min: None,
                    expires_at_min: Some(custom_expires_at), // Explicit value
                },
            ],
            constraints: None,
        };

        // Valid response with matching expires_at_min values
        let valid_response = ProofResponse {
            id: "req_expires_test".into(),
            version: RequestVersion::V1,
            session_id: None,
            error: None,
            responses: vec![
                ResponseItem {
                    identifier: "orb".into(),
                    issuer_schema_id: 100,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1001),
                    expires_at_min: request_created_at, // Matches default
                },
                ResponseItem {
                    identifier: "document".into(),
                    issuer_schema_id: 101,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1002),
                    expires_at_min: custom_expires_at, // Matches explicit value
                },
            ],
        };
        assert!(request.validate_response(&valid_response).is_ok());

        // Invalid response with mismatched expires_at_min for first item
        let invalid_response_1 = ProofResponse {
            id: "req_expires_test".into(),
            version: RequestVersion::V1,
            session_id: None,
            error: None,
            responses: vec![
                ResponseItem {
                    identifier: "orb".into(),
                    issuer_schema_id: 100,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1001),
                    expires_at_min: custom_expires_at, // Wrong! Should be request_created_at
                },
                ResponseItem {
                    identifier: "document".into(),
                    issuer_schema_id: 101,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1002),
                    expires_at_min: custom_expires_at,
                },
            ],
        };
        let err1 = request.validate_response(&invalid_response_1).unwrap_err();
        assert!(matches!(
            err1,
            ValidationError::ExpiresAtMinMismatch(_, _, _)
        ));
        if let ValidationError::ExpiresAtMinMismatch(identifier, expected, got) = err1 {
            assert_eq!(identifier, "orb");
            assert_eq!(expected, request_created_at);
            assert_eq!(got, custom_expires_at);
        }

        // Invalid response with mismatched expires_at_min for second item
        let invalid_response_2 = ProofResponse {
            id: "req_expires_test".into(),
            version: RequestVersion::V1,
            session_id: None,
            error: None,
            responses: vec![
                ResponseItem {
                    identifier: "orb".into(),
                    issuer_schema_id: 100,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1001),
                    expires_at_min: request_created_at,
                },
                ResponseItem {
                    identifier: "document".into(),
                    issuer_schema_id: 101,
                    proof: ZeroKnowledgeProof::default(),
                    nullifier: test_field_element(1002),
                    expires_at_min: request_created_at, // Wrong! Should be custom_expires_at
                },
            ],
        };
        let err2 = request.validate_response(&invalid_response_2).unwrap_err();
        assert!(matches!(
            err2,
            ValidationError::ExpiresAtMinMismatch(_, _, _)
        ));
        if let ValidationError::ExpiresAtMinMismatch(identifier, expected, got) = err2 {
            assert_eq!(identifier, "document");
            assert_eq!(expected, custom_expires_at);
            assert_eq!(got, request_created_at);
        }
    }

    #[test]
    fn computed_action_returns_explicit_action() {
        let action = test_field_element(42);
        let request = ProofRequest {
            id: "req".into(),
            version: RequestVersion::V1,
            created_at: 1_700_000_000,
            expires_at: 1_700_100_000,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: None,
            action: Some(action),
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![],
            constraints: None,
        };
        assert_eq!(request.computed_action(&mut rand::rngs::OsRng), action);
    }

    #[test]
    fn computed_action_generates_random_when_none() {
        let request = ProofRequest {
            id: "req".into(),
            version: RequestVersion::V1,
            created_at: 1_700_000_000,
            expires_at: 1_700_100_000,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(uint!(1_U160)),
            session_id: Some(test_field_element(99)),
            action: None,
            signature: test_signature(),
            nonce: test_nonce(),
            requests: vec![],
            constraints: None,
        };

        let action1 = request.computed_action(&mut rand::rngs::OsRng);
        let action2 = request.computed_action(&mut rand::rngs::OsRng);
        // Each call generates a different random action
        assert_ne!(action1, action2);
    }
}
