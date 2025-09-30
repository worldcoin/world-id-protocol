use crate::requests::constraints::ConstraintExpr;
use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use time::OffsetDateTime;

/// Authenticator request
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatorRequest {
    /// Unique identifier for this request
    pub id: String,
    /// Version of the request
    pub version: u8,
    /// ISO8601 timestamp when created
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub created_at: Option<OffsetDateTime>,
    /// ISO8601 timestamp when request expires
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Registered RP id (chain-level identifier)
    pub rp_id: U256,
    /// App id
    pub app_id: String,
    /// Encoded action string (act_...)
    pub encoded_action: String,
    /// Credential requests
    pub requests: Vec<CredentialRequest>,
    /// Constraint expression (all/any) optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<ConstraintExpr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// Credential type string
    #[serde(rename = "type")]
    pub credential_type: String,
    /// Optional signal commitment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

/// Authenticator response per docs spec
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatorResponse {
    /// Echo request id
    pub id: String,
    /// Version corresponding to request version
    pub version: u8,
    /// Per-credential results
    pub responses: Vec<ResponseItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseItem {
    /// Credential type string this item refers to
    #[serde(rename = "type")]
    pub credential_type: String,
    /// Proof payload when applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// Computed nullifier when applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullifier: Option<String>,
    /// Session identifier if established
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Present if credential not provided
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AuthenticatorResponse {
    /// Determine if constraints are satisfied given an optional constraint expression.
    pub fn constraints_satisfied(&self, constraints: Option<&ConstraintExpr>) -> bool {
        match constraints {
            None => true,
            Some(expr) => {
                // Build a set of provided credential types that are successful (no error)
                let provided: HashSet<&str> = self
                    .responses
                    .iter()
                    .filter(|item| item.error.is_none())
                    .map(|item| item.credential_type.as_str())
                    .collect();
                expr.evaluate(&|t| provided.contains(t))
            }
        }
    }
}

impl AuthenticatorRequest {
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
        if self.id != response.id {
            return Err(ValidationError::RequestIdMismatch);
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
        serde_json::from_str(json)
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
    #[error("Missing required credential: {0}")]
    MissingCredential(String),
    #[error("Constraints not satisfied")]
    ConstraintNotSatisfied,
    #[error("Constraints nesting exceeds maximum allowed depth")]
    ConstraintTooDeep,
}


