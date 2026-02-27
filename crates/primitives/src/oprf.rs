use ark_bn254::Bn254;
use ark_serde_compat::babyjubjub;
use circom_types::groth16::Proof;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::rp::RpId;

/// Maximum size of a WebSocket close frame reason in bytes (RFC 6455).
pub const MAX_CLOSE_REASON_BYTES: usize = 123;

/// Structured OPRF authentication error, serialized as JSON inside WebSocket
/// close frame reason fields.
///
/// Each variant maps to a `"type"` tag in the JSON representation. Variants
/// that carry client-safe detail include typed fields.
///
/// # Wire format examples
///
/// - `{"type":"invalid_proof"}`
/// - `{"type":"unknown_rp","rp_id":"42"}`
/// - `{"type":"internal_server_error","error_id":"<uuid>"}`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OprfRequestErrorResponse {
    /// The zero-knowledge proof failed verification.
    InvalidProof,
    /// The provided Merkle root is not valid.
    InvalidMerkleRoot,
    /// The request timestamp is too far from the current time.
    TimestampTooLarge,
    /// The RP signature on the request could not be recovered.
    InvalidSignature {
        /// Human-readable description of the signature failure.
        detail: String,
    },
    /// The recovered signer is not an authorized signer for this RP.
    InvalidSigner,
    /// The same signature was already used in a previous request.
    DuplicateSignature,
    /// The specified RP ID does not exist in the registry.
    UnknownRp {
        /// The RP ID that was not found.
        rp_id: String,
    },
    /// The RP exists but has been deactivated.
    RpInactive,
    /// The provided action value is not valid.
    InvalidAction,
    /// The specified schema issuer ID does not exist in the registry.
    UnknownSchemaIssuer {
        /// The schema issuer ID that was not found.
        issuer_schema_id: String,
    },
    /// A backend dependency (blockchain RPC, cache) is temporarily unavailable.
    ServiceUnavailable,
    /// An unexpected internal error occurred. Check server logs using the correlation ID.
    InternalServerError {
        /// Correlation UUID for looking up details in server logs.
        error_id: String,
    },
}

impl OprfRequestErrorResponse {
    /// Serializes this response to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("OprfRequestErrorResponse is always serializable")
    }

    /// Attempts to deserialize an `OprfRequestErrorResponse` from a JSON string.
    pub fn from_json(s: &str) -> Option<Self> {
        serde_json::from_str(s).ok()
    }
}

impl fmt::Display for OprfRequestErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature { detail } => write!(f, "invalid_signature: {detail}"),
            Self::UnknownRp { rp_id } => write!(f, "unknown_rp: {rp_id}"),
            Self::UnknownSchemaIssuer { issuer_schema_id } => {
                write!(f, "unknown_schema_issuer: {issuer_schema_id}")
            }
            Self::InternalServerError { error_id } => {
                write!(f, "internal_server_error: {error_id}")
            }
            other => {
                let json = serde_json::to_value(other).expect("always serializable");
                f.write_str(json["type"].as_str().unwrap_or("unknown"))
            }
        }
    }
}

/// A module identifier for OPRF evaluations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OprfModule {
    /// Oprf module for generating nullifiers
    Nullifier,
    /// Oprf module for generating credential blinding factors
    CredentialBlindingFactor,
}

impl std::fmt::Display for OprfModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nullifier => write!(f, "nullifier"),
            Self::CredentialBlindingFactor => write!(f, "credential_blinding_factor"),
        }
    }
}

/// A request sent by a client for OPRF nullifier authentication.
#[derive(Clone, Serialize, Deserialize)]
pub struct NullifierOprfRequestAuthV1 {
    /// Zero-knowledge proof provided by the user.
    pub proof: Proof<Bn254>,
    /// The action
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    pub action: ark_babyjubjub::Fq,
    /// The nonce
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    pub nonce: ark_babyjubjub::Fq,
    /// The Merkle root associated with this request.
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    pub merkle_root: ark_babyjubjub::Fq,
    /// The current time stamp (unix secs)
    pub current_time_stamp: u64,
    /// Expiration timestamp of the request (unix secs)
    pub expiration_timestamp: u64,
    /// The RP's signature on the request, see `compute_rp_signature_msg` for details.
    pub signature: alloy_primitives::Signature,
    /// The `rp_id`
    pub rp_id: RpId,
}

/// A request sent by a client for OPRF credential blinding factor authentication.
#[derive(Clone, Serialize, Deserialize)]
pub struct CredentialBlindingFactorOprfRequestAuthV1 {
    /// Zero-knowledge proof provided by the user.
    pub proof: Proof<Bn254>,
    /// The action
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    pub action: ark_babyjubjub::Fq,
    /// The nonce
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    pub nonce: ark_babyjubjub::Fq,
    /// The Merkle root associated with this request.
    #[serde(serialize_with = "babyjubjub::serialize_fq")]
    #[serde(deserialize_with = "babyjubjub::deserialize_fq")]
    pub merkle_root: ark_babyjubjub::Fq,
    /// The `issuer_schema_id` in the `CredentialSchemaIssuerRegistry` contract
    pub issuer_schema_id: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip_all_variants() {
        let variants = [
            OprfRequestErrorResponse::InvalidProof,
            OprfRequestErrorResponse::InvalidMerkleRoot,
            OprfRequestErrorResponse::TimestampTooLarge,
            OprfRequestErrorResponse::InvalidSignature {
                detail: "invalid parity: 5".into(),
            },
            OprfRequestErrorResponse::InvalidSigner,
            OprfRequestErrorResponse::DuplicateSignature,
            OprfRequestErrorResponse::UnknownRp { rp_id: "42".into() },
            OprfRequestErrorResponse::RpInactive,
            OprfRequestErrorResponse::InvalidAction,
            OprfRequestErrorResponse::UnknownSchemaIssuer {
                issuer_schema_id: "99".into(),
            },
            OprfRequestErrorResponse::ServiceUnavailable,
            OprfRequestErrorResponse::InternalServerError {
                error_id: "00000000-0000-0000-0000-000000000000".into(),
            },
        ];
        for variant in &variants {
            let json = variant.to_json();
            let parsed = OprfRequestErrorResponse::from_json(&json).unwrap();
            assert_eq!(&parsed, variant, "roundtrip failed for {json}");
        }
    }

    #[test]
    fn unit_variant_wire_format() {
        let resp = OprfRequestErrorResponse::InvalidProof;
        assert_eq!(resp.to_json(), r#"{"type":"invalid_proof"}"#);
    }

    #[test]
    fn data_variant_wire_format() {
        let resp = OprfRequestErrorResponse::UnknownRp { rp_id: "42".into() };
        assert_eq!(resp.to_json(), r#"{"type":"unknown_rp","rp_id":"42"}"#);
    }

    #[test]
    fn from_json_invalid_input() {
        assert!(OprfRequestErrorResponse::from_json("not json").is_none());
        assert!(OprfRequestErrorResponse::from_json("").is_none());
        assert!(OprfRequestErrorResponse::from_json("{}").is_none());
        assert!(OprfRequestErrorResponse::from_json(r#"{"type":"totally_unknown_code"}"#).is_none());
    }

    #[test]
    fn all_responses_fit_close_frame() {
        let cases = [
            OprfRequestErrorResponse::InvalidProof,
            OprfRequestErrorResponse::InvalidMerkleRoot,
            OprfRequestErrorResponse::TimestampTooLarge,
            OprfRequestErrorResponse::InvalidSigner,
            OprfRequestErrorResponse::DuplicateSignature,
            OprfRequestErrorResponse::RpInactive,
            OprfRequestErrorResponse::InvalidAction,
            OprfRequestErrorResponse::ServiceUnavailable,
            OprfRequestErrorResponse::UnknownRp {
                rp_id: u64::MAX.to_string(),
            },
            OprfRequestErrorResponse::UnknownSchemaIssuer {
                issuer_schema_id: u64::MAX.to_string(),
            },
            OprfRequestErrorResponse::InvalidSignature {
                detail: format!("invalid parity: {}", u64::MAX),
            },
            OprfRequestErrorResponse::InvalidSignature {
                detail: format!(
                    "{}",
                    hex::FromHexError::InvalidHexCharacter { c: 'g', index: 129 }
                ),
            },
            OprfRequestErrorResponse::InternalServerError {
                error_id: uuid::Uuid::max().to_string(),
            },
        ];
        for resp in &cases {
            let json = resp.to_json();
            assert!(
                json.len() <= MAX_CLOSE_REASON_BYTES,
                "{resp:?} is {} bytes ({json}), exceeds {MAX_CLOSE_REASON_BYTES}",
                json.len(),
            );
        }
    }
}
