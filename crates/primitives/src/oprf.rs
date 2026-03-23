use ark_bn254::Bn254;
use ark_serde_compat::babyjubjub;
use circom_types::groth16::Proof;
use serde::{Deserialize, Serialize};
use taceo_oprf::types::api::OprfRequestAuthenticatorError;

use crate::rp::RpId;

/// A module identifier for OPRF evaluations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OprfModule {
    /// Oprf module for generating nullifiers
    Nullifier,
    /// Oprf module for generating credential blinding factors
    CredentialBlindingFactor,
    /// Oprf module for generating internal nullifiers for sessions proofs and the `session_id_r_seed`
    Session,
}

impl std::fmt::Display for OprfModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nullifier => write!(f, "nullifier"),
            Self::CredentialBlindingFactor => write!(f, "credential_blinding_factor"),
            Self::Session => write!(f, "session"),
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

/// Concrete error type returned by OPRF request authentication.
///
/// Variants map 1-to-1 with the numeric close-frame error codes in [`error_codes`], which are
/// sent to the client over the WebSocket connection when authentication fails.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WorldIdRequestAuthError {
    /// Unknown RP.
    #[error("unknown RP")]
    UnknownRp,
    /// Inactive RP, an RP that was deactivated.
    #[error("inactive RP")]
    InactiveRp,
    /// Unknown schema-issuer.
    #[error("unknown schema-issuer")]
    UnknownSchemaIssuer,
    /// The request timestamp is too far from the current time.
    #[error("request timestamp too old")]
    TimeStampTooOld,
    /// The RP's signature on the request could not be verified.
    #[error("invalid RP signature")]
    InvalidRpSignature,
    /// A duplicate signature was detected (replay attack).
    #[error("duplicate signature")]
    DuplicateNonce,
    /// The provided Merkle root is not valid.
    #[error("invalid merkle root")]
    InvalidMerkleRoot,
    /// The client query proof did not verify.
    #[error("invalid query proof")]
    InvalidQueryProof,
    /// Invalid action for schema-issuer blinding
    #[error("invalid action - must be 0 for schema-issuer blinding")]
    InvalidActionSchemaIssuer,
    /// Invalid action for nullifier computation
    #[error("invalid action - MSB must be 0x00 for nullifier")]
    InvalidActionNullifier,
    /// Invalid action for nullifier computation
    #[error(
        "invalid action - MSB must be 0x00 for internal nullifier or 0x01 for session_id_r_seed"
    )]
    InvalidActionSession,
    /// Internal server error.
    #[error("internal server error")]
    Internal,
    /// Unknown error code not mapped to a known variant.
    #[error("unknown error: {0}")]
    Unknown(u16),
}

impl From<u16> for WorldIdRequestAuthError {
    fn from(value: u16) -> Self {
        match value {
            error_codes::UNKNOWN_RP => Self::UnknownRp,
            error_codes::INACTIVE_RP => Self::InactiveRp,
            error_codes::TIMESTAMP_TOO_OLD => Self::TimeStampTooOld,
            error_codes::INVALID_RP_SIGNATURE => Self::InvalidRpSignature,
            error_codes::DUPLICATE_NONCE => Self::DuplicateNonce,
            error_codes::INVALID_MERKLE_ROOT => Self::InvalidMerkleRoot,
            error_codes::INVALID_QUERY_PROOF => Self::InvalidQueryProof,
            error_codes::INVALID_ACTION_SCHEMA_ISSUER => Self::InvalidActionSchemaIssuer,
            error_codes::UNKNOWN_SCHEMA_ISSUER => Self::UnknownSchemaIssuer,
            error_codes::INVALID_ACTION_NULLIFIER => Self::InvalidActionNullifier,
            error_codes::INVALID_ACTION_SESSION => Self::InvalidActionSession,
            error_codes::INTERNAL => Self::Internal,
            other => Self::Unknown(other),
        }
    }
}

/// Numeric close-frame error codes sent to the client when [`WorldIdRequestAuthError`] occurs.
pub mod error_codes {
    /// Error code for [`super::WorldIdRequestAuthError::UnknownRp`].
    pub const UNKNOWN_RP: u16 = 4500;
    /// Error code for [`super::WorldIdRequestAuthError::TimeStampTooOld`].
    pub const TIMESTAMP_TOO_OLD: u16 = 4501;
    /// Error code for [`super::WorldIdRequestAuthError::InvalidRpSignature`].
    pub const INVALID_RP_SIGNATURE: u16 = 4502;
    /// Error code for [`super::WorldIdRequestAuthError::DuplicateNonce`].
    pub const DUPLICATE_NONCE: u16 = 4503;
    /// Error code for [`super::WorldIdRequestAuthError::InvalidMerkleRoot`].
    pub const INVALID_MERKLE_ROOT: u16 = 4504;
    /// Error code for [`super::WorldIdRequestAuthError::InvalidQueryProof`].
    pub const INVALID_QUERY_PROOF: u16 = 4505;
    /// Error code for [`super::WorldIdRequestAuthError::InvalidActionSchemaIssuer`].
    pub const INVALID_ACTION_SCHEMA_ISSUER: u16 = 4506;
    /// Error code for [`super::WorldIdRequestAuthError::UnknownSchemaIssuer`].
    pub const UNKNOWN_SCHEMA_ISSUER: u16 = 4507;
    /// Error code for [`super::WorldIdRequestAuthError::InvalidActionNullifier`].
    pub const INVALID_ACTION_NULLIFIER: u16 = 4508;
    /// Error code for [`super::WorldIdRequestAuthError::InvalidActionSession`].
    pub const INVALID_ACTION_SESSION: u16 = 4509;
    /// Error code for [`super::WorldIdRequestAuthError::InactiveRp`].
    pub const INACTIVE_RP: u16 = 4510;
    /// Error code for [`super::WorldIdRequestAuthError::Internal`].
    pub const INTERNAL: u16 = 1011;
}

impl From<WorldIdRequestAuthError> for OprfRequestAuthenticatorError {
    fn from(value: WorldIdRequestAuthError) -> Self {
        let (code, msg) = match value {
            WorldIdRequestAuthError::UnknownRp => (
                error_codes::UNKNOWN_RP,
                taceo_oprf::types::close_frame_message!("unknown RP"),
            ),
            WorldIdRequestAuthError::TimeStampTooOld => (
                error_codes::TIMESTAMP_TOO_OLD,
                taceo_oprf::types::close_frame_message!("timestamp in request too old"),
            ),
            WorldIdRequestAuthError::InvalidRpSignature => (
                error_codes::INVALID_RP_SIGNATURE,
                taceo_oprf::types::close_frame_message!("signature from RP cannot be verified"),
            ),
            WorldIdRequestAuthError::DuplicateNonce => (
                error_codes::DUPLICATE_NONCE,
                taceo_oprf::types::close_frame_message!("signature nonce already used"),
            ),
            WorldIdRequestAuthError::InvalidMerkleRoot => (
                error_codes::INVALID_MERKLE_ROOT,
                taceo_oprf::types::close_frame_message!("invalid merkle root"),
            ),
            WorldIdRequestAuthError::InvalidQueryProof => (
                error_codes::INVALID_QUERY_PROOF,
                taceo_oprf::types::close_frame_message!("cannot verify query proof"),
            ),
            WorldIdRequestAuthError::InvalidActionSchemaIssuer => (
                error_codes::INVALID_ACTION_SCHEMA_ISSUER,
                taceo_oprf::types::close_frame_message!(
                    "invalid action - must be 0 for schema-issuer blinding"
                ),
            ),
            WorldIdRequestAuthError::UnknownSchemaIssuer => (
                error_codes::UNKNOWN_SCHEMA_ISSUER,
                taceo_oprf::types::close_frame_message!("unknown schema issuer"),
            ),
            WorldIdRequestAuthError::InvalidActionNullifier => (
                error_codes::INVALID_ACTION_NULLIFIER,
                taceo_oprf::types::close_frame_message!(
                    "invalid action - MSB must be 0x00 for nullifier"
                ),
            ),
            WorldIdRequestAuthError::InvalidActionSession => (
                error_codes::INVALID_ACTION_SESSION,
                taceo_oprf::types::close_frame_message!(
                    "invalid action - MSB must be 0x00 for internal nullifier or 0x01 for session_id_r_seed"
                ),
            ),
            WorldIdRequestAuthError::InactiveRp => (
                error_codes::INACTIVE_RP,
                taceo_oprf::types::close_frame_message!("inactive RP"),
            ),
            WorldIdRequestAuthError::Internal => (
                error_codes::INTERNAL, // RFC 6455 error code
                taceo_oprf::types::close_frame_message!("internal server error"),
            ),
            WorldIdRequestAuthError::Unknown(unknown) => {
                (unknown, taceo_oprf::types::close_frame_message!("unknown"))
            }
        };
        Self::with_message(code, msg)
    }
}
