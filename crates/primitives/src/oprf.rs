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

/// Concrete error type returned by OPRF request authentication.
///
/// Variants map 1-to-1 with the numeric close-frame error codes in [`error_codes`], which are
/// sent to the client over the WebSocket connection when authentication fails.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WorldIdRequestAuthError {
    /// Unknown RP. The RP is likely not registerd in the `RpRegistry`.
    #[error("unknown_rp")]
    UnknownRp,
    /// Inactive RP. The RP was deactivated in the `RpRegistry`. Inactive RPs cannot
    /// request proofs. If you are the RP, call `updateRp` to re-activate.
    #[error("inactive_rp")]
    InactiveRp,
    /// **Only valid for Credential Blinding Factor generation**.
    ///
    /// The `issuerSchemaId` provided to generate a blinding factor is not valid. The
    /// value is either incorrect or the `issuerSchemaId` is not correctly registered in
    /// the `CredentialSchemaIssuerRegistry`.
    #[error("unknown_schema_issuer_id")]
    UnknownSchemaIssuerId,
    /// The request timestamp is too old. If you are the RP please sign a request with
    /// a fresh timestamp.
    #[error("timestamp_too_old")]
    TimestampTooOld,
    /// The RP's signature on the request could not be verified. The signature may be
    /// incorrect, the wrong public key used, or does not match the expected message.
    #[error("invalid_rp_signature")]
    InvalidRpSignature,
    /// A duplicate nonce was detected. Duplicate nonces are not allowed to prevent
    /// replay attacks. If you are the RP please generate a new nonce.
    #[error("duplicate_nonce")]
    DuplicateNonce,
    /// The provided Merkle root is not valid for the `WorldIDRegistry`. This can happen
    /// when the inclusion proof is too old. Please compute a new inclusion proof.
    #[error("invalid_merkle_root")]
    InvalidMerkleRoot,
    /// The client Query Proof, used to authenticate the user did not verify correctly
    /// for the provided inputs.
    #[error("invalid_query_proof")]
    InvalidQueryProof,
    /// **Only valid for Credential Blinding Factor generation**.
    ///
    /// The provided action for the blinding factor generation is not valid.
    #[error("invalid_action_for_blinding_factor")]
    InvalidActionSchemaIssuer,
    /// Internal server error.
    #[error("internal_server_error")]
    Internal,
    /// Unknown error code not mapped to a known variant.
    #[error("unknown_error_{0}")]
    Unknown(u16),
}

/// The actor where a provided OPRF error likely originated and with ability
/// to fix it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorActor {
    /// The Relying Party requesting a Proof
    Rp,
    /// The Issuer of a Credential
    Issuer,
    /// The Authenticator of the user
    Authenticator,
    /// Error attributable to an OPRF node
    OprfNode,
}

impl WorldIdRequestAuthError {
    /// Return the [`ErrorActor`] associated for this error.
    #[must_use]
    pub const fn as_actor(&self) -> ErrorActor {
        match self {
            Self::UnknownRp
            | Self::InactiveRp
            | Self::TimestampTooOld
            | Self::InvalidRpSignature
            | Self::DuplicateNonce => ErrorActor::Rp,
            Self::UnknownSchemaIssuerId => ErrorActor::Issuer,
            Self::InvalidMerkleRoot | Self::InvalidQueryProof | Self::InvalidActionSchemaIssuer => {
                ErrorActor::Authenticator
            }
            Self::Internal | Self::Unknown(_) => ErrorActor::OprfNode,
        }
    }
}

impl From<u16> for WorldIdRequestAuthError {
    fn from(value: u16) -> Self {
        match value {
            error_codes::UNKNOWN_RP => Self::UnknownRp,
            error_codes::INACTIVE_RP => Self::InactiveRp,
            error_codes::TIMESTAMP_TOO_OLD => Self::TimestampTooOld,
            error_codes::INVALID_RP_SIGNATURE => Self::InvalidRpSignature,
            error_codes::DUPLICATE_NONCE => Self::DuplicateNonce,
            error_codes::INVALID_MERKLE_ROOT => Self::InvalidMerkleRoot,
            error_codes::INVALID_QUERY_PROOF => Self::InvalidQueryProof,
            error_codes::INVALID_ACTION_SCHEMA_ISSUER => Self::InvalidActionSchemaIssuer,
            error_codes::UNKNOWN_SCHEMA_ISSUER => Self::UnknownSchemaIssuerId,
            error_codes::INTERNAL => Self::Internal,
            other => Self::Unknown(other),
        }
    }
}

/// Numeric close-frame error codes sent to the client when [`WorldIdRequestAuthError`] occurs.
pub mod error_codes {
    /// Error code for [`super::WorldIdRequestAuthError::UnknownRp`].
    pub const UNKNOWN_RP: u16 = 4500;
    /// Error code for [`super::WorldIdRequestAuthError::TimestampTooOld`].
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
    /// Error code for [`super::WorldIdRequestAuthError::UnknownSchemaIssuerId`].
    pub const UNKNOWN_SCHEMA_ISSUER: u16 = 4507;
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
            WorldIdRequestAuthError::TimestampTooOld => (
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
            WorldIdRequestAuthError::UnknownSchemaIssuerId => (
                error_codes::UNKNOWN_SCHEMA_ISSUER,
                taceo_oprf::types::close_frame_message!("unknown schema issuer"),
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
