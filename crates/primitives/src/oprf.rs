use crate::serde_utils;
use alloy_primitives::U256;
use ark_bn254::Bn254;
use circom_types::groth16::Proof;
use serde::{Deserialize, Serialize};
use taceo_oprf::types::api::{CloseFrameMessage, OprfRequestAuthenticatorError};

use crate::rp::RpId;

#[expect(unused_imports, reason = "used in doc comments")]
use crate::SessionFeType;

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
    #[serde(with = "ark_serde_compat::field")]
    pub action: ark_babyjubjub::Fq,
    /// The nonce
    #[serde(with = "ark_serde_compat::field")]
    pub nonce: ark_babyjubjub::Fq,
    /// The Merkle root associated with this request.
    #[serde(with = "ark_serde_compat::field")]
    pub merkle_root: ark_babyjubjub::Fq,
    /// The current time stamp (unix secs)
    pub current_time_stamp: u64,
    /// Expiration timestamp of the request (unix secs)
    pub expiration_timestamp: u64,
    /// The RP's signature on the request, see `compute_rp_signature_msg` for details.
    ///
    /// Can be `None` if the RP is a WIP101 conform contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<alloy_primitives::Signature>,
    /// The `rp_id`
    pub rp_id: RpId,
    /// Auxiliary data for WIP101 verification.
    ///
    /// Maximum length of this field is 1024 bytes. If the RP is not backed by a WIP101 signer contract, you can omit this value is it will be ignored by the OPRF-nodes anyways.
    ///
    /// If the RP signer is an WIP101 backed contract, this data is send verbatim to the contract without any form of validation (except size).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_utils::hex_bytes_opt"
    )]
    pub wip101_data: Option<Vec<u8>>,
}

/// A request sent by a client for OPRF credential blinding factor authentication.
#[derive(Clone, Serialize, Deserialize)]
pub struct CredentialBlindingFactorOprfRequestAuthV1 {
    /// Zero-knowledge proof provided by the user.
    pub proof: Proof<Bn254>,
    /// The action
    #[serde(with = "ark_serde_compat::field")]
    pub action: ark_babyjubjub::Fq,
    /// The nonce
    #[serde(with = "ark_serde_compat::field")]
    pub nonce: ark_babyjubjub::Fq,
    /// The Merkle root associated with this request.
    #[serde(with = "ark_serde_compat::field")]
    pub merkle_root: ark_babyjubjub::Fq,
    /// The `issuer_schema_id` in the `CredentialSchemaIssuerRegistry` contract
    pub issuer_schema_id: u64,
}

/// Concrete error type returned by OPRF request authentication.
///
/// Variants map 1-to-1 with the numeric close-frame error codes in [`error_codes`], which are
/// sent to the client over the WebSocket connection when authentication fails.
#[derive(Copy, Clone, Debug, thiserror::Error)]
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
    /// The request timestamp is too far in the future. If you are the RP please sign a request with
    /// a fresh timestamp.
    #[error("timestamp_too_far_in_future")]
    TimestampTooFarInFuture,
    /// The timestamp cannot be parsed as it was not a valid unix epoch timestamp.
    #[error("invalid_timestamp")]
    InvalidTimestamp,
    /// The RP signature has expired. If you are the RP please sign a request
    /// with a fresh timestamp.
    #[error("rp_signature_expired")]
    RpSignatureExpired,
    /// The RP's signature on the request could not be verified. The signature may be
    /// incorrect, the wrong public key used, or does not match the expected message.
    #[error("invalid_rp_signature")]
    InvalidRpSignature,
    /// Requester did not provide a signature of the RP, but the RP's signer
    /// is an EOA.
    /// Empty signatures are only supported for WIP101 backed RPs.
    #[error("rp_signature_missing")]
    RpSignatureMissing,
    /// RP signer is an EOA but request had auxiliary data.
    #[error("wip101_aux_data_on_eoa")]
    Wip101AuxDataOnEoa,
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
    /// The provided action for the credential issuer blinding factor computation is not valid.
    #[error("invalid_action_for_blinding_factor")]
    InvalidActionSchemaIssuer,
    /// The provided action for the nullifier computation is not valid. Nullifier actions must
    /// start with `0x00` (MSB).
    #[error("invalid_action_for_nullifier")]
    InvalidActionNullifier,
    /// **Only valid for Session Proofs**.
    ///
    /// The provided action for the Session Proof is invalid. See [`SessionFeType`] for the valid action
    /// prefixes.
    #[error("invalid_action_for_session")]
    InvalidActionSession,
    /// The RP signer is a contract but does not implement the WIP101 interface.
    #[error("wip101_incompatible_rp_signer")]
    Wip101IncompatibleRpSigner,
    /// The WIP101 signer contract rejected the request.
    ///
    /// The contract may optionally return a rejection code (`U256`), which is captured in this error as `Some(code)`. If no additional code is provided, this will be `None`.
    ///
    /// When constructing this variant from just the `CloseFrame`'s `code`, the contract's additional code will be lost. The additional code, if any, is sent as `reason` in the `CloseFrame`.
    #[error("wip101_verification_failed")]
    Wip101VerificationFailed(Option<U256>),
    /// Invalid custom revert for WIP101 contract.
    ///
    /// WIP101 specifies that contracts must revert with `error RpInvalidRequest(uint256 code)` but contract reverted with unknown error.
    #[error("wip101_custom_revert")]
    Wip101CustomRevert,
    /// Provided auxiliary data is too large.
    ///
    /// WIP101 specifies that provided `data` must be smaller than 1024 bytes.
    #[error("wip101_aux_data_too_large")]
    Wip101AuxDataTooLarge,
    /// WIP101 signature verification ran into timeout.
    #[error("wip101_verification_timeout")]
    Wip101VerificationTimeout,
    /// Doing WIP101/ERC165 check on RP's signer ran into timeout.
    #[error("wip101_account_check_timeout")]
    Wip101AccountCheckTimeout,
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
            | Self::TimestampTooFarInFuture
            | Self::InvalidTimestamp
            | Self::RpSignatureExpired
            | Self::InvalidRpSignature
            | Self::DuplicateNonce
            | Self::InvalidActionNullifier
            | Self::Wip101IncompatibleRpSigner
            | Self::Wip101VerificationFailed(_)
            | Self::Wip101CustomRevert
            | Self::Wip101VerificationTimeout
            | Self::Wip101AuxDataOnEoa
            | Self::Wip101AuxDataTooLarge
            | Self::Wip101AccountCheckTimeout => ErrorActor::Rp,
            Self::UnknownSchemaIssuerId => ErrorActor::Issuer,
            Self::InvalidMerkleRoot
            | Self::InvalidQueryProof
            | Self::InvalidActionSchemaIssuer
            | Self::InvalidActionSession
            | Self::RpSignatureMissing => ErrorActor::Authenticator,
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
            error_codes::INVALID_ACTION_NULLIFIER => Self::InvalidActionNullifier,
            error_codes::INVALID_ACTION_SESSION => Self::InvalidActionSession,
            error_codes::RP_SIGNATURE_EXPIRED => Self::RpSignatureExpired,
            error_codes::RP_SIGNATURE_MISSING => Self::RpSignatureMissing,
            error_codes::INVALID_TIMESTAMP => Self::InvalidTimestamp,
            error_codes::TIMESTAMP_TOO_FAR_IN_FUTURE => Self::TimestampTooFarInFuture,
            error_codes::WIP101_INCOMPATIBLE_RP_SIGNER => Self::Wip101IncompatibleRpSigner,
            error_codes::WIP101_VERIFICATION_TIMEOUT => Self::Wip101VerificationTimeout,
            error_codes::WIP101_ACCOUNT_CHECK_TIMEOUT => Self::Wip101AccountCheckTimeout,
            // we lost the additional code when converting from just the u16
            error_codes::WIP101_VERIFICATION_FAILED => Self::Wip101VerificationFailed(None),
            error_codes::WIP101_CUSTOM_REVERT => Self::Wip101CustomRevert,
            error_codes::INTERNAL => Self::Internal,
            other => Self::Unknown(other),
        }
    }
}

impl From<WorldIdRequestAuthError> for u16 {
    fn from(value: WorldIdRequestAuthError) -> Self {
        match value {
            WorldIdRequestAuthError::UnknownRp => error_codes::UNKNOWN_RP,
            WorldIdRequestAuthError::InactiveRp => error_codes::INACTIVE_RP,
            WorldIdRequestAuthError::TimestampTooOld => error_codes::TIMESTAMP_TOO_OLD,
            WorldIdRequestAuthError::InvalidTimestamp => error_codes::INVALID_TIMESTAMP,
            WorldIdRequestAuthError::InvalidRpSignature => error_codes::INVALID_RP_SIGNATURE,
            WorldIdRequestAuthError::RpSignatureMissing => error_codes::RP_SIGNATURE_MISSING,
            WorldIdRequestAuthError::DuplicateNonce => error_codes::DUPLICATE_NONCE,
            WorldIdRequestAuthError::InvalidMerkleRoot => error_codes::INVALID_MERKLE_ROOT,
            WorldIdRequestAuthError::InvalidQueryProof => error_codes::INVALID_QUERY_PROOF,
            WorldIdRequestAuthError::InvalidActionSchemaIssuer => {
                error_codes::INVALID_ACTION_SCHEMA_ISSUER
            }
            WorldIdRequestAuthError::UnknownSchemaIssuerId => error_codes::UNKNOWN_SCHEMA_ISSUER,
            WorldIdRequestAuthError::InvalidActionNullifier => {
                error_codes::INVALID_ACTION_NULLIFIER
            }
            WorldIdRequestAuthError::InvalidActionSession => error_codes::INVALID_ACTION_SESSION,
            WorldIdRequestAuthError::RpSignatureExpired => error_codes::RP_SIGNATURE_EXPIRED,
            WorldIdRequestAuthError::TimestampTooFarInFuture => {
                error_codes::TIMESTAMP_TOO_FAR_IN_FUTURE
            }
            WorldIdRequestAuthError::Wip101IncompatibleRpSigner => {
                error_codes::WIP101_INCOMPATIBLE_RP_SIGNER
            }
            WorldIdRequestAuthError::Wip101VerificationFailed(_) => {
                error_codes::WIP101_VERIFICATION_FAILED
            }
            WorldIdRequestAuthError::Wip101VerificationTimeout => {
                error_codes::WIP101_VERIFICATION_TIMEOUT
            }
            WorldIdRequestAuthError::Wip101CustomRevert => error_codes::WIP101_CUSTOM_REVERT,
            WorldIdRequestAuthError::Wip101AuxDataOnEoa => error_codes::WIP101_AUX_DATA_ON_EOA,
            WorldIdRequestAuthError::Wip101AuxDataTooLarge => {
                error_codes::WIP101_AUX_DATA_TOO_LARGE
            }
            WorldIdRequestAuthError::Wip101AccountCheckTimeout => {
                error_codes::WIP101_ACCOUNT_CHECK_TIMEOUT
            }
            WorldIdRequestAuthError::Internal => error_codes::INTERNAL,
            WorldIdRequestAuthError::Unknown(other) => other,
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
    /// Error code for [`super::WorldIdRequestAuthError::InvalidActionNullifier`].
    pub const INVALID_ACTION_NULLIFIER: u16 = 4508;
    /// Error code for [`super::WorldIdRequestAuthError::InvalidActionSession`].
    pub const INVALID_ACTION_SESSION: u16 = 4509;
    /// Error code for [`super::WorldIdRequestAuthError::InactiveRp`].
    pub const INACTIVE_RP: u16 = 4510;
    /// Error code for [`super::WorldIdRequestAuthError::RpSignatureExpired`].
    pub const RP_SIGNATURE_EXPIRED: u16 = 4511;
    /// Error code for [`super::WorldIdRequestAuthError::InvalidTimestamp`].
    pub const INVALID_TIMESTAMP: u16 = 4512;
    /// Error code for [`super::WorldIdRequestAuthError::TimestampTooFarInFuture`].
    pub const TIMESTAMP_TOO_FAR_IN_FUTURE: u16 = 4513;
    /// Error code for [`super::WorldIdRequestAuthError::Wip101IncompatibleRpSigner`].
    pub const WIP101_INCOMPATIBLE_RP_SIGNER: u16 = 4514;
    /// Error code for [`super::WorldIdRequestAuthError::Wip101VerificationFailed`].
    pub const WIP101_VERIFICATION_FAILED: u16 = 4515;
    /// Error code for [`super::WorldIdRequestAuthError::Wip101CustomRevert`].
    pub const WIP101_CUSTOM_REVERT: u16 = 4516;
    /// Error code for [`super::WorldIdRequestAuthError::Wip101AuxDataTooLarge`].
    pub const WIP101_AUX_DATA_TOO_LARGE: u16 = 4517;
    /// Error code for [`super::WorldIdRequestAuthError::RpSignatureMissing`]
    pub const RP_SIGNATURE_MISSING: u16 = 4518;
    /// Error code for [`super::WorldIdRequestAuthError::Wip101AuxDataOnEoa`]
    pub const WIP101_AUX_DATA_ON_EOA: u16 = 4519;
    /// Error code for [`super::WorldIdRequestAuthError::Wip101VerificationTimeout`]
    pub const WIP101_VERIFICATION_TIMEOUT: u16 = 4520;
    /// Error code for [`super::WorldIdRequestAuthError::Wip101AccountCheckTimeout`]
    pub const WIP101_ACCOUNT_CHECK_TIMEOUT: u16 = 4521;
    /// Error code for [`super::WorldIdRequestAuthError::Internal`].
    pub const INTERNAL: u16 = 1011;
}

impl From<WorldIdRequestAuthError> for OprfRequestAuthenticatorError {
    fn from(value: WorldIdRequestAuthError) -> Self {
        let code = u16::from(value);
        let msg = match value {
            WorldIdRequestAuthError::UnknownRp => {
                taceo_oprf::types::close_frame_message!("unknown RP")
            }
            WorldIdRequestAuthError::TimestampTooOld => {
                taceo_oprf::types::close_frame_message!("timestamp in request too old")
            }
            WorldIdRequestAuthError::TimestampTooFarInFuture => {
                taceo_oprf::types::close_frame_message!("timestamp too far in future")
            }
            WorldIdRequestAuthError::InvalidRpSignature => {
                taceo_oprf::types::close_frame_message!("signature from RP cannot be verified")
            }
            WorldIdRequestAuthError::RpSignatureMissing => {
                taceo_oprf::types::close_frame_message!("RP signature missing but signer is an EOA")
            }
            WorldIdRequestAuthError::DuplicateNonce => {
                taceo_oprf::types::close_frame_message!("signature nonce already used")
            }
            WorldIdRequestAuthError::InvalidMerkleRoot => {
                taceo_oprf::types::close_frame_message!("invalid merkle root")
            }
            WorldIdRequestAuthError::InvalidQueryProof => {
                taceo_oprf::types::close_frame_message!("cannot verify query proof")
            }
            WorldIdRequestAuthError::InvalidActionSchemaIssuer => {
                taceo_oprf::types::close_frame_message!(
                    "invalid action for credential sub blinding factor"
                )
            }
            WorldIdRequestAuthError::UnknownSchemaIssuerId => {
                taceo_oprf::types::close_frame_message!("unknown schema issuer id")
            }
            WorldIdRequestAuthError::InvalidActionNullifier => {
                taceo_oprf::types::close_frame_message!("invalid action for nullifier")
            }
            WorldIdRequestAuthError::InvalidActionSession => {
                taceo_oprf::types::close_frame_message!("invalid action for session proofs")
            }
            WorldIdRequestAuthError::InactiveRp => {
                taceo_oprf::types::close_frame_message!("inactive RP")
            }
            WorldIdRequestAuthError::RpSignatureExpired => {
                taceo_oprf::types::close_frame_message!("RP signature expired")
            }
            WorldIdRequestAuthError::InvalidTimestamp => {
                taceo_oprf::types::close_frame_message!("cannot parse timestamp on request")
            }
            WorldIdRequestAuthError::Wip101IncompatibleRpSigner => {
                taceo_oprf::types::close_frame_message!(
                    "RP has a contract backed signer but doesn't conform to WIP101"
                )
            }
            WorldIdRequestAuthError::Wip101CustomRevert => {
                taceo_oprf::types::close_frame_message!(
                    "RP signer contract reverted with custom error (and not error RpInvalidRequest(uint256 code);)"
                )
            }
            WorldIdRequestAuthError::Wip101VerificationFailed(None) => {
                // send empty message so that it is easier to parse the code in case there is any
                taceo_oprf::types::close_frame_message!("")
            }
            WorldIdRequestAuthError::Wip101VerificationTimeout => {
                taceo_oprf::types::close_frame_message!("WIP101 verification ran into timeout")
            }
            WorldIdRequestAuthError::Wip101VerificationFailed(Some(code)) => {
                // this should never truncate as code is a U256 encoded as hex
                CloseFrameMessage::new_truncate(format!("{:#x}", code))
            }
            WorldIdRequestAuthError::Wip101AuxDataOnEoa => taceo_oprf::types::close_frame_message!(
                "Auxiliary data must be empty with EOA backed signer"
            ),
            WorldIdRequestAuthError::Wip101AuxDataTooLarge => {
                taceo_oprf::types::close_frame_message!(
                    "Auxiliary data for WIP101 contract too large - max 1024 bytes"
                )
            }
            WorldIdRequestAuthError::Wip101AccountCheckTimeout => {
                taceo_oprf::types::close_frame_message!(
                    "Ran into timeout while doing WIP101/ERC165 check on RP's signer"
                )
            }
            WorldIdRequestAuthError::Internal => {
                taceo_oprf::types::close_frame_message!("internal server error")
            }
            WorldIdRequestAuthError::Unknown(_) => {
                taceo_oprf::types::close_frame_message!("unknown")
            }
        };
        Self::with_message(code, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_roundtrip() {
        let codes: &[u16] = &[
            error_codes::UNKNOWN_RP,
            error_codes::TIMESTAMP_TOO_OLD,
            error_codes::TIMESTAMP_TOO_FAR_IN_FUTURE,
            error_codes::INVALID_RP_SIGNATURE,
            error_codes::DUPLICATE_NONCE,
            error_codes::INVALID_MERKLE_ROOT,
            error_codes::INVALID_QUERY_PROOF,
            error_codes::INVALID_ACTION_SCHEMA_ISSUER,
            error_codes::UNKNOWN_SCHEMA_ISSUER,
            error_codes::INVALID_ACTION_NULLIFIER,
            error_codes::INVALID_ACTION_SESSION,
            error_codes::INACTIVE_RP,
            error_codes::RP_SIGNATURE_EXPIRED,
            error_codes::INVALID_TIMESTAMP,
            error_codes::WIP101_INCOMPATIBLE_RP_SIGNER,
            error_codes::WIP101_VERIFICATION_FAILED,
            error_codes::WIP101_CUSTOM_REVERT,
            error_codes::WIP101_AUX_DATA_TOO_LARGE,
            error_codes::RP_SIGNATURE_MISSING,
            error_codes::WIP101_AUX_DATA_ON_EOA,
            error_codes::WIP101_VERIFICATION_TIMEOUT,
            error_codes::WIP101_ACCOUNT_CHECK_TIMEOUT,
            error_codes::INTERNAL,
        ];
        for &code in codes {
            let error = WorldIdRequestAuthError::from(code);
            let back: u16 = error.into();
            assert_eq!(code, back, "roundtrip failed for code {code}");
        }
    }
}
