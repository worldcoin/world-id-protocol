//! Errors of proof generation, verification and input checks.
//!
//! [`ProofInputError`]s assist in producing more helpful error messages for a given proof.
//! If the circuits change in any way, the checks that raise them may also need to be updated.

use groth16_material::Groth16Error;
use world_id_primitives::{PrimitiveError, oprf::WorldIdRequestAuthError};

use crate::artifacts;

type BaseField = ark_babyjubjub::Fq;

/// Error type for OPRF operations and proof generation.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    /// Authentication error returned by the OPRF nodes (e.g. unknown RP, invalid proof).
    #[error(transparent)]
    RequestAuthError(#[from] WorldIdRequestAuthError),
    /// Non-auth error originating from `oprf_client`.
    #[error(transparent)]
    OprfError(taceo_oprf::client::Error),
    /// Errors originating from proof inputs
    #[error(transparent)]
    ProofInputError(#[from] ProofInputError),
    /// Errors originating from Groth16 proof generation or verification.
    #[error(transparent)]
    ZkError(#[from] Groth16Error),
    /// Error loading ZK artifacts from a [`artifacts::ZkArtifactSource`].
    #[error(transparent)]
    ZkArtifact(#[from] artifacts::ZkArtifactError),
    /// Error generating a Noir Proof with ProveKit
    #[error("proof generation error: {0}")]
    GenerationError(String),
    /// Error verifying a Noir Proof with ProveKit. This usually means the proof is invalid.
    #[error("proof verification error: {0}")]
    Verification(String),
    /// The proof cannot be generated because the credential has an error
    #[error(transparent)]
    CredentialError(#[from] PrimitiveError),
    /// Catch-all for other internal errors.
    #[error(transparent)]
    InternalError(#[from] eyre::Report),
}

impl From<taceo_oprf::client::Error> for ProofError {
    fn from(err: taceo_oprf::client::Error) -> Self {
        if let taceo_oprf::client::Error::ThresholdServiceError(ref svc) = err
            && svc.kind.is_auth()
        {
            return Self::RequestAuthError(WorldIdRequestAuthError::from(svc.error_code));
        }
        Self::OprfError(err)
    }
}

#[derive(Debug, thiserror::Error)]
/// Errors that can occur when validating the inputs for a single World ID proof.
pub enum ProofInputError {
    /// The specified Merkle tree depth is invalid.
    #[error("The specified Merkle tree depth is invalid (expected: {expected}, got: {is}).")]
    InvalidMerkleTreeDepth {
        /// Expected depth.
        expected: usize,
        /// Actual depth.
        is: BaseField,
    },
    /// The set of authenticator public keys is invalid.
    #[error("The set of authenticator public keys is invalid.")]
    InvalidAuthenticatorPublicKeySet,
    /// The provided Merkle tree **inclusion proof** is invalid (the root may or may not be valid for the `WorldIDRegistry` tree)
    #[error("The provided Merkle tree inclusion proof is invalid.")]
    InvalidMerkleTreeInclusionProof,
    /// The authenticator signature over the message the circuit verifies is invalid.
    #[error("The authenticator signature over the circuit's message is invalid.")]
    InvalidAuthenticatorSignature,
    /// The Flamingo Verifier signature over the token digest is invalid.
    #[error("The Flamingo Token signature is invalid for the given Verifier key.")]
    InvalidFlamingoTokenSignature,
    /// The PCP `hashes.json` cannot be encoded for the circuit.
    #[error("The provided hashes.json is invalid: {reason}.")]
    InvalidHashesJson {
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The Credential claim does not commit to the provided `hashes.json`.
    #[error("The credential claim does not match the provided hashes.json.")]
    InvalidHashesJsonClaim,
    /// The AAT's `user_presence` (bits 0-2 of `authenticator_meta`) is one of the values 5 to 7
    /// WIP-106 reserves.
    #[error("The AAT's user_presence {user_presence} is reserved.")]
    ReservedUserPresence {
        /// The reserved value.
        user_presence: u8,
    },
    /// The proof request is not a valid Proof of Embedding Similarity request.
    #[error("The proof request is not a valid embedding similarity request: {reason}.")]
    InvalidEmbeddingSimilarityRequest {
        /// Why it is not.
        reason: String,
    },
    /// The billing nullifier is neither `0` nor this World ID's WIP-107 nullifier for the RP.
    #[error("The billing nullifier is not this World ID's nullifier for the RP.")]
    InvalidBillingNullifier,
    /// The provided blinding factor is invalid, or the sub is incorrect.
    #[error("The provided blinding factor is invalid.")]
    InvalidBlindingFactor,
    /// The provided credential has expired.
    #[error(
        "The provided credential has expired (expires_at: {expires_at}, check_timestamp: {current_timestamp})."
    )]
    CredentialExpired {
        /// Current timestamp.
        current_timestamp: u64,
        /// Expiration timestamp.
        expires_at: u64,
    },
    /// The provided credential genesis issue timestamp is expired.
    #[error(
        "The provided credential has a genesis issued at date that is too old (genesis_issued_at: {genesis_issued_at}, check_timestamp: {genesis_issued_at_min})."
    )]
    CredentialGenesisExpired {
        /// Minimum Issue date.
        genesis_issued_at_min: u64,
        /// Genesis issue timestamp.
        genesis_issued_at: u64,
    },
    /// A value is out of bounds.
    #[error("The value '{name}' is out of bounds (got: {is}, limit: {limit}).")]
    ValueOutOfBounds {
        /// Name of the value for error message.
        name: &'static str,
        /// Actual value.
        is: BaseField,
        /// Upper limit, not inclusive.
        limit: BaseField,
    },
    /// The credential signature is invalid. This signals the issued credential is invalid.
    #[error("The credential signature is invalid for the given issuer public key.")]
    InvalidCredentialSignature,
    /// The provided point is not a valid point in the prime-order subgroup of the `BabyJubJub` curve.
    #[error(
        "The provided point '{name}' is not a valid point in the prime-order subgroup of the BabyJubJub curve."
    )]
    InvalidBabyJubJubPoint {
        /// Name of the point for error message.
        name: &'static str,
    },
    /// The provided OPRF proof is invalid.
    #[error("The provided OPRF DlogEquality proof is invalid.")]
    InvalidOprfProof,
    /// The provided unblinded OPRF response point is invalid.
    #[error("The provided unblinded OPRF response point is invalid.")]
    InvalidOprfResponse,
    /// The provided session ID commitment is invalid.
    #[error(
        "The provided session ID commitment is invalid for the given id and session id randomness."
    )]
    InvalidSessionId,
    /// The proof request is expired.
    #[error(
        "The provided proof request has expired (expires_at: {expires_at}, check_timestamp: {current_timestamp})."
    )]
    ProofRequestExpired {
        /// Current timestamp.
        current_timestamp: u64,
        /// Expiration timestamp.
        expires_at: u64,
    },
    /// The proof's expires_at is greater than the created_at.
    #[error("The proof's expires_at {expires_at} happens before the created_at {created_at}.")]
    InvalidExpiresAt { created_at: u64, expires_at: u64 },
    /// A value that the circuit requires to be non-zero was zero.
    #[error("The value '{name}' must not be zero.")]
    ValueMustNotBeZero {
        /// Name of the value for error message.
        name: &'static str,
    },
    /// The provided commitment does not match the one derived from the leaf index and blinder.
    #[error("The provided expected commitment does not match the derived commitment")]
    InvalidExpectedCommitment,
    /// The selected authenticator key slot holds no registered key.
    #[error("The authenticator key at index {index} is not registered.")]
    InactiveAuthenticatorKey {
        /// The selected key slot.
        index: u64,
    },
}
