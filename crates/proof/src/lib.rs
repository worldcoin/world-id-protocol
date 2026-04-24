#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use eddsa_babyjubjub::EdDSAPrivateKey;
use groth16_material::Groth16Error;

use world_id_primitives::{
    AuthenticatorPublicKeySet, TREE_DEPTH, merkle::MerkleInclusionProof,
    oprf::WorldIdRequestAuthError,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Circuit input types for Circom/Groth16 circuits (query, nullifier, ownership proofs).
pub mod circuit_inputs;

pub mod compress;
pub use compress::ProofCompression;
pub(crate) mod oprf_query;
pub use oprf_query::{FullOprfOutput, OprfEntrypoint};

pub mod proof;
pub use proof::*;

use provekit_common::{InputMap, InputValue, NoirElement};

use world_id_primitives::FieldElement;

#[cfg(any(feature = "zk-ownership-prove", feature = "zk-ownership-verify"))]
pub mod ownership_proof;

pub use provekit_common::{NoirProof, WhirR1CSProof};

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
    ProofInputError(#[from] errors::ProofInputError),
    /// Errors originating from Groth16 proof generation or verification.
    #[error(transparent)]
    ZkError(#[from] Groth16Error),
    /// Error generating a Noir Proof with ProveKit
    #[error("proof generation error: {0}")]
    GenerationError(String),
    /// Error verifying a Noir Proof with ProveKit. This usually means the proof is invalid.
    #[error("proof verification error: {0}")]
    Verification(String),
    /// Catch-all for other internal errors.
    #[error(transparent)]
    InternalError(#[from] eyre::Report),
}

pub trait NoirCircuitInput {
    fn into_witness(self) -> Result<InputMap, ProofError>;
}

pub trait NoirRepresentable {
    fn into_noir_value(self) -> InputValue;
}

impl NoirRepresentable for FieldElement {
    fn into_noir_value(self) -> InputValue {
        InputValue::Field(NoirElement::from_repr(*self))
    }
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

/// Inputs from the Authenticator to generate a nullifier or blinding factor.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthenticatorProofInput {
    /// The set of all public keys for all the user's authenticators.
    #[zeroize(skip)]
    pub key_set: AuthenticatorPublicKeySet,
    /// Inclusion proof in the World ID Registry.
    #[zeroize(skip)]
    pub inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    /// The off-chain signer key for the Authenticator.
    private_key: EdDSAPrivateKey,
    /// The index at which the authenticator key is located in the `key_set`.
    pub key_index: u64,
}

impl AuthenticatorProofInput {
    /// Creates a new authenticator proof input.
    #[must_use]
    pub const fn new(
        key_set: AuthenticatorPublicKeySet,
        inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
        private_key: EdDSAPrivateKey,
        key_index: u64,
    ) -> Self {
        Self {
            key_set,
            inclusion_proof,
            private_key,
            key_index,
        }
    }
}
