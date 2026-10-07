#![cfg_attr(not(test), warn(unused_crate_dependencies))]

#[cfg(feature = "prover")]
use eddsa_babyjubjub::EdDSAPrivateKey;
#[cfg(feature = "prover")]
use groth16_material::Groth16Error;

#[cfg(feature = "prover")]
use world_id_primitives::{
    AuthenticatorPublicKeySet, PrimitiveError, TREE_DEPTH, merkle::MerkleInclusionProof,
    oprf::WorldIdRequestAuthError,
};
#[cfg(feature = "prover")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ZK artifact source abstractions.
#[cfg(feature = "prover")]
pub mod artifacts;

/// Circuit input types for Circom/Groth16 circuits (query, nullifier, ownership proofs).
#[cfg(feature = "prover")]
pub mod circuit_inputs;

/// Static circuit input fixtures shared by the tests and the generated circuit examples.
#[cfg(all(test, feature = "prover"))]
mod fixtures;

#[cfg(feature = "prover")]
pub mod compress;
#[cfg(feature = "prover")]
pub use compress::ProofCompression;
#[cfg(feature = "prover")]
pub(crate) mod oprf_query;
#[cfg(feature = "prover")]
pub use oprf_query::{
    FullOprfOutput, OprfEntrypoint, QUERY_GRAPH_FINGERPRINT, QUERY_ZKEY_FINGERPRINT,
    load_query_material_from_paths, load_query_material_from_reader,
};

#[cfg(feature = "prover")]
pub mod nullifier_proof;
#[cfg(feature = "prover")]
pub use nullifier_proof::*;

/// Authenticator Assertions (WIP-106): token generation.
pub mod authenticator_assertion;

#[cfg(feature = "prover")]
use ark_ff::BigInteger as _;
#[cfg(feature = "prover")]
use provekit_common::{InputMap, InputValue, NoirElement};

#[cfg(feature = "prover")]
use world_id_primitives::FieldElement;

// TODO: Currently ownership proofs are not supported for WASM targets
#[cfg(all(feature = "prover", not(target_arch = "wasm32")))]
pub mod ownership_proof;

#[cfg(feature = "prover")]
pub use provekit_common::{
    NoirProof, Prover as OwnershipProver, Verifier as OwnershipVerifier, WhirR1CSProof,
};

/// Error type for OPRF operations and proof generation.
#[cfg(feature = "prover")]
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

#[cfg(feature = "prover")]
pub trait NoirCircuitInput {
    fn into_witness(self) -> Result<InputMap, ProofError>;
}

#[cfg(feature = "prover")]
pub trait NoirRepresentable {
    fn into_noir_value(self) -> InputValue;
}

/// Re-encodes a prime field element as provekit's `NoirElement` via its canonical big-endian bytes.
///
/// Reduction is a no-op for any field whose modulus does not exceed BN254's scalar field, which
/// holds for every caller here (including Baby Jubjub scalars).
#[cfg(feature = "prover")]
pub(crate) fn to_noir_element<F: ark_ff::PrimeField>(value: F) -> NoirElement {
    NoirElement::from_repr(ark_ff::PrimeField::from_be_bytes_mod_order(
        &value.into_bigint().to_bytes_be(),
    ))
}

#[cfg(feature = "prover")]
impl NoirRepresentable for FieldElement {
    fn into_noir_value(self) -> InputValue {
        InputValue::Field(to_noir_element(*self))
    }
}

#[cfg(feature = "prover")]
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
#[cfg(feature = "prover")]
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

#[cfg(feature = "prover")]
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
