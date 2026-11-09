#![cfg_attr(not(test), warn(unused_crate_dependencies))]

// Enforce the portable transcript version even though ProveKit uses Spongefish indirectly.
use spongefish as _;
// TODO: remove this line once the crate uses world-id-flamingo (#1177). Only the test fixtures use
// it so far; it is a normal dependency so that release-plz, which orders crates by their normal
// dependencies, publishes world-id-flamingo before this crate.
use world_id_flamingo as _;

use eddsa_babyjubjub::EdDSAPrivateKey;

use world_id_primitives::{AuthenticatorPublicKeySet, TREE_DEPTH, merkle::MerkleInclusionProof};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ZK artifact source abstractions.
pub mod artifacts;

/// Circuit input types for Circom/Groth16 circuits (query, nullifier, ownership proofs).
pub mod circuit_inputs;

/// Errors of proof generation, verification and input checks.
pub mod error;
pub use artifacts::ZkArtifactError;
pub use error::{ProofError, ProofInputError};

/// Static circuit input fixtures shared by the tests and the generated circuit examples.
#[cfg(test)]
mod fixtures;

/// Fixture generator for the WIP-202 Proof of Embedding Similarity circuit.
#[cfg(test)]
mod embedding_similarity_fixtures;

pub mod compress;
pub use compress::ProofCompression;
pub mod oprf_query_proof;
pub use oprf_query_proof::{
    FullOprfOutput, OprfEntrypoint, QUERY_GRAPH_FINGERPRINT, QUERY_ZKEY_FINGERPRINT,
    load_query_material_from_paths, load_query_material_from_reader,
};

pub mod nullifier_proof;
pub use nullifier_proof::{
    CircomGroth16Material, CircomGroth16MaterialBuilder, NULLIFIER_GRAPH_FINGERPRINT,
    NULLIFIER_ZKEY_FINGERPRINT, ZkeyError, generate_nullifier_proof,
    load_nullifier_material_from_paths, load_nullifier_material_from_reader,
};

/// Moved to [`world_id_primitives::authenticator_assertion`]; re-exported for existing imports.
pub use world_id_primitives::authenticator_assertion;

use ark_ff::BigInteger as _;
use provekit_common::{InputMap, InputValue, NoirElement};

use world_id_primitives::FieldElement;

pub mod ownership_proof;

mod noir_components;

/// UNAUDITED. Embedded artifacts of the WIP-202 Proof of Embedding Similarity circuit.
#[cfg(any(
    feature = "embed-embedding-similarity-prover",
    all(
        not(target_arch = "wasm32"),
        feature = "embed-embedding-similarity-verifier"
    )
))]
pub mod embedding_similarity;

pub use provekit_common::{
    NoirProof, Prover as OwnershipProver, Verifier as OwnershipVerifier, WhirR1CSProof,
};

pub trait NoirCircuitInput {
    fn into_witness(self) -> Result<InputMap, ProofError>;
}

pub trait NoirRepresentable {
    fn into_noir_value(self) -> InputValue;
}

/// Re-encodes a prime field element as provekit's `NoirElement` via its canonical big-endian bytes.
///
/// Reduction is a no-op for any field whose modulus does not exceed BN254's scalar field, which
/// holds for every caller here (including Baby Jubjub scalars).
pub(crate) fn to_noir_element<F: ark_ff::PrimeField>(value: F) -> NoirElement {
    NoirElement::from_repr(ark_ff::PrimeField::from_be_bytes_mod_order(
        &value.into_bigint().to_bytes_be(),
    ))
}

impl NoirRepresentable for FieldElement {
    fn into_noir_value(self) -> InputValue {
        InputValue::Field(to_noir_element(*self))
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
