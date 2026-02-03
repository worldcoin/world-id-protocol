#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use eddsa_babyjubjub::EdDSAPrivateKey;
use world_id_primitives::{
    TREE_DEPTH, authenticator::AuthenticatorPublicKeySet, merkle::MerkleInclusionProof,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod credential_blinding_factor;
pub mod nullifier;
pub mod proof;

/// Inputs from the Authenticator to generate a nullifier or blinding factor.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthenticatorProofInput {
    /// The set of all public keys for all the user's authenticators.
    #[zeroize(skip)]
    key_set: AuthenticatorPublicKeySet,
    /// Inclusion proof in the World ID Registry.
    #[zeroize(skip)]
    inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    /// The off-chain signer key for the Authenticator.
    private_key: EdDSAPrivateKey,
    /// The index at which the authenticator key is located in the `key_set`.
    key_index: u64,
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
