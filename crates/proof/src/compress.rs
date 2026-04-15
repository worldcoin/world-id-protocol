//! Proof compression helpers.
//!
//! Converts an [`ark_groth16::Proof`] into a [`ZeroKnowledgeProof`] by compressing the
//! elliptic-curve points into a Solidity-friendly `[U256; 5]` representation.

use ark_bn254::Bn254;
use ark_groth16::Proof;
use world_id_primitives::{FieldElement, ZeroKnowledgeProof};

/// Extension trait for constructing a [`ZeroKnowledgeProof`] from a raw Groth16 proof.
pub trait ZeroKnowledgeProofExt {
    /// Compresses a raw Groth16 proof together with a Merkle root into a
    /// [`ZeroKnowledgeProof`].
    ///
    /// The first 4 `U256` elements are the compressed proof points
    /// (a, b₀, b₁, c) produced by [`taceo_groth16_sol::prepare_compressed_proof`].
    /// The 5th element is the `merkle_root` field element, which serves as the
    /// public input required by `WorldIDVerifier.sol`.
    fn from_groth16_proof(groth16_proof: &Proof<Bn254>, merkle_root: FieldElement) -> Self;
}

impl ZeroKnowledgeProofExt for ZeroKnowledgeProof {
    fn from_groth16_proof(groth16_proof: &Proof<Bn254>, merkle_root: FieldElement) -> Self {
        let compressed_proof = taceo_groth16_sol::prepare_compressed_proof(groth16_proof);
        Self::from_ethereum_representation([
            compressed_proof[0],
            compressed_proof[1],
            compressed_proof[2],
            compressed_proof[3],
            merkle_root.into(),
        ])
    }
}
