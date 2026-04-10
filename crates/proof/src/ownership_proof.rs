//! WIP-103: Proof of Ownership using ProveKit (Noir circuit backend).
//!
//! Generates ownership proofs by signing a Poseidon2-derived message
//! with the authenticator's EdDSA key, then proving the Noir circuit
//! via ProveKit.

use std::fmt::Write as _;

use ark_ff::PrimeField;
use noirc_abi::{InputMap, input_parser::InputValue};
use provekit_common::NoirProof;
use provekit_prover::Prove;

use crate::{AuthenticatorProofInput, NoirCircuitInput, ProofError};
use world_id_primitives::{TREE_DEPTH, circuit_inputs::OwnershipProofCircuitInput};

/// Raw bytes of the embedded Proving Key Package (PKP).
const PKP_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ownership_proof.pkp"));
/// Loads a [`provekit_common::Prover`] from the embedded PKP bytes.
fn load_ownership_prover() -> Result<provekit_common::Prover, ProofError> {
    provekit_common::register_ntt();
    provekit_common::file::deserialize(PKP_BYTES)
        .map_err(|e| ProofError::InternalError(eyre::eyre!(e)))
}

/// Generates an ownership proof for WIP-103.
///
/// # Arguments
/// * `input` - Authenticator keys, Merkle inclusion proof, signing
///   key, and key index.
/// * `nonce` - Public nonce (signal hash placeholder).
/// * `commitment_r` - Randomness used to derive the commitment.
///
/// # Errors
/// Returns [`ProofError`] if signing, serialization, or proving
/// fails.
pub fn generate_ownership_proof(
    input: OwnershipProofCircuitInput<TREE_DEPTH>,
) -> Result<NoirProof, ProofError> {
    let prover = load_ownership_prover()?;
    panic!("todo");
    // let witness = input.into_witness()?;
    // prover
    //     .prove(witness)
    //     .map_err(|e| ProofError::GenerationError(e.to_string()))
}

impl NoirCircuitInput for OwnershipProofCircuitInput<TREE_DEPTH> {
    fn into_witness(&self) -> Result<InputMap, ProofError> {
        let mut map = InputMap::new();

        // map.insert(
        //     "root".to_string(),
        //     InputValue::Field(*self.inclusion_proof.root),
        // );

        Ok(map)
    }
}
