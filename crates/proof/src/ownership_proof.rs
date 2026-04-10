//! WIP-103: Proof of Ownership using ProveKit (Noir circuit backend).
//!
//! Generates ownership proofs by signing a Poseidon2-derived message
//! with the authenticator's EdDSA key, then proving the Noir circuit
//! via ProveKit.

use std::collections::BTreeMap;

use ark_ff::{BigInteger as _, PrimeField as _};
use provekit_common::{InputMap, InputValue, NoirElement, NoirProof};
use provekit_prover::Prove;

use crate::{NoirCircuitInput, NoirRepresentable, ProofError};
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
    let witness = input.into_witness()?;
    prover
        .prove(witness)
        .map_err(|e| ProofError::GenerationError(e.to_string()))
}

impl NoirCircuitInput for OwnershipProofCircuitInput<TREE_DEPTH> {
    fn into_witness(self) -> Result<InputMap, ProofError> {
        let mut map = InputMap::new();

        // Public inputs
        map.insert("root".into(), self.inclusion_proof.root.into_noir_value());
        map.insert(
            "depth".into(),
            InputValue::Field(NoirElement::from(TREE_DEPTH)),
        );
        map.insert("nonce".into(), self.nonce.into_noir_value());

        // Private inputs struct
        let mut inputs: BTreeMap<String, InputValue> = BTreeMap::new();

        // user_pk: [PublicKey; 7]
        let affine_keys = self.key_set.as_affine_array();
        let user_pk: Vec<InputValue> = affine_keys
            .iter()
            .map(|pk| {
                let mut s = BTreeMap::new();
                s.insert("x".into(), InputValue::Field(NoirElement::from_repr(pk.x)));
                s.insert("y".into(), InputValue::Field(NoirElement::from_repr(pk.y)));
                InputValue::Struct(s)
            })
            .collect();
        inputs.insert("user_pk".into(), InputValue::Vec(user_pk));

        // pk_index
        inputs.insert(
            "pk_index".into(),
            InputValue::Field(NoirElement::from(self.key_index)),
        );

        // query_s (babyjubjub scalar → bn254 scalar via big-endian bytes)
        let s_native =
            ark_bn254::Fr::from_be_bytes_mod_order(&self.signature.s.into_bigint().to_bytes_be());
        inputs.insert(
            "query_s".into(),
            InputValue::Field(NoirElement::from_repr(s_native)),
        );

        // query_r: [Field; 2]  (point x, y)
        inputs.insert(
            "query_r".into(),
            InputValue::Vec(vec![
                InputValue::Field(NoirElement::from_repr(self.signature.r.x)),
                InputValue::Field(NoirElement::from_repr(self.signature.r.y)),
            ]),
        );

        let siblings: Vec<InputValue> = self
            .inclusion_proof
            .siblings
            .iter()
            .map(|s| (*s).into_noir_value())
            .collect();
        let mut merkle = BTreeMap::new();
        merkle.insert(
            "mt_index".into(),
            InputValue::Field(NoirElement::from(self.inclusion_proof.leaf_index)),
        );
        merkle.insert("siblings".into(), InputValue::Vec(siblings));
        inputs.insert("merkle_proof".into(), InputValue::Struct(merkle));
        inputs.insert(
            "commitment_r".into(),
            self.commitment_blinder.into_noir_value(),
        );

        map.insert("inputs".into(), InputValue::Struct(inputs));

        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_bn254::Fr;
    use eddsa_babyjubjub::EdDSAPrivateKey;
    use world_id_primitives::{
        Credential, FieldElement, authenticator::AuthenticatorPublicKeySet,
        merkle::MerkleInclusionProof,
    };

    /// Builds a Merkle inclusion proof for a single leaf at index 1
    /// in an otherwise empty (all-zeros) tree of depth `TREE_DEPTH`.
    fn build_merkle_proof(leaf: ark_bn254::Fr) -> MerkleInclusionProof<TREE_DEPTH> {
        let (siblings, root) = world_id_test_utils::merkle::first_leaf_merkle_path(leaf);
        MerkleInclusionProof::new(root, 1, siblings)
    }

    #[test]
    fn test_generate_ownership_proof() {
        // 1. Generate an EdDSA keypair
        let sk = EdDSAPrivateKey::from_bytes([42u8; 32]);
        let pk = sk.public();

        // 2. Build a key set containing a single authenticator key
        let key_set = AuthenticatorPublicKeySet::new(vec![pk]).expect("single key fits");

        // 3. Compute the leaf hash and build a Merkle proof
        let leaf = key_set.leaf_hash();
        let inclusion_proof = build_merkle_proof(leaf);

        // 4. Compute the message and sign it
        let nonce = FieldElement::from(1234567890u64);
        let commitment_blinder = FieldElement::from(999u64);
        let commitment = Credential::compute_sub(1, commitment_blinder);
        let signature = sk.sign(*commitment);

        // 5. Construct circuit input and generate proof
        let circuit_input = OwnershipProofCircuitInput {
            key_index: 0,
            key_set,
            inclusion_proof: inclusion_proof.clone(),
            nonce,
            signature,
            commitment_blinder,
        };

        let proof = generate_ownership_proof(circuit_input).unwrap();

        assert!(!proof.public_inputs.is_empty());

        assert_eq!(proof.public_inputs.0[0], *inclusion_proof.root);
        assert_eq!(proof.public_inputs.0[1], Fr::from(30));
        assert_eq!(proof.public_inputs.0[2], *nonce);
        assert_eq!(proof.public_inputs.0[3], *commitment);
    }
}
