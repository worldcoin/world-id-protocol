//! WIP-103: Proof of Ownership using ProveKit (Noir circuit backend).
//!
//! Generates ownership proofs by signing a Poseidon2-derived message
//! with the authenticator's EdDSA key, then proving the Noir circuit
//! via ProveKit.

#[cfg(feature = "zk-ownership-prove")]
pub use prover::generate_ownership_proof;

#[cfg(feature = "zk-ownership-prove")]
mod prover {
    use crate::{
        NoirCircuitInput, NoirRepresentable, ProofError, circuit_inputs::OwnershipProofCircuitInput,
    };
    use provekit_common::{InputMap, InputValue, NoirElement};
    use provekit_prover::Prove;
    use std::collections::BTreeMap;

    use ark_ff::{BigInteger as _, PrimeField as _};

    use world_id_primitives::{TREE_DEPTH, proof::OwnershipProof};

    /// Raw bytes of the embedded ProveKit Prover (PKP).
    #[cfg(not(docsrs))]

    const PKP_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ownership_proof.pkp"));

    #[cfg(docsrs)]
    const PKP_BYTES: &[u8] = &[];

    /// Cached deserialized prover (or the error message from the first attempt).
    static OWNERSHIP_PROVER: std::sync::OnceLock<Result<provekit_common::Prover, String>> =
        std::sync::OnceLock::new();

    /// Returns a clone of the cached [`provekit_common::Prover`] deserialized
    /// from the embedded PKP bytes. The deserialization happens only once.
    fn load_ownership_prover() -> Result<provekit_common::Prover, ProofError> {
        let cached = OWNERSHIP_PROVER.get_or_init(|| {
            provekit_common::register_ntt();
            provekit_common::file::deserialize(PKP_BYTES).map_err(|e| e.to_string())
        });
        match cached {
            Ok(prover) => Ok(prover.clone()),
            Err(err) => Err(ProofError::InternalError(eyre::eyre!(err.clone()))),
        }
    }

    /// Generates an ownership proof for WIP-103.
    ///
    /// # Errors
    /// Returns [`ProofError`] if signing, serialization, or proving
    /// fails.
    pub fn generate_ownership_proof(
        input: OwnershipProofCircuitInput<TREE_DEPTH>,
    ) -> Result<OwnershipProof, ProofError> {
        let merkle_root = input.inclusion_proof.root;
        let prover = load_ownership_prover()?;
        let witness = input.into_witness()?;
        let noir_proof = prover
            .prove(witness)
            .map_err(|e| ProofError::GenerationError(e.to_string()))?;

        Ok(OwnershipProof {
            proof: noir_proof.whir_r1cs_proof,
            merkle_root,
        })
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
            let s_native = ark_bn254::Fr::from_be_bytes_mod_order(
                &self.signature.s.into_bigint().to_bytes_be(),
            );
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
}

#[cfg(feature = "zk-ownership-verify")]
pub use verifier::verify_ownership_proof;

#[cfg(feature = "zk-ownership-verify")]
mod verifier {
    use crate::ProofError;
    use ark_babyjubjub::Fq;
    use provekit_common::{NoirProof, PublicInputs};
    use provekit_verifier::Verify;
    use world_id_primitives::{FieldElement, TREE_DEPTH, proof::OwnershipProof};

    /// Raw bytes of the embedded Verifying Key Package (PKV).
    #[cfg(not(docsrs))]
    const PKV_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ownership_proof.pkv"));

    #[cfg(docsrs)]
    const PKV_BYTES: &[u8] = &[];

    /// Cached deserialized verifier (or the error message from the first attempt).
    static OWNERSHIP_VERIFIER: std::sync::OnceLock<Result<provekit_common::Verifier, String>> =
        std::sync::OnceLock::new();

    /// Returns a clone of the cached [`provekit_common::Verifier`] deserialized
    /// from the embedded PKV bytes. The deserialization happens only once.
    fn load_ownership_verifier() -> Result<provekit_common::Verifier, ProofError> {
        let cached = OWNERSHIP_VERIFIER.get_or_init(|| {
            provekit_common::register_ntt();
            provekit_common::file::deserialize(PKV_BYTES).map_err(|e| e.to_string())
        });
        match cached {
            Ok(verifier) => Ok(verifier.clone()),
            Err(err) => Err(ProofError::InternalError(eyre::eyre!(err.clone()))),
        }
    }

    /// Verifies an ownership proof.
    ///
    /// # Errors
    /// Returns an error if the proof bytes are malformed, the verifier
    /// cannot be loaded, or verification fails.
    pub fn verify_ownership_proof(
        proof: &OwnershipProof,
        nonce: FieldElement,
        commitment: FieldElement,
    ) -> Result<(), ProofError> {
        let mut verifier = load_ownership_verifier()?;

        let public_inputs = PublicInputs::from_vec(vec![
            *proof.merkle_root,
            Fq::from(TREE_DEPTH as u64),
            *nonce,
            *commitment,
        ]);

        let noir_proof = NoirProof {
            public_inputs,
            whir_r1cs_proof: proof.proof.clone(),
        };
        verifier
            .verify(&noir_proof)
            .map_err(|e| ProofError::Verification(e.to_string()))
    }
}

#[cfg(all(test, feature = "zk-ownership-prove", feature = "zk-ownership-verify"))]
mod tests {
    use crate::{ProofError, circuit_inputs::OwnershipProofCircuitInput};

    use super::*;

    use eddsa_babyjubjub::EdDSAPrivateKey;
    use world_id_primitives::{
        AuthenticatorPublicKeySet, Credential, FieldElement, TREE_DEPTH,
        merkle::MerkleInclusionProof,
    };

    fn build_merkle_proof(leaf: ark_bn254::Fr) -> MerkleInclusionProof<TREE_DEPTH> {
        let (siblings, root) = world_id_test_utils::merkle::first_leaf_merkle_path(leaf);
        MerkleInclusionProof::new(root, 1, siblings)
    }

    fn generate_valid_ownership_proof_fixture()
    -> (super::OwnershipProof, FieldElement, FieldElement) {
        let sk = EdDSAPrivateKey::from_bytes([42u8; 32]);
        let pk = sk.public();
        let key_set = AuthenticatorPublicKeySet::new(vec![pk]).expect("single key fits");
        let leaf = key_set.leaf_hash();
        let inclusion_proof = build_merkle_proof(leaf);

        let nonce = FieldElement::from(1234567890u64);
        let commitment_blinder = FieldElement::from(999u64);
        let commitment = Credential::compute_sub(1, commitment_blinder);
        let signature = sk.sign(*commitment);

        let circuit_input = OwnershipProofCircuitInput {
            key_index: 0,
            key_set,
            inclusion_proof: inclusion_proof.clone(),
            nonce,
            signature,
            commitment_blinder,
        };

        let proof = generate_ownership_proof(circuit_input).unwrap();

        // Public input: merkle root is directly accessible
        assert_eq!(proof.merkle_root, inclusion_proof.root);
        assert!(!proof.proof.narg_string.is_empty());

        (proof, nonce, commitment)
    }

    #[test]
    fn test_generate_and_verify_ownership_proof() {
        let (proof, nonce, commitment) = generate_valid_ownership_proof_fixture();

        // Verification succeeds with correct public inputs. Depth is currently hardcoded in the
        // verification call.
        verify_ownership_proof(&proof, nonce, commitment).expect("ownership proof verifies");

        // Wrong commitment → verification fails
        let err = verify_ownership_proof(&proof, nonce, FieldElement::from(1u64)).unwrap_err();
        assert!(matches!(err, ProofError::Verification(_)));

        // Wrong nonce → verification fails
        let err = verify_ownership_proof(&proof, FieldElement::from(1234567891u64), commitment)
            .unwrap_err();
        assert!(matches!(err, ProofError::Verification(_)));
    }

    #[test]
    fn test_verify_ownership_proof_fails_with_wrong_merkle_root() {
        let (proof, nonce, commitment) = generate_valid_ownership_proof_fixture();

        let mut tampered_proof = proof.clone();
        let mut merkle_root_bytes = tampered_proof.merkle_root.to_be_bytes();
        merkle_root_bytes[31] ^= 0x01;
        tampered_proof.merkle_root = FieldElement::from_be_bytes(&merkle_root_bytes).unwrap();

        let err = verify_ownership_proof(&tampered_proof, nonce, commitment).unwrap_err();
        assert!(matches!(err, ProofError::Verification(_)));
    }

    #[test]
    fn test_verify_ownership_proof_fails_with_tampered_proof_bytes() {
        let (proof, nonce, commitment) = generate_valid_ownership_proof_fixture();

        let mut tampered_proof = proof.clone();
        tampered_proof.proof.narg_string[0] ^= 0x01;

        let err = verify_ownership_proof(&tampered_proof, nonce, commitment).unwrap_err();
        assert!(matches!(err, ProofError::Verification(_)));
    }
}
