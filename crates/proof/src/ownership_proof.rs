//! WIP-103: Proof of Ownership using ProveKit (Noir circuit backend).
//!
//! Generates ownership proofs by signing a Poseidon2-derived message
//! with the authenticator's EdDSA key, then proving the Noir circuit
//! via ProveKit.

use std::{collections::BTreeMap, io::Read, path::Path};

use ark_ff::{BigInteger as _, PrimeField as _};
use provekit_common::{InputMap, InputValue, NoirElement, NoirProof, PublicInputs};
use provekit_prover::Prove;
use provekit_verifier::Verify;
use world_id_primitives::{FieldElement, TREE_DEPTH, proof::OwnershipProof};

use crate::{
    NoirCircuitInput, NoirRepresentable, ProofError, circuit_inputs::OwnershipProofCircuitInput,
};

/// Domain separator for the Ownership Proof Hash Message.
pub const DS_OWNERSHIP_PROOF: &[u8; 6] = b"WIP103";

/// Loads an ownership proof prover from a reader containing PKP bytes.
///
/// # Errors
/// Returns an error if the reader cannot be read or the prover cannot be deserialized.
pub fn load_ownership_prover_from_reader(
    mut reader: impl Read,
) -> eyre::Result<provekit_common::Prover> {
    provekit_common::register_ntt();

    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    provekit_common::file::deserialize(&bytes).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Loads an ownership proof prover from a PKP file path.
///
/// # Errors
/// Returns an error if the file cannot be read or the prover cannot be deserialized.
pub fn load_ownership_prover_from_path(
    path: impl AsRef<Path>,
) -> eyre::Result<provekit_common::Prover> {
    provekit_common::register_ntt();
    provekit_common::file::read(path.as_ref()).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Loads an ownership proof verifier from a reader containing PKV bytes.
///
/// # Errors
/// Returns an error if the reader cannot be read or the verifier cannot be deserialized.
pub fn load_ownership_verifier_from_reader(
    mut reader: impl Read,
) -> eyre::Result<provekit_common::Verifier> {
    provekit_common::register_ntt();

    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    provekit_common::file::deserialize(&bytes).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Loads an ownership proof verifier from a PKV file path.
///
/// # Errors
/// Returns an error if the file cannot be read or the verifier cannot be deserialized.
pub fn load_ownership_verifier_from_path(
    path: impl AsRef<Path>,
) -> eyre::Result<provekit_common::Verifier> {
    provekit_common::register_ntt();
    provekit_common::file::read(path.as_ref()).map_err(|e| eyre::eyre!(e.to_string()))
}

#[cfg(all(feature = "embed-noir-artifacts", not(docsrs)))]
const PKP_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ownership_proof.pkp"));

#[cfg(all(feature = "embed-noir-artifacts", docsrs))]
const PKP_BYTES: &[u8] = &[];

#[cfg(feature = "embed-noir-artifacts")]
static OWNERSHIP_PROVER: std::sync::OnceLock<Result<provekit_common::Prover, String>> =
    std::sync::OnceLock::new();

/// Loads the embedded ownership proof prover.
///
/// # Errors
/// Returns an error if embedded Noir artifacts are missing or invalid.
#[cfg(feature = "embed-noir-artifacts")]
pub fn load_embedded_ownership_prover() -> eyre::Result<provekit_common::Prover> {
    let cached = OWNERSHIP_PROVER
        .get_or_init(|| load_ownership_prover_from_reader(PKP_BYTES).map_err(|e| e.to_string()));
    match cached {
        Ok(prover) => Ok(prover.clone()),
        Err(err) => Err(eyre::eyre!(err.clone())),
    }
}

#[cfg(all(feature = "embed-noir-artifacts", not(docsrs)))]
const PKV_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ownership_proof.pkv"));

#[cfg(all(feature = "embed-noir-artifacts", docsrs))]
const PKV_BYTES: &[u8] = &[];

#[cfg(feature = "embed-noir-artifacts")]
static OWNERSHIP_VERIFIER: std::sync::OnceLock<Result<provekit_common::Verifier, String>> =
    std::sync::OnceLock::new();

/// Loads the embedded ownership proof verifier.
///
/// # Errors
/// Returns an error if embedded Noir artifacts are missing or invalid.
#[cfg(feature = "embed-noir-artifacts")]
pub fn load_embedded_ownership_verifier() -> eyre::Result<provekit_common::Verifier> {
    let cached = OWNERSHIP_VERIFIER
        .get_or_init(|| load_ownership_verifier_from_reader(PKV_BYTES).map_err(|e| e.to_string()));
    match cached {
        Ok(verifier) => Ok(verifier.clone()),
        Err(err) => Err(eyre::eyre!(err.clone())),
    }
}

/// Generates an ownership proof using the embedded prover.
///
/// # Errors
/// Returns [`ProofError`] if embedded Noir artifacts are disabled or proving fails.
pub fn generate_ownership_proof(
    input: OwnershipProofCircuitInput<TREE_DEPTH>,
) -> Result<OwnershipProof, ProofError> {
    #[cfg(feature = "embed-noir-artifacts")]
    {
        let prover = load_embedded_ownership_prover().map_err(ProofError::InternalError)?;
        generate_ownership_proof_with_prover(input, prover)
    }

    #[cfg(not(feature = "embed-noir-artifacts"))]
    {
        let _ = input;
        Err(embedded_noir_artifacts_disabled(
            "generate_ownership_proof_with_prover",
        ))
    }
}

/// Generates an ownership proof using the provided prover.
///
/// # Errors
/// Returns [`ProofError`] if witness generation or proving fails.
pub fn generate_ownership_proof_with_prover(
    input: OwnershipProofCircuitInput<TREE_DEPTH>,
    prover: provekit_common::Prover,
) -> Result<OwnershipProof, ProofError> {
    provekit_common::register_ntt();

    let merkle_root = input.inclusion_proof.root;
    let witness = input.into_witness()?;
    let noir_proof = prover
        .prove(witness)
        .map_err(|e| ProofError::GenerationError(e.to_string()))?;

    Ok(OwnershipProof {
        proof: noir_proof.whir_r1cs_proof,
        merkle_root,
    })
}

/// Verifies an ownership proof using the embedded verifier.
///
/// # Errors
/// Returns an error if embedded Noir artifacts are disabled, the proof bytes are malformed,
/// or verification fails.
pub fn verify_ownership_proof(
    proof: &OwnershipProof,
    nonce: FieldElement,
    commitment: FieldElement,
) -> Result<(), ProofError> {
    #[cfg(feature = "embed-noir-artifacts")]
    {
        let mut verifier = load_embedded_ownership_verifier().map_err(ProofError::InternalError)?;
        verify_ownership_proof_with_verifier(proof, nonce, commitment, &mut verifier)
    }

    #[cfg(not(feature = "embed-noir-artifacts"))]
    {
        let _ = (proof, nonce, commitment);
        Err(embedded_noir_artifacts_disabled(
            "verify_ownership_proof_with_verifier",
        ))
    }
}

/// Verifies an ownership proof using the provided verifier.
///
/// # Errors
/// Returns an error if the proof bytes are malformed or verification fails.
pub fn verify_ownership_proof_with_verifier(
    proof: &OwnershipProof,
    nonce: FieldElement,
    commitment: FieldElement,
    verifier: &mut provekit_common::Verifier,
) -> Result<(), ProofError> {
    provekit_common::register_ntt();

    let public_inputs = PublicInputs::from_vec(vec![
        *proof.merkle_root,
        ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
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

#[cfg(not(feature = "embed-noir-artifacts"))]
fn embedded_noir_artifacts_disabled(alternative: &str) -> ProofError {
    ProofError::InternalError(eyre::eyre!(
        "embedded Noir ownership proof artifacts are disabled; enable `embed-noir-artifacts` or use `{alternative}`"
    ))
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

#[cfg(all(test, feature = "embed-noir-artifacts"))]
mod tests {
    use crate::circuit_inputs::OwnershipProofCircuitInput;

    use super::*;

    use eddsa_babyjubjub::EdDSAPrivateKey;
    use world_id_primitives::{
        AuthenticatorPublicKeySet, Credential, TREE_DEPTH, merkle::MerkleInclusionProof,
    };

    const LEAF_INDEX: u64 = 1;

    fn build_merkle_proof(leaf: ark_bn254::Fr) -> MerkleInclusionProof<TREE_DEPTH> {
        let (siblings, root) = world_id_test_utils::merkle::first_leaf_merkle_path(leaf);
        MerkleInclusionProof::new(root, LEAF_INDEX, siblings)
    }

    fn generate_valid_ownership_proof_fixture() -> (OwnershipProof, FieldElement, FieldElement) {
        let sk = EdDSAPrivateKey::from_bytes([42u8; 32]);
        let pk = sk.public();
        let key_set = AuthenticatorPublicKeySet::new(vec![pk]).expect("single key fits");
        let leaf = key_set.leaf_hash();
        let inclusion_proof = build_merkle_proof(leaf);

        let nonce = FieldElement::from(1234567890u64);
        let commitment_blinder = FieldElement::from(999u64);
        let commitment = Credential::compute_sub(LEAF_INDEX, commitment_blinder);

        // The circuit signs `Poseidon2(DS_OWNERSHIP_PROOF, commitment, nonce)`, not the raw
        // commitment. See `Authenticator::prove_credential_sub`.
        let mut message = [
            *FieldElement::from_be_bytes_mod_order(DS_OWNERSHIP_PROOF),
            *commitment,
            *nonce,
        ];
        poseidon2::bn254::t3::permutation_in_place(&mut message);
        let signature = sk.sign(message[1]);

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
