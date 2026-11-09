//! WIP-103: Proof of Ownership using ProveKit (Noir circuit backend).
//!
//! Generates ownership proofs by signing a Poseidon2-derived message
//! with the authenticator's EdDSA key, then proving the Noir circuit
//! via ProveKit.

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::{collections::BTreeMap, io::Read};

use provekit_common::{InputMap, InputValue};
use world_id_primitives::{
    Credential, FieldElement, TREE_DEPTH,
    poseidon::{self, ds},
    proof::OwnershipProof,
};

use crate::{
    NoirCircuitInput, NoirRepresentable, ProofError,
    artifacts::ZkArtifactSource,
    circuit_inputs::OwnershipProofCircuitInput,
    error::ProofInputError,
    noir_components::{account_inputs, check_account_input_validity},
    provekit,
};

/// Loads an ownership proof prover from a reader containing PKP bytes.
///
/// # Errors
/// Returns an error if the reader cannot be read or the prover cannot be deserialized.
pub fn load_ownership_prover_from_reader(
    reader: impl Read,
) -> eyre::Result<provekit_common::Prover> {
    provekit::load_prover_from_reader(reader)
}

/// Loads an ownership proof prover from a PKP file path.
///
/// # Errors
/// Returns an error if the file cannot be read or the prover cannot be deserialized.
#[cfg(not(target_arch = "wasm32"))]
pub fn load_ownership_prover_from_path(
    path: impl AsRef<Path>,
) -> eyre::Result<provekit_common::Prover> {
    provekit::load_prover_from_path(path)
}

/// Loads an ownership proof verifier from a reader containing PKV bytes.
///
/// # Errors
/// Returns an error if the reader cannot be read or the verifier cannot be deserialized.
#[cfg(not(target_arch = "wasm32"))]
pub fn load_ownership_verifier_from_reader(
    reader: impl Read,
) -> eyre::Result<provekit_common::Verifier> {
    provekit::load_verifier_from_reader(reader)
}

/// Loads an ownership proof verifier from a PKV file path.
///
/// # Errors
/// Returns an error if the file cannot be read or the verifier cannot be deserialized.
#[cfg(not(target_arch = "wasm32"))]
pub fn load_ownership_verifier_from_path(
    path: impl AsRef<Path>,
) -> eyre::Result<provekit_common::Verifier> {
    provekit::load_verifier_from_path(path)
}

/// Checks the ownership proof inputs by emulating the constraints the circuit enforces, so a
/// caller mistake surfaces as a specific error instead of an opaque proving failure. This is only
/// for error convenience, the actual constraints are verified in the circuit.
///
/// # Errors
/// Returns a [`ProofInputError`] if any check fails.
pub fn check_ownership_input_validity<const MAX_DEPTH: usize>(
    inputs: &OwnershipProofCircuitInput<MAX_DEPTH>,
) -> Result<(), ProofInputError> {
    // 1. The verifier-supplied inputs must be set. Zero is a field element's default value.
    if inputs.nonce == FieldElement::ZERO {
        return Err(ProofInputError::ValueMustNotBeZero { name: "nonce" });
    }
    if inputs.context == FieldElement::ZERO {
        return Err(ProofInputError::ValueMustNotBeZero { name: "context" });
    }

    // 2. The account must be a registered World ID, whose key at `key_index` signs below.
    let key =
        check_account_input_validity(&inputs.key_set, inputs.key_index, &inputs.inclusion_proof)?;

    // 3. The commitment being proven must match the leaf index and blinder it is derived from.
    let derived =
        Credential::compute_sub(inputs.inclusion_proof.leaf_index, inputs.commitment_blinder);
    if derived != inputs.expected_commitment {
        return Err(ProofInputError::InvalidExpectedCommitment);
    }

    // 4. The registered key must have signed the ownership message.
    let message = poseidon::hash(
        ds::OWNERSHIP_PROOF,
        [inputs.expected_commitment, inputs.nonce, inputs.context],
    );
    if !key.verify(*message, &inputs.signature) {
        return Err(ProofInputError::InvalidAuthenticatorSignature);
    }

    Ok(())
}

/// Generates an ownership proof using artifacts from the provided source.
///
/// # Errors
/// Returns [`ProofError`] if Noir artifacts cannot be loaded or proving fails.
pub fn generate_ownership_proof(
    input: OwnershipProofCircuitInput<TREE_DEPTH>,
    artifacts: &dyn ZkArtifactSource,
) -> Result<OwnershipProof, ProofError> {
    let prover = artifacts.ownership_prover()?;
    generate_ownership_proof_with_prover(input, prover)
}

/// Generates an ownership proof using the provided prover.
///
/// # Errors
/// Returns [`ProofError`] if witness generation or proving fails.
pub fn generate_ownership_proof_with_prover(
    input: OwnershipProofCircuitInput<TREE_DEPTH>,
    prover: provekit_common::Prover,
) -> Result<OwnershipProof, ProofError> {
    check_ownership_input_validity(&input)?;

    let merkle_root = input.inclusion_proof.root;
    let proof = provekit::prove(prover, input.into_witness()?)?;
    Ok(OwnershipProof { proof, merkle_root })
}

/// Verifies an ownership proof using artifacts from the provided source.
///
/// # Errors
/// Returns an error if Noir artifacts cannot be loaded, the proof bytes are malformed,
/// or verification fails.
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_ownership_proof(
    proof: &OwnershipProof,
    nonce: FieldElement,
    expected_commitment: FieldElement,
    context: FieldElement,
    artifacts: &dyn ZkArtifactSource,
) -> Result<(), ProofError> {
    let mut verifier = artifacts.ownership_verifier()?;
    verify_ownership_proof_with_verifier(proof, nonce, expected_commitment, context, &mut verifier)
}

/// Verifies an ownership proof using the provided verifier.
///
/// # Errors
/// Returns an error if the proof bytes are malformed or verification fails.
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_ownership_proof_with_verifier(
    proof: &OwnershipProof,
    nonce: FieldElement,
    expected_commitment: FieldElement,
    context: FieldElement,
    verifier: &mut provekit_common::Verifier,
) -> Result<(), ProofError> {
    // Order must match the public parameters of `main` in the Noir circuit.
    provekit::verify(
        verifier,
        &[proof.merkle_root, nonce, expected_commitment, context],
        &proof.proof,
    )
}

impl NoirCircuitInput for OwnershipProofCircuitInput<TREE_DEPTH> {
    fn into_witness(self) -> Result<InputMap, ProofError> {
        let mut map = InputMap::new();

        // Public inputs
        map.insert(
            "merkle_root".into(),
            self.inclusion_proof.root.into_noir_value(),
        );
        map.insert("nonce".into(), self.nonce.into_noir_value());
        map.insert(
            "expected_commitment".into(),
            self.expected_commitment.into_noir_value(),
        );
        map.insert("context".into(), self.context.into_noir_value());

        // Private inputs struct
        let mut inputs: BTreeMap<String, InputValue> = BTreeMap::new();
        inputs.insert(
            "account".into(),
            account_inputs(
                &self.key_set,
                self.key_index,
                &self.signature,
                &self.inclusion_proof,
            ),
        );
        inputs.insert(
            "commitment_blinder".into(),
            self.commitment_blinder.into_noir_value(),
        );

        map.insert("inputs".into(), InputValue::Struct(inputs));

        Ok(map)
    }
}

#[cfg(test)]
mod input_validation_tests {
    use world_id_primitives::{
        MAX_AUTHENTICATOR_KEYS,
        poseidon::{self, ds},
    };

    use super::*;
    use std::str::FromStr as _;

    use crate::fixtures::ownership_proof_fixture;

    /// Known-answer tests sharing their inputs and expected outputs with the Noir known-answer tests
    /// in `noir/ownership-proof/src/commitment.nr`
    #[test]
    fn test_commitment_matches_the_circuit() {
        assert_eq!(
            Credential::compute_sub(1, FieldElement::from(100u64)),
            FieldElement::from_str(
                "0x26dc60a1544db4dad905da6967a536d6c37b3ae4b7cf951b925275096f5cbb1e"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_message_digest_matches_the_circuit() {
        assert_eq!(
            poseidon::hash(
                ds::OWNERSHIP_PROOF,
                [
                    FieldElement::from(1u64),
                    FieldElement::from(100u64),
                    FieldElement::from(7u64)
                ]
            ),
            FieldElement::from_str(
                "0x2125296e4b6fd60e191076334d52688d10c2ada7b2ccd4610af289be1c973b41"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_accepts_the_valid_fixture() {
        check_ownership_input_validity(&ownership_proof_fixture()).expect("fixture is valid");
    }

    #[test]
    fn test_rejects_zero_nonce() {
        let mut input = ownership_proof_fixture();
        input.nonce = FieldElement::ZERO;

        let err = check_ownership_input_validity(&input).unwrap_err();
        assert!(matches!(
            err,
            ProofInputError::ValueMustNotBeZero { name: "nonce" }
        ));
    }

    #[test]
    fn test_rejects_zero_context() {
        let mut input = ownership_proof_fixture();
        input.context = FieldElement::ZERO;

        let err = check_ownership_input_validity(&input).unwrap_err();
        assert!(matches!(
            err,
            ProofInputError::ValueMustNotBeZero { name: "context" }
        ));
    }

    #[test]
    fn test_rejects_key_index_beyond_the_key_slots() {
        let mut input = ownership_proof_fixture();
        input.key_index = MAX_AUTHENTICATOR_KEYS as u64;

        let err = check_ownership_input_validity(&input).unwrap_err();
        assert!(matches!(
            err,
            ProofInputError::ValueOutOfBounds {
                name: "key_index",
                ..
            }
        ));
    }

    #[test]
    fn test_rejects_an_inactive_key_slot() {
        let mut input = ownership_proof_fixture();
        input.key_index = 1;

        let err = check_ownership_input_validity(&input).unwrap_err();
        assert!(matches!(
            err,
            ProofInputError::InactiveAuthenticatorKey { index: 1 }
        ));
    }

    #[test]
    fn test_rejects_a_key_set_outside_the_registry() {
        let mut input = ownership_proof_fixture();
        input.inclusion_proof.root = FieldElement::from(12345_u64);

        let err = check_ownership_input_validity(&input).unwrap_err();
        assert!(matches!(
            err,
            ProofInputError::InvalidMerkleTreeInclusionProof
        ));
    }

    #[test]
    fn test_rejects_a_signature_over_another_context() {
        let mut input = ownership_proof_fixture();
        input.context = FieldElement::from(43_u64);

        let err = check_ownership_input_validity(&input).unwrap_err();
        assert!(matches!(
            err,
            ProofInputError::InvalidAuthenticatorSignature
        ));
    }

    #[test]
    fn test_rejects_leaf_index_beyond_the_tree() {
        let mut input = ownership_proof_fixture();
        input.inclusion_proof.leaf_index = 1 << TREE_DEPTH;

        let err = check_ownership_input_validity(&input).unwrap_err();
        assert!(matches!(
            err,
            ProofInputError::ValueOutOfBounds {
                name: "leaf_index",
                ..
            }
        ));
    }

    #[test]
    fn test_rejects_zero_leaf_index() {
        let mut input = ownership_proof_fixture();
        input.inclusion_proof.leaf_index = 0;

        let err = check_ownership_input_validity(&input).unwrap_err();
        assert!(matches!(
            err,
            ProofInputError::ValueMustNotBeZero { name: "leaf_index" }
        ));
    }

    #[test]
    fn test_rejects_expected_commitment_for_another_leaf_index() {
        let mut input = ownership_proof_fixture();
        input.expected_commitment = Credential::compute_sub(
            input.inclusion_proof.leaf_index + 1,
            input.commitment_blinder,
        );

        let err = check_ownership_input_validity(&input).unwrap_err();
        assert!(matches!(err, ProofInputError::InvalidExpectedCommitment));
    }

    #[test]
    fn test_rejects_tampered_commitment_blinder() {
        let mut input = ownership_proof_fixture();
        input.commitment_blinder = FieldElement::from(1000u64);

        let err = check_ownership_input_validity(&input).unwrap_err();
        assert!(matches!(err, ProofInputError::InvalidExpectedCommitment));
    }
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    feature = "embed-ownership-prover",
    feature = "embed-ownership-verifier"
))]
mod tests {
    use provekit_prover::Prove as _;

    use crate::{artifacts::embedded::EmbeddedZkArtifacts, provekit::solve_witness};

    use super::*;

    use crate::fixtures::ownership_proof_fixture;
    use world_id_primitives::Credential;

    #[test]
    fn test_ownership_artifacts_bind_public_input_count() {
        let artifacts = EmbeddedZkArtifacts;
        let prover = artifacts.ownership_prover().expect("embedded prover loads");
        let verifier = artifacts
            .ownership_verifier()
            .expect("embedded verifier loads");

        // ProveKit 1.0.2 artifacts recorded zero here despite the circuit's public inputs.
        // Both keys must be regenerated with 1.0.3 for its stricter verifier checks to pass.
        assert_eq!(prover.r1cs.num_public_inputs, 4);
        assert_eq!(verifier.r1cs.num_public_inputs, 4);
        let r1cs_hash = prover.r1cs.hash();
        assert_eq!(verifier.r1cs.hash(), r1cs_hash);
        assert_eq!(prover.whir_for_witness.r1cs_hash, r1cs_hash);
        assert_eq!(verifier.whir_for_witness.unwrap().r1cs_hash, r1cs_hash);
    }

    /// A valid proof together with its `(nonce, expected_commitment, context)` public inputs.
    fn generate_valid_ownership_proof_fixture()
    -> (OwnershipProof, FieldElement, FieldElement, FieldElement) {
        let circuit_input = ownership_proof_fixture();
        let (nonce, commitment, context) = (
            circuit_input.nonce,
            circuit_input.expected_commitment,
            circuit_input.context,
        );
        let root = circuit_input.inclusion_proof.root;

        let artifacts = EmbeddedZkArtifacts;
        let proof = generate_ownership_proof(circuit_input, &artifacts).unwrap();

        // Public input: merkle root is directly accessible
        assert_eq!(proof.merkle_root, root);
        assert!(!proof.proof.narg_string.is_empty());

        (proof, nonce, commitment, context)
    }

    #[test]
    fn test_generate_and_verify_ownership_proof() {
        let (proof, nonce, commitment, context) = generate_valid_ownership_proof_fixture();

        // Verification succeeds with correct public inputs.
        let artifacts = EmbeddedZkArtifacts;
        verify_ownership_proof(&proof, nonce, commitment, context, &artifacts)
            .expect("ownership proof verifies");

        // Wrong commitment → verification fails
        let err =
            verify_ownership_proof(&proof, nonce, FieldElement::from(1u64), context, &artifacts)
                .unwrap_err();
        assert!(matches!(err, ProofError::Verification(_)));

        // Wrong nonce → verification fails
        let err = verify_ownership_proof(
            &proof,
            FieldElement::from(1234567891u64),
            commitment,
            context,
            &artifacts,
        )
        .unwrap_err();
        assert!(matches!(err, ProofError::Verification(_)));

        // Wrong context → verification fails
        let err = verify_ownership_proof(
            &proof,
            nonce,
            commitment,
            FieldElement::from(43u64),
            &artifacts,
        )
        .unwrap_err();
        assert!(matches!(err, ProofError::Verification(_)));
    }

    #[test]
    fn test_verify_ownership_proof_fails_with_wrong_merkle_root() {
        let (proof, nonce, commitment, context) = generate_valid_ownership_proof_fixture();

        let mut tampered_proof = proof.clone();
        let mut merkle_root_bytes = tampered_proof.merkle_root.to_be_bytes();
        merkle_root_bytes[31] ^= 0x01;
        tampered_proof.merkle_root = FieldElement::from_be_bytes(&merkle_root_bytes).unwrap();

        let artifacts = EmbeddedZkArtifacts;
        let err = verify_ownership_proof(&tampered_proof, nonce, commitment, context, &artifacts)
            .unwrap_err();
        assert!(matches!(err, ProofError::Verification(_)));
    }

    #[test]
    fn test_verify_ownership_proof_fails_with_tampered_proof_bytes() {
        let (proof, nonce, commitment, context) = generate_valid_ownership_proof_fixture();

        let mut tampered_proof = proof.clone();
        tampered_proof.proof.narg_string[0] ^= 0x01;

        let artifacts = EmbeddedZkArtifacts;
        let err = verify_ownership_proof(&tampered_proof, nonce, commitment, context, &artifacts)
            .unwrap_err();
        assert!(matches!(err, ProofError::Verification(_)));
    }

    /// [`check_ownership_input_validity`] rejects a bad input before proving, so it is bypassed
    /// here to assert the constraint is also enforced by the *compiled* circuit.
    #[test]
    fn test_compiled_circuit_rejects_mismatched_commitment() {
        let mut input = ownership_proof_fixture();

        // The fixture signature stays valid over the commitment the circuit derives, so the only
        // violated constraint is `commitment == expected_commitment`
        input.expected_commitment = Credential::compute_sub(
            input.inclusion_proof.leaf_index + 1,
            input.commitment_blinder,
        );

        let prover = EmbeddedZkArtifacts
            .ownership_prover()
            .expect("embedded prover loads");
        let witness = input.into_witness().expect("witness maps");

        let err = solve_witness(&prover, witness.clone())
            .expect_err("the WASM solver must reject a commitment it cannot derive");
        assert!(matches!(err, ProofError::GenerationError(_)));
        prover
            .prove(witness)
            .expect_err("the native prover must reject a commitment it cannot derive");
    }

    #[test]
    fn test_wasm_witness_solver_matches_provekit() {
        let mut prover = EmbeddedZkArtifacts
            .ownership_prover()
            .expect("embedded prover loads");
        let input = ownership_proof_fixture().into_witness().unwrap();
        let actual = solve_witness(&prover, input.clone()).expect("WASM solver succeeds");
        let expected = prover
            .generate_witness(input)
            .expect("native solver succeeds");

        assert_eq!(
            postcard::to_allocvec(&actual).unwrap(),
            postcard::to_allocvec(&expected).unwrap()
        );
    }
}
