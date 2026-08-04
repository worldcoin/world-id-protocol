//! DeepFace Query Proof: the billing gate presented to the Verifier TEE.
//!
//! Implements the prover/verifier side of `noir/deepface-query-proof`, the `Query Proof`
//! of the YABS "Updated Design". The user proves it is enrolled for billing under some
//! `(rp_id, period)` billing tree, that the enrolled leaf opens to its own World ID, and
//! that a valid Proof of Human credential for that World ID carries the PCP hash the TEE
//! is about to match against.
//!
//! Unlike the Circom circuits in this crate, the artifacts need no trusted setup: they are
//! derived from the checked-in Noir source by the ProveKit R1CS compiler, exactly like the
//! [`crate::ownership_proof`] artifacts.
//!
//! # Status
//!
//! UNAUDITED, and the circuit deliberately does not prove control of the World ID it opens
//! the billing leaf to. See the module docs of `noir/deepface-query-proof/src/main.nr`.

use std::{collections::BTreeMap, io::Read, path::Path};

use ark_ff::{BigInteger as _, PrimeField as _};
use provekit_common::{InputMap, InputValue, NoirElement, NoirProof};
use provekit_prover::Prove;
use provekit_verifier::Verify;

use crate::{
    NoirCircuitInput, NoirProver, NoirRepresentable, NoirVerifier, ProofError,
    circuit_inputs::DeepFaceQueryProofCircuitInput,
};

/// Loads a DeepFace query proof prover from a reader containing PKP bytes.
///
/// # Errors
/// Returns an error if the reader cannot be read or the prover cannot be deserialized.
pub fn load_deepface_query_prover_from_reader(mut reader: impl Read) -> eyre::Result<NoirProver> {
    provekit_common::register_ntt();

    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    provekit_common::file::deserialize(&bytes).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Loads a DeepFace query proof prover from a PKP file path.
///
/// # Errors
/// Returns an error if the file cannot be read or the prover cannot be deserialized.
pub fn load_deepface_query_prover_from_path(path: impl AsRef<Path>) -> eyre::Result<NoirProver> {
    provekit_common::register_ntt();
    provekit_common::file::read(path.as_ref()).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Loads a DeepFace query proof verifier from a reader containing PKV bytes.
///
/// # Errors
/// Returns an error if the reader cannot be read or the verifier cannot be deserialized.
pub fn load_deepface_query_verifier_from_reader(
    mut reader: impl Read,
) -> eyre::Result<NoirVerifier> {
    provekit_common::register_ntt();

    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    provekit_common::file::deserialize(&bytes).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Loads a DeepFace query proof verifier from a PKV file path.
///
/// # Errors
/// Returns an error if the file cannot be read or the verifier cannot be deserialized.
pub fn load_deepface_query_verifier_from_path(
    path: impl AsRef<Path>,
) -> eyre::Result<NoirVerifier> {
    provekit_common::register_ntt();
    provekit_common::file::read(path.as_ref()).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Generates a DeepFace query proof with the provided prover.
///
/// The returned [`NoirProof`] carries its own public inputs, so the TEE verifies it
/// without the caller having to restate them.
///
/// # Note
/// [`provekit_prover::Prove::prove`] consumes the prover, so repeated proving needs a
/// clone per call. This mirrors [`crate::ownership_proof::generate_ownership_proof_with_prover`].
///
/// # Errors
/// Returns [`ProofError`] if witness generation or proving fails.
pub fn generate_deepface_query_proof_with_prover(
    input: DeepFaceQueryProofCircuitInput,
    prover: NoirProver,
) -> Result<NoirProof, ProofError> {
    provekit_common::register_ntt();

    let witness = input.into_witness()?;
    prover
        .prove(witness)
        .map_err(|e| ProofError::GenerationError(e.to_string()))
}

/// Verifies a DeepFace query proof with the provided verifier.
///
/// # Note
/// This only establishes that the proof is valid for the public inputs *it carries*. The
/// TEE must separately check those public inputs: that `billing_root` is in its host-fed
/// root map and that `billing_depth` is the depth it recorded for that root, that
/// `pcp_hash` matches the hash it derives from `hashes.json`, that
/// `issuer_schema_id`/`issuer_pk` are accepted, that `current_timestamp` is current
/// against its trusted clock, and that `nonce` has not been seen.
///
/// A wrong `billing_depth` is not exploitable on its own — the recomputed root would have
/// to collide with a root the host fed in — but checking it keeps `root unknown` and
/// `inclusion proof invalid` distinguishable as reject reasons.
///
/// # Errors
/// Returns [`ProofError`] if verification fails.
pub fn verify_deepface_query_proof_with_verifier(
    proof: &NoirProof,
    verifier: &mut NoirVerifier,
) -> Result<(), ProofError> {
    provekit_common::register_ntt();

    verifier
        .verify(proof)
        .map_err(|e| ProofError::Verification(e.to_string()))
}

impl NoirCircuitInput for DeepFaceQueryProofCircuitInput {
    fn into_witness(self) -> Result<InputMap, ProofError> {
        let mut map = InputMap::new();

        // Public inputs, in the declaration order of `main`.
        map.insert("billing_root".into(), self.billing_root.into_noir_value());
        map.insert(
            "billing_depth".into(),
            InputValue::Field(NoirElement::from(self.billing_depth)),
        );
        map.insert("pcp_hash".into(), self.pcp_hash.into_noir_value());
        map.insert(
            "issuer_schema_id".into(),
            InputValue::Field(NoirElement::from(self.issuer_schema_id)),
        );

        let mut issuer_pk = BTreeMap::new();
        issuer_pk.insert(
            "x".into(),
            InputValue::Field(NoirElement::from_repr(self.issuer_pk.x)),
        );
        issuer_pk.insert(
            "y".into(),
            InputValue::Field(NoirElement::from_repr(self.issuer_pk.y)),
        );
        map.insert("issuer_pk".into(), InputValue::Struct(issuer_pk));

        map.insert(
            "current_timestamp".into(),
            InputValue::Field(NoirElement::from(self.current_timestamp)),
        );
        map.insert(
            "genesis_issued_at_min".into(),
            InputValue::Field(NoirElement::from(self.genesis_issued_at_min)),
        );
        map.insert("nonce".into(), self.nonce.into_noir_value());

        // Private input struct.
        let mut inputs: BTreeMap<String, InputValue> = BTreeMap::new();
        inputs.insert(
            "mt_index".into(),
            InputValue::Field(NoirElement::from(self.mt_index)),
        );
        inputs.insert("commitment_r".into(), self.commitment_r.into_noir_value());

        let siblings: Vec<InputValue> = self
            .billing_siblings
            .iter()
            .map(|s| (*s).into_noir_value())
            .collect();
        let mut billing_proof = BTreeMap::new();
        billing_proof.insert(
            "mt_index".into(),
            InputValue::Field(NoirElement::from(self.billing_leaf_index)),
        );
        billing_proof.insert("siblings".into(), InputValue::Vec(siblings));
        inputs.insert("billing_proof".into(), InputValue::Struct(billing_proof));

        // The credential's EdDSA `s` lives in the BabyJubJub scalar field; the circuit
        // takes it as a bn254 base field element, same as the ownership proof.
        let sig_s = ark_bn254::Fr::from_be_bytes_mod_order(
            &self.credential_signature.s.into_bigint().to_bytes_be(),
        );

        let mut credential: BTreeMap<String, InputValue> = BTreeMap::new();
        credential.insert(
            "associated_data_hash".into(),
            self.credential_associated_data_hash.into_noir_value(),
        );
        credential.insert(
            "genesis_issued_at".into(),
            InputValue::Field(NoirElement::from(self.credential_genesis_issued_at)),
        );
        credential.insert(
            "expires_at".into(),
            InputValue::Field(NoirElement::from(self.credential_expires_at)),
        );
        credential.insert(
            "sig_s".into(),
            InputValue::Field(NoirElement::from_repr(sig_s)),
        );
        credential.insert(
            "sig_r".into(),
            InputValue::Vec(vec![
                InputValue::Field(NoirElement::from_repr(self.credential_signature.r.x)),
                InputValue::Field(NoirElement::from_repr(self.credential_signature.r.y)),
            ]),
        );
        credential.insert(
            "sub_blinding_factor".into(),
            self.credential_sub_blinding_factor.into_noir_value(),
        );
        credential.insert(
            "cred_id".into(),
            InputValue::Field(NoirElement::from_repr(self.credential_id)),
        );
        inputs.insert("credential".into(), InputValue::Struct(credential));

        map.insert("inputs".into(), InputValue::Struct(inputs));

        Ok(map)
    }
}
