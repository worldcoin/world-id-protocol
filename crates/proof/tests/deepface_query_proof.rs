//! End-to-end tests for the DeepFace Query Proof.
//!
//! These are the correctness evidence behind the benchmark numbers in
//! `noir/deepface-query-proof/docs/benchmarks.md`: a green proving run alone is not enough,
//! because a proof over a witness that does not actually constrain anything would also be
//! green. Each negative control therefore breaks exactly one constraint.
//!
//! Run with:
//! ```sh
//! cargo test -p world-id-proof --features embed-deepface-query-prover,embed-deepface-query-verifier
//! ```

#![cfg(all(
    not(target_arch = "wasm32"),
    feature = "embed-deepface-query-prover",
    feature = "embed-deepface-query-verifier"
))]

use ark_babyjubjub::Fq;
use ark_ff::{BigInt, UniformRand};
use eddsa_babyjubjub::EdDSAPrivateKey;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use world_id_primitives::{Credential, FieldElement, SessionId};
use world_id_proof::{
    artifacts::embedded::deepface_query::{
        load_embedded_deepface_query_prover, load_embedded_deepface_query_verifier,
    },
    circuit_inputs::{BILLING_TREE_DEPTH, DeepFaceQueryProofCircuitInput},
    deepface_query_proof::{
        generate_deepface_query_proof_with_prover, verify_deepface_query_proof_with_verifier,
    },
};
use world_id_test_utils::merkle::first_leaf_merkle_path;

const GENESIS_ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_900_000_000;
const CURRENT_TIMESTAMP: u64 = 1_800_000_000;
const LEAF_INDEX: u64 = 1;
const ISSUER_SCHEMA_ID: u64 = 1;

/// Builds a fully valid circuit input.
///
/// Duplicated in spirit by `zk-mobile-bench`, which cannot depend on `world-id-test-utils`
/// (it drags in anvil/alloy, which must not reach a mobile build).
fn valid_input(seed: u64) -> DeepFaceQueryProofCircuitInput {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let issuer_sk = EdDSAPrivateKey::random(&mut rng);
    let sub_blinding_factor: FieldElement = Fq::rand(&mut rng).into();

    let mut credential = Credential::new();
    credential.id = 0x1234_5678_9abc_def0;
    credential.issuer_version = 0;
    credential.issuer_schema_id = ISSUER_SCHEMA_ID;
    credential.sub = Credential::compute_sub(LEAF_INDEX, sub_blinding_factor);
    credential.genesis_issued_at = GENESIS_ISSUED_AT;
    credential.expires_at = EXPIRES_AT;
    credential.associated_data_commitment = Fq::rand(&mut rng).into();

    let credential = credential.sign(&issuer_sk).expect("credential signing");
    let pcp_hash = credential.claims_hash().expect("claims hash");

    let oprf_seed = SessionId::generate_oprf_seed(&mut rng);
    let commitment_r: FieldElement = Fq::rand(&mut rng).into();
    let session_id =
        SessionId::from_r_seed(LEAF_INDEX, commitment_r, oprf_seed).expect("session id");

    let (billing_siblings, billing_root) = first_leaf_merkle_path(*session_id.commitment);

    DeepFaceQueryProofCircuitInput {
        billing_root,
        billing_depth: BILLING_TREE_DEPTH as u64,
        pcp_hash,
        issuer_schema_id: ISSUER_SCHEMA_ID,
        issuer_pk: issuer_sk.public().pk,
        current_timestamp: CURRENT_TIMESTAMP,
        genesis_issued_at_min: GENESIS_ISSUED_AT,
        nonce: Fq::rand(&mut rng).into(),
        mt_index: LEAF_INDEX,
        commitment_r,
        billing_leaf_index: LEAF_INDEX,
        billing_siblings,
        credential_associated_data_hash: credential.associated_data_commitment,
        credential_genesis_issued_at: credential.genesis_issued_at,
        credential_expires_at: credential.expires_at,
        credential_signature: credential.signature.expect("signed credential"),
        credential_sub_blinding_factor: sub_blinding_factor,
        credential_id: Fq::from(BigInt([
            credential.id,
            u64::from(credential.issuer_version),
            0,
            0,
        ])),
    }
}

fn prove_and_verify(input: DeepFaceQueryProofCircuitInput) -> Result<(), String> {
    let prover = load_embedded_deepface_query_prover().map_err(|e| format!("load prover: {e}"))?;
    let proof = generate_deepface_query_proof_with_prover(input, prover)
        .map_err(|e| format!("prove: {e}"))?;

    let mut verifier =
        load_embedded_deepface_query_verifier().map_err(|e| format!("load verifier: {e}"))?;
    verify_deepface_query_proof_with_verifier(&proof, &mut verifier)
        .map_err(|e| format!("verify: {e}"))
}

#[test]
fn valid_proof_verifies() {
    prove_and_verify(valid_input(42)).expect("a valid witness must prove and verify");
}

#[test]
fn rejects_billing_root_the_leaf_is_not_under() {
    let mut input = valid_input(42);
    // Claim enrollment under a root this session id commitment is not in.
    input.billing_root = Fq::from(0xdead_beef_u64).into();

    assert!(
        prove_and_verify(input).is_err(),
        "an unenrolled human must not be able to prove billing inclusion"
    );
}

#[test]
fn rejects_credential_belonging_to_another_world_id() {
    let mut input = valid_input(42);
    // The billing leaf still opens to LEAF_INDEX, but the credential was issued to a
    // different `mt_index`, so `sub` no longer matches the signed credential.
    input.mt_index = LEAF_INDEX + 1;

    assert!(
        prove_and_verify(input).is_err(),
        "the credential must be bound to the World ID the billing leaf opens to"
    );
}

#[test]
fn rejects_pcp_hash_the_credential_does_not_carry() {
    let mut input = valid_input(42);
    // This is the binding that stops an enrolled World ID from being used to verify a
    // different human: the PCP hash is inside the issuer-signed credential.
    input.pcp_hash = Fq::from(0x1234_u64).into();

    assert!(
        prove_and_verify(input).is_err(),
        "pcp_hash must be authenticated by the credential signature"
    );
}

#[test]
fn rejects_expired_credential() {
    let mut input = valid_input(42);
    input.current_timestamp = EXPIRES_AT + 1;

    assert!(
        prove_and_verify(input).is_err(),
        "an expired credential must not pass"
    );
}

#[test]
fn rejects_credential_older_than_genesis_minimum() {
    let mut input = valid_input(42);
    input.genesis_issued_at_min = GENESIS_ISSUED_AT + 1;

    assert!(
        prove_and_verify(input).is_err(),
        "a credential issued before the minimum genesis time must not pass"
    );
}

#[test]
fn rejects_wrong_session_secret() {
    let mut input = valid_input(42);
    // Knowing the leaf is not enough: the prover must know the `r` it opens to.
    input.commitment_r = Fq::rand(&mut ChaCha20Rng::seed_from_u64(7)).into();

    assert!(
        prove_and_verify(input).is_err(),
        "the billing leaf must only be openable by the holder of r"
    );
}
