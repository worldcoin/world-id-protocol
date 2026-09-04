//! Fixture utilities for benchmark input generation.
//!
//! These utilities create valid circuit inputs without requiring
//! network calls or on-chain interactions.

use ark_babyjubjub::{EdwardsAffine, Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use eddsa_babyjubjub::EdDSAPrivateKey;
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use rand::{CryptoRng, Rng};
use sha2::{Digest as _, Sha256};
use std::str::FromStr as _;
use world_id_primitives::{
    AuthenticatorPublicKeySet, Credential, FieldElement, TREE_DEPTH,
    merkle::MerkleInclusionProof,
    poseidon::{self, ds},
    rp::RpId,
};
use world_id_proof::{
    circuit_inputs::OwnershipProofCircuitInput,
    passkey_ownership_proof::{
        PASSKEY_OWNERSHIP_NUM_SLOTS, PasskeyOwnershipCircuitInput, WebAuthnWitness,
        proof_request_challenge,
    },
};

const DS_PASSKEY_SLOT: &str = "1946547295039501641724099466078281182247605809";
const DS_MIXED_AUTH_SET: &str = "127568923526698591992218025179744430956107526002225";

fn p256_limbs(bytes: &[u8; 32]) -> [Fq; 3] {
    [
        Fq::from_be_bytes_mod_order(&bytes[17..]),
        Fq::from_be_bytes_mod_order(&bytes[2..17]),
        Fq::from_be_bytes_mod_order(&bytes[..2]),
    ]
}

fn passkey_slot_commitment(x: &[u8; 32], y: &[u8; 32]) -> FieldElement {
    let mut state = [Fq::from(0u64); 16];
    state[0] = Fq::from_str(DS_PASSKEY_SLOT).expect("passkey domain separator");
    state[1..4].copy_from_slice(&p256_limbs(x));
    state[4..7].copy_from_slice(&p256_limbs(y));
    poseidon2::bn254::t16::permutation_in_place(&mut state);
    state[1].into()
}

fn mixed_authenticator_set_commitment(slots: &[FieldElement; PASSKEY_OWNERSHIP_NUM_SLOTS]) -> Fq {
    let mut state = [Fq::from(0u64); 16];
    state[0] = Fq::from_str(DS_MIXED_AUTH_SET).expect("mixed-authenticator domain separator");
    for (target, slot) in state[1..=PASSKEY_OWNERSHIP_NUM_SLOTS].iter_mut().zip(slots) {
        *target = **slot;
    }
    poseidon2::bn254::t16::permutation_in_place(&mut state);
    state[1]
}

/// Builds a deterministic, cryptographically valid ES256 assertion and its
/// World ID registry inclusion witness.
pub fn passkey_ownership_fixture() -> PasskeyOwnershipCircuitInput {
    const PASSKEY_SLOT_INDEX: usize = 1;

    let signing_key = SigningKey::from_slice(&[1u8; 32]).expect("valid P-256 secret key");
    let encoded = signing_key.verifying_key().to_encoded_point(false);
    let mut public_key_x = [0u8; 32];
    public_key_x.copy_from_slice(encoded.x().expect("uncompressed x"));
    let mut public_key_y = [0u8; 32];
    public_key_y.copy_from_slice(encoded.y().expect("uncompressed y"));

    let mut slot_commitments = [FieldElement::ZERO; PASSKEY_OWNERSHIP_NUM_SLOTS];
    slot_commitments[PASSKEY_SLOT_INDEX] = passkey_slot_commitment(&public_key_x, &public_key_y);
    let account_leaf = mixed_authenticator_set_commitment(&slot_commitments);
    let (siblings, root) = first_leaf_merkle_path(account_leaf);

    // The signed challenge is bound to the registry root and nonce exactly as
    // the browser demo derives it.
    let rp_id_hash: [u8; 32] = Sha256::digest(b"localhost").into();
    let nonce = std::array::from_fn(|index| index as u8 + 1);
    let challenge = proof_request_challenge(&rp_id_hash, &root, &nonce);
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge_b64}","origin":"http://localhost"}}"#,
    )
    .into_bytes();
    let challenge_index = client_data_json
        .windows(challenge_b64.len())
        .position(|window| window == challenge_b64.as_bytes())
        .expect("challenge in client data") as u32;
    let mut authenticator_data = vec![0u8; 37];
    authenticator_data[..32].copy_from_slice(&rp_id_hash);
    authenticator_data[32] = 0x05; // UP | UV

    let client_data_hash = Sha256::digest(&client_data_json);
    let mut signed_data = authenticator_data.clone();
    signed_data.extend_from_slice(&client_data_hash);
    let signature: Signature = signing_key.sign(&signed_data);

    PasskeyOwnershipCircuitInput {
        root,
        challenge,
        rp_id_hash,
        nonce,
        webauthn: WebAuthnWitness {
            public_key_x,
            public_key_y,
            signature: signature.to_bytes().into(),
            client_data_json,
            authenticator_data,
            challenge_index,
        },
        slot_commitments,
        passkey_slot_index: PASSKEY_SLOT_INDEX as u32,
        leaf_index: 1,
        siblings,
    }
}

/// RP fixture data for benchmarks
pub struct RpFixture {
    pub world_rp_id: RpId,
    pub action: Fq,
    pub nonce: Fq,
    pub current_timestamp: u64,
    pub rp_secret: Fr,
    pub rp_nullifier_point: EdwardsAffine,
}

/// Generate RP fixture with deterministic randomness
pub fn generate_rp_fixture<R: Rng + CryptoRng>(rng: &mut R) -> RpFixture {
    let rp_id_value: u64 = rng.r#gen();
    let world_rp_id = RpId::new(rp_id_value);

    let action = Fq::rand(rng);
    let nonce = Fq::rand(rng);
    let current_timestamp = 1700000000u64; // Fixed for reproducibility

    let rp_secret = Fr::rand(rng);
    let rp_nullifier_point = (EdwardsAffine::generator() * rp_secret).into_affine();

    RpFixture {
        world_rp_id,
        action,
        nonce,
        current_timestamp,
        rp_secret,
        rp_nullifier_point,
    }
}

/// Builds a deterministic, valid WIP-103 ownership-proof input.
pub fn ownership_proof_fixture() -> OwnershipProofCircuitInput<TREE_DEPTH> {
    const LEAF_INDEX: u64 = 1;

    let sk = EdDSAPrivateKey::from_bytes([42u8; 32]);
    let key_set = AuthenticatorPublicKeySet::new(vec![sk.public()]).expect("valid key set");
    let (siblings, root) = first_leaf_merkle_path(key_set.leaf_hash());
    let nonce = FieldElement::from(1_234_567_890u64);
    let context = FieldElement::from(42u64);
    let commitment_blinder = FieldElement::from(999u64);
    let expected_commitment = Credential::compute_sub(LEAF_INDEX, commitment_blinder);
    let message = poseidon::hash(ds::OWNERSHIP_PROOF, [expected_commitment, nonce, context]);

    OwnershipProofCircuitInput {
        key_index: 0,
        key_set,
        inclusion_proof: MerkleInclusionProof::new(root, LEAF_INDEX, siblings),
        nonce,
        expected_commitment,
        context,
        signature: sk.sign(*message),
        commitment_blinder,
    }
}

/// Builds the default-zero sibling path for index 1 and computes the Merkle root
/// after inserting the provided `leaf` at that index, using Poseidon2 T2 compress.
pub fn first_leaf_merkle_path(leaf: Fq) -> ([FieldElement; TREE_DEPTH], FieldElement) {
    let mut siblings = [FieldElement::ZERO; TREE_DEPTH];
    let mut zero = FieldElement::ZERO;
    for sibling in siblings.iter_mut() {
        *sibling = zero;
        zero = poseidon::compress(zero, zero);
    }

    let mut current = poseidon::compress(siblings[0], leaf.into());
    // For the remaining levels, continue hashing with current on the left
    for sibling in &siblings[1..] {
        current = poseidon::compress(current, *sibling);
    }

    (siblings, current)
}

#[cfg(test)]
mod tests {
    use provekit_prover::Prove as _;
    use world_id_proof::{
        NoirCircuitInput as _,
        passkey_ownership_proof::{load_embedded_passkey_prover, verify_passkey_ownership_proof},
    };

    #[test]
    fn passkey_fixture_satisfies_the_checked_in_circuit() {
        let input = super::passkey_ownership_fixture()
            .into_witness()
            .expect("passkey input map");
        let mut prover = load_embedded_passkey_prover().expect("embedded passkey prover");
        prover
            .generate_witness(input)
            .expect("valid WebAuthn and registry witness");
    }

    #[test]
    fn passkey_fixture_proves_and_verifies() {
        let input = super::passkey_ownership_fixture()
            .into_witness()
            .expect("passkey input map");
        let prover = load_embedded_passkey_prover().expect("embedded passkey prover");
        let proof = prover.prove(input).expect("passkey proof");
        verify_passkey_ownership_proof(&proof).expect("valid passkey proof");
    }
}
