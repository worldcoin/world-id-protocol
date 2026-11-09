//! Fixture utilities for benchmark input generation.
//!
//! These utilities create valid circuit inputs without requiring
//! network calls or on-chain interactions.

use std::collections::BTreeMap;

use ark_babyjubjub::{EdwardsAffine, Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField as _, UniformRand};
use eddsa_babyjubjub::EdDSAPrivateKey;
use rand::{CryptoRng, Rng};
use sha2::{Digest as _, Sha256};
use world_id_flamingo::{FlamingoAatClaims, FlamingoClaims};
use world_id_primitives::{
    AuthenticatorPublicKeySet, Credential, FieldElement, TREE_DEPTH,
    authenticator_assertion::AatPublicValues,
    merkle::MerkleInclusionProof,
    poseidon::{self, ds},
    rp::RpId,
};
use world_id_proof::{
    circuit_inputs::{
        EmbeddingSimilarityCircuitInput, EmbeddingSimilarityRequestInputs,
        OwnershipProofCircuitInput,
    },
    embedding_similarity_proof::COMPARE_SOURCES,
};

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

/// Builds the static WIP-103 Ownership Proof fixture.
///
/// Mirrors `world_id_proof::fixtures::ownership_proof_fixture`, which is `#[cfg(test)]` and so
/// unreachable from here. Keep the two in sync — the same fixture backs the circuit's
/// `Prover.toml`.
///
/// # Panics
/// Panics if the fixture cannot be built, not expected.
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

// ============================================================================
// WIP-202 Proof of Embedding Similarity
// ============================================================================
//
// The witness of `world-id-proof`'s committed `noir/embedding-similarity/Prover.toml` as a typed
// circuit input: unbilled, with an AAT. `test_embedding_similarity_fixture_matches_the_prover_toml`
// keeps the two in sync.

/// The `hashes.json` keys of a v3 PCP as written by orb-core, besides `version`.
const PCP_V3_KEYS: [&str; 44] = [
    "backend_keys.json",
    "face_embeddings.json",
    "iris_code_shares_0.json",
    "iris_code_shares_1.json",
    "iris_code_shares_2.json",
    "iris_codes.json",
    "left_ir.png",
    "left_normalized_image.bin",
    "left_normalized_image_blinding_factors.bin",
    "left_normalized_image_blinding_factors_resized.bin",
    "left_normalized_image_commitment.bin",
    "left_normalized_image_commitment_resized.bin",
    "left_normalized_image_resized.bin",
    "left_normalized_mask.bin",
    "left_normalized_mask_blinding_factors.bin",
    "left_normalized_mask_blinding_factors_resized.bin",
    "left_normalized_mask_commitment.bin",
    "left_normalized_mask_commitment_resized.bin",
    "left_normalized_mask_resized.bin",
    "orb_country",
    "orb_id",
    "qr_code",
    "right_ir.png",
    "right_normalized_image.bin",
    "right_normalized_image_blinding_factors.bin",
    "right_normalized_image_blinding_factors_resized.bin",
    "right_normalized_image_commitment.bin",
    "right_normalized_image_commitment_resized.bin",
    "right_normalized_image_resized.bin",
    "right_normalized_mask.bin",
    "right_normalized_mask_blinding_factors.bin",
    "right_normalized_mask_blinding_factors_resized.bin",
    "right_normalized_mask_commitment.bin",
    "right_normalized_mask_commitment_resized.bin",
    "right_normalized_mask_resized.bin",
    "signup_id",
    "software_version",
    "thumbnail.png",
    "tier_1",
    "tier_2",
    "tier_3",
    "tier_4",
    "tier_5",
    "timestamp",
];

// WIP-201 Appendix A1 values.
const NOW: u32 = 1_783_446_000;
const RP_ID: u64 = 1_928_118;
const NONCE: u64 = 42;
const PLATFORM: u8 = 2;
const SEC_LEVEL: u8 = 1;
const SEC_META: u8 = 3;
/// `user_presence` 2 with provider bits `0b01`.
const AUTHENTICATOR_META: u8 = 10;
const ENGINE_CONFIG_HASH: &str = "2f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d";
const TRUST_ANCHOR_KEY_HASH: &str =
    "14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8";
const CREDENTIAL_IMAGE: &[u8] = b"credential image";
const LIVE_IMAGE: &[u8] = b"live image";
const CHALLENGE_IMAGE: &[u8] = b"challenge image";
/// The RP's signal, hashed as for Uniqueness Proofs.
const SIGNAL: &[u8] = b"rp signal";

const LEAF_INDEX: u64 = 1;
const GENESIS_ISSUED_AT: u64 = 1_600_000_000;
const GENESIS_ISSUED_AT_MIN: u64 = 1_500_000_000;
/// The RP's minimum expiration; WIP-114 defaults it to the request's `created_at`.
const EXPIRES_AT_MIN: u32 = NOW;
const EXPIRES_AT: u32 = 1_900_000_000;
/// The PoH Credential, the one a WIP-202 request can name.
const ISSUER_SCHEMA_ID: u64 = world_id_primitives::POH_ISSUER_SCHEMA_ID;
const ISSUER_VERSION: u8 = 1;
const CRED_ID: u64 = 7;

fn from_hex(hex: &str) -> FieldElement {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect();
    Fq::from_be_bytes_mod_order(&bytes).into()
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `R(SHA-256(bytes))`: the digest read as a big-endian integer modulo p (WIP-201).
fn sha256_field(bytes: &[u8]) -> FieldElement {
    Fq::from_be_bytes_mod_order(&Sha256::digest(bytes)).into()
}

/// A compact, sorted v3 PCP `hashes.json` whose thumbnail is the compared Credential image.
fn hashes_json() -> Vec<u8> {
    let mut entries: BTreeMap<&str, String> = PCP_V3_KEYS
        .iter()
        .map(|key| (*key, lower_hex(&Sha256::digest(key.as_bytes()))))
        .collect();
    entries.insert(
        "thumbnail.png",
        lower_hex(&Sha256::digest(CREDENTIAL_IMAGE)),
    );
    entries.insert("version", "3.0".into());
    let entries: Vec<String> = entries
        .iter()
        .map(|(key, value)| format!("\"{key}\":\"{value}\""))
        .collect();
    format!("{{{}}}", entries.join(",")).into_bytes()
}

/// The WIP-202 circuit input behind `Prover.toml`.
///
/// # Panics
/// Panics if the fixture cannot be built, not expected.
pub fn embedding_similarity_fixture() -> EmbeddingSimilarityCircuitInput<TREE_DEPTH> {
    // Deterministic test keys, not real key material. The Verifier key is WIP-201's.
    let authenticator_sk = EdDSAPrivateKey::from_bytes([42_u8; 32]);
    let issuer_sk = EdDSAPrivateKey::from_bytes([13_u8; 32]);
    let verifier_sk = EdDSAPrivateKey::from_bytes([0x15_u8; 32]);
    let key_set =
        AuthenticatorPublicKeySet::new(vec![authenticator_sk.public()]).expect("valid key set");
    let (siblings, merkle_root) = first_leaf_merkle_path(key_set.leaf_hash());

    let hashes_json = hashes_json();
    let sub_blinding_factor = FieldElement::from(777_u64);
    let credential = Credential::new()
        .id(CRED_ID)
        .issuer_version(ISSUER_VERSION)
        .issuer_schema_id(ISSUER_SCHEMA_ID)
        .subject(Credential::compute_sub(LEAF_INDEX, sub_blinding_factor))
        .genesis_issued_at(GENESIS_ISSUED_AT)
        .expires_at(u64::from(EXPIRES_AT))
        .claim(0, &hashes_json)
        .expect("claim fits")
        .sign(&issuer_sk)
        .expect("credential signs");

    let aat = AatPublicValues {
        trust_anchor_key_hash: from_hex(TRUST_ANCHOR_KEY_HASH),
        platform: PLATFORM,
        sec_level: SEC_LEVEL,
        sec_meta: SEC_META,
        authenticator_meta: AUTHENTICATOR_META,
    };
    let live_capture_hash = sha256_field(LIVE_IMAGE);
    let challenge_hash = sha256_field(CHALLENGE_IMAGE);
    let digest = FlamingoClaims {
        now: NOW,
        compared_entry_hashes: [
            sha256_field(CREDENTIAL_IMAGE),
            live_capture_hash,
            challenge_hash,
            FieldElement::ZERO,
        ],
        aud: FieldElement::from(RP_ID),
        nonce: FieldElement::from(NONCE),
        aat: Some(FlamingoAatClaims {
            trust_anchor_key_hash: aat.trust_anchor_key_hash,
            // `min_build_version` (bits 16-47) is 0, since WIP-202 fixes it to 0.
            aat_flags: u64::from(PLATFORM)
                | (u64::from(SEC_LEVEL) << 8)
                | (u64::from(SEC_META) << 48)
                | (u64::from(AUTHENTICATOR_META) << 52),
        }),
        compare_sources: COMPARE_SOURCES,
        engine_config_hash: from_hex(ENGINE_CONFIG_HASH),
        billing_nullifier: FieldElement::ZERO,
    }
    .digest();
    let signal_hash = FieldElement::from_arbitrary_raw_bytes(SIGNAL);
    let verifier_key = verifier_sk.public();
    let authorization = poseidon::hash(
        ds::EMBEDDING_SIMILARITY_AUTH,
        [
            digest,
            verifier_key.pk.x.into(),
            verifier_key.pk.y.into(),
            signal_hash,
        ],
    );
    let session_id_r = FieldElement::from(555_u64);

    EmbeddingSimilarityCircuitInput {
        request: EmbeddingSimilarityRequestInputs {
            rp_id: FieldElement::from(RP_ID),
            nonce: FieldElement::from(NONCE),
            challenge_hash,
            signal_hash,
            session_id: poseidon::hash(
                ds::SESSION_COMMITMENT,
                [FieldElement::from(LEAF_INDEX), session_id_r],
            ),
            issuer_schema_id: ISSUER_SCHEMA_ID,
            issuer_version: ISSUER_VERSION,
            genesis_issued_at_min: GENESIS_ISSUED_AT_MIN,
            expires_at_min: u64::from(EXPIRES_AT_MIN),
        },
        now: NOW,
        flamingo_verifier_key: verifier_key,
        engine_config_hash: from_hex(ENGINE_CONFIG_HASH),
        aat: Some(aat),
        cred_pk: credential.issuer.clone(),
        live_capture_hash,
        billing_nullifier: FieldElement::ZERO,
        token_signature: verifier_sk.sign(*digest),
        key_index: 0,
        key_set,
        inclusion_proof: MerkleInclusionProof::new(merkle_root, LEAF_INDEX, siblings),
        signature: authenticator_sk.sign(*authorization),
        claims: credential.claims.clone().try_into().expect("15 claims"),
        associated_data_hash: credential.associated_data_commitment,
        genesis_issued_at: GENESIS_ISSUED_AT,
        expires_at: u64::from(EXPIRES_AT),
        sub_blinding_factor,
        credential_id: CRED_ID,
        credential_signature: credential.signature.expect("signed credential"),
        hashes_json,
        session_id_r,
        billing_action: FieldElement::ZERO,
        billing_oprf_output: [FieldElement::ZERO; 2],
    }
}
