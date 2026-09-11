//! Fixture utilities for benchmark input generation.
//!
//! These utilities create valid circuit inputs without requiring
//! network calls or on-chain interactions.

use ark_babyjubjub::{EdwardsAffine, Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use coset::{CborSerializable as _, CoseSign1};
use eddsa_babyjubjub::EdDSAPrivateKey;
use rand::{CryptoRng, Rng};
use world_id_primitives::{FieldElement, TREE_DEPTH, poseidon, rp::RpId};
use world_id_proof::authenticator_attestation::{
    AuthenticatorAssertionClaims, AuthenticatorAssertionToken, AuthenticatorMeta, Platform,
    SecLevel, TrustAnchorKeyClaims, TrustAnchorKeyToken, UserPresence,
};

use crate::authenticator_assertion_bench::AuthenticatorAssertionBenchInput;

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

/// Builds the static, deterministic WIP-106 fixture; the same fixture backs the bench
/// circuit's committed `Prover.toml`.
///
/// # Panics
/// Panics if the fixture cannot be built, not expected.
pub fn authenticator_assertion_bench_fixture() -> AuthenticatorAssertionBenchInput {
    let trust_anchor_key = EdDSAPrivateKey::from_bytes([7u8; 32]);
    let assertion_secret = p256::SecretKey::from_slice(&[11u8; 32]).expect("valid P-256 secret");

    let takt_claims = TrustAnchorKeyClaims {
        exp: 1_783_446_925,
        assertion_key: assertion_secret.public_key(),
        sec_level: SecLevel::SecureElement,
        platform: Platform::Ios,
        build_version: 2006,
        sec_meta: 0b11,
    };
    let takt = TrustAnchorKeyToken::new(takt_claims).expect("valid TAKT claims");
    let takt_signature = trust_anchor_key.sign(*takt.message_hash().expect("TAKT digest"));

    let aat_claims = AuthenticatorAssertionClaims {
        aud: RpId::new(1_928_118),
        exp: 1_783_446_925,
        nonce: FieldElement::from(0x11d2_23ce_7b91_ac21_u64),
        cdh: FieldElement::from(0x9f2c_1abc_u64),
        authenticator_meta: AuthenticatorMeta {
            user_presence: UserPresence::PresentBiometric,
            provider_bits: 0b01,
        },
    };
    let aat = AuthenticatorAssertionToken::new(aat_claims).expect("valid AAT claims");
    let signed = aat.sign(&assertion_secret).expect("AAT signs");
    let aat_signature: [u8; 64] = CoseSign1::from_slice(&signed)
        .expect("valid COSE_Sign1")
        .signature
        .try_into()
        .expect("64-byte ES256 signature");

    AuthenticatorAssertionBenchInput {
        trust_anchor_key: trust_anchor_key.public().pk,
        now: 1_783_446_025, // exp - 900, within both lifetime caps
        aat_claims,
        aat_signature,
        takt_claims,
        takt_signature,
    }
}
