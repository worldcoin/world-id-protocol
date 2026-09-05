//! Pins every protocol hash that was migrated onto
//! [`world_id_primitives::poseidon::hash`] to the value produced by the
//! hand-rolled permutation it replaced.
//!
//! The expected values are built here from the raw permutation, with the domain
//! separators re-typed in the exact form the pre-refactor call sites used (down to
//! `key_set`'s decimal literal). A mistake in either the layout or a
//! [`ds`](world_id_primitives::poseidon::ds) constant therefore fails this test
//! rather than silently changing the wire format.

use std::str::FromStr as _;

use ark_babyjubjub::Fq;
use ark_ff::{AdditiveGroup as _, BigInt, PrimeField as _};
use eddsa_babyjubjub::EdDSAPrivateKey;
use world_id_primitives::{
    AuthenticatorPublicKeySet, Credential, FieldElement, MAX_AUTHENTICATOR_KEYS, SessionId,
    authenticator::oprf_query_digest,
};

/// The pre-refactor layout: domain separator in slot 0, inputs in the rate, digest
/// squeezed from slot 1.
fn hand_rolled<const T: usize>(ds: Fq, inputs: &[Fq], permute: fn(&mut [Fq; T])) -> FieldElement {
    let mut state = [Fq::ZERO; T];
    state[0] = ds;
    for (slot, input) in state[1..].iter_mut().zip(inputs) {
        *slot = *input;
    }
    permute(&mut state);
    state[1].into()
}

#[test]
fn oprf_query_digest_is_unchanged() {
    let expected = hand_rolled(
        Fq::from_be_bytes_mod_order(b"World ID Query"),
        &[Fq::from(7u64), Fq::from(11u64), Fq::from(13u64)],
        poseidon2::bn254::t4::permutation_in_place,
    );

    // Note the argument order: the digest absorbs `query_origin_id` before `action`.
    let actual = oprf_query_digest(7, FieldElement::from(13u64), FieldElement::from(11u64));

    assert_eq!(actual, expected);
}

#[test]
fn session_id_commitment_is_unchanged() {
    let mut rng = rand::thread_rng();
    let oprf_seed = SessionId::generate_oprf_seed(&mut rng);
    let r_seed = FieldElement::from(1234u64);

    let expected = hand_rolled(
        Fq::from_be_bytes_mod_order(b"H(id, r)"),
        &[Fq::from(42u64), *r_seed],
        poseidon2::bn254::t3::permutation_in_place,
    );

    let session_id = SessionId::from_r_seed(42, r_seed, oprf_seed).unwrap();

    assert_eq!(session_id.commitment, expected);
}

#[test]
fn credential_sub_is_unchanged() {
    let blinding_factor = FieldElement::from(999u64);

    let expected = hand_rolled(
        Fq::from_be_bytes_mod_order(b"H_CS(id, r)"),
        &[Fq::from(3u64), *blinding_factor],
        poseidon2::bn254::t3::permutation_in_place,
    );

    assert_eq!(Credential::compute_sub(3, blinding_factor), expected);
}

#[test]
fn authenticator_key_set_leaf_hash_is_unchanged() {
    let keys: Vec<_> = (0..MAX_AUTHENTICATOR_KEYS)
        .map(|i| EdDSAPrivateKey::from_bytes([i as u8 + 1; 32]).public())
        .collect();
    let key_set = AuthenticatorPublicKeySet::new(keys).unwrap();

    let affine = key_set.as_affine_array();
    let mut coordinates = Vec::with_capacity(MAX_AUTHENTICATOR_KEYS * 2);
    for key in &affine {
        coordinates.push(key.x);
        coordinates.push(key.y);
    }

    let expected = hand_rolled(
        Fq::from_str("105702839725298824521994315").unwrap(),
        &coordinates,
        poseidon2::bn254::t16::permutation_in_place,
    );

    assert_eq!(FieldElement::from(key_set.leaf_hash()), expected);
    // The decimal literal the pre-refactor code used is the same tag, lowered.
    assert_eq!(
        Fq::from_str("105702839725298824521994315").unwrap(),
        Fq::from_be_bytes_mod_order(b"World ID PK")
    );
}

#[test]
fn credential_hash_is_unchanged() {
    let mut credential = Credential::new()
        .claim_hash(0, ruint::aliases::U256::from(7u64))
        .unwrap();
    credential.id = 1234;
    credential.issuer_version = 2;
    credential.issuer_schema_id = 5;
    credential.sub = Credential::compute_sub(3, FieldElement::from(999u64));
    credential.genesis_issued_at = 1_700_000_000;
    credential.expires_at = 1_800_000_000;
    credential = credential
        .associated_data_commitment_from_raw_bytes(b"associated data")
        .unwrap();

    let id_issuer_version = BigInt([credential.id, u64::from(credential.issuer_version), 0, 0]);
    let expected = hand_rolled(
        Fq::from_be_bytes_mod_order(b"POSEIDON2+EDDSA-BJJ"),
        &[
            Fq::from(credential.issuer_schema_id),
            *credential.sub,
            Fq::from(credential.genesis_issued_at),
            Fq::from(credential.expires_at),
            *credential.claims_hash().unwrap(),
            *credential.associated_data_commitment,
            Fq::from(id_issuer_version),
        ],
        poseidon2::bn254::t8::permutation_in_place,
    );

    assert_eq!(credential.hash().unwrap(), expected);
}
