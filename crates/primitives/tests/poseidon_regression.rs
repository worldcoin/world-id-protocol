//! Pins every protocol hash that was migrated onto
//! [`world_id_primitives::poseidon::hash`] to the value produced by the
//! hand-rolled permutation it replaced.
//!
//! The expected values are built here from the raw permutation, with the domain
//! separators re-typed in the exact form the pre-refactor call sites used (down to
//! `key_set`'s decimal literal). A mistake in either the layout or a
//! [`ds`](world_id_primitives::poseidon::ds) constant therefore fails this test
//! rather than silently changing the wire format.
//!
//! Also checks the WIP-201 signed digest against its published test vector.

use std::str::FromStr as _;

use ark_babyjubjub::Fq;
use ark_ff::{AdditiveGroup as _, BigInt, PrimeField as _};
use eddsa_babyjubjub::EdDSAPrivateKey;
#[cfg(feature = "protocol")]
use world_id_primitives::SessionId;
use world_id_primitives::{
    AuthenticatorPublicKeySet, Credential, FieldElement, MAX_AUTHENTICATOR_KEYS,
    authenticator::oprf_query_digest,
    poseidon::{self, DomainSeparator},
};

#[test]
fn wip_201_signed_digest_matches_spec() {
    // WIP-201 Appendix A1, "With an AAT": https://github.com/worldcoin/world-id-protocol/pull/979
    let field =
        |hex: &str| FieldElement::from(Fq::from_be_bytes_mod_order(&hex::decode(hex).unwrap()));
    // WIP-201 pins t=16, so reserve the full rate and zero-pad its 11 claims.
    let digest = poseidon::hash(
        DomainSeparator::<15>::new(b"WORLD-ID/WIP-201/SIGN"),
        [
            1_783_446_000u64.into(),
            field("21e9fe96ff18807a727830c56281c96af824005400bcb8ef0f463b34cb20c415"),
            field("010cff8544f0007179c076ddb49de551bd5743797bfe05cb3b26f55c696f507b"),
            field("2abb4a81875eb0e308f0fbfb8c0a0f57e77243e095b145ae7973e0b2771e044d"),
            FieldElement::ZERO,
            1_928_118u64.into(),
            42u64.into(),
            field("14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8"),
            0x0013_0000_07d6_0102u64.into(),
            1u64.into(),
            field("2f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d"),
            FieldElement::ZERO,
            FieldElement::ZERO,
            FieldElement::ZERO,
            FieldElement::ZERO,
        ],
    );

    assert_eq!(
        digest,
        field("229f44f2caa18f609df2c1819223d778ef8b08a30ce9de589dbe754275e123bd")
    );
}

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

#[cfg(feature = "protocol")]
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
