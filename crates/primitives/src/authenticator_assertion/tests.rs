use crate::FieldElement;
use eddsa_babyjubjub::EdDSAPrivateKey;

use super::*;

/// Shared with `crates/proof/noir/authenticator-assertion/src/tests.nr`.
const EXPECTED_AAT_COMMITMENT: &str =
    "0x17785a9691e9ee99df657ce545bfe748eab27cf21f118361d87cf64ff024495d";
const EXPECTED_MESSAGE: &str = "0x28f0b633f40ea69da7c2399aa958f48f4a4c582889eb563d8efd37e330c70332";
const EXPECTED_KEY_HASH: &str =
    "0x14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8";
/// WIP-106 Appendix A1.
const EXPECTED_CWT: &str = "8447a1013a00010000a10458202d4bdf6ee60feda0975c770bb7a23dc6e4e0ed1e35ff3c2426cded4ec030d9875859a4041a6a4d3d8d0a582017785a9691e9ee99df657ce545bfe748eab27cf21f118361d87cf64ff024495d190109781c68747470733a2f2f776f726c642e6f72672f6561742f6161742f76313a0001116f480013000007d60102584057c0b136c9c752669a3ad304ee30d45901678a0313d96debd06da712fde9402876071885070c0919ff6e425eb50b152540acd660240b73092d43025023858c01";

fn fixture() -> (AuthenticatorAssertionToken, EdDSAPrivateKey) {
    let aat_commitment = request_commitment(
        FieldElement::from(1_928_118u64),
        FieldElement::from(42u64),
        FieldElement::ZERO,
        FieldElement::from(7u64),
    );
    let flags = SecFlags::new(
        Platform::Ios.into(),
        SecLevel::HardwareKey.into(),
        2006,
        3,
        UserPresence::PresentVerified,
    )
    .unwrap();
    (
        AuthenticatorAssertionToken::new(1_783_446_925, aat_commitment, flags).unwrap(),
        EdDSAPrivateKey::from_bytes([7u8; 32]),
    )
}

#[test]
fn known_answer_matches_circuit_fixture() {
    let (aat, key) = fixture();
    assert_eq!(aat.aat_commitment().to_string(), EXPECTED_AAT_COMMITMENT);
    assert_eq!(aat.message_hash().to_string(), EXPECTED_MESSAGE);
    assert_eq!(aat.sec_flags().pack(), 0x0013_0000_07d6_0102);

    // The Noir fixture's signature and key; EdDSA signing is deterministic.
    let sig = key.sign(*aat.message_hash());
    assert_eq!(
        sig.s.to_string(),
        "700590321940410723084584768113203723815849273971186961535723633376375605110"
    );
    assert_eq!(
        sig.r.x.to_string(),
        "9464927411176877143242073132305067532985742345968954357966273354098472816787"
    );
    assert_eq!(
        key.public().pk.x.to_string(),
        "19037598474602150174935475944965340829216795940473064039209388058233204431288"
    );
    assert_eq!(
        authenticator_provider_key_hash(&key.public()).to_string(),
        EXPECTED_KEY_HASH
    );
}

#[test]
fn cwt_matches_spec_test_vector() {
    let (aat, key) = fixture();
    let cwt = aat.sign(&key).unwrap();
    assert_eq!(hex::encode(&cwt), EXPECTED_CWT);
    assert_eq!(
        hex::encode(key.public().to_compressed_bytes().unwrap()),
        &EXPECTED_CWT[26..90]
    );
}

#[test]
fn cwt_round_trips_and_verifies() {
    let (aat, key) = fixture();
    let cwt = aat.sign(&key).unwrap();
    let decoded = SignedAuthenticatorAssertionToken::decode(&cwt).unwrap();

    assert_eq!(decoded.token.exp(), aat.exp());
    assert_eq!(decoded.token.aat_commitment(), aat.aat_commitment());
    assert_eq!(decoded.token.sec_flags(), aat.sec_flags());
    assert_eq!(
        decoded.kid,
        Some(key.public().to_compressed_bytes().unwrap())
    );
    assert!(
        key.public()
            .verify(*decoded.token.message_hash(), &decoded.signature)
    );
}

#[test]
fn cwt_without_kid_decodes() {
    let (aat, key) = fixture();
    let cwt = aat.sign(&key).unwrap();
    // Replace the 36-byte `{4: kid}` unprotected header with an empty map.
    let mut without_kid = cwt[..9].to_vec();
    without_kid.push(0xa0);
    without_kid.extend_from_slice(&cwt[9 + 36..]);

    let decoded = SignedAuthenticatorAssertionToken::decode(&without_kid).unwrap();
    assert_eq!(decoded.kid, None);
    assert_eq!(decoded.token.aat_commitment(), aat.aat_commitment());
}

#[test]
fn non_canonical_encodings_rejected() {
    let (aat, key) = fixture();
    let cwt = aat.sign(&key).unwrap();
    let payload = 9 + 36 + 2;

    // Different `eat_profile` byte.
    let mut tampered = cwt.clone();
    tampered[payload + 50] ^= 1;
    assert!(matches!(
        SignedAuthenticatorAssertionToken::decode(&tampered),
        Err(AssertionError::InvalidEncoding("claims"))
    ));

    // `nonce` not less than the field order.
    let mut tampered = cwt.clone();
    tampered[payload + 10..payload + 42].fill(0xff);
    assert!(matches!(
        SignedAuthenticatorAssertionToken::decode(&tampered),
        Err(AssertionError::InvalidEncoding(
            "non-canonical aat_commitment"
        ))
    ));

    // Trailing bytes.
    let mut tampered = cwt.clone();
    tampered.push(0);
    assert!(SignedAuthenticatorAssertionToken::decode(&tampered).is_err());

    // Truncated.
    assert!(SignedAuthenticatorAssertionToken::decode(&cwt[..cwt.len() - 1]).is_err());
}

#[test]
fn invalid_claims_rejected() {
    let (aat, _) = fixture();
    let flags = aat.sec_flags();
    assert!(matches!(
        AuthenticatorAssertionToken::new(0xffff, aat.aat_commitment(), flags),
        Err(AssertionError::ExpirationOutOfRange(0xffff))
    ));
    // A 4-bit `sec_meta` would overflow into `user_presence`.
    assert!(matches!(
        SecFlags::new(2, 1, 2006, 0x8, UserPresence::PresentVerified),
        Err(AssertionError::SecMetaTooLarge(0x8))
    ));
    // Bit 54, a reserved `user_presence` of 5, and bits 56 and above.
    assert!(SecFlags::unpack(0x0043_0000_07d6_0102).is_err());
    assert!(SecFlags::unpack(0x002b_0000_07d6_0102).is_err());
    assert!(SecFlags::unpack(0x0100_0000_07d6_0102).is_err());
    assert_eq!(SecFlags::unpack(flags.pack()).unwrap(), flags);
    // Unknown identifiers pass through for the RP to allowlist, as in the circuit.
    let unknown = SecFlags::unpack(0x0003_0000_07d6_0203).unwrap();
    assert_eq!((unknown.platform(), unknown.sec_level()), (3, 2));
}

#[test]
fn request_commitment_binds_every_input() {
    let base = [1u64, 2, 3, 4].map(FieldElement::from);
    let commit = |v: [FieldElement; 4]| request_commitment(v[0], v[1], v[2], v[3]);
    let reference = commit(base);
    for i in 0..4 {
        let mut changed = base;
        changed[i] = FieldElement::from(99u64);
        assert_ne!(commit(changed), reference);
    }
}

/// The Noir `tests.nr` fixture: `now` 925 seconds before `exp`.
const NOW: u32 = 1_783_446_000;

fn inputs() -> (
    AuthenticatorAssertionPublicInputs,
    AuthenticatorAssertionPrivateInputs,
    EdDSAPrivateKey,
) {
    let (aat, key) = fixture();
    let public = AuthenticatorAssertionPublicInputs {
        authenticator_provider_key_hash: authenticator_provider_key_hash(&key.public()),
        now: NOW,
        aud: FieldElement::from(1_928_118u64),
        nonce: FieldElement::from(42u64),
        platform: 2,
        sec_level: 1,
        sec_meta: 3,
        user_presence: UserPresence::PresentVerified,
        min_build_version: 2006,
    };
    let private = AuthenticatorAssertionPrivateInputs {
        authenticator_provider_key: key.public(),
        exp: aat.exp(),
        sec_flags: aat.sec_flags().pack(),
        sig: key.sign(*aat.message_hash()),
        cdh: FieldElement::ZERO,
        blind: FieldElement::from(7u64),
    };
    (public, private, key)
}

#[test]
fn verify_accepts_circuit_fixture() {
    let (public, private, _) = inputs();
    assert_eq!(verify_aat(&public, &private), Ok(()));
}

#[test]
fn private_inputs_derive_from_decoded_token() {
    let (aat, key) = fixture();
    let (public, private, _) = inputs();
    let decoded = SignedAuthenticatorAssertionToken::decode(&aat.sign(&key).unwrap()).unwrap();
    assert_eq!(
        decoded.into_private_inputs(key.public(), private.cdh, private.blind),
        private
    );
    assert_eq!(
        private.public_inputs(
            public.now,
            public.aud,
            public.nonce,
            public.min_build_version
        ),
        Ok(public)
    );
}

#[test]
fn verify_rejects_each_constraint() {
    let (public, private, key) = inputs();
    let check =
        |p: AuthenticatorAssertionPublicInputs, s: AuthenticatorAssertionPrivateInputs, err| {
            assert_eq!(verify_aat(&p, &s), Err(err));
        };
    let with_public = |f: fn(&mut AuthenticatorAssertionPublicInputs)| {
        let mut p = public;
        f(&mut p);
        p
    };
    let with_private = |f: fn(&mut AuthenticatorAssertionPrivateInputs)| {
        let mut s = private.clone();
        f(&mut s);
        s
    };
    use VerificationError::*;

    check(
        with_public(|p| p.nonce = FieldElement::ZERO),
        private.clone(),
        ZeroNonce,
    );
    // Every request input and claim is bound through the signature.
    check(
        with_public(|p| p.aud = FieldElement::from(1u64)),
        private.clone(),
        InvalidSignature,
    );
    check(
        with_public(|p| p.nonce = FieldElement::from(43u64)),
        private.clone(),
        InvalidSignature,
    );
    check(
        public,
        with_private(|s| s.cdh = FieldElement::from(1u64)),
        InvalidSignature,
    );
    check(
        public,
        with_private(|s| s.blind = FieldElement::from(8u64)),
        InvalidSignature,
    );
    check(
        public,
        with_private(|s| s.sec_flags ^= 0x4),
        InvalidSignature,
    );
    check(public, with_private(|s| s.exp += 1), InvalidSignature);
    // A key that did not sign the token, with its hash supplied as the public input.
    let other_key = EdDSAPrivateKey::from_bytes([8u8; 32]).public();
    check(
        AuthenticatorAssertionPublicInputs {
            authenticator_provider_key_hash: authenticator_provider_key_hash(&other_key),
            ..public
        },
        AuthenticatorAssertionPrivateInputs {
            authenticator_provider_key: other_key.clone(),
            ..private.clone()
        },
        InvalidSignature,
    );
    check(
        public,
        AuthenticatorAssertionPrivateInputs {
            authenticator_provider_key: other_key,
            ..private.clone()
        },
        KeyHashMismatch,
    );
    // Public flags must equal the signed ones.
    check(
        with_public(|p| p.platform = 4),
        private.clone(),
        SecFlagsMismatch,
    );
    check(
        with_public(|p| p.sec_level = 3),
        private.clone(),
        SecFlagsMismatch,
    );
    check(
        with_public(|p| p.sec_meta = 1),
        private.clone(),
        SecFlagsMismatch,
    );
    check(
        with_public(|p| p.user_presence = UserPresence::Undetermined),
        private.clone(),
        SecFlagsMismatch,
    );
    // Freshness, at both boundaries.
    check(
        with_public(|p| p.now = 1_783_446_925),
        private.clone(),
        Expired,
    );
    assert!(
        verify_aat(
            &with_public(|p| p.now = 1_783_446_925 - MAX_AAT_LIFETIME_SECS),
            &private
        )
        .is_ok()
    );
    check(
        with_public(|p| p.now = 1_783_446_925 - MAX_AAT_LIFETIME_SECS - 1),
        private.clone(),
        LifetimeExceeded,
    );
    check(
        with_public(|p| p.min_build_version = 2007),
        private.clone(),
        BuildVersionBelowMinimum,
    );

    // Reserved values can only reach the verifier in a token the provider's key signed.
    let aat_commitment = request_commitment(public.aud, public.nonce, private.cdh, private.blind);
    let signed = |sec_flags: u64| AuthenticatorAssertionPrivateInputs {
        sec_flags,
        sig: key.sign(*message_hash(private.exp, aat_commitment, sec_flags)),
        ..private.clone()
    };
    let reserved_bit = private.sec_flags | 1 << 54;
    check(public, signed(reserved_bit), InvalidSecFlags(reserved_bit));
    let reserved_presence = (private.sec_flags & !(0x7 << 51)) | 5 << 51;
    check(
        public,
        signed(reserved_presence),
        InvalidSecFlags(reserved_presence),
    );
}

#[test]
fn presence_round_trips_through_u8() {
    for value in 0..5u8 {
        assert_eq!(u8::from(UserPresence::try_from(value).unwrap()), value);
    }
    assert!(matches!(
        UserPresence::try_from(5),
        Err(AssertionError::ReservedPresence(5))
    ));
}
