use p256::ecdsa::{Signature, SigningKey};

use super::*;

/// WIP-201 Appendix A1; shared with `crates/proof/noir/authenticator-assertion/src/tests.nr`.
const TAKT_HEX: &str = "845826a20126045820fd65f050c9c3b53337cf17eee589eb11a81a91c55ac10aa48361c0508d959e4da05885a4041a6a4e8b7008a101a4010220012158207135fa4fd93a09dce98bbf681b4bfcf50e7c0d6354e62afb0bff2a3429617865225820ed4c1f02ddb9023ee56a557e515d6a9dc66c11f220960de594334df588776724190109781d68747470733a2f2f776f726c642e6f72672f6561742f74616b742f76313a0001116f480003000007d601025840d6e8303773aeb9c7b04e602e7a3ec822fc34f72609eed01814cd7c34877a664973519aa5e952b74b72fd05918587b52d61bdffd2d8728705d78f41ac06b42bd7";
const AAT_HEX: &str = "8443a10126a05882a6034800000000001d6bb6041a6a4d3d8d0a5820000000000000000000000000000000000000000000000000000000000000002a190109781c68747470733a2f2f776f726c642e6f72672f6561742f6161742f76313a0001387f582006559c686e02e6fdd317c3faf3d3a871f1660465552dc3c15e36290a443461503a00013880025840480fd81ee950f3df613d1e4f333a441ae4f7db080efed620e77199cd37e44d151f4897dfafb0ed67b59afa6b00a55b43b25fe8f7d58ecd183c8bb0ce838b55a8";
const KID_HEX: &str = "fd65f050c9c3b53337cf17eee589eb11a81a91c55ac10aa48361c0508d959e4d";
const CDH_HEX: &str = "06559c686e02e6fdd317c3faf3d3a871f1660465552dc3c15e36290a44346150";

const NOW: u32 = 1_783_446_000;
const TAKT_EXP: u32 = NOW + 86_400;
const AAT_EXP: u32 = 1_783_446_925;
const AUD: u64 = 1_928_118;

fn trust_anchor_key() -> SigningKey {
    SigningKey::from_bytes(&[0x07; 32].into()).unwrap()
}

fn assertion_key() -> SigningKey {
    SigningKey::from_bytes(&[0x09; 32].into()).unwrap()
}

fn cdh() -> FieldElement {
    FieldElement::from_be_bytes(&hex::decode(CDH_HEX).unwrap().try_into().unwrap()).unwrap()
}

fn sec_flags() -> SecFlags {
    SecFlags::new(Platform::Ios.into(), SecLevel::HardwareKey.into(), 2006, 3).unwrap()
}

fn takt() -> TrustAnchorKeyToken {
    TrustAnchorKeyToken::new(NOW, TAKT_EXP, *assertion_key().verifying_key(), sec_flags()).unwrap()
}

fn aat() -> AuthenticatorAssertionToken {
    AuthenticatorAssertionToken::new(
        NOW,
        AUD,
        AAT_EXP,
        42u64.into(),
        cdh(),
        UserPresence::PresentVerified,
    )
    .unwrap()
}

fn inputs() -> (
    AuthenticatorAssertionPublicInputs,
    AuthenticatorAssertionPrivateInputs,
) {
    let public = AuthenticatorAssertionPublicInputs {
        trust_anchor_key: *trust_anchor_key().verifying_key(),
        now: NOW,
        aud: AUD,
        nonce: 42u64.into(),
        platform: 2,
        sec_level: 1,
        sec_meta: 3,
        user_presence: UserPresence::PresentVerified,
        min_build_version: 2006,
    };
    let private = AuthenticatorAssertionPrivateInputs {
        takt: takt().sign(&trust_anchor_key()),
        aat: aat().sign(&assertion_key()),
        cdh: cdh(),
    };
    (public, private)
}

#[test]
fn tokens_match_spec_vectors() {
    assert_eq!(
        hex::encode(kid(trust_anchor_key().verifying_key())),
        KID_HEX
    );
    assert_eq!(hex::encode(takt().sign(&trust_anchor_key())), TAKT_HEX);
    assert_eq!(hex::encode(aat().sign(&assertion_key())), AAT_HEX);
    assert_eq!(sec_flags().pack(), 0x0003_0000_07d6_0102);
}

#[test]
fn verify_accepts_spec_vectors() {
    let (public, private) = inputs();
    assert_eq!(verify(&public, &private), Ok(()));
    assert_eq!(
        private.public_inputs(public.trust_anchor_key, NOW, AUD, public.nonce, 2006),
        Ok(public)
    );
}

#[test]
fn tokens_round_trip() {
    let takt_cwt = takt().sign(&trust_anchor_key());
    let aat_cwt = aat().sign(&assertion_key());
    assert_eq!(
        TrustAnchorKeyToken::verify(&takt_cwt, trust_anchor_key().verifying_key()),
        Ok(takt())
    );
    assert_eq!(
        AuthenticatorAssertionToken::verify(&aat_cwt, assertion_key().verifying_key()),
        Ok(aat())
    );
}

/// Platform keys do not normalize `s`, and WIP-106 does not require it.
#[test]
fn high_s_signatures_verify() {
    let (public, mut private) = inputs();
    let sig_at = private.aat.len() - 64;
    let signature = Signature::from_slice(&private.aat[sig_at..]).unwrap();
    let (r, s) = signature.split_scalars();
    let flipped = Signature::from_scalars(r, -*s).unwrap();
    assert_ne!(flipped, signature);
    private.aat[sig_at..].copy_from_slice(&flipped.to_bytes());
    assert_eq!(verify(&public, &private), Ok(()));
}

#[test]
fn verify_rejects_each_check() {
    use VerificationError::*;
    let (public, private) = inputs();
    let check = |p: AuthenticatorAssertionPublicInputs,
                 s: &AuthenticatorAssertionPrivateInputs,
                 err: VerificationError| assert_eq!(verify(&p, s), Err(err));
    let with_public = |f: &dyn Fn(&mut AuthenticatorAssertionPublicInputs)| {
        let mut p = public;
        f(&mut p);
        p
    };

    check(
        with_public(&|p| p.nonce = FieldElement::ZERO),
        &private,
        ZeroNonce,
    );

    // A key other than the signer: its thumbprint does not match the TAKT's `kid`.
    let other = SigningKey::from_bytes(&[0x08; 32].into()).unwrap();
    check(
        with_public(&|p| p.trust_anchor_key = *other.verifying_key()),
        &private,
        Takt(TokenError::Encoding(AssertionError::InvalidEncoding(
            "TAKT protected header",
        ))),
    );
    let mut forged = private.clone();
    let last = forged.takt.len() - 1;
    forged.takt[last] ^= 1;
    check(public, &forged, Takt(TokenError::Signature));

    // An AAT signed by a key the TAKT does not attest.
    let mut unattested = private.clone();
    unattested.aat = aat().sign(&other);
    check(public, &unattested, Aat(TokenError::Signature));

    // Freshness, at both boundaries of both tokens.
    check(with_public(&|p| p.now = AAT_EXP), &private, AatExpired);
    check(
        with_public(&|p| p.now = AAT_EXP - MAX_AAT_LIFETIME_SECS - 1),
        &private,
        AatLifetimeExceeded,
    );
    assert_eq!(
        verify(
            &with_public(&|p| p.now = AAT_EXP - MAX_AAT_LIFETIME_SECS),
            &private
        ),
        Ok(())
    );
    check(with_public(&|p| p.now = TAKT_EXP), &private, TaktExpired);
    let long_takt = AuthenticatorAssertionPrivateInputs {
        takt: TrustAnchorKeyToken {
            exp: NOW + MAX_TAKT_LIFETIME_SECS + 1,
            ..takt()
        }
        .sign(&trust_anchor_key()),
        ..private.clone()
    };
    check(public, &long_takt, TaktLifetimeExceeded);

    // Request binding.
    check(with_public(&|p| p.aud = AUD + 1), &private, RequestMismatch);
    check(
        with_public(&|p| p.nonce = 43u64.into()),
        &private,
        RequestMismatch,
    );
    let wrong_cdh = AuthenticatorAssertionPrivateInputs {
        cdh: FieldElement::ONE,
        ..private.clone()
    };
    check(public, &wrong_cdh, RequestMismatch);

    // Public flags must equal the signed ones.
    check(with_public(&|p| p.platform = 4), &private, SecFlagsMismatch);
    check(
        with_public(&|p| p.sec_level = 3),
        &private,
        SecFlagsMismatch,
    );
    check(with_public(&|p| p.sec_meta = 1), &private, SecFlagsMismatch);
    check(
        with_public(&|p| p.user_presence = UserPresence::Undetermined),
        &private,
        UserPresenceMismatch,
    );
    check(
        with_public(&|p| p.min_build_version = 2007),
        &private,
        BuildVersionBelowMinimum,
    );
}

#[test]
fn non_canonical_encodings_rejected() {
    let takt_key = *trust_anchor_key().verifying_key();
    let aat_key = *assertion_key().verifying_key();
    let takt_cwt = takt().sign(&trust_anchor_key());
    let aat_cwt = aat().sign(&assertion_key());
    let decode_aat = |cwt: &[u8]| AuthenticatorAssertionToken::verify(cwt, &aat_key);
    // Payload offsets after the `COSE_Sign1` framing.
    let takt_payload = 1 + 2 + 38 + 1 + 2;
    let aat_payload = 1 + 1 + 3 + 1 + 2;

    let mut trailing = aat_cwt.clone();
    trailing.push(0);
    assert_eq!(
        decode_aat(&trailing).unwrap_err(),
        TokenError::Encoding(AssertionError::InvalidEncoding("signature"))
    );
    assert_eq!(
        decode_aat(&aat_cwt[..aat_cwt.len() - 1]).unwrap_err(),
        TokenError::Encoding(AssertionError::InvalidEncoding("signature"))
    );

    // A non-empty unprotected header.
    let mut unprotected = aat_cwt.clone();
    unprotected[5] = 0xa1;
    assert_eq!(
        decode_aat(&unprotected).unwrap_err(),
        TokenError::Encoding(AssertionError::InvalidEncoding("unprotected header"))
    );

    // `nonce` not less than the field order.
    let mut nonce = aat_cwt.clone();
    nonce[aat_payload + 20..aat_payload + 52].fill(0xff);
    assert_eq!(
        decode_aat(&nonce).unwrap_err(),
        TokenError::Encoding(AssertionError::InvalidEncoding("non-canonical nonce"))
    );

    // Reserved `user_presence`.
    let mut presence = aat_cwt.clone();
    presence[aat_payload + 129] = 5;
    assert_eq!(
        decode_aat(&presence).unwrap_err(),
        TokenError::Encoding(AssertionError::ReservedPresence(5))
    );

    // `exp` below 2^16, still a 4-byte uint.
    let mut exp = aat_cwt.clone();
    exp[aat_payload + 13..aat_payload + 17].copy_from_slice(&0xffffu32.to_be_bytes());
    assert_eq!(
        decode_aat(&exp).unwrap_err(),
        TokenError::Encoding(AssertionError::ExpirationOutOfRange(0xffff))
    );

    // A different `eat_profile` byte.
    let mut profile = aat_cwt;
    profile[aat_payload + 60] ^= 1;
    assert_eq!(
        decode_aat(&profile).unwrap_err(),
        TokenError::Encoding(AssertionError::InvalidEncoding("AAT claims"))
    );

    // TAKT `sec_flags` bit 51.
    let mut flags = takt_cwt.clone();
    flags[takt_payload + 126] |= 0x08;
    assert_eq!(
        TrustAnchorKeyToken::verify(&flags, &takt_key).unwrap_err(),
        TokenError::Encoding(AssertionError::InvalidSecFlags)
    );

    // TAKT `cnf` key not on the curve.
    let mut key = takt_cwt;
    key[takt_payload + 18] ^= 1;
    assert_eq!(
        TrustAnchorKeyToken::verify(&key, &takt_key).unwrap_err(),
        TokenError::Encoding(AssertionError::InvalidEncoding("assertion_key"))
    );
}

#[test]
fn issuance_enforces_lifetimes() {
    let key = *assertion_key().verifying_key();
    for exp in [NOW, NOW - 1, NOW + MAX_TAKT_LIFETIME_SECS + 1] {
        assert_eq!(
            TrustAnchorKeyToken::new(NOW, exp, key, sec_flags()),
            Err(AssertionError::LifetimeOutOfRange { now: NOW, exp })
        );
    }
    assert!(TrustAnchorKeyToken::new(NOW, NOW + MAX_TAKT_LIFETIME_SECS, key, sec_flags()).is_ok());
    let aat_at = |exp| {
        AuthenticatorAssertionToken::new(
            NOW,
            AUD,
            exp,
            1u64.into(),
            FieldElement::ZERO,
            UserPresence::Undetermined,
        )
    };
    assert!(matches!(
        aat_at(NOW + MAX_AAT_LIFETIME_SECS + 1),
        Err(AssertionError::LifetimeOutOfRange { .. })
    ));
    assert!(aat_at(NOW + MAX_AAT_LIFETIME_SECS).is_ok());
    assert_eq!(
        AuthenticatorAssertionToken::new(
            0xff00,
            AUD,
            0xffff,
            1u64.into(),
            FieldElement::ZERO,
            UserPresence::Undetermined
        ),
        Err(AssertionError::ExpirationOutOfRange(0xffff))
    );
}

#[test]
fn sec_flags_pack_and_unpack() {
    assert_eq!(
        SecFlags::new(2, 1, 2006, 0x8),
        Err(AssertionError::SecMetaTooLarge(0x8))
    );
    assert_eq!(SecFlags::unpack(sec_flags().pack()), Ok(sec_flags()));
    assert_eq!(
        SecFlags::unpack(1 << 51),
        Err(AssertionError::InvalidSecFlags)
    );
    // Unknown identifiers pass through for the RP to allowlist.
    let unknown = SecFlags::unpack(0x0000_0000_07d6_0203).unwrap();
    assert_eq!((unknown.platform(), unknown.sec_level()), (3, 2));
}

#[test]
fn presence_round_trips_through_u8() {
    for value in 0..5u8 {
        assert_eq!(u8::from(UserPresence::try_from(value).unwrap()), value);
    }
    assert_eq!(
        UserPresence::try_from(5),
        Err(AssertionError::ReservedPresence(5))
    );
}

#[test]
fn debug_hides_confidential_values() {
    let (_, private) = inputs();
    for debug in [
        format!("{private:?}"),
        format!("{:?}", takt()),
        format!("{:?}", aat()),
    ] {
        assert!(!debug.contains(&AAT_EXP.to_string()), "{debug}");
        assert!(!debug.contains(&TAKT_EXP.to_string()), "{debug}");
        assert!(!debug.contains("takt:"), "{debug}");
    }
    assert_eq!(
        VerificationError::Takt(TokenError::Encoding(AssertionError::InvalidSecFlags)).to_string(),
        "invalid TAKT: sec_flags bits 51 and above are reserved"
    );
}
