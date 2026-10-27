use eddsa_babyjubjub::EdDSAPrivateKey;
use p256::ecdsa::{Signature, SigningKey};

use super::*;

/// WIP-201 Appendix A1; shared with `crates/proof/noir/authenticator-assertion/src/tests.nr`.
const TAKT_HEX: &str = "84582aa2013a000100000458202d4bdf6ee60feda0975c770bb7a23dc6e4e0ed1e35ff3c2426cded4ec030d987a05885a4041a6a4e8b7008a101a4010220012158207135fa4fd93a09dce98bbf681b4bfcf50e7c0d6354e62afb0bff2a3429617865225820ed4c1f02ddb9023ee56a557e515d6a9dc66c11f220960de594334df588776724190109781d68747470733a2f2f776f726c642e6f72672f6561742f74616b742f76313a0001116f480003000007d6010258409a97b6c24c4873234fc4e72a4a239cedec22652cc9206f87a7b9735db9d54885aa069707c532d0ae86c41add78279ac40c949459193361e166c2705d3cca4c05";
const AAT_HEX: &str = "8443a10126a058a3a6034800000000001d6bb6041a6a4d3d8d0a5820000000000000000000000000000000000000000000000000000000000000002a190109781c68747470733a2f2f776f726c642e6f72672f6561742f6161742f76313a0001387f582006559c686e02e6fdd317c3faf3d3a871f1660465552dc3c15e36290a443461503a000138805820000000000000000000000000000000000000000000000000000000000000000a5840c9deddf6657d8d624fc90f035ca1818de26d24aeb9becd946877d7a9f37520ad605b173c60660179227e019370ae9ea824b35f26fefb5b7592b2ab1865263d27";
const KEY_HASH_HEX: &str = "14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8";
const CDH_HEX: &str = "06559c686e02e6fdd317c3faf3d3a871f1660465552dc3c15e36290a44346150";

const NOW: u32 = 1_783_446_000;
const TAKT_EXP: u32 = NOW + 86_400;
const AAT_EXP: u32 = 1_783_446_925;
const AUD: u64 = 1_928_118;
/// Offset of the claims set in a TAKT.
const TAKT_PAYLOAD: usize = 1 + 2 + 42 + 1 + 2;

fn trust_anchor_key() -> EdDSAPrivateKey {
    EdDSAPrivateKey::from_bytes([0x07; 32])
}

fn key_hash() -> FieldElement {
    FieldElement::from_be_bytes(&hex::decode(KEY_HASH_HEX).unwrap().try_into().unwrap()).unwrap()
}

fn assertion_key() -> SigningKey {
    SigningKey::from_bytes(&[0x09; 32].into()).unwrap()
}

fn cdh() -> FieldElement {
    FieldElement::from_be_bytes(&hex::decode(CDH_HEX).unwrap().try_into().unwrap()).unwrap()
}

/// User presence `PresentVerified` with provider bits `0b01`.
fn meta() -> AuthenticatorMeta {
    AuthenticatorMeta::new(UserPresence::PresentVerified, 0b01).unwrap()
}

fn sec_flags() -> SecFlags {
    SecFlags::new(Platform::Ios.into(), SecLevel::HardwareKey.into(), 2006, 3).unwrap()
}

fn takt() -> TaktClaims {
    TaktClaims::new(
        NOW,
        TAKT_EXP,
        u32::MAX,
        *assertion_key().verifying_key(),
        sec_flags(),
    )
    .unwrap()
}

fn aat() -> AatClaims {
    AatClaims::new(NOW, AUD, AAT_EXP, 42u64.into(), cdh(), meta()).unwrap()
}

fn takt_cwt() -> Vec<u8> {
    TrustAnchorKeyToken::sign(takt(), &trust_anchor_key())
        .unwrap()
        .to_cwt()
        .unwrap()
}

fn aat_cwt() -> Vec<u8> {
    AuthenticatorAssertionToken::sign(aat(), &assertion_key())
        .to_cwt()
        .unwrap()
}

fn inputs() -> (
    AuthenticatorAssertionPublicInputs,
    AuthenticatorAssertionPrivateInputs,
) {
    let public = AuthenticatorAssertionPublicInputs {
        trust_anchor_key_hash: key_hash(),
        now: NOW,
        aud: AUD,
        nonce: 42u64.into(),
        platform: 2,
        sec_level: 1,
        sec_meta: 3,
        authenticator_meta: meta(),
        min_build_version: 2006,
    };
    let private = AuthenticatorAssertionPrivateInputs {
        trust_anchor_key: trust_anchor_key().public(),
        takt: TrustAnchorKeyToken::sign(takt(), &trust_anchor_key()).unwrap(),
        aat: AuthenticatorAssertionToken::sign(aat(), &assertion_key()),
        cdh: cdh(),
    };
    (public, private)
}

#[test]
fn tokens_match_spec_vectors() {
    assert_eq!(
        trust_anchor_key_hash(&trust_anchor_key().public()),
        key_hash()
    );
    let takt_cwt = takt_cwt();
    // The Noir fixture's message and signature; EdDSA signing is deterministic.
    let signature = trust_anchor_key().sign(*takt().message_hash());
    assert_eq!(
        takt().message_hash().to_string(),
        "0x17a7e201265aef7edbe89f804b16ff8c98a7f87e1da7ed566bcaa91340053879"
    );
    assert_eq!(
        signature.s.to_string(),
        "2397240400038770518390470117102122304061354532851818695499495078413578208938"
    );
    assert_eq!(
        (signature.r.x.to_string(), signature.r.y.to_string()),
        (
            "15307277759014775981403811608064749853061020498219662916284177626515398769025".into(),
            "2390252300984025142885518919517646868494177410033079022009450775404847994778".into()
        )
    );
    assert_eq!(hex::encode(takt_cwt), TAKT_HEX);
    assert_eq!(hex::encode(aat_cwt()), AAT_HEX);
    assert_eq!(sec_flags().pack(), 0x0003_0000_07d6_0102);
}

#[test]
fn verify_accepts_spec_vectors() {
    let (public, private) = inputs();
    assert_eq!(verify(&public, &private), Ok(()));
    assert_eq!(
        private.takt.kid(),
        trust_anchor_key().public().to_compressed_bytes().unwrap()
    );
    assert_eq!(private.public_inputs(NOW, AUD, public.nonce, 2006), public);
}

/// Platform keys do not normalize `s`, and WIP-106 does not require it.
#[test]
fn high_s_signatures_verify() {
    let (public, mut private) = inputs();
    let mut cwt = aat_cwt();
    let sig_at = cwt.len() - 64;
    let signature = Signature::from_slice(&cwt[sig_at..]).unwrap();
    let (r, s) = signature.split_scalars();
    let flipped = Signature::from_scalars(r, -*s).unwrap();
    assert_ne!(flipped, signature);
    cwt[sig_at..].copy_from_slice(&flipped.to_bytes());
    private.aat = AuthenticatorAssertionToken::from_cwt(&cwt).unwrap();
    assert_eq!(verify(&public, &private), Ok(()));
}

#[test]
fn verify_rejects_each_check() {
    use AuthenticatorAssertionError::*;
    let (public, private) = inputs();
    let check =
        |p: AuthenticatorAssertionPublicInputs,
         s: &AuthenticatorAssertionPrivateInputs,
         err: AuthenticatorAssertionError| assert_eq!(verify(&p, s), Err(err));
    let with_public = |f: &dyn Fn(&mut AuthenticatorAssertionPublicInputs)| {
        let mut p = public;
        f(&mut p);
        p
    };

    check(
        with_public(&|p| p.nonce = FieldElement::ZERO),
        &private,
        InvalidField("nonce"),
    );

    // A key that did not sign the TAKT, with or without its hash as the public input.
    let other_key = EdDSAPrivateKey::from_bytes([0x08; 32]).public();
    let mut with_other_key = AuthenticatorAssertionPrivateInputs {
        trust_anchor_key: other_key.clone(),
        ..private.clone()
    };
    check(public, &with_other_key, KeyMismatch);
    check(
        with_public(&|p| p.trust_anchor_key_hash = trust_anchor_key_hash(&other_key)),
        &with_other_key,
        KeyMismatch,
    );
    // With the other key's `kid`, the failure comes from the signature check.
    let mut cwt = takt_cwt();
    cwt[13..45].copy_from_slice(&other_key.to_compressed_bytes().unwrap());
    with_other_key.takt = TrustAnchorKeyToken::from_cwt(&cwt).unwrap();
    check(
        with_public(&|p| p.trust_anchor_key_hash = trust_anchor_key_hash(&other_key)),
        &with_other_key,
        InvalidSignature(Token::Takt),
    );
    // A tampered `exp` byte changes the signed message.
    let mut forged = private.clone();
    let mut cwt = takt_cwt();
    cwt[TAKT_PAYLOAD + 6] ^= 1;
    forged.takt = TrustAnchorKeyToken::from_cwt(&cwt).unwrap();
    check(public, &forged, InvalidSignature(Token::Takt));

    // An AAT signed by a key the TAKT does not attest.
    let mut unattested = private.clone();
    unattested.aat = AuthenticatorAssertionToken::sign(
        aat(),
        &SigningKey::from_bytes(&[0x08; 32].into()).unwrap(),
    );
    check(public, &unattested, InvalidSignature(Token::Aat));

    // Freshness, at both boundaries of both tokens.
    check(
        with_public(&|p| p.now = AAT_EXP),
        &private,
        Expired(Token::Aat),
    );
    check(
        with_public(&|p| p.now = AAT_EXP - MAX_AAT_LIFETIME_SECS - 1),
        &private,
        LifetimeExceeded(Token::Aat),
    );
    assert_eq!(
        verify(
            &with_public(&|p| p.now = AAT_EXP - MAX_AAT_LIFETIME_SECS),
            &private
        ),
        Ok(())
    );
    check(
        with_public(&|p| p.now = TAKT_EXP),
        &private,
        Expired(Token::Takt),
    );
    let long_takt = AuthenticatorAssertionPrivateInputs {
        takt: TrustAnchorKeyToken::sign(
            TaktClaims {
                exp: NOW + MAX_TAKT_LIFETIME_SECS + 1,
                ..takt()
            },
            &trust_anchor_key(),
        )
        .unwrap(),
        ..private.clone()
    };
    check(public, &long_takt, LifetimeExceeded(Token::Takt));

    // Request binding.
    check(
        with_public(&|p| p.aud = AUD + 1),
        &private,
        Mismatch("request"),
    );
    check(
        with_public(&|p| p.nonce = 43u64.into()),
        &private,
        Mismatch("request"),
    );
    let wrong_cdh = AuthenticatorAssertionPrivateInputs {
        cdh: FieldElement::ONE,
        ..private.clone()
    };
    check(public, &wrong_cdh, Mismatch("request"));

    // Public flags must equal the signed ones.
    check(
        with_public(&|p| p.platform = 4),
        &private,
        Mismatch("sec_flags"),
    );
    check(
        with_public(&|p| p.sec_level = 3),
        &private,
        Mismatch("sec_flags"),
    );
    check(
        with_public(&|p| p.sec_meta = 1),
        &private,
        Mismatch("sec_flags"),
    );
    check(
        with_public(&|p| {
            p.authenticator_meta = AuthenticatorMeta::new(UserPresence::PresentVerified, 0).unwrap()
        }),
        &private,
        Mismatch("authenticator_meta"),
    );
    check(
        with_public(&|p| p.min_build_version = 2007),
        &private,
        BuildVersionBelowMinimum,
    );
}

#[test]
fn non_canonical_encodings_rejected() {
    let takt_key = trust_anchor_key().public();
    let takt_cwt = takt_cwt();
    let aat_cwt = aat_cwt();
    let decode_aat = |cwt: &[u8]| AuthenticatorAssertionToken::from_cwt(cwt).map(|_| ());
    // Payload offset after the `COSE_Sign1` framing.
    let aat_payload = 1 + 1 + 3 + 1 + 2;
    assert_eq!(aat_payload + 162, aat_cwt.len() - 67);

    let mut trailing = aat_cwt.clone();
    trailing.push(0);
    assert_eq!(
        decode_aat(&trailing).unwrap_err(),
        AuthenticatorAssertionError::InvalidEncoding("length")
    );
    assert_eq!(
        decode_aat(&aat_cwt[..aat_cwt.len() - 1]).unwrap_err(),
        AuthenticatorAssertionError::InvalidEncoding("length")
    );

    // A non-empty unprotected header.
    let mut unprotected = aat_cwt.clone();
    unprotected[5] = 0xa1;
    assert!(matches!(
        decode_aat(&unprotected),
        Err(AuthenticatorAssertionError::InvalidEncoding(_))
    ));

    // `nonce` not less than the field order.
    let mut nonce = aat_cwt.clone();
    nonce[aat_payload + 20..aat_payload + 52].fill(0xff);
    assert_eq!(
        decode_aat(&nonce).unwrap_err(),
        (AuthenticatorAssertionError::InvalidEncoding("AAT claims"))
    );

    // Reserved `user_presence`, reserved `authenticator_meta` bits.
    let mut presence = aat_cwt.clone();
    presence[aat_payload + 162] = 5;
    assert_eq!(
        decode_aat(&presence).unwrap_err(),
        (AuthenticatorAssertionError::InvalidField("user_presence"))
    );
    for (index, value) in [(162, 0x20), (131, 0x01)] {
        let mut reserved = aat_cwt.clone();
        reserved[aat_payload + index] = value;
        assert_eq!(
            decode_aat(&reserved).unwrap_err(),
            (AuthenticatorAssertionError::InvalidField("authenticator_meta"))
        );
    }

    // `exp` below 2^16, still a 4-byte uint.
    let mut exp = aat_cwt.clone();
    exp[aat_payload + 13..aat_payload + 17].copy_from_slice(&0xffffu32.to_be_bytes());
    assert_eq!(
        decode_aat(&exp).unwrap_err(),
        (AuthenticatorAssertionError::InvalidField("exp"))
    );

    // A different `eat_profile` byte.
    let mut profile = aat_cwt;
    profile[aat_payload + 60] ^= 1;
    assert_eq!(
        decode_aat(&profile).unwrap_err(),
        (AuthenticatorAssertionError::InvalidEncoding("AAT claims"))
    );

    // A TAKT whose `kid` is not that of the verifying key.
    let mut other_kid = takt_cwt.clone();
    other_kid[13] ^= 1;
    assert_eq!(
        TrustAnchorKeyToken::from_cwt(&other_kid)
            .unwrap()
            .verify(&takt_key),
        Err(AuthenticatorAssertionError::KeyMismatch)
    );

    // TAKT `sec_flags` bit 52.
    let mut flags = takt_cwt.clone();
    flags[TAKT_PAYLOAD + 126] |= 0x10;
    assert_eq!(
        TrustAnchorKeyToken::from_cwt(&flags).unwrap_err(),
        (AuthenticatorAssertionError::InvalidField("sec_flags"))
    );

    // TAKT `cnf` key not on the curve.
    let mut key = takt_cwt;
    key[TAKT_PAYLOAD + 18] ^= 1;
    assert_eq!(
        TrustAnchorKeyToken::from_cwt(&key).unwrap_err(),
        (AuthenticatorAssertionError::InvalidEncoding("assertion_key"))
    );

    // Extra and duplicate map entries.
    use ciborium::Value;
    use coset::{CborSerializable, CoseSign1};

    type Entries = Vec<(Value, Value)>;

    // Re-frames `hex` with its claims map edited by `edit`.
    let edited = |hex: &str, edit: &dyn Fn(&mut Entries)| {
        let mut sign1 = CoseSign1::from_slice(&hex::decode(hex).unwrap()).unwrap();
        let mut claims: Value = ciborium::from_reader(sign1.payload.unwrap().as_slice()).unwrap();
        edit(claims.as_map_mut().unwrap());
        let mut payload = Vec::new();
        ciborium::into_writer(&claims, &mut payload).unwrap();
        sign1.payload = Some(payload);
        sign1.to_vec().unwrap()
    };
    let extra = (Value::from(-90_000), Value::from(0));
    // The `cnf` map inside the TAKT claims.
    fn nested(claims: &mut [(Value, Value)]) -> &mut Entries {
        claims
            .iter_mut()
            .find(|(key, _)| *key == Value::from(8))
            .unwrap()
            .1
            .as_map_mut()
            .unwrap()
    }

    let aat = edited(AAT_HEX, &|claims| claims.push(extra.clone()));
    assert!(AuthenticatorAssertionToken::from_cwt(&aat).is_err());
    let takt = edited(TAKT_HEX, &|claims| claims.push(extra.clone()));
    assert!(TrustAnchorKeyToken::from_cwt(&takt).is_err());
    let cnf = edited(TAKT_HEX, &|claims| nested(claims).push(extra.clone()));
    assert!(TrustAnchorKeyToken::from_cwt(&cnf).is_err());
    let key = edited(TAKT_HEX, &|claims| {
        nested(claims)[0]
            .1
            .as_map_mut()
            .unwrap()
            .push(extra.clone());
    });
    assert!(TrustAnchorKeyToken::from_cwt(&key).is_err());

    // Same length: `authenticator_meta`'s key (-80001) replaced by `cdh`'s (-80000).
    let duplicate = AAT_HEX.replace("3a00013880", "3a0001387f");
    assert_ne!(duplicate, AAT_HEX);
    assert!(AuthenticatorAssertionToken::from_cwt(&hex::decode(duplicate).unwrap()).is_err());
}

#[test]
fn issuance_enforces_lifetimes() {
    let key = *assertion_key().verifying_key();
    for exp in [NOW, NOW - 1, NOW + MAX_TAKT_LIFETIME_SECS + 1] {
        assert_eq!(
            TaktClaims::new(NOW, exp, u32::MAX, key, sec_flags()),
            Err(if exp <= NOW {
                AuthenticatorAssertionError::Expired(Token::Takt)
            } else {
                AuthenticatorAssertionError::LifetimeExceeded(Token::Takt)
            })
        );
    }
    assert!(
        TaktClaims::new(
            NOW,
            NOW + MAX_TAKT_LIFETIME_SECS,
            u32::MAX,
            key,
            sec_flags()
        )
        .is_ok()
    );
    // A TAKT can not outlive the key that signs it; `exp == not_after` is allowed.
    assert_eq!(
        TaktClaims::new(NOW, TAKT_EXP, TAKT_EXP - 1, key, sec_flags()),
        Err(AuthenticatorAssertionError::LifetimeExceeded(Token::Takt))
    );
    assert!(TaktClaims::new(NOW, TAKT_EXP, TAKT_EXP, key, sec_flags()).is_ok());
    let aat_at = |exp| {
        AatClaims::new(
            NOW,
            AUD,
            exp,
            1u64.into(),
            FieldElement::ZERO,
            AuthenticatorMeta::new(UserPresence::Undetermined, 0).unwrap(),
        )
    };
    assert_eq!(
        aat_at(NOW + MAX_AAT_LIFETIME_SECS + 1),
        Err(AuthenticatorAssertionError::LifetimeExceeded(Token::Aat))
    );
    assert!(aat_at(NOW + MAX_AAT_LIFETIME_SECS).is_ok());
    assert_eq!(
        AatClaims::new(
            0xff00,
            AUD,
            0xffff,
            1u64.into(),
            FieldElement::ZERO,
            AuthenticatorMeta::new(UserPresence::Undetermined, 0).unwrap()
        ),
        Err(AuthenticatorAssertionError::InvalidField("exp"))
    );
}

#[test]
fn sec_flags_pack_and_unpack() {
    assert_eq!(
        SecFlags::new(2, 1, 2006, 0x10),
        Err(AuthenticatorAssertionError::InvalidField("sec_meta"))
    );
    assert_eq!(SecFlags::unpack(sec_flags().pack()), Ok(sec_flags()));
    assert_eq!(
        SecFlags::unpack(1 << 52),
        Err(AuthenticatorAssertionError::InvalidField("sec_flags"))
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
    assert_eq!(meta().pack(), 10);
    assert_eq!(AuthenticatorMeta::unpack(10), Ok(meta()));
    assert_eq!(
        AuthenticatorMeta::new(UserPresence::Undetermined, 4),
        Err(AuthenticatorAssertionError::InvalidField("provider_bits"))
    );
    assert_eq!(
        UserPresence::try_from(5),
        Err(AuthenticatorAssertionError::InvalidField("user_presence"))
    );
}

#[test]
fn debug_hides_confidential_values() {
    let (_, private) = inputs();
    for debug in [
        format!("{private:?}"),
        format!("{:?}", takt()),
        format!("{:?}", aat()),
        format!(
            "{:?}",
            TrustAnchorKeyToken::sign(takt(), &trust_anchor_key()).unwrap()
        ),
        format!(
            "{:?}",
            AuthenticatorAssertionToken::sign(aat(), &assertion_key())
        ),
    ] {
        assert!(!debug.contains(&AAT_EXP.to_string()), "{debug}");
        assert!(!debug.contains(&TAKT_EXP.to_string()), "{debug}");
        assert!(!debug.contains("takt:"), "{debug}");
    }
}

/// The `cnf` claim, built by hand, is an EC2 P-256 `COSE_Key` holding the `assertion_key`.
#[test]
fn cnf_is_a_cose_key() {
    use coset::{AsCborValue, CborSerializable, CoseKey, CoseSign1, KeyType, Label, iana};

    let takt = CoseSign1::from_slice(&hex::decode(TAKT_HEX).unwrap()).unwrap();
    let claims: ciborium::Value = ciborium::from_reader(takt.payload.unwrap().as_slice()).unwrap();
    let cnf = claims
        .as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_integer() == Some(8.into()))
        .and_then(|(_, v)| v.as_map())
        .and_then(|m| m.first())
        .map(|(_, key)| key.clone())
        .unwrap();
    let key = CoseKey::from_cbor_value(cnf).unwrap();
    assert_eq!(key.kty, KeyType::Assigned(iana::KeyType::EC2));
    let point = assertion_key().verifying_key().to_encoded_point(false);
    let param = |label: i64| {
        key.params
            .iter()
            .find(|(l, _)| *l == Label::Int(label))
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    assert_eq!(param(-1), ciborium::Value::Integer(1.into()));
    assert_eq!(
        param(-2),
        ciborium::Value::Bytes(point.x().unwrap().to_vec())
    );
    assert_eq!(
        param(-3),
        ciborium::Value::Bytes(point.y().unwrap().to_vec())
    );
}
