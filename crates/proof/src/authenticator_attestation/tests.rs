use coset::{CborSerializable, CoseSign1, RegisteredLabelWithPrivate, cbor::value::Value, iana};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSASignature};
use p256::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    elliptic_curve::sec1::ToEncodedPoint,
};
use rand::rngs::OsRng;
use world_id_primitives::{FieldElement, rp::RpId};

use crate::authenticator_attestation::{
    AttestationError, AuthenticatorAssertionClaims, AuthenticatorAssertionToken, AuthenticatorMeta,
    COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2, Platform, SecLevel, TrustAnchorKeyClaims,
    TrustAnchorKeyToken, UserPresence,
};

fn sample_claims(assertion_key: p256::PublicKey) -> TrustAnchorKeyClaims {
    TrustAnchorKeyClaims {
        exp: 1_783_446_925,
        assertion_key,
        sec_level: SecLevel::SecureElement,
        platform: Platform::Ios,
        build_version: 2006,
        sec_meta: 0b11,
    }
}

/// `sec_flags` for [`sample_claims`]: platform 2, sec_level 1, build_version
/// 2006, sec_meta 3, packed LSB-first.
const SAMPLE_SEC_FLAGS: u64 = 0x0003_0000_07D6_0102;

fn sample_aat_claims() -> AuthenticatorAssertionClaims {
    AuthenticatorAssertionClaims {
        aud: RpId::new(1_928_118),
        exp: 1_783_446_925,
        nonce: FieldElement::from(0x11d2_23ce_7b91_ac21_u64),
        cdh: FieldElement::from(0x9f2c_1abc_u64),
        authenticator_meta: AuthenticatorMeta {
            user_presence: UserPresence::PresentBiometric,
            provider_bits: 0b01,
        },
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Known-answer test: pins the digest and signature produced for fixed keys and
/// claims so any unintended change to the claim encoding, hash layout, or
/// signing breaks loudly.
///
/// Keys are derived from constant test seeds (not real key material).
#[test]
fn known_answer_digest_and_signature() {
    let trust_anchor_key = EdDSAPrivateKey::from_bytes([7_u8; 32]);
    let assertion_secret = p256::SecretKey::from_slice(&[11_u8; 32]).unwrap();

    let token = TrustAnchorKeyToken::new(sample_claims(assertion_secret.public_key())).unwrap();

    let digest = token.message_hash().unwrap();
    assert_eq!(
        to_hex(&digest.to_be_bytes()),
        "1e9a18fda703ca092a9055bca74d82401f5450407d9578b3fb0135d6c6ec2e69"
    );

    let sign1 = CoseSign1::from_slice(&token.sign(&trust_anchor_key).unwrap()).unwrap();
    assert_eq!(
        to_hex(&sign1.signature),
        "f32e95cf56faf261db27f501f1be33d91f5ecfc91c1c2158b62f33a3c89be7078574f9cdda5841d5b50b803cb82336d50896ce39a98a83e06d0bd03d900c0a01"
    );
}

#[test]
fn signature_verifies_over_poseidon2_message() {
    let trust_anchor_key = EdDSAPrivateKey::random(&mut OsRng);
    let assertion_key = p256::SecretKey::random(&mut OsRng).public_key();
    let claims = sample_claims(assertion_key);

    let token = TrustAnchorKeyToken::new(claims).unwrap();
    let sign1 = CoseSign1::from_slice(&token.sign(&trust_anchor_key).unwrap()).unwrap();

    assert_eq!(
        sign1.protected.header.alg,
        Some(RegisteredLabelWithPrivate::PrivateUse(
            COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2
        ))
    );
    assert_eq!(
        sign1.protected.header.key_id,
        trust_anchor_key
            .public()
            .to_compressed_bytes()
            .unwrap()
            .to_vec()
    );

    let signature_bytes: [u8; 64] = sign1.signature.clone().try_into().unwrap();
    let signature = EdDSASignature::from_compressed_bytes(signature_bytes).unwrap();
    assert!(
        trust_anchor_key
            .public()
            .verify(*token.message_hash().unwrap(), &signature)
    );
}

#[test]
fn takt_claims_follow_deterministic_cbor_map_order() {
    let trust_anchor_key = EdDSAPrivateKey::random(&mut OsRng);
    let assertion_key = p256::SecretKey::random(&mut OsRng).public_key();
    let claims = sample_claims(assertion_key);

    let token = TrustAnchorKeyToken::new(claims).unwrap();
    let sign1 = CoseSign1::from_slice(&token.sign(&trust_anchor_key).unwrap()).unwrap();
    let payload: Value = coset::cbor::from_reader(sign1.payload.unwrap().as_slice()).unwrap();
    let Value::Map(entries) = payload else {
        panic!("payload must be a CBOR map");
    };

    let keys: Vec<i128> = entries
        .iter()
        .map(|(key, _)| i128::from(key.as_integer().unwrap()))
        .collect();
    assert_eq!(keys, vec![4, 8, 265, -70_000]);

    assert_eq!(entries[0].1, Value::Integer(claims.exp.into()));
    assert_eq!(
        entries[2].1,
        Value::Text("https://world.org/eat/takt/v1".to_string())
    );
    // sec_flags: 8-byte byte string, 64-bit big-endian packed bitfield.
    assert_eq!(
        entries[3].1,
        Value::Bytes(SAMPLE_SEC_FLAGS.to_be_bytes().to_vec())
    );

    // cnf is {1: COSE_Key} with the assertion key as an EC2 P-256 key.
    let cnf = entries[1].1.as_map().unwrap();
    assert_eq!(cnf.len(), 1);
    assert_eq!(cnf[0].0, Value::Integer(1.into()));
    let cose_key = cnf[0].1.as_map().unwrap();
    let cose_key_labels: Vec<i128> = cose_key
        .iter()
        .map(|(label, _)| i128::from(label.as_integer().unwrap()))
        .collect();
    assert_eq!(cose_key_labels, vec![1, -1, -2, -3]);
    assert_eq!(cose_key[0].1, Value::Integer(2.into()));
    assert_eq!(cose_key[1].1, Value::Integer(1.into()));
    let point = assertion_key.to_encoded_point(false);
    assert_eq!(
        cose_key[2].1.as_bytes().unwrap().as_slice(),
        &point.x().unwrap()[..]
    );
    assert_eq!(
        cose_key[3].1.as_bytes().unwrap().as_slice(),
        &point.y().unwrap()[..]
    );
}

#[test]
fn token_serialization_is_deterministic() {
    let trust_anchor_key = EdDSAPrivateKey::random(&mut OsRng);
    let assertion_key = p256::SecretKey::random(&mut OsRng).public_key();
    let claims = sample_claims(assertion_key);

    let token = TrustAnchorKeyToken::new(claims).unwrap();
    assert_eq!(
        token.sign(&trust_anchor_key).unwrap(),
        token.sign(&trust_anchor_key).unwrap()
    );
}

#[test]
fn rejects_sec_meta_with_more_than_four_bits() {
    let assertion_key = p256::SecretKey::random(&mut OsRng).public_key();
    let claims = TrustAnchorKeyClaims {
        sec_meta: 0b1_0000,
        ..sample_claims(assertion_key)
    };

    let err = TrustAnchorKeyToken::new(claims).unwrap_err();
    assert!(matches!(err, AttestationError::SecMetaTooLarge(0b1_0000)));
}

#[test]
fn signature_binds_to_claims() {
    let trust_anchor_key = EdDSAPrivateKey::random(&mut OsRng);
    let assertion_key = p256::SecretKey::random(&mut OsRng).public_key();
    let claims = sample_claims(assertion_key);

    let token = TrustAnchorKeyToken::new(claims).unwrap();
    let sign1 = CoseSign1::from_slice(&token.sign(&trust_anchor_key).unwrap()).unwrap();
    let signature_bytes: [u8; 64] = sign1.signature.clone().try_into().unwrap();
    let signature = EdDSASignature::from_compressed_bytes(signature_bytes).unwrap();

    let tampered_claims = TrustAnchorKeyClaims {
        exp: claims.exp + 1,
        ..claims
    };
    let tampered = TrustAnchorKeyToken::new(tampered_claims).unwrap();
    assert!(
        !trust_anchor_key
            .public()
            .verify(*tampered.message_hash().unwrap(), &signature)
    );

    let other_assertion_key = p256::SecretKey::random(&mut OsRng).public_key();
    let other_key = TrustAnchorKeyToken::new(TrustAnchorKeyClaims {
        assertion_key: other_assertion_key,
        ..claims
    })
    .unwrap();
    assert!(
        !trust_anchor_key
            .public()
            .verify(*other_key.message_hash().unwrap(), &signature)
    );
}

#[test]
fn aat_signature_verifies_with_es256() {
    let assertion_secret = p256::SecretKey::random(&mut OsRng);

    let token = AuthenticatorAssertionToken::new(sample_aat_claims()).unwrap();
    let sign1 = CoseSign1::from_slice(&token.sign(&assertion_secret).unwrap()).unwrap();

    assert_eq!(
        sign1.protected.header.alg,
        Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256))
    );

    let verifying_key = VerifyingKey::from(assertion_secret.public_key());
    sign1
        .verify_signature(&[], |signature, message| {
            let signature = Signature::from_slice(signature)?;
            verifying_key.verify(message, &signature)
        })
        .unwrap();
}

#[test]
fn aat_claims_follow_deterministic_cbor_map_order() {
    let assertion_secret = p256::SecretKey::random(&mut OsRng);
    let claims = sample_aat_claims();

    let token = AuthenticatorAssertionToken::new(claims).unwrap();
    let token_bytes = token.sign(&assertion_secret).unwrap();
    let sign1 = CoseSign1::from_slice(&token_bytes).unwrap();
    let payload: Value = coset::cbor::from_reader(sign1.payload.unwrap().as_slice()).unwrap();
    let Value::Map(entries) = payload else {
        panic!("payload must be a CBOR map");
    };

    let keys: Vec<i128> = entries
        .iter()
        .map(|(key, _)| i128::from(key.as_integer().unwrap()))
        .collect();
    assert_eq!(keys, vec![3, 4, 10, 265, -80_000, -80_001]);

    assert_eq!(
        entries[0].1,
        Value::Bytes(claims.aud.into_inner().to_be_bytes().to_vec())
    );
    assert_eq!(entries[1].1, Value::Integer(claims.exp.into()));
    assert_eq!(
        entries[2].1,
        Value::Bytes(claims.nonce.to_be_bytes().to_vec())
    );
    assert_eq!(
        entries[3].1,
        Value::Text("https://world.org/eat/aat/v1".to_string())
    );
    assert_eq!(
        entries[4].1,
        Value::Bytes(claims.cdh.to_be_bytes().to_vec())
    );
    // authenticator_meta: presence 0b010 | provider 0b01 << 3 = 10, as a
    // 32-byte canonical big-endian field element.
    assert_eq!(
        entries[5].1,
        Value::Bytes(FieldElement::from(10_u64).to_be_bytes().to_vec())
    );
}

/// Cross-implementation known-answer test: pins the exact COSE `Sig_structure`
/// the assertion key signs, and the resulting signature, for fixed test keys.
///
/// The Noir circuit rebuilds this byte layout at constant offsets
/// (`aat.nr::aat_sig_structure`), so this is the source fixture that keeps the
/// two implementations from drifting. Its `Sig_structure` hex is copied as the
/// byte array in Noir's `test_aat_sig_structure_matches_rust_fixture`, and its
/// signature is copied into `test_deterministic_aat`. An intentional change to
/// either expectation must update the corresponding Noir fixture.
#[test]
fn aat_known_answer_sig_structure_and_signature() {
    let assertion_secret = p256::SecretKey::from_slice(&[11_u8; 32]).unwrap();

    let token = AuthenticatorAssertionToken::new(sample_aat_claims()).unwrap();
    let sign1 = CoseSign1::from_slice(&token.sign(&assertion_secret).unwrap()).unwrap();

    let tbs = sign1.tbs_data(&[]);
    assert_eq!(
        tbs.len(),
        182,
        "must equal AAT_SIG_STRUCTURE_LEN in crates/proof/noir/.../aat.nr"
    );
    assert_eq!(
        to_hex(&tbs),
        "846a5369676e61747572653143a101264058a3a6034800000000001d6bb6041a6a4d3d8d0a582000000000000000000000000000000000000000000000000011d223ce7b91ac21190109781c68747470733a2f2f776f726c642e6f72672f6561742f6161742f76313a0001387f5820000000000000000000000000000000000000000000000000000000009f2c1abc3a000138805820000000000000000000000000000000000000000000000000000000000000000a"
    );
    assert_eq!(
        to_hex(&sign1.signature),
        "516ef88b3c523474644e3148c1db2a50259e81dca36f4276768d65d46309e82663de9c50116673b778d72bafc4414f384b54d7ba661c3e2d76d8a6cf8d32a463"
    );
}

#[test]
fn aat_rejects_provider_bits_with_more_than_two_bits() {
    let claims = AuthenticatorAssertionClaims {
        authenticator_meta: AuthenticatorMeta {
            user_presence: UserPresence::Undetermined,
            provider_bits: 0b100,
        },
        ..sample_aat_claims()
    };

    let err = AuthenticatorAssertionToken::new(claims).unwrap_err();
    assert!(matches!(err, AttestationError::ProviderBitsTooLarge(0b100)));
}

/// `aud` is an 8-byte byte string rather than a CBOR uint precisely so that the
/// whole `u64` range keeps a constant-width encoding. A uint would need the
/// shortest form under deterministic CBOR (RFC 8949 section 4.2.1), which makes
/// its width depend on the value: `RpId` is a `u64` protocol-wide, and ids as
/// small as `1` are in use.
#[test]
fn aat_accepts_the_full_u64_aud_range() {
    let assertion_secret = p256::SecretKey::from_slice(&[11_u8; 32]).unwrap();
    for aud in [0, 1, 100, u64::from(u32::MAX) + 1, u64::MAX] {
        let claims = AuthenticatorAssertionClaims {
            aud: RpId::new(aud),
            ..sample_aat_claims()
        };
        let token = AuthenticatorAssertionToken::new(claims).unwrap();
        let sign1 = CoseSign1::from_slice(&token.sign(&assertion_secret).unwrap()).unwrap();
        let payload: Value = coset::cbor::from_reader(sign1.payload.unwrap().as_slice()).unwrap();
        let Value::Map(entries) = payload else {
            panic!("payload must be a CBOR map");
        };

        // Always the same 8 bytes on the wire, whatever the magnitude.
        assert_eq!(entries[0].1, Value::Bytes(aud.to_be_bytes().to_vec()));
    }
}

#[test]
fn aat_rejects_exp_outside_fixed_width_range() {
    let claims = AuthenticatorAssertionClaims {
        // Fits a 2-byte CBOR uint, which would shift every payload offset the
        // circuit relies on.
        exp: 100,
        ..sample_aat_claims()
    };

    let err = AuthenticatorAssertionToken::new(claims).unwrap_err();
    assert!(matches!(err, AttestationError::ExpirationOutOfRange(100)));
}

#[test]
fn takt_rejects_exp_outside_fixed_width_range() {
    let assertion_secret = p256::SecretKey::random(&mut OsRng);
    let claims = TrustAnchorKeyClaims {
        // Fits a 2-byte CBOR uint; same fixed-offset violation from below.
        exp: 100,
        ..sample_claims(assertion_secret.public_key())
    };

    let err = TrustAnchorKeyToken::new(claims).unwrap_err();
    assert!(matches!(err, AttestationError::ExpirationOutOfRange(100)));
}
