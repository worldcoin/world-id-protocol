use coset::{CborSerializable, CoseSign1, RegisteredLabelWithPrivate, cbor::value::Value};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSASignature};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;

use crate::authenticator_attestation::{
    AttestationError, COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2, Platform, RootOfTrustClaims,
    RootOfTrustToken, SecLevel,
};

fn sample_claims(assertion_key: p256::PublicKey) -> RootOfTrustClaims {
    RootOfTrustClaims {
        exp: 1_783_446_925,
        assertion_key,
        sec_level: SecLevel::SecureElement,
        platform: Platform::Ios,
        build_version: 2006,
        sec_meta: 0b11,
    }
}

#[test]
fn signature_verifies_over_poseidon2_message() {
    let root_key = EdDSAPrivateKey::random(&mut OsRng);
    let assertion_key = p256::SecretKey::random(&mut OsRng).public_key();
    let claims = sample_claims(assertion_key);

    let token = RootOfTrustToken::new(claims).unwrap();
    let sign1 = CoseSign1::from_slice(&token.sign(&root_key).unwrap()).unwrap();

    assert_eq!(
        sign1.protected.header.alg,
        Some(RegisteredLabelWithPrivate::PrivateUse(
            COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2
        ))
    );
    assert_eq!(
        sign1.protected.header.key_id,
        root_key.public().to_compressed_bytes().unwrap().to_vec()
    );

    let signature_bytes: [u8; 64] = sign1.signature.clone().try_into().unwrap();
    let signature = EdDSASignature::from_compressed_bytes(signature_bytes).unwrap();
    assert!(
        root_key
            .public()
            .verify(*token.message_hash().unwrap(), &signature)
    );
}

#[test]
fn claims_follow_deterministic_cbor_map_order() {
    let root_key = EdDSAPrivateKey::random(&mut OsRng);
    let assertion_key = p256::SecretKey::random(&mut OsRng).public_key();
    let claims = sample_claims(assertion_key);

    let token = RootOfTrustToken::new(claims).unwrap();
    let sign1 = CoseSign1::from_slice(&token.sign(&root_key).unwrap()).unwrap();
    let payload: Value = coset::cbor::from_reader(sign1.payload.unwrap().as_slice()).unwrap();
    let Value::Map(entries) = payload else {
        panic!("payload must be a CBOR map");
    };

    let keys: Vec<i128> = entries
        .iter()
        .map(|(key, _)| i128::from(key.as_integer().unwrap()))
        .collect();
    assert_eq!(keys, vec![4, 8, 265, -70_000, -70_001, -70_003, -70_005]);

    assert_eq!(entries[0].1, Value::Integer(claims.exp.into()));
    assert_eq!(
        entries[2].1,
        Value::Text("https://worldcoin.org/eat/rot/v1".to_string())
    );
    assert_eq!(entries[3].1, Value::Integer(1.into()));
    assert_eq!(entries[4].1, Value::Integer(2.into()));
    assert_eq!(entries[5].1, Value::Integer(claims.build_version.into()));
    assert_eq!(entries[6].1, Value::Integer(claims.sec_meta.into()));

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
    let root_key = EdDSAPrivateKey::random(&mut OsRng);
    let assertion_key = p256::SecretKey::random(&mut OsRng).public_key();
    let claims = sample_claims(assertion_key);

    let token = RootOfTrustToken::new(claims).unwrap();
    assert_eq!(
        token.sign(&root_key).unwrap(),
        token.sign(&root_key).unwrap()
    );
}

#[test]
fn rejects_sec_meta_with_more_than_two_bits() {
    let assertion_key = p256::SecretKey::random(&mut OsRng).public_key();
    let claims = RootOfTrustClaims {
        sec_meta: 0b100,
        ..sample_claims(assertion_key)
    };

    let err = RootOfTrustToken::new(claims).unwrap_err();
    assert!(matches!(err, AttestationError::SecMetaTooLarge(0b100)));
}

#[test]
fn rejects_exp_beyond_cwt_numeric_date_range() {
    let assertion_key = p256::SecretKey::random(&mut OsRng).public_key();
    let claims = RootOfTrustClaims {
        exp: u64::MAX,
        ..sample_claims(assertion_key)
    };

    let err = RootOfTrustToken::new(claims).unwrap_err();
    assert!(matches!(err, AttestationError::ExpirationOutOfRange(_)));
}

#[test]
fn signature_binds_to_claims() {
    let root_key = EdDSAPrivateKey::random(&mut OsRng);
    let assertion_key = p256::SecretKey::random(&mut OsRng).public_key();
    let claims = sample_claims(assertion_key);

    let token = RootOfTrustToken::new(claims).unwrap();
    let sign1 = CoseSign1::from_slice(&token.sign(&root_key).unwrap()).unwrap();
    let signature_bytes: [u8; 64] = sign1.signature.clone().try_into().unwrap();
    let signature = EdDSASignature::from_compressed_bytes(signature_bytes).unwrap();

    let tampered_claims = RootOfTrustClaims {
        exp: claims.exp + 1,
        ..claims
    };
    let tampered = RootOfTrustToken::new(tampered_claims).unwrap();
    assert!(
        !root_key
            .public()
            .verify(*tampered.message_hash().unwrap(), &signature)
    );

    let other_assertion_key = p256::SecretKey::random(&mut OsRng).public_key();
    let other_key = RootOfTrustToken::new(RootOfTrustClaims {
        assertion_key: other_assertion_key,
        ..claims
    })
    .unwrap();
    assert!(
        !root_key
            .public()
            .verify(*other_key.message_hash().unwrap(), &signature)
    );
}
