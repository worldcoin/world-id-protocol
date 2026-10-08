use super::*;
use crate::{DS_ENGINE, digest_to_field, engine_config_hash};
use sha2::{Digest, Sha256};

// WIP-201 Appendix A1.
const ENGINE_CONFIG_HASH: &str = "2f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d";
const PROVIDER_KEY_HASH: &str = "14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8";
const DIGEST_WITH_AAT: &str = "229f44f2caa18f609df2c1819223d778ef8b08a30ce9de589dbe754275e123bd";
const DIGEST_WITHOUT_AAT: &str = "046b836383d9d9fd350fbed1197e1c1c17f2b187fb6ef1571e5f9b42ec6fc8fc";
const KID: &str = "f2d46cc6aa89d38add66256beb34e089ebd1e33951c5085b3c228ed5dd8f1c12";
const CWT_WITH_AAT: &str = "84582aa2013a00010000045820f2d46cc6aa89d38add66256beb34e089ebd1e33951c5085b3c228ed5dd8f1c12a059017dac190109782168747470733a2f2f776f726c642e6f72672f6561742f666c616d696e676f2f76313a00015f8f582021e9fe96ff18807a727830c56281c96af824005400bcb8ef0f463b34cb20c4153a00015f905820010cff8544f0007179c076ddb49de551bd5743797bfe05cb3b26f55c696f507b3a00015f9158202abb4a81875eb0e308f0fbfb8c0a0f57e77243e095b145ae7973e0b2771e044d3a00015f92582000000000000000000000000000000000000000000000000000000000000000003a00015f93582000000000000000000000000000000000000000000000000000000000001d6bb63a00015f945820000000000000000000000000000000000000000000000000000000000000002a3a00015f95582014b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d83a00015f961b0013000007d601023a00015f97013a00015f981a6a4d39f03a00015f9958202f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d5840cbf2231e80118d266870d7277931546a19bca6ee1d7bbe8c9a8df15659b175908eb3bcbd8c10258173e6130d02539bb720f85db7479c17ad224ca11e66741903";
const CWT_WITHOUT_AAT: &str = "84582aa2013a00010000045820f2d46cc6aa89d38add66256beb34e089ebd1e33951c5085b3c228ed5dd8f1c12a0590171ac190109782168747470733a2f2f776f726c642e6f72672f6561742f666c616d696e676f2f76313a00015f8f582021e9fe96ff18807a727830c56281c96af824005400bcb8ef0f463b34cb20c4153a00015f905820010cff8544f0007179c076ddb49de551bd5743797bfe05cb3b26f55c696f507b3a00015f9158202abb4a81875eb0e308f0fbfb8c0a0f57e77243e095b145ae7973e0b2771e044d3a00015f92582000000000000000000000000000000000000000000000000000000000000000003a00015f93582000000000000000000000000000000000000000000000000000000000001d6bb63a00015f945820000000000000000000000000000000000000000000000000000000000000002a3a00015f95582000000000000000000000000000000000000000000000000000000000000000003a00015f96003a00015f97003a00015f98003a00015f9958202f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d5840a2c1883fd414440ca4df81723869407caa35ef840b0438ec1fb9280757b572abe2ebb272225105813188bff8dd3d5d236636ad7c9aa002413121164697265705";

fn hex_field(hex: &str) -> FieldElement {
    FieldElement::from_be_bytes(&hex::decode(hex).unwrap().try_into().unwrap()).unwrap()
}

fn sha256_field(bytes: &[u8]) -> FieldElement {
    digest_to_field(&Sha256::digest(bytes).into())
}

fn signing_key() -> EdDSAPrivateKey {
    EdDSAPrivateKey::from_bytes([0x15; 32])
}

fn claims(aat: Option<AatClaims>) -> FlamingoClaims {
    FlamingoClaims {
        compared_entry_hashes: [
            sha256_field(b"credential image"),
            sha256_field(b"live image"),
            sha256_field(b"challenge image"),
            FieldElement::ZERO,
        ],
        aud: 1_928_118u64.into(),
        nonce: 42u64.into(),
        aat,
        engine_config_hash: hex_field(ENGINE_CONFIG_HASH),
    }
}

fn with_aat() -> FlamingoClaims {
    claims(Some(AatClaims {
        authenticator_provider_key_hash: hex_field(PROVIDER_KEY_HASH),
        aat_flags: 0x0013_0000_07d6_0102,
        now: 1_783_446_000,
    }))
}

fn sign(claims: &FlamingoClaims) -> FlamingoToken {
    claims.sign(&signing_key()).unwrap()
}

#[test]
fn domain_separators_match_the_spec() {
    assert_eq!(
        (*DS_SIGN.as_field_element()).to_string(),
        "127603488023523044162070750169730750022280897185614"
    );
    assert_eq!(
        (*DS_ENGINE.as_field_element()).to_string(),
        "8362622191109606222205468683123474433460185506268139077"
    );
}

#[test]
fn engine_config_hash_matches_the_vector() {
    assert_eq!(
        engine_config_hash(&[0x2a; 32], 1, 2),
        hex_field(ENGINE_CONFIG_HASH)
    );
}

#[test]
fn tokens_match_the_vectors() {
    assert_eq!(
        hex::encode(signing_key().public().to_compressed_bytes().unwrap()),
        KID
    );
    for (claims, digest, cwt) in [
        (with_aat(), DIGEST_WITH_AAT, CWT_WITH_AAT),
        (claims(None), DIGEST_WITHOUT_AAT, CWT_WITHOUT_AAT),
    ] {
        assert_eq!(claims.digest(), hex_field(digest));
        let token = sign(&claims);
        assert_eq!(hex::encode(token.as_bytes()), cwt);
        assert_eq!(token.verify(&signing_key().public()), Ok(claims));
    }
}

#[test]
fn rejects_another_key() {
    let other = EdDSAPrivateKey::from_bytes([0x16; 32]).public();
    assert_eq!(
        sign(&with_aat()).verify(&other),
        Err(TokenError::SignatureInvalid)
    );
}

#[test]
fn every_claim_is_in_the_digest() {
    let base = with_aat();
    let one = FieldElement::ONE;
    let aat = base.aat.unwrap();
    let mut changed = vec![
        FlamingoClaims { aud: one, ..base },
        FlamingoClaims { nonce: one, ..base },
        FlamingoClaims {
            engine_config_hash: one,
            ..base
        },
        FlamingoClaims { aat: None, ..base },
    ];
    for k in 0..MAX_COMPARED {
        let mut claims = base;
        claims.compared_entry_hashes[k] = one;
        changed.push(claims);
    }
    for aat in [
        AatClaims {
            authenticator_provider_key_hash: one,
            ..aat
        },
        AatClaims {
            aat_flags: 1,
            ..aat
        },
        AatClaims { now: 1, ..aat },
    ] {
        changed.push(FlamingoClaims {
            aat: Some(aat),
            ..base
        });
    }
    for claims in changed {
        assert_ne!(claims.digest(), base.digest());
    }
}

/// Re-encodes a valid token with `payload` in place of its claims.
fn resign(payload: Vec<(Value, Value)>) -> FlamingoToken {
    let sign1 = CoseSign1::from_slice(sign(&with_aat()).as_bytes()).unwrap();
    let mut encoded = Vec::new();
    coset::cbor::into_writer(&Value::Map(payload), &mut encoded).unwrap();
    CoseSign1Builder::new()
        .protected(sign1.protected.header)
        .payload(encoded)
        .signature(sign1.signature)
        .build()
        .to_vec()
        .map(FlamingoToken::from_bytes)
        .unwrap()
}

fn payload(claims: &FlamingoClaims) -> Vec<(Value, Value)> {
    coset::cbor::from_reader::<Value, _>(claims.payload().unwrap().as_slice())
        .unwrap()
        .into_map()
        .unwrap()
}

#[test]
fn rejects_payloads_that_are_not_the_exact_claim_set() {
    let mut extra = payload(&with_aat());
    extra.push((Value::Integer(1.into()), Value::Integer(1.into())));
    let mut reordered = payload(&with_aat());
    reordered.swap(1, 2);
    let mut profile = payload(&with_aat());
    profile[0].1 = Value::Text("https://example.org".into());
    let mut missing = payload(&with_aat());
    missing.pop();
    let mut has_aat = payload(&with_aat());
    has_aat[9].1 = Value::Integer(2.into());
    let mut stray_aat = payload(&claims(None));
    stray_aat[10].1 = Value::Integer(1.into());
    let mut non_canonical = payload(&with_aat());
    non_canonical[5].1 = Value::Bytes(vec![0xff; 32]);

    for payload in [
        extra,
        reordered,
        profile,
        missing,
        has_aat,
        stray_aat,
        non_canonical,
    ] {
        assert_eq!(
            resign(payload).verify(&signing_key().public()),
            Err(TokenError::Malformed)
        );
    }
}

#[test]
fn rejects_another_algorithm() {
    let mut sign1 = CoseSign1::from_slice(sign(&with_aat()).as_bytes()).unwrap();
    sign1.protected.header.alg = Some(RegisteredLabelWithPrivate::PrivateUse(-65538));
    sign1.protected.original_data = None;
    let token = FlamingoToken::from_bytes(sign1.to_vec().unwrap());
    assert_eq!(
        token.verify(&signing_key().public()),
        Err(TokenError::UnexpectedAlgorithm)
    );
}
