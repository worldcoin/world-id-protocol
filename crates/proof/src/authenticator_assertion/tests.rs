use eddsa_babyjubjub::EdDSAPrivateKey;
use world_id_primitives::FieldElement;

use super::*;

/// Shared with `crates/proof/noir/authenticator-assertion/src/tests.nr`.
const EXPECTED_REQ: &str = "0x073b684cfbb5426fa6e7c366e16afe927f32094114ba1315fb0d25303ebd98f4";
const EXPECTED_MESSAGE: &str = "0x23d4df386e7075e777fb44a52ed4858abf3a34275f8adb81e6d89176480d6e30";

fn fixture() -> (AuthenticatorAssertionToken, EdDSAPrivateKey) {
    let req = request_commitment(
        FieldElement::from(1_928_118u64),
        FieldElement::from(42u64),
        FieldElement::ZERO,
        FieldElement::from(7u64),
    );
    let flags = SecFlags {
        platform: Platform::Ios,
        sec_level: SecLevel::HardwareKey,
        sec_meta: 3,
    };
    (
        AuthenticatorAssertionToken::new(1_783_446_925, req, flags).unwrap(),
        EdDSAPrivateKey::from_bytes([7u8; 32]),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn known_answer_matches_circuit_fixture() {
    let (aat, key) = fixture();
    assert_eq!(aat.req().to_string(), EXPECTED_REQ);
    assert_eq!(aat.message_hash().to_string(), EXPECTED_MESSAGE);
    assert_eq!(aat.sec_flags().pack(), 0x03_0102);

    // The Noir fixture's signature and key; EdDSA signing is deterministic.
    let sig = key.sign(*aat.message_hash());
    assert_eq!(
        sig.s.to_string(),
        "144418557646667652646254429367096501294052844800449307777329231192038056714"
    );
    assert_eq!(
        sig.r.x.to_string(),
        "3116733758525930913643034808623136189072613978903991388122497481019837111764"
    );
    assert_eq!(
        key.public().pk.x.to_string(),
        "19037598474602150174935475944965340829216795940473064039209388058233204431288"
    );
}

#[test]
fn sig_structure_matches_spec_template() {
    let (aat, _) = fixture();
    let expected = format!(
        "846a5369676e61747572653147a1013a00010000405855a4041a{}0a5820{}190109781c68747470733a2f2f776f726c642e6f72672f6561742f6161742f76313a0001116f44{}",
        hex(&aat.exp().to_be_bytes()),
        hex(&aat.req().to_be_bytes()),
        hex(&aat.sec_flags().pack().to_be_bytes()),
    );
    assert_eq!(hex(&aat.sig_structure()), expected);
    assert_eq!(aat.sig_structure().len(), 108);
}

#[test]
fn cwt_round_trips_and_verifies() {
    let (aat, key) = fixture();
    let cwt = aat.sign(&key).unwrap();
    let decoded = SignedAuthenticatorAssertionToken::decode(&cwt).unwrap();

    assert_eq!(decoded.token.exp(), aat.exp());
    assert_eq!(decoded.token.req(), aat.req());
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
    assert_eq!(decoded.token.req(), aat.req());
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
        Err(AssertionError::InvalidEncoding("non-canonical nonce"))
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
        AuthenticatorAssertionToken::new(0xffff, aat.req(), flags),
        Err(AssertionError::ExpirationOutOfRange(0xffff))
    ));
    assert!(matches!(
        AuthenticatorAssertionToken::new(
            aat.exp(),
            aat.req(),
            SecFlags {
                sec_meta: 0x10,
                ..flags
            }
        ),
        Err(AssertionError::SecMetaTooLarge(0x10))
    ));
    assert!(SecFlags::unpack(0x13_0102).is_err());
    assert!(SecFlags::unpack(0x03_0103).is_err());
    assert_eq!(SecFlags::unpack(flags.pack()).unwrap(), flags);
}

#[test]
fn request_commitment_binds_every_input() {
    let base = [1u64, 2, 3, 4].map(FieldElement::from);
    let commit = |v: [FieldElement; 4]| request_commitment(v[0], v[1], v[2], v[3]);
    for i in 0..4 {
        let mut changed = base;
        changed[i] = FieldElement::from(99u64);
        assert_ne!(commit(changed), commit(base));
    }
}
