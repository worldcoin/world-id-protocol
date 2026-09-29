use super::{
    AuthenticatorAssertionToken, MAX_AAT_LIFETIME, request_commitment, SecFlags, verify_aat,
};
use poseidon2::bn254::perm;

// Known-answer fixture shared with `crates/proof/src/authenticator_assertion/tests.rs`.
global TRUST_ANCHOR_KEY: [Field; 2] = [
    19037598474602150174935475944965340829216795940473064039209388058233204431288,
    3549932221586364715003722955756497910920276078443163728621283280434115857197,
];
global EXP: Field = 1783446925;
global NOW: Field = 1783446000;
global AUD: Field = 1928118;
global NONCE: Field = 42;
global CDH: Field = 0;
global PRESENCE: u8 = 2;
global BLIND: Field = 7;
global EXPECTED_REQ: Field = 0x2a09ead9ab7c0b2e0f6f7a5b5fc8128261bf10849e151d0b757aa949f0597367;
global EXPECTED_MESSAGE: Field = 0x250193b370e6d704c20ed37317246ff40d04226b77a970107778e475a80c9531;

fn fixture() -> AuthenticatorAssertionToken {
    AuthenticatorAssertionToken {
        exp: EXP,
        // platform 2 (iOS) | sec_level 1 << 8 | sec_meta 3 << 16
        sec_flags: 0x030102,
        sig_s: 1462272513541365883280968055772542535687228844730885273921268486514987470338,
        sig_r: [
            21613790725172622325362156722653543041337718166900891470499267681863821127153,
            9483405006072346718418037267607200727700887000659830653610819289716621548185,
        ],
    }
}

fn verify(aat: AuthenticatorAssertionToken, now: Field) -> SecFlags {
    verify_aat(aat, TRUST_ANCHOR_KEY, now, AUD, NONCE, CDH, PRESENCE, BLIND)
}

#[test]
fn test_known_answer_digests() {
    let req = request_commitment(AUD, NONCE, CDH, PRESENCE as Field, BLIND);
    assert_eq(req, EXPECTED_REQ);
    let aat = fixture();
    assert_eq(perm::x5_4([super::DS_AAT, aat.exp, req, aat.sec_flags])[1], EXPECTED_MESSAGE);
}

#[test]
fn test_valid_token() {
    let flags = verify(fixture(), NOW);
    assert_eq(flags.platform, 2);
    assert_eq(flags.sec_level, 1);
    assert_eq(flags.sec_meta, 3);
}

#[test]
fn test_max_lifetime_boundary_accepted() {
    let _ = verify(fixture(), EXP - MAX_AAT_LIFETIME);
}

#[test(should_fail_with = "token lifetime exceeds maximum")]
fn test_lifetime_above_maximum_rejected() {
    let _ = verify(fixture(), EXP - MAX_AAT_LIFETIME - 1);
}

#[test(should_fail_with = "token is expired")]
fn test_expired_token_rejected() {
    // At `exp` the token is already expired.
    let _ = verify(fixture(), EXP);
}

#[test(should_fail_with = "invalid signature")]
fn test_tampered_sec_flags_rejected() {
    let mut aat = fixture();
    aat.sec_flags = 0x030104;
    let _ = verify(aat, NOW);
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_aud_rejected() {
    let _ = verify_aat(
        fixture(),
        TRUST_ANCHOR_KEY,
        NOW,
        AUD + 1,
        NONCE,
        CDH,
        PRESENCE,
        BLIND,
    );
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_nonce_rejected() {
    let _ = verify_aat(
        fixture(),
        TRUST_ANCHOR_KEY,
        NOW,
        AUD,
        NONCE + 1,
        CDH,
        PRESENCE,
        BLIND,
    );
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_cdh_rejected() {
    let _ = verify_aat(
        fixture(),
        TRUST_ANCHOR_KEY,
        NOW,
        AUD,
        NONCE,
        1,
        PRESENCE,
        BLIND,
    );
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_blind_rejected() {
    let _ = verify_aat(
        fixture(),
        TRUST_ANCHOR_KEY,
        NOW,
        AUD,
        NONCE,
        CDH,
        PRESENCE,
        BLIND + 1,
    );
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_trust_anchor_key_rejected() {
    // The BabyJubJub subgroup generator: a valid key that did not sign the token, so the
    // failure comes from the signature check rather than the key validation.
    let other_key = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203,
    ];
    let _ = verify_aat(fixture(), other_key, NOW, AUD, NONCE, CDH, PRESENCE, BLIND);
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_presence_rejected() {
    let _ = verify_aat(fixture(), TRUST_ANCHOR_KEY, NOW, AUD, NONCE, CDH, 1, BLIND);
}

#[test(should_fail_with = "presence values 5 to 7 are reserved")]
fn test_reserved_presence_rejected() {
    let _ = verify_aat(fixture(), TRUST_ANCHOR_KEY, NOW, AUD, NONCE, CDH, 5, BLIND);
}

#[test(should_fail_with = "nonce must not be 0")]
fn test_zero_nonce_rejected() {
    let _ = verify_aat(
        fixture(),
        TRUST_ANCHOR_KEY,
        NOW,
        AUD,
        0,
        CDH,
        PRESENCE,
        BLIND,
    );
}

#[test(should_fail_with = "sec_flags bits 19 and above are reserved and must be 0")]
fn test_reserved_sec_flags_bits_rejected() {
    // Exercised directly: a signed token with reserved bits would need the provider's key.
    let _ = super::unpack_sec_flags(0x130102);
}

#[test(should_fail_with = "sec_flags bits 19 and above are reserved and must be 0")]
fn test_sec_meta_bit_3_rejected() {
    let _ = super::unpack_sec_flags(0x080102);
}

#[test(should_fail)]
fn test_sec_flags_above_24_bits_rejected() {
    let _ = super::unpack_sec_flags(0x1000000);
}

#[test(should_fail)]
fn test_now_above_32_bits_rejected() {
    super::assert_fresh(EXP, 0x100000000);
}
