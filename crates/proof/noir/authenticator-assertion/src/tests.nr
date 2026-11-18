use super::{
    AuthenticatorAssertionPrivateInputs, AuthenticatorAssertionPublicInputs, MAX_AAT_LIFETIME,
    MAX_TAKT_LIFETIME, verify_assertion,
};
use bigcurve::curves::secp256r1::Secp256r1_Fr;
use bignum::BigNum;

// WIP-106 Appendix A1; shared with `crates/primitives/src/authenticator_assertion/tests.rs`.
global ASSERTION_KEY_X: [u8; 32] = [
    0x71, 0x35, 0xfa, 0x4f, 0xd9, 0x3a, 0x09, 0xdc, 0xe9, 0x8b, 0xbf, 0x68, 0x1b, 0x4b, 0xfc, 0xf5,
    0x0e, 0x7c, 0x0d, 0x63, 0x54, 0xe6, 0x2a, 0xfb, 0x0b, 0xff, 0x2a, 0x34, 0x29, 0x61, 0x78, 0x65,
];
global ASSERTION_KEY_Y: [u8; 32] = [
    0xed, 0x4c, 0x1f, 0x02, 0xdd, 0xb9, 0x02, 0x3e, 0xe5, 0x6a, 0x55, 0x7e, 0x51, 0x5d, 0x6a, 0x9d,
    0xc6, 0x6c, 0x11, 0xf2, 0x20, 0x96, 0x0d, 0xe5, 0x94, 0x33, 0x4d, 0xf5, 0x88, 0x77, 0x67, 0x24,
];
global AAT_SIGNATURE: [u8; 64] = [
    0x5f, 0xd3, 0x2b, 0x98, 0xbf, 0x3e, 0xcb, 0x65, 0x4c, 0xc0, 0xa2, 0xde, 0xed, 0x30, 0x28, 0x3b,
    0xc4, 0x39, 0x00, 0x88, 0x6e, 0x5f, 0xcc, 0x50, 0x34, 0xa0, 0x2e, 0x94, 0xc8, 0xb5, 0x79, 0x6e,
    0xb1, 0x36, 0xbe, 0xed, 0xee, 0xe9, 0xc6, 0x01, 0xf3, 0x12, 0x60, 0x4a, 0xe6, 0x4b, 0xf7, 0x3a,
    0x5d, 0xeb, 0x79, 0x42, 0x17, 0x9e, 0x2d, 0xf0, 0xcc, 0x43, 0xdf, 0x90, 0x49, 0xf3, 0xbc, 0xdd,
];
global TRUST_ANCHOR_KEY: [Field; 2] = [
    19037598474602150174935475944965340829216795940473064039209388058233204431288,
    3549932221586364715003722955756497910920276078443163728621283280434115857197,
];
global TRUST_ANCHOR_KEY_HASH: Field =
    0x14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8;
global TAKT_MESSAGE: Field = 0x287479947525d64bb041dbbbc36462f46ccb75d3be505ab83e69a38ca3299cea;
// The BabyJubJub subgroup generator: a valid key that did not sign the fixture TAKT.
global OTHER_KEY: [Field; 2] = [
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203,
];
global NOW: Field = 1783446000;
global TAKT_EXP: Field = 1783532400;
global AAT_EXP: Field = 1783446925;
global CDH: Field = 0x06559c686e02e6fdd317c3faf3d3a871f1660465552dc3c15e36290a44346150;

fn public() -> AuthenticatorAssertionPublicInputs {
    AuthenticatorAssertionPublicInputs {
        trust_anchor_key_hash: TRUST_ANCHOR_KEY_HASH,
        now: NOW,
        aud: 1928118,
        nonce: 42,
        platform: 2,
        integrity_level: 1,
        key_protection: 3,
        sec_meta: 3,
        // provider bits 0b01
        authenticator_meta: 1,
        min_build_version: 2006,
    }
}

fn private() -> AuthenticatorAssertionPrivateInputs {
    AuthenticatorAssertionPrivateInputs {
        trust_anchor_key: TRUST_ANCHOR_KEY,
        takt_exp: TAKT_EXP,
        assertion_key_x: ASSERTION_KEY_X,
        assertion_key_y: ASSERTION_KEY_Y,
        // platform 2 | integrity_level 1 << 8 | build_version 2006 << 16 | sec_meta 3 << 48
        // | key_protection 3 << 52
        sec_flags: 0x0033000007D60102,
        takt_sig_s: 2358271662210144119452071820160048538741534859901531750634697046917306896412,
        takt_sig_r: [
            20421980338803122010777117778973137794948709268084389261502187299763870483274,
            21517044705661979807367039403922915424567391340559514125034686868758403919915,
        ],
        aat_exp: AAT_EXP,
        aat_signature: AAT_SIGNATURE,
        cdh: CDH,
    }
}

#[test]
fn test_known_answer_digests() {
    assert_eq(super::takt_message(private()), TAKT_MESSAGE);
    let key = TRUST_ANCHOR_KEY;
    assert_eq(
        poseidon2::bn254::permutation::t3([super::DS_KEY, key[0], key[1]])[1],
        TRUST_ANCHOR_KEY_HASH,
    );
}

#[test]
fn test_valid_tokens() {
    verify_assertion(public(), private());
}

#[test]
fn test_high_s_signature_accepted() {
    // Platform keys do not normalize `s`, so `(r, n - s)` must verify like `(r, s)`.
    let mut private = private();
    let s = super::signature_scalar(private.aat_signature, 32);
    let high_s: [u8; 32] = (Secp256r1_Fr::zero() - s).to_be_bytes();
    for i in 0..32 {
        private.aat_signature[32 + i] = high_s[i];
    }
    verify_assertion(public(), private);
}

#[test(should_fail_with = "nonce must not be 0")]
fn test_zero_nonce_rejected() {
    let mut public = public();
    public.nonce = 0;
    verify_assertion(public, private());
}

#[test(should_fail_with = "authenticator_meta bits 2 and above are reserved")]
fn test_reserved_authenticator_meta_bits_rejected() {
    let mut public = public();
    public.authenticator_meta = 4;
    verify_assertion(public, private());
}

#[test(should_fail_with = "trust_anchor_key does not match its hash")]
fn test_key_hash_mismatch_rejected() {
    let mut private = private();
    private.trust_anchor_key = OTHER_KEY;
    verify_assertion(public(), private);
}

#[test(should_fail_with = "invalid TAKT signature")]
fn test_wrong_trust_anchor_key_rejected() {
    // The key matches the public hash, so the failure comes from the signature check.
    let mut public = public();
    public.trust_anchor_key_hash =
        poseidon2::bn254::permutation::t3([super::DS_KEY, OTHER_KEY[0], OTHER_KEY[1]])[1];
    let mut private = private();
    private.trust_anchor_key = OTHER_KEY;
    verify_assertion(public, private);
}

#[test(should_fail_with = "invalid TAKT signature")]
fn test_unattested_assertion_key_rejected() {
    // The TAKT signs the `assertion_key`, so swapping it breaks the TAKT signature.
    let mut private = private();
    private.assertion_key_x = ASSERTION_KEY_Y;
    private.assertion_key_y = ASSERTION_KEY_X;
    verify_assertion(public(), private);
}

#[test(should_fail)]
fn test_non_canonical_takt_sig_s_rejected() {
    // `s + l`, with `l` the subgroup order, satisfies the verification equation but is not a
    // reduced scalar. The scalar range check has no message, so `should_fail_with` can not pin it.
    let mut private = private();
    private.takt_sig_s = private.takt_sig_s
        + 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    verify_assertion(public(), private);
}

#[test(should_fail_with = "invalid TAKT signature")]
fn test_tampered_sec_flags_rejected() {
    let mut private = private();
    private.sec_flags = 0x0033000007D70102;
    verify_assertion(public(), private);
}

#[test(should_fail_with = "invalid TAKT signature")]
fn test_tampered_takt_exp_rejected() {
    let mut private = private();
    private.takt_exp = TAKT_EXP + 1;
    verify_assertion(public(), private);
}

#[test(should_fail_with = "invalid AAT signature")]
fn test_wrong_aud_rejected() {
    let mut public = public();
    public.aud = 1928119;
    verify_assertion(public, private());
}

#[test(should_fail_with = "invalid AAT signature")]
fn test_wrong_nonce_rejected() {
    let mut public = public();
    public.nonce = 43;
    verify_assertion(public, private());
}

#[test(should_fail_with = "invalid AAT signature")]
fn test_wrong_cdh_rejected() {
    let mut private = private();
    private.cdh = 1;
    verify_assertion(public(), private);
}

#[test(should_fail_with = "invalid AAT signature")]
fn test_wrong_authenticator_meta_rejected() {
    let mut public = public();
    public.authenticator_meta = 2;
    verify_assertion(public, private());
}

#[test(should_fail_with = "invalid AAT signature")]
fn test_tampered_aat_exp_rejected() {
    let mut private = private();
    private.aat_exp = AAT_EXP + 1;
    verify_assertion(public(), private);
}

#[test(should_fail_with = "TAKT is expired")]
fn test_expired_takt_rejected() {
    let mut public = public();
    public.now = TAKT_EXP;
    verify_assertion(public, private());
}

#[test(should_fail_with = "TAKT lifetime exceeds maximum")]
fn test_takt_lifetime_above_maximum_rejected() {
    let mut public = public();
    public.now = TAKT_EXP - MAX_TAKT_LIFETIME - 1;
    verify_assertion(public, private());
}

#[test(should_fail_with = "AAT is expired")]
fn test_expired_aat_rejected() {
    // At `exp` the token is already expired.
    let mut public = public();
    public.now = AAT_EXP;
    verify_assertion(public, private());
}

#[test(should_fail_with = "AAT lifetime exceeds maximum")]
fn test_aat_lifetime_above_maximum_rejected() {
    let mut public = public();
    public.now = AAT_EXP - MAX_AAT_LIFETIME - 1;
    verify_assertion(public, private());
}

#[test]
fn test_aat_max_lifetime_boundary_accepted() {
    let mut public = public();
    public.now = AAT_EXP - MAX_AAT_LIFETIME;
    verify_assertion(public, private());
}

#[test(should_fail_with = "sec_flags do not match the public security flags")]
fn test_wrong_platform_rejected() {
    let mut public = public();
    public.platform = 4;
    verify_assertion(public, private());
}

#[test(should_fail_with = "sec_flags do not match the public security flags")]
fn test_wrong_integrity_level_rejected() {
    let mut public = public();
    public.integrity_level = 3;
    verify_assertion(public, private());
}

#[test(should_fail_with = "sec_flags do not match the public security flags")]
fn test_wrong_key_protection_rejected() {
    let mut public = public();
    public.key_protection = 2;
    verify_assertion(public, private());
}

#[test(should_fail_with = "sec_flags do not match the public security flags")]
fn test_wide_sec_meta_rejected() {
    // `sec_meta` 0x13 must not alias `sec_meta` 3 with `key_protection` bit 0 set.
    let _ = super::assert_sec_flags(0x0013000007D60102, 2, 1, 0, 0x13);
}

#[test(should_fail_with = "sec_flags do not match the public security flags")]
fn test_wrong_sec_meta_rejected() {
    let mut public = public();
    public.sec_meta = 1;
    verify_assertion(public, private());
}

#[test]
fn test_build_version_at_minimum_accepted() {
    let mut public = public();
    public.min_build_version = 2006;
    verify_assertion(public, private());
}

#[test(should_fail_with = "build_version below minimum")]
fn test_build_version_below_minimum_rejected() {
    let mut public = public();
    public.min_build_version = 2007;
    verify_assertion(public, private());
}

#[test]
fn test_full_width_key_protection_accepted() {
    let _ = super::assert_sec_flags(0x0FF3000007D60102, 2, 1, 0xff, 3);
}

#[test(should_fail_with = "sec_flags bits 60 and above are reserved and must be 0")]
fn test_reserved_sec_flags_bits_rejected() {
    // Exercised directly: a signed TAKT with reserved bits would need the trust anchor's key.
    let _ = super::assert_sec_flags(0x1033000007D60102, 2, 1, 3, 3);
}

#[test(should_fail_with = "exp must take a 4-byte CBOR uint")]
fn test_short_exp_rejected() {
    let _ = super::exp_bytes(0xffff);
}

#[test(should_fail)]
fn test_exp_above_32_bits_rejected() {
    let _ = super::exp_bytes(0x100000000);
}

#[test(should_fail)]
fn test_now_above_32_bits_rejected() {
    super::now_below_2_32(0x100000000);
}
