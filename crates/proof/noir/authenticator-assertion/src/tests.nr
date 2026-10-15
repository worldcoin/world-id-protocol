use super::{
    AuthenticatorAssertionPrivateInputs, AuthenticatorAssertionPublicInputs, MAX_AAT_LIFETIME,
    MAX_TAKT_LIFETIME, verify_assertion,
};
use bigcurve::curves::secp256r1::Secp256r1_Fr;
use bignum::BigNum;

// WIP-201 Appendix A1; shared with `crates/primitives/src/authenticator_assertion/tests.rs`.
global TRUST_ANCHOR_KEY_X: [u8; 32] = [
    0x1e, 0x18, 0x53, 0x2f, 0xd4, 0x75, 0x4c, 0x02, 0xf3, 0x04, 0x1d, 0x9c, 0x75, 0xce, 0xb3, 0x3b,
    0x83, 0xff, 0xd8, 0x1a, 0xc7, 0xce, 0x4f, 0xe8, 0x82, 0xcc, 0xb1, 0xc9, 0x8b, 0xc5, 0x89, 0x6e,
];
global TRUST_ANCHOR_KEY_Y: [u8; 32] = [
    0xa4, 0x6c, 0x31, 0x1c, 0x4e, 0x2f, 0xf4, 0x0d, 0xd9, 0x6a, 0x36, 0x53, 0xe6, 0xe4, 0x54, 0x45,
    0xd3, 0x2d, 0xfe, 0x48, 0x6e, 0xce, 0xd7, 0x5c, 0x7a, 0x90, 0xc6, 0xa1, 0x88, 0x81, 0xc0, 0xa3,
];
global ASSERTION_KEY_X: [u8; 32] = [
    0x71, 0x35, 0xfa, 0x4f, 0xd9, 0x3a, 0x09, 0xdc, 0xe9, 0x8b, 0xbf, 0x68, 0x1b, 0x4b, 0xfc, 0xf5,
    0x0e, 0x7c, 0x0d, 0x63, 0x54, 0xe6, 0x2a, 0xfb, 0x0b, 0xff, 0x2a, 0x34, 0x29, 0x61, 0x78, 0x65,
];
global ASSERTION_KEY_Y: [u8; 32] = [
    0xed, 0x4c, 0x1f, 0x02, 0xdd, 0xb9, 0x02, 0x3e, 0xe5, 0x6a, 0x55, 0x7e, 0x51, 0x5d, 0x6a, 0x9d,
    0xc6, 0x6c, 0x11, 0xf2, 0x20, 0x96, 0x0d, 0xe5, 0x94, 0x33, 0x4d, 0xf5, 0x88, 0x77, 0x67, 0x24,
];
global TAKT_SIGNATURE: [u8; 64] = [
    0xd6, 0xe8, 0x30, 0x37, 0x73, 0xae, 0xb9, 0xc7, 0xb0, 0x4e, 0x60, 0x2e, 0x7a, 0x3e, 0xc8, 0x22,
    0xfc, 0x34, 0xf7, 0x26, 0x09, 0xee, 0xd0, 0x18, 0x14, 0xcd, 0x7c, 0x34, 0x87, 0x7a, 0x66, 0x49,
    0x73, 0x51, 0x9a, 0xa5, 0xe9, 0x52, 0xb7, 0x4b, 0x72, 0xfd, 0x05, 0x91, 0x85, 0x87, 0xb5, 0x2d,
    0x61, 0xbd, 0xff, 0xd2, 0xd8, 0x72, 0x87, 0x05, 0xd7, 0x8f, 0x41, 0xac, 0x06, 0xb4, 0x2b, 0xd7,
];
global AAT_SIGNATURE: [u8; 64] = [
    0x48, 0x0f, 0xd8, 0x1e, 0xe9, 0x50, 0xf3, 0xdf, 0x61, 0x3d, 0x1e, 0x4f, 0x33, 0x3a, 0x44, 0x1a,
    0xe4, 0xf7, 0xdb, 0x08, 0x0e, 0xfe, 0xd6, 0x20, 0xe7, 0x71, 0x99, 0xcd, 0x37, 0xe4, 0x4d, 0x15,
    0x1f, 0x48, 0x97, 0xdf, 0xaf, 0xb0, 0xed, 0x67, 0xb5, 0x9a, 0xfa, 0x6b, 0x00, 0xa5, 0x5b, 0x43,
    0xb2, 0x5f, 0xe8, 0xf7, 0xd5, 0x8e, 0xcd, 0x18, 0x3c, 0x8b, 0xb0, 0xce, 0x83, 0x8b, 0x55, 0xa8,
];
global KID: [u8; 32] = [
    0xfd, 0x65, 0xf0, 0x50, 0xc9, 0xc3, 0xb5, 0x33, 0x37, 0xcf, 0x17, 0xee, 0xe5, 0x89, 0xeb, 0x11,
    0xa8, 0x1a, 0x91, 0xc5, 0x5a, 0xc1, 0x0a, 0xa4, 0x83, 0x61, 0xc0, 0x50, 0x8d, 0x95, 0x9e, 0x4d,
];
global NOW: Field = 1783446000;
global TAKT_EXP: Field = 1783532400;
global AAT_EXP: Field = 1783446925;
global CDH: Field = 0x06559c686e02e6fdd317c3faf3d3a871f1660465552dc3c15e36290a44346150;

fn public() -> AuthenticatorAssertionPublicInputs {
    AuthenticatorAssertionPublicInputs {
        trust_anchor_key_x: TRUST_ANCHOR_KEY_X,
        trust_anchor_key_y: TRUST_ANCHOR_KEY_Y,
        now: NOW,
        aud: 1928118,
        nonce: 42,
        platform: 2,
        sec_level: 1,
        sec_meta: 3,
        user_presence: 2,
        min_build_version: 2006,
    }
}

fn private() -> AuthenticatorAssertionPrivateInputs {
    AuthenticatorAssertionPrivateInputs {
        takt_exp: TAKT_EXP,
        assertion_key_x: ASSERTION_KEY_X,
        assertion_key_y: ASSERTION_KEY_Y,
        // platform 2 | sec_level 1 << 8 | build_version 2006 << 16 | sec_meta 3 << 48
        sec_flags: 0x0003000007D60102,
        takt_signature: TAKT_SIGNATURE,
        aat_exp: AAT_EXP,
        aat_signature: AAT_SIGNATURE,
        cdh: CDH,
    }
}

#[test]
fn test_kid_matches_spec_vector() {
    let kid = sha256::digest(super::cose_key(TRUST_ANCHOR_KEY_X, TRUST_ANCHOR_KEY_Y));
    assert_eq(kid, KID);
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

#[test(should_fail_with = "user_presence values 5 and above are reserved")]
fn test_reserved_user_presence_rejected() {
    let mut public = public();
    public.user_presence = 5;
    verify_assertion(public, private());
}

#[test(should_fail_with = "invalid TAKT signature")]
fn test_wrong_trust_anchor_key_rejected() {
    // The assertion key is a valid P-256 key that did not sign the TAKT.
    let mut public = public();
    public.trust_anchor_key_x = ASSERTION_KEY_X;
    public.trust_anchor_key_y = ASSERTION_KEY_Y;
    verify_assertion(public, private());
}

#[test(should_fail_with = "invalid TAKT signature")]
fn test_unattested_assertion_key_rejected() {
    // The TAKT signs the `assertion_key`, so swapping it breaks the TAKT signature.
    let mut private = private();
    private.assertion_key_x = TRUST_ANCHOR_KEY_X;
    private.assertion_key_y = TRUST_ANCHOR_KEY_Y;
    verify_assertion(public(), private);
}

#[test(should_fail_with = "invalid TAKT signature")]
fn test_tampered_sec_flags_rejected() {
    let mut private = private();
    private.sec_flags = 0x0003000007D70102;
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
fn test_wrong_user_presence_rejected() {
    let mut public = public();
    public.user_presence = 0;
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
fn test_wrong_sec_level_rejected() {
    let mut public = public();
    public.sec_level = 3;
    verify_assertion(public, private());
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

#[test(should_fail_with = "sec_flags bits 51 and above are reserved and must be 0")]
fn test_reserved_sec_flags_bits_rejected() {
    // Exercised directly: a signed TAKT with reserved bits would need the trust anchor's key.
    let _ = super::assert_sec_flags(0x000B000007D60102, 2, 1, 3);
}

#[test(should_fail_with = "exp must take a 4-byte CBOR uint")]
fn test_short_exp_rejected() {
    let _ = super::exp_bytes(0xffff);
}

#[test(should_fail)]
fn test_now_above_32_bits_rejected() {
    super::now_below_2_32(0x100000000);
}
