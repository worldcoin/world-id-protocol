// Known-answer vectors of WIP-201 Appendix A1. The signature is the Verifier's over the AAT vector.
use super::{digest, FlamingoTokenClaims, FlamingoTokenPublic, verify};
use world_id_components::types::{PublicKey, Signature};

global VERIFIER_KEY: PublicKey = PublicKey {
    x: 4417214393686375319944320810341694814369485096296978272105534111779387689568,
    y: 8192095922678382794800511095399932292627837066826129560890929861066610234610,
};
global SIG_WITH_AAT: Signature = Signature {
    s: 1969218470857421179612216617885300341933585808705462210241951989030402260427,
    r: [
        10898103243790445823020157806913554943821302574928683895392306544241075006101,
        14128763278302702215475356469690679032385742977262314480676182646441392930522,
    ],
};

fn public() -> FlamingoTokenPublic {
    FlamingoTokenPublic {
        verifier_key: VERIFIER_KEY,
        now: 1783446000,
        aud: 1928118,
        nonce: 42,
        has_aat: 1,
        trust_anchor_key_hash: 0x14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8,
        platform: 2,
        integrity_level: 1,
        key_protection: 3,
        sec_meta: 3,
        authenticator_meta: 1,
        min_build_version: 0,
        engine_config_hash: 0x2f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d,
    }
}

fn public_without_aat() -> FlamingoTokenPublic {
    let mut p = public();
    p.has_aat = 0;
    p.trust_anchor_key_hash = 0;
    p.platform = 0;
    p.integrity_level = 0;
    p.key_protection = 0;
    p.sec_meta = 0;
    p.authenticator_meta = 0;
    p
}

fn claims() -> FlamingoTokenClaims {
    FlamingoTokenClaims {
        compared_entry_hashes: [
            0x21e9fe96ff18807a727830c56281c96af824005400bcb8ef0f463b34cb20c415,
            0x010cff8544f0007179c076ddb49de551bd5743797bfe05cb3b26f55c696f507b,
            0x2abb4a81875eb0e308f0fbfb8c0a0f57e77243e095b145ae7973e0b2771e044d,
            0,
        ],
        compare_sources: 256,
        billing_nullifier: 0,
    }
}

#[test]
fn test_digests_match_the_wip_201_vectors() {
    assert_eq(
        digest(public(), claims()),
        0x2492a71b9b13030ae5b45d035616da00bcc4f48e070079a1fcdf55deec1b299b,
    );
    assert_eq(
        digest(public_without_aat(), claims()),
        0x045442bd20ef9bbcf96e1d5534508467891d17532204659aa56e80c8a5ff0b06,
    );
    let mut billed = claims();
    billed.billing_nullifier = 7;
    assert_eq(
        digest(public(), billed),
        0x22807948f9c3e75fe556f7a2ad5eb14952d810a4eef82e56975f5cd2decad0d6,
    );
}

#[test]
fn test_verifies_the_vector_token() {
    assert_eq(
        verify(public(), claims(), SIG_WITH_AAT),
        0x2492a71b9b13030ae5b45d035616da00bcc4f48e070079a1fcdf55deec1b299b,
    );
}

#[test(should_fail_with = "invalid flamingo token signature")]
fn test_rejects_another_billing_nullifier() {
    let mut c = claims();
    c.billing_nullifier = 1;
    let _ = verify(public(), c, SIG_WITH_AAT);
}

#[test(should_fail_with = "invalid flamingo token signature")]
fn test_rejects_another_compare_sources() {
    let mut c = claims();
    c.compare_sources = 1;
    let _ = verify(public(), c, SIG_WITH_AAT);
}

#[test(should_fail_with = "invalid flamingo token signature")]
fn test_rejects_another_min_build_version() {
    let mut p = public();
    p.min_build_version = 1;
    let _ = verify(p, claims(), SIG_WITH_AAT);
}

#[test(should_fail_with = "AAT values must be zero without an AAT")]
fn test_rejects_aat_values_without_an_aat() {
    let mut p = public_without_aat();
    p.min_build_version = 1;
    let _ = verify(p, claims(), SIG_WITH_AAT);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_rejects_a_wide_authenticator_meta() {
    let mut p = public();
    p.authenticator_meta = 4;
    let _ = verify(p, claims(), SIG_WITH_AAT);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_rejects_a_key_protection_beyond_8_bits() {
    let mut p = public();
    p.key_protection = 0x103;
    let _ = verify(p, claims(), SIG_WITH_AAT);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_rejects_a_wide_sec_meta() {
    let mut p = public();
    p.sec_meta = 16;
    let _ = verify(p, claims(), SIG_WITH_AAT);
}

// SECTION: widths are checked here, so a caller's truncating cast cannot bypass them.

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_rejects_a_now_beyond_32_bits() {
    let mut p = public();
    p.now += 0x100000000;
    let _ = verify(p, claims(), SIG_WITH_AAT);
}

#[test(should_fail_with = "has_aat must be 0 or 1")]
fn test_rejects_a_non_boolean_has_aat() {
    let mut p = public();
    p.has_aat = 2;
    let _ = verify(p, claims(), SIG_WITH_AAT);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_rejects_a_platform_beyond_8_bits() {
    let mut p = public();
    p.platform = 0x102;
    let _ = verify(p, claims(), SIG_WITH_AAT);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_rejects_a_compare_sources_beyond_32_bits() {
    let mut c = claims();
    c.compare_sources += 0x100000000;
    let _ = verify(public(), c, SIG_WITH_AAT);
}
