// Known-answer vectors of WIP-201 Appendix A1. The signature is the Verifier's over the AAT vector.
use super::{digest, FlamingoTokenClaims, FlamingoTokenPublic, verify};
use world_id_components::types::{PublicKey, Signature};

global VERIFIER_KEY: PublicKey = PublicKey {
    x: 4417214393686375319944320810341694814369485096296978272105534111779387689568,
    y: 8192095922678382794800511095399932292627837066826129560890929861066610234610,
};
global SIG_WITH_AAT: Signature = Signature {
    s: 85143753451258670685773953983050244260973240479185012721111924728710374067,
    r: [
        17877026434229155501335672876063010881746851858765314564265636504040982607477,
        19650826414168530413253526482971547572157267537446832165701684202088017113169,
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
        sec_level: 1,
        sec_meta: 3,
        authenticator_meta: 10,
        min_build_version: 0,
        engine_config_hash: 0x2f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d,
        compare_kinds: 131585,
    }
}

fn public_without_aat() -> FlamingoTokenPublic {
    let mut p = public();
    p.has_aat = 0;
    p.trust_anchor_key_hash = 0;
    p.platform = 0;
    p.sec_level = 0;
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
        0x1f5ebd25ce05ff6ce9c876abfcb3af9e9b4b5a405f2c91e742f14479f13d2022,
    );
    assert_eq(
        digest(public_without_aat(), claims()),
        0x18d540ab21adabe66c73f57ff0c8a5ffb8962a4293354edb1f0ee69cda7f6f23,
    );
    let mut billed = claims();
    billed.billing_nullifier = 7;
    assert_eq(
        digest(public(), billed),
        0x1353bd7a341e5e7e615696b015b398eb88589c3ede756c85c73e0263acf9e7e0,
    );
}

#[test]
fn test_verifies_the_vector_token() {
    assert_eq(
        verify(public(), claims(), SIG_WITH_AAT),
        0x1f5ebd25ce05ff6ce9c876abfcb3af9e9b4b5a405f2c91e742f14479f13d2022,
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
fn test_rejects_another_compare_kinds() {
    let mut p = public();
    p.compare_kinds = 513;
    let _ = verify(p, claims(), SIG_WITH_AAT);
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

#[test(should_fail_with = "user_presence values 5 to 7 are reserved")]
fn test_rejects_a_reserved_user_presence() {
    let mut p = public();
    p.authenticator_meta = 13;
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

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_rejects_a_compare_kinds_beyond_32_bits() {
    let mut p = public();
    p.compare_kinds += 0x100000000;
    let _ = verify(p, claims(), SIG_WITH_AAT);
}
