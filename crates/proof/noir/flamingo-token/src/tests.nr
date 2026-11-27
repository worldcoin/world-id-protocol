// Known-answer vectors of WIP-201 Appendix A1. The signature is the Verifier's over the AAT vector.
use super::{digest, FlamingoTokenClaims, FlamingoTokenPublic, verify};
use world_id_components::types::{PublicKey, Signature};

global VERIFIER_KEY: PublicKey = PublicKey {
    x: 4417214393686375319944320810341694814369485096296978272105534111779387689568,
    y: 8192095922678382794800511095399932292627837066826129560890929861066610234610,
};
global SIG_WITH_AAT: Signature = Signature {
    s: 2031309174716827707623010221389519885313978162025361233377794419472221062122,
    r: [
        20912884977208786685384409272660943129890804061870675888546036845202683370996,
        3648206410505437953514755587274540817326819979994828116042746664770909037337,
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
        entry_hashes: [
            0x24fd129204ff263484224657d234fd2eb3438b02900efdc8d1afb07a81064b03,
            0x010cff8544f0007179c076ddb49de551bd5743797bfe05cb3b26f55c696f507b,
            0,
            0,
        ],
        // `pipeline_type` of `EXAMPLE<2>(reference#,live#,evidence*)`.
        pipeline_type: 0x1ed281544d1f50f69387ef3f3d6d24f0001f0a42f8740b5f5e86a70e4b2198a8,
        strictness: 2,
        billing_nullifier: 0,
    }
}

#[test]
fn test_digests_match_the_wip_201_vectors() {
    assert_eq(
        digest(public(), claims()),
        0x020fdf466e0a1e0f0fde36ce03a9459bbcbc4355a2c8e479d2a06ddd584621df,
    );
    assert_eq(
        digest(public_without_aat(), claims()),
        0x1e8e707bff80c78a20f7c176a7eb9dd846d8988db3a8028bf5411bdb028644df,
    );
    let mut billed = claims();
    billed.billing_nullifier = 7;
    assert_eq(
        digest(public(), billed),
        0x298c48deeedeac4f445952140118e2859c549f94faadb4d42569d2e29ad003e4,
    );
}

#[test]
fn test_verifies_the_vector_token() {
    assert_eq(
        verify(public(), claims(), SIG_WITH_AAT),
        0x020fdf466e0a1e0f0fde36ce03a9459bbcbc4355a2c8e479d2a06ddd584621df,
    );
}

#[test(should_fail_with = "invalid flamingo token signature")]
fn test_rejects_another_billing_nullifier() {
    let mut c = claims();
    c.billing_nullifier = 1;
    let _ = verify(public(), c, SIG_WITH_AAT);
}

#[test(should_fail_with = "invalid flamingo token signature")]
fn test_rejects_another_pipeline_type() {
    let mut c = claims();
    c.pipeline_type = 1;
    let _ = verify(public(), c, SIG_WITH_AAT);
}

#[test(should_fail_with = "invalid flamingo token signature")]
fn test_rejects_another_strictness() {
    let mut c = claims();
    c.strictness = 1;
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
fn test_rejects_a_strictness_beyond_8_bits() {
    let mut c = claims();
    c.strictness += 0x100;
    let _ = verify(public(), c, SIG_WITH_AAT);
}
