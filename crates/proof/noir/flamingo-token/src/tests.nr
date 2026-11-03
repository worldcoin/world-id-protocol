// Known-answer vectors of WIP-201 Appendix A1. The signature is the Verifier's over the AAT vector.
use super::{digest, FlamingoTokenClaims, FlamingoTokenPublic, verify};
use world_id_components::types::{PublicKey, Signature};

global VERIFIER_KEY: PublicKey = PublicKey {
    x: 4417214393686375319944320810341694814369485096296978272105534111779387689568,
    y: 8192095922678382794800511095399932292627837066826129560890929861066610234610,
};
global SIG_WITH_AAT: Signature = Signature {
    s: 1974479143804279392582966793003637700370117014073707568489823009312216105805,
    r: [
        16613254563570858836313967071310512340260378742803372667136760646645052547804,
        15617754246088094067902926374354607839798802083713556585896183891600075703392,
    ],
};

fn public() -> FlamingoTokenPublic {
    FlamingoTokenPublic {
        verifier_key: VERIFIER_KEY,
        now: 1783446000,
        aud: 1928118,
        nonce: 42,
        has_aat: true,
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
    p.has_aat = false;
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
        0x24a02c43c27878dc6623224138ec390efe9044be4271c8a2f82bb5a78910bc4f,
    );
    assert_eq(
        digest(public_without_aat(), claims()),
        0x045442bd20ef9bbcf96e1d5534508467891d17532204659aa56e80c8a5ff0b06,
    );
    let mut billed = claims();
    billed.billing_nullifier = 7;
    assert_eq(
        digest(public(), billed),
        0x247f7f653466f20e24fbac90c9c36055c7036d2c8d26c100907164723c7bb118,
    );
}

#[test]
fn test_verifies_the_vector_token() {
    assert_eq(
        verify(public(), claims(), SIG_WITH_AAT),
        0x24a02c43c27878dc6623224138ec390efe9044be4271c8a2f82bb5a78910bc4f,
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

#[test(should_fail_with = "user_presence values 5 to 7 are reserved")]
fn test_rejects_a_reserved_user_presence() {
    let mut p = public();
    p.authenticator_meta = 13;
    let _ = verify(p, claims(), SIG_WITH_AAT);
}

#[test(should_fail_with = "sec_meta exceeds 4 bits")]
fn test_rejects_a_wide_sec_meta() {
    let mut p = public();
    p.sec_meta = 16;
    let _ = verify(p, claims(), SIG_WITH_AAT);
}
