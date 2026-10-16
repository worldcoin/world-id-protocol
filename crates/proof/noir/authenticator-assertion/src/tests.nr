use super::{
    AuthenticatorAssertionPrivateInputs, AuthenticatorAssertionPublicInputs, MAX_AAT_LIFETIME,
    request_commitment, verify_aat,
};
use poseidon2::bn254::permutation;

// Known-answer fixture shared with `crates/primitives/src/authenticator_assertion/tests.rs`.
global AUTHENTICATOR_PROVIDER_KEY: [Field; 2] = [
    19037598474602150174935475944965340829216795940473064039209388058233204431288,
    3549932221586364715003722955756497910920276078443163728621283280434115857197,
];
global EXP: Field = 1783446925;
global NOW: Field = 1783446000;
global AUD: Field = 1928118;
global NONCE: Field = 42;
global CDH: Field = 0;
global MIN_BUILD_VERSION: u32 = 2006;
global BLIND: Field = 7;
global EXPECTED_AAT_COMMITMENT: Field =
    0x17785a9691e9ee99df657ce545bfe748eab27cf21f118361d87cf64ff024495d;
global EXPECTED_MESSAGE: Field = 0x28f0b633f40ea69da7c2399aa958f48f4a4c582889eb563d8efd37e330c70332;
global EXPECTED_KEY_HASH: Field =
    0x14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8;
// The BabyJubJub subgroup generator: a valid key that did not sign the fixture token.
global OTHER_KEY: [Field; 2] = [
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203,
];

fn public() -> AuthenticatorAssertionPublicInputs {
    AuthenticatorAssertionPublicInputs {
        authenticator_provider_key_hash: EXPECTED_KEY_HASH,
        now: NOW,
        aud: AUD,
        nonce: NONCE,
        platform: 2,
        sec_level: 1,
        sec_meta: 3,
        user_presence: 2,
        min_build_version: MIN_BUILD_VERSION,
    }
}

fn private() -> AuthenticatorAssertionPrivateInputs {
    AuthenticatorAssertionPrivateInputs {
        authenticator_provider_key: AUTHENTICATOR_PROVIDER_KEY,
        exp: EXP,
        // platform 2 | sec_level 1 << 8 | build_version 2006 << 16 | sec_meta 3 << 48
        // | user_presence 2 << 51
        sec_flags: 0x0013000007D60102,
        sig_s: 700590321940410723084584768113203723815849273971186961535723633376375605110,
        sig_r: [
            9464927411176877143242073132305067532985742345968954357966273354098472816787,
            18207207085206278655459517276373479902429501683178223921050583289961974448215,
        ],
        cdh: CDH,
        blind: BLIND,
    }
}

#[test]
fn test_known_answer_digests() {
    let aat_commitment = request_commitment(AUD, NONCE, CDH, BLIND);
    assert_eq(aat_commitment, EXPECTED_AAT_COMMITMENT);
    let aat = private();
    assert_eq(
        permutation::t4([super::DS_AAT, aat.exp, aat_commitment, aat.sec_flags])[1],
        EXPECTED_MESSAGE,
    );
    let key = AUTHENTICATOR_PROVIDER_KEY;
    assert_eq(permutation::t3([super::DS_KEY, key[0], key[1]])[1], EXPECTED_KEY_HASH);
}

#[test]
fn test_valid_token() {
    verify_aat(public(), private());
}

#[test]
fn test_max_lifetime_boundary_accepted() {
    let mut public = public();
    public.now = EXP - MAX_AAT_LIFETIME;
    verify_aat(public, private());
}

#[test(should_fail_with = "token lifetime exceeds maximum")]
fn test_lifetime_above_maximum_rejected() {
    let mut public = public();
    public.now = EXP - MAX_AAT_LIFETIME - 1;
    verify_aat(public, private());
}

#[test(should_fail_with = "token is expired")]
fn test_expired_token_rejected() {
    // At `exp` the token is already expired.
    let mut public = public();
    public.now = EXP;
    verify_aat(public, private());
}

#[test(should_fail_with = "invalid signature")]
fn test_tampered_sec_flags_rejected() {
    let mut private = private();
    private.sec_flags = 0x0013000007D60104;
    verify_aat(public(), private);
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_aud_rejected() {
    let mut public = public();
    public.aud = AUD + 1;
    verify_aat(public, private());
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_nonce_rejected() {
    let mut public = public();
    public.nonce = NONCE + 1;
    verify_aat(public, private());
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_cdh_rejected() {
    let mut private = private();
    private.cdh = 1;
    verify_aat(public(), private);
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_blind_rejected() {
    let mut private = private();
    private.blind = BLIND + 1;
    verify_aat(public(), private);
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_authenticator_provider_key_rejected() {
    // The key matches the public hash, so the failure comes from the signature check.
    let mut public = public();
    public.authenticator_provider_key_hash =
        permutation::t3([super::DS_KEY, OTHER_KEY[0], OTHER_KEY[1]])[1];
    let mut private = private();
    private.authenticator_provider_key = OTHER_KEY;
    verify_aat(public, private);
}

#[test(should_fail_with = "authenticator_provider_key does not match its hash")]
fn test_key_hash_mismatch_rejected() {
    let mut private = private();
    private.authenticator_provider_key = OTHER_KEY;
    verify_aat(public(), private);
}

#[test(should_fail_with = "sec_flags do not match the public security flags")]
fn test_wrong_platform_rejected() {
    let mut public = public();
    public.platform = 4;
    verify_aat(public, private());
}

#[test(should_fail_with = "sec_flags do not match the public security flags")]
fn test_wrong_sec_level_rejected() {
    let mut public = public();
    public.sec_level = 3;
    verify_aat(public, private());
}

#[test(should_fail_with = "sec_flags do not match the public security flags")]
fn test_wrong_sec_meta_rejected() {
    let mut public = public();
    public.sec_meta = 1;
    verify_aat(public, private());
}

#[test(should_fail_with = "sec_flags do not match the public security flags")]
fn test_wrong_user_presence_rejected() {
    let mut public = public();
    public.user_presence = 0;
    verify_aat(public, private());
}

#[test]
fn test_build_version_at_minimum_accepted() {
    let mut public = public();
    public.min_build_version = 2006;
    verify_aat(public, private());
}

#[test(should_fail_with = "build_version below minimum")]
fn test_build_version_below_minimum_rejected() {
    let mut public = public();
    public.min_build_version = 2007;
    verify_aat(public, private());
}

#[test(should_fail)]
fn test_non_canonical_sig_s_rejected() {
    // `s + r` satisfies the verification equation but is not a reduced scalar.
    let mut private = private();
    private.sig_s = private.sig_s
        + 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    verify_aat(public(), private);
}

#[test(should_fail_with = "nonce must not be 0")]
fn test_zero_nonce_rejected() {
    let mut public = public();
    public.nonce = 0;
    verify_aat(public, private());
}

#[test(should_fail_with = "sec_flags bits 54 and above are reserved and must be 0")]
fn test_reserved_sec_flags_bits_rejected() {
    // Exercised directly: a signed token with reserved bits would need the provider's key.
    let _ = super::assert_sec_flags(0x0053000007D60102, 2, 1, 3, 2);
}

#[test(should_fail_with = "user_presence values 5 to 7 are reserved")]
fn test_reserved_user_presence_rejected() {
    let _ = super::assert_sec_flags(0x002B000007D60102, 2, 1, 3, 5);
}

#[test]
fn test_user_presence_unpacks_from_bits_51_to_53() {
    let build_version = super::assert_sec_flags(0x0023000007D60102, 2, 1, 3, 4);
    assert_eq(build_version, 2006);
}

#[test(should_fail)]
fn test_sec_flags_above_56_bits_rejected() {
    let _ = super::assert_sec_flags(0x100000000000000, 0, 0, 0, 0);
}

#[test(should_fail)]
fn test_now_above_32_bits_rejected() {
    super::assert_fresh(EXP, 0x100000000);
}
