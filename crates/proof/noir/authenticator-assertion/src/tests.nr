use super::{
    AuthenticatorAssertionPrivateInputs, AuthenticatorAssertionPublicInputs, MAX_AAT_LIFETIME,
    request_commitment, SecFlags, verify_aat,
};
use poseidon2::bn254::permutation;

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
global MIN_BUILD_VERSION: Field = 2006;
global BLIND: Field = 7;
global EXPECTED_REQ: Field = 0x17785a9691e9ee99df657ce545bfe748eab27cf21f118361d87cf64ff024495d;
global EXPECTED_MESSAGE: Field = 0x28f0b633f40ea69da7c2399aa958f48f4a4c582889eb563d8efd37e330c70332;

fn public() -> AuthenticatorAssertionPublicInputs {
    AuthenticatorAssertionPublicInputs {
        trust_anchor_key: TRUST_ANCHOR_KEY,
        now: NOW,
        aud: AUD,
        nonce: NONCE,
        min_build_version: MIN_BUILD_VERSION,
    }
}

fn private() -> AuthenticatorAssertionPrivateInputs {
    AuthenticatorAssertionPrivateInputs {
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
    let req = request_commitment(AUD, NONCE, CDH, BLIND);
    assert_eq(req, EXPECTED_REQ);
    let aat = private();
    assert_eq(permutation::t4([super::DS_AAT, aat.exp, req, aat.sec_flags])[1], EXPECTED_MESSAGE);
}

#[test]
fn test_valid_token() {
    let flags: SecFlags = verify_aat(public(), private());
    assert_eq(flags.platform, 2);
    assert_eq(flags.sec_level, 1);
    assert_eq(flags.sec_meta, 3);
    assert_eq(flags.user_presence, 2);
}

#[test]
fn test_max_lifetime_boundary_accepted() {
    let mut public = public();
    public.now = EXP - MAX_AAT_LIFETIME;
    let _ = verify_aat(public, private());
}

#[test(should_fail_with = "token lifetime exceeds maximum")]
fn test_lifetime_above_maximum_rejected() {
    let mut public = public();
    public.now = EXP - MAX_AAT_LIFETIME - 1;
    let _ = verify_aat(public, private());
}

#[test(should_fail_with = "token is expired")]
fn test_expired_token_rejected() {
    // At `exp` the token is already expired.
    let mut public = public();
    public.now = EXP;
    let _ = verify_aat(public, private());
}

#[test(should_fail_with = "invalid signature")]
fn test_tampered_sec_flags_rejected() {
    let mut private = private();
    private.sec_flags = 0x0013000007D60104;
    let _ = verify_aat(public(), private);
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_aud_rejected() {
    let mut public = public();
    public.aud = AUD + 1;
    let _ = verify_aat(public, private());
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_nonce_rejected() {
    let mut public = public();
    public.nonce = NONCE + 1;
    let _ = verify_aat(public, private());
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_cdh_rejected() {
    let mut private = private();
    private.cdh = 1;
    let _ = verify_aat(public(), private);
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_blind_rejected() {
    let mut private = private();
    private.blind = BLIND + 1;
    let _ = verify_aat(public(), private);
}

#[test(should_fail_with = "invalid signature")]
fn test_wrong_trust_anchor_key_rejected() {
    // The BabyJubJub subgroup generator: a valid key that did not sign the token, so the
    // failure comes from the signature check rather than the key validation.
    let mut public = public();
    public.trust_anchor_key = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203,
    ];
    let _ = verify_aat(public, private());
}

#[test]
fn test_build_version_at_minimum_accepted() {
    let mut public = public();
    public.min_build_version = 2006;
    let _ = verify_aat(public, private());
}

#[test(should_fail_with = "build_version below minimum")]
fn test_build_version_below_minimum_rejected() {
    let mut public = public();
    public.min_build_version = 2007;
    let _ = verify_aat(public, private());
}

#[test(should_fail)]
fn test_non_canonical_sig_s_rejected() {
    // `s + r` satisfies the verification equation but is not a reduced scalar.
    let mut private = private();
    private.sig_s = private.sig_s
        + 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    let _ = verify_aat(public(), private);
}

#[test(should_fail_with = "nonce must not be 0")]
fn test_zero_nonce_rejected() {
    let mut public = public();
    public.nonce = 0;
    let _ = verify_aat(public, private());
}

#[test(should_fail_with = "sec_flags bits 54 and above are reserved and must be 0")]
fn test_reserved_sec_flags_bits_rejected() {
    // Exercised directly: a signed token with reserved bits would need the provider's key.
    let _ = super::unpack_sec_flags(0x0053000007D60102);
}

#[test(should_fail_with = "user_presence values 5 to 7 are reserved")]
fn test_reserved_user_presence_rejected() {
    let _ = super::unpack_sec_flags(0x002B000007D60102);
}

#[test]
fn test_user_presence_unpacks_from_bits_51_to_53() {
    let (flags, build_version) = super::unpack_sec_flags(0x0023000007D60102);
    assert_eq(flags.sec_meta, 3);
    assert_eq(flags.user_presence, 4);
    assert_eq(build_version, 2006);
}

#[test(should_fail)]
fn test_sec_flags_above_56_bits_rejected() {
    let _ = super::unpack_sec_flags(0x100000000000000);
}

#[test(should_fail)]
fn test_now_above_32_bits_rejected() {
    super::assert_fresh(EXP, 0x100000000);
}
