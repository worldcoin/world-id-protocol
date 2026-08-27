// Verification of an Authenticator Assertion Token (AAT): a token
// representing integrity of a specific environment through an environment-bound
// key which is attested by a Trust Anchor Key Token (TAKT).
use super::utils::{assert_cbor_uint32, assert_max_lifetime, assert_not_expired};
use bigcurve::curves::secp256r1::{Secp256r1_Fq, Secp256r1_Fr};
use bignum::BigNum;
use noir_ecdsa::ecdsa::verify_secp256r1_ecdsa;

/// Total length of the COSE `Sig_structure` signed by the assertion key: the
/// `Signature1` framing, protected header, `external_aad`, and the six-entry
/// CWT claims map.
///
/// 19-byte prefix + 163-byte payload. Both the payload length (`0x58 0xa3`) and
/// every claim length take the minimal CBOR form, as deterministic encoding
/// requires (RFC 8949 section 4.2.1).
pub global AAT_SIG_STRUCTURE_LEN: u32 = 182;

/// Maximum remaining validity of an AAT, in seconds (12h), mandated by WIP-106
/// and enforced in [`verify_aat`].
///
/// AATs have no revocation mechanism, so this bound is the whole of what keeps a
/// stolen or misused token short-lived.
pub global MAX_AAT_LIFETIME_SECS: Field = 43200;

/// The claims and signature of an Authenticator Assertion Token, as parsed from
/// its `COSE_Sign1` encoding.
pub struct AuthenticatorAssertionToken {
    /// The `rpId` of the requesting RP (CWT `aud`), encoded as a fixed 8-byte
    /// big-endian byte string. MUST be below `2^64`; the whole `u64` range is
    /// allowed because a byte string's width is fixed by the encoder rather
    /// than by the value's magnitude, unlike a CBOR uint, whose deterministic
    /// encoding is the shortest form that fits.
    pub aud: Field,
    /// Expiration as seconds since the Unix epoch (CWT `exp`). MUST require a
    /// 4-byte CBOR uint encoding (`2^16 <= exp < 2^32`), i.e. any instant from
    /// 1970-01-01T18:12:16Z up to 2106.
    pub exp: Field,
    /// The `ProofRequest` nonce binding the token to a specific request.
    pub nonce: Field,
    /// Client data hash (CWT `cdh`): an arbitrary commitment binding the token
    /// to its upstream use case. A nil value is 32 zero bytes.
    pub cdh: Field,
    /// Structured integrity metadata: user presence (bits 0-2) and
    /// provider-defined bits (3-4); all other bits are reserved (zero).
    pub authenticator_meta: Field,
    /// ES256 signature over the COSE `Sig_structure` (`r || s`, low-S).
    pub signature: [u8; 64],
}

/// Verifies that `assertion_key` signed this AAT (`ES256` over the COSE
/// `Sig_structure`) and that the token is unexpired.
///
/// Crate-private on purpose. This proves only that *some* key signed these
/// claims. The full verification requires a TAKT attesting that key, which is
/// why consumers must go through the crate-root `verify_attestation` instead.
///
/// `now` is the verifier-supplied Unix time (seconds) checked against CWT `exp`
/// (`now < exp`, and no more than [`MAX_AAT_LIFETIME_SECS`] before it), and MUST
/// be a public input of the outer circuit.
pub(crate) fn verify_aat(
    aat: AuthenticatorAssertionToken,
    assertion_key_x: [u8; 32],
    assertion_key_y: [u8; 32],
    now: Field,
) {
    // CBOR uint32 encoding of `exp` is checked later in `aat_sig_structure`.
    assert_not_expired(aat.exp, now);
    // Ordering matters: `assert_max_lifetime` relies on the `now < exp` above.
    assert_max_lifetime(aat.exp, now, MAX_AAT_LIFETIME_SECS);

    let message = aat_sig_structure(aat);
    let digest = sha256::digest(message);

    // Pure-Noir ECDSA (bignum/bigcurve). Deliberately NOT the stdlib
    // `ecdsa_secp256r1` black box: provekit does not implement it, so the
    // black box passes `nargo test` but cannot be proven. Only black boxes
    // from provekit's allowlist may be used here; see crates/proof/noir/README.md.
    let assertion_key_x_fq = Secp256r1_Fq::from_be_bytes(assertion_key_x);
    let assertion_key_y_fq = Secp256r1_Fq::from_be_bytes(assertion_key_y);
    let r = signature_scalar(aat.signature, 0);
    let s = signature_scalar(aat.signature, 32);

    // `noir_ecdsa` only rejects `r == 0` from v0.4.1 onwards, and we pin v0.2.9
    // (see crates/proof/noir/README.md), so the check lives here instead. With
    // `r = 0` the verification equation collapses to `R = u1*G`, dropping the
    // public key entirely: a single forgery would then verify under *every*
    // key. `s == 0` is already rejected by the `s * s^-1 == 1` constraint.
    assert(r != Secp256r1_Fr::zero(), "AAT signature r value is zero");

    let is_valid = verify_secp256r1_ecdsa(assertion_key_x_fq, assertion_key_y_fq, digest, (r, s));
    assert(is_valid, "invalid AAT signature");
}

/// Reads one 32-byte big-endian half of an `r || s` signature as a P-256 scalar.
fn signature_scalar(signature: [u8; 64], offset: u32) -> Secp256r1_Fr {
    let mut bytes = [0; 32];
    for i in 0..32 {
        bytes[i] = signature[offset + i];
    }
    Secp256r1_Fr::from_be_bytes(bytes)
}

/// Rebuilds the COSE `Sig_structure` (RFC 9052 section 4.4) signed by the
/// assertion key: a constant deterministic-CBOR template with the claim values
/// written at fixed offsets.
fn aat_sig_structure(input: AuthenticatorAssertionToken) -> [u8; AAT_SIG_STRUCTURE_LEN] {
    // The payload is everything after the 19-byte Sig_structure prefix.
    let payload_len: u32 = AAT_SIG_STRUCTURE_LEN - 19;

    // Fixed-width claim encodings; see the struct field requirements. `aud`
    // needs no explicit range check: the 8-byte decomposition below constrains
    // it to `u64` on its own.
    assert_cbor_uint32(input.exp);
    let aud_bytes: [u8; 8] = input.aud.to_be_bytes();
    let exp_bytes: [u8; 4] = input.exp.to_be_bytes();
    let nonce_bytes: [u8; 32] = input.nonce.to_be_bytes();
    let cdh_bytes: [u8; 32] = input.cdh.to_be_bytes();
    let meta_bytes: [u8; 32] = input.authenticator_meta.to_be_bytes();
    assert(meta_bytes[31] < 32, "authenticator_meta bits 5+ are reserved");
    for i in 0..31 {
        assert(meta_bytes[i] == 0, "authenticator_meta bits 5+ are reserved");
    }

    let mut msg: [u8; AAT_SIG_STRUCTURE_LEN] = [0; AAT_SIG_STRUCTURE_LEN];

    // Sig_structure = [context, body_protected, external_aad, payload]
    msg[0] = 0x84; // array(4)
    msg[1] = 0x6a; // text(10)
    let context = "Signature1".as_bytes();
    for i in 0..10 {
        msg[2 + i] = context[i];
    }
    msg[12] = 0x43; // bytes(3): protected header
    msg[13] = 0xa1; // map(1)
    msg[14] = 0x01; // alg:
    msg[15] = 0x26; // ES256 (-7)
    msg[16] = 0x40; // bytes(0): empty external_aad
    msg[17] = 0x58; // bytes(1-byte length): payload
    msg[18] = payload_len as u8;

    // Payload: the CWT claims map in deterministic CBOR map-key order.
    msg[19] = 0xa6; // map(6)
    msg[20] = 0x03; // aud (3):
    msg[21] = 0x48; // bytes(8)
    for i in 0..8 {
        msg[22 + i] = aud_bytes[i];
    }
    msg[30] = 0x04; // exp (4):
    msg[31] = 0x1a; // uint32
    for i in 0..4 {
        msg[32 + i] = exp_bytes[i];
    }
    msg[36] = 0x0a; // nonce (10):
    msg[37] = 0x58; // bytes(1-byte length)
    msg[38] = 0x20; // 32
    for i in 0..32 {
        msg[39 + i] = nonce_bytes[i];
    }
    msg[71] = 0x19; // eat_profile (265, 2-byte uint):
    msg[72] = 0x01;
    msg[73] = 0x09;
    msg[74] = 0x78; // text(1-byte length)
    msg[75] = 0x1c; // 28
    let profile = "https://world.org/eat/aat/v1".as_bytes();
    for i in 0..28 {
        msg[76 + i] = profile[i];
    }
    msg[104] = 0x3a; // cdh (-80000, 4-byte negative):
    msg[105] = 0x00;
    msg[106] = 0x01;
    msg[107] = 0x38;
    msg[108] = 0x7f;
    msg[109] = 0x58; // bytes(1-byte length)
    msg[110] = 0x20; // 32
    for i in 0..32 {
        msg[111 + i] = cdh_bytes[i];
    }
    msg[143] = 0x3a; // authenticator_meta (-80001):
    msg[144] = 0x00;
    msg[145] = 0x01;
    msg[146] = 0x38;
    msg[147] = 0x80;
    msg[148] = 0x58; // bytes(1-byte length)
    msg[149] = 0x20; // 32
    for i in 0..32 {
        msg[150 + i] = meta_bytes[i];
    }

    msg
}

/// Known-answer test companion to `test_deterministic_takt`: an AAT signed by
/// the key that fixture attests (`ES256`, RFC 6979 deterministic, low-S
/// normalized). The signature fixture comes from
/// `crates/proof/src/authenticator_attestation/tests.rs::
/// aat_known_answer_sig_structure_and_signature`; an intentional change to
/// that Rust expectation must update the signature below.
pub(crate) fn test_deterministic_aat() -> AuthenticatorAssertionToken {
    AuthenticatorAssertionToken {
        aud: 1928118,
        exp: super::takt::TEST_EXP,
        nonce: 0x11d223ce7b91ac21,
        cdh: 0x9f2c1abc,
        // presence PresentBiometric (0b010) | provider 0b01 << 3
        authenticator_meta: 10,
        signature: [
            0x51, 0x6e, 0xf8, 0x8b, 0x3c, 0x52, 0x34, 0x74, 0x64, 0x4e, 0x31, 0x48, 0xc1, 0xdb,
            0x2a, 0x50, 0x25, 0x9e, 0x81, 0xdc, 0xa3, 0x6f, 0x42, 0x76, 0x76, 0x8d, 0x65, 0xd4,
            0x63, 0x09, 0xe8, 0x26, 0x63, 0xde, 0x9c, 0x50, 0x11, 0x66, 0x73, 0xb7, 0x78, 0xd7,
            0x2b, 0xaf, 0xc4, 0x41, 0x4f, 0x38, 0x4b, 0x54, 0xd7, 0xba, 0x66, 0x1c, 0x3e, 0x2d,
            0x76, 0xd8, 0xa6, 0xcf, 0x8d, 0x32, 0xa4, 0x63,
        ],
    }
}

/// Pins the exact `Sig_structure` emitted by the Rust implementation.
///
/// Source fixture: the hex expectation in
/// `crates/proof/src/authenticator_attestation/tests.rs::
/// aat_known_answer_sig_structure_and_signature`. An intentional
/// change to the Rust fixture must update this array.
#[test]
fn test_aat_sig_structure_matches_rust_fixture() {
    let expected: [u8; AAT_SIG_STRUCTURE_LEN] = [
        0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x43, 0xa1, 0x01,
        0x26, 0x40, 0x58, 0xa3, 0xa6, 0x03, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1d, 0x6b, 0xb6,
        0x04, 0x1a, 0x6a, 0x4d, 0x3d, 0x8d, 0x0a, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x11, 0xd2, 0x23, 0xce, 0x7b, 0x91, 0xac, 0x21, 0x19, 0x01, 0x09, 0x78,
        0x1c, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x2e,
        0x6f, 0x72, 0x67, 0x2f, 0x65, 0x61, 0x74, 0x2f, 0x61, 0x61, 0x74, 0x2f, 0x76, 0x31, 0x3a,
        0x00, 0x01, 0x38, 0x7f, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x9f, 0x2c, 0x1a, 0xbc, 0x3a, 0x00, 0x01, 0x38, 0x80, 0x58, 0x20,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x0a,
    ];
    let actual = aat_sig_structure(test_deterministic_aat());

    for i in 0..AAT_SIG_STRUCTURE_LEN {
        assert(actual[i] == expected[i], "AAT Sig_structure differs from Rust fixture");
    }
}

/// `aud` spans the whole `u64` range, which is the point of encoding it as a
/// byte string: `RpId` is a `u64` protocol-wide and ids as small as `1` are in
/// use, so the `[2^16, 2^32)` window a 4-byte CBOR uint would force is not a
/// window the protocol can live inside.
#[test]
fn test_aud_covers_the_full_u64_range() {
    let cases: [Field; 4] = [0, 1, 0x100000000, 0xffffffffffffffff];
    for c in 0..4 {
        let mut aat = test_deterministic_aat();
        aat.aud = cases[c];
        let msg = aat_sig_structure(aat);
        // Always the same eight bytes on the wire, whatever the magnitude.
        let expected: [u8; 8] = cases[c].to_be_bytes();
        for i in 0..8 {
            assert(msg[22 + i] == expected[i], "aud must be 8 big-endian bytes");
        }
    }
}

#[test(should_fail_with = "Field failed to decompose into specified 8 limbs")]
fn test_aud_above_u64_rejected() {
    // The 8-byte decomposition is the only bound on `aud`, so it has to be the
    // thing that rejects `2^64`: a wider value would silently truncate into the
    // template and sign a different audience than the one bound outside.
    let mut aat = test_deterministic_aat();
    aat.aud = 0x10000000000000000;
    let _ = aat_sig_structure(aat);
}

/// The assertion key attested by `test_deterministic_takt`, which signed
/// `test_deterministic_aat`.
fn test_assertion_key() -> ([u8; 32], [u8; 32]) {
    let takt = super::takt::test_deterministic_takt();
    (takt.assertion_key_x, takt.assertion_key_y)
}

#[test]
fn test_deterministic_aat_verification() {
    let (key_x, key_y) = test_assertion_key();
    verify_aat(
        test_deterministic_aat(),
        key_x,
        key_y,
        super::takt::TEST_NOW,
    );
}

#[test(should_fail_with = "invalid AAT signature")]
fn test_aat_tampered_claim() {
    let (key_x, key_y) = test_assertion_key();
    let mut aat = test_deterministic_aat();
    aat.nonce += 1;
    verify_aat(aat, key_x, key_y, super::takt::TEST_NOW);
}

#[test(should_fail_with = "invalid AAT signature")]
fn test_aat_wrong_assertion_key() {
    // Verifying under any key other than the one that signed must fail. The
    // composite entrypoint is what guarantees the key came from a TAKT; see
    // `test_aat_key_not_attested` in `lib.nr`.
    let unrelated = super::takt::test_deterministic_takt_unrelated_key();
    verify_aat(
        test_deterministic_aat(),
        unrelated.assertion_key_x,
        unrelated.assertion_key_y,
        super::takt::TEST_NOW,
    );
}

#[test(should_fail_with = "AAT signature r value is zero")]
fn test_aat_zero_r_rejected() {
    // Guards the check `noir_ecdsa` only gained in v0.4.1; we pin v0.2.9, so
    // without our explicit assertion an `r = 0` signature would verify against
    // any public key. Delete this test only if the pin moves to >= v0.4.1.
    let (key_x, key_y) = test_assertion_key();
    let mut aat = test_deterministic_aat();
    for i in 0..32 {
        aat.signature[i] = 0;
    }
    verify_aat(aat, key_x, key_y, super::takt::TEST_NOW);
}

#[test(should_fail_with = "Signature s value is not in canonical form")]
fn test_aat_high_s_signature_rejected() {
    // WIP-106 requires verifiers to reject high-S signatures. `(r, n - s)`
    // verifies under textbook ECDSA exactly as `(r, s)` does, so without this
    // check every AAT would have a second, equally valid signature.
    //
    // The check lives in `noir_ecdsa` (`assert(s <= n/2)`) rather than here, so
    // this test pins the pinned dependency: a version bump that drops, renames
    // or reworks that assertion fails loudly instead of silently dropping a
    // spec MUST. `n - s` is derived from the fixture rather than hardcoded so
    // the two cannot drift apart.
    let (key_x, key_y) = test_assertion_key();
    let mut aat = test_deterministic_aat();
    let s = signature_scalar(aat.signature, 32);
    let high_s: [u8; 32] = (Secp256r1_Fr::zero() - s).to_be_bytes();
    for i in 0..32 {
        aat.signature[32 + i] = high_s[i];
    }
    verify_aat(aat, key_x, key_y, super::takt::TEST_NOW);
}

#[test(should_fail_with = "authenticator_meta bits 5+ are reserved")]
fn test_aat_reserved_meta_bits_rejected() {
    let (key_x, key_y) = test_assertion_key();
    let mut aat = test_deterministic_aat();
    aat.authenticator_meta = 32; // bit 5 set
    verify_aat(aat, key_x, key_y, super::takt::TEST_NOW);
}

#[test(should_fail_with = "token is expired")]
fn test_expired_aat_rejected() {
    // At `exp` the token is already expired (RFC 8392: "on or after").
    let (key_x, key_y) = test_assertion_key();
    verify_aat(
        test_deterministic_aat(),
        key_x,
        key_y,
        super::takt::TEST_EXP,
    );
}

#[test]
fn test_aat_at_max_lifetime_accepted() {
    // Exactly `MAX_AAT_LIFETIME_SECS` of remaining validity is allowed: the
    // WIP-106 bound is inclusive.
    let (key_x, key_y) = test_assertion_key();
    verify_aat(
        test_deterministic_aat(),
        key_x,
        key_y,
        super::takt::TEST_EXP - MAX_AAT_LIFETIME_SECS,
    );
}

#[test(should_fail_with = "token lifetime exceeds the maximum")]
fn test_aat_lifetime_too_long_rejected() {
    // One second past the 12h cap. Without this bound an authenticator could
    // mint AATs valid until 2106 (the only other constraint on `exp` is
    // `exp < 2^32`), and since AATs have no revocation mechanism a stolen
    // token would stay usable for decades.
    let (key_x, key_y) = test_assertion_key();
    verify_aat(
        test_deterministic_aat(),
        key_x,
        key_y,
        super::takt::TEST_EXP - MAX_AAT_LIFETIME_SECS - 1,
    );
}
