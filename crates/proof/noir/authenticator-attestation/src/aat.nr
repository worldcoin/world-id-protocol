// Verification of an Authenticator Assertion Token (AAT): a token
// representing integrity of a specific environment through an environment-bound
// key which is attested by a Trust Anchor Key Token (TAKT).
use super::takt::{TrustAnchorKeyToken, verify_takt};
use bigcurve::curves::secp256r1::{Secp256r1_Fq, Secp256r1_Fr};
use bignum::BigNum;
use noir_ecdsa::ecdsa::verify_secp256r1_ecdsa;

/// Total length of the COSE `Sig_structure` signed by the assertion key: the
/// `Signature1` framing, protected header, `external_aad`, and the six-entry
/// CWT claims map.
///
/// The TAKT is *not* part of this. It travels in the AAT's `COSE_Sign1`
/// unprotected header, which never enters the `Sig_structure` (RFC 9052 section 4.4),
/// so this circuit never reserializes it.
///
/// 19-byte prefix + 159-byte payload. The prefix is one byte shorter than it
/// would be with the TAKT: a 159-byte payload takes the minimal 1-byte CBOR
/// length (`0x58 0x9f`), where the old 417-byte payload needed the 2-byte form.
pub global AAT_SIG_STRUCTURE_LEN: u32 = 178;

pub struct AuthenticatorAssertionToken {
    /// The `rpId` of the requesting RP (CWT `aud`). MUST require a 4-byte
    /// CBOR uint encoding (`2^16 <= aud < 2^32`) so offsets stay constant.
    aud: Field,
    /// Expiration as seconds since the Unix epoch (CWT `exp`). MUST require a
    /// 4-byte CBOR uint encoding (holds for dates between 1971 and 2106).
    exp: Field,
    /// The `ProofRequest` nonce binding the token to a specific request.
    nonce: Field,
    /// Client data hash (CWT `cdh`): an arbitrary commitment binding the token
    /// to its upstream use case. A nil value is 32 zero bytes.
    cdh: Field,
    /// Structured integrity metadata: user presence (bits 0-2) and
    /// provider-defined bits (3-4); all other bits are reserved (zero).
    authenticator_meta: Field,
    /// The TAKT attesting the assertion key. It is carried outside the AAT
    /// signature, so nothing here proves the pairing on its own -- the binding
    /// is `verify_takt` plus the ES256 key equality enforced in `verify_aat`.
    takt: TrustAnchorKeyToken,
    /// ES256 signature over the COSE `Sig_structure` (`r || s`, low-S).
    signature: [u8; 64],
}

/// Verifies the full WIP-106 attestation chain:
/// 1. the TAKT attests the assertion key (`BabyJubJub-EdDSA-Poseidon2`), and
/// 2. the attested assertion key signs the AAT (`ES256` over the COSE
///    `Sig_structure`).
///
/// This is the primary entrypoint; the TAKT digest is computed exactly once
/// along this path (inside `verify_takt`).
pub fn verify_aat(aat: AuthenticatorAssertionToken) {
    verify_takt(aat.takt);

    let message = aat_sig_structure(aat);
    let digest = sha256::digest(message);

    // Pure-Noir ECDSA (bignum/bigcurve). Deliberately NOT the stdlib
    // `ecdsa_secp256r1` black box: provekit does not implement it, so the
    // black box passes `nargo test` but cannot be proven. Only black boxes
    // from provekit's allowlist may be used here; see crates/proof/noir/README.md.
    let public_key_x = Secp256r1_Fq::from_be_bytes(aat.takt.assertion_key_x);
    let public_key_y = Secp256r1_Fq::from_be_bytes(aat.takt.assertion_key_y);
    let r = signature_scalar(aat.signature, 0);
    let s = signature_scalar(aat.signature, 32);

    // `noir_ecdsa` only rejects `r == 0` from v0.4.1 onwards, and we pin v0.2.9
    // (see crates/proof/noir/README.md), so the check lives here instead. With
    // `r = 0` the verification equation collapses to `R = u1*G`, dropping the
    // public key entirely: a single forgery would then verify under *every*
    // key. `s == 0` is already rejected by the `s * s^-1 == 1` constraint.
    assert(r != Secp256r1_Fr::zero(), "AAT signature r value is zero");

    let is_valid = verify_secp256r1_ecdsa(public_key_x, public_key_y, digest, (r, s));
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

    // Fixed-width claim encodings; see the struct field requirements.
    let aud_bytes: [u8; 4] = input.aud.to_be_bytes();
    assert(
        (aud_bytes[0] != 0) | (aud_bytes[1] != 0),
        "aud must require a 4-byte CBOR uint encoding",
    );
    let exp_bytes: [u8; 4] = input.exp.to_be_bytes();
    assert(
        (exp_bytes[0] != 0) | (exp_bytes[1] != 0),
        "exp must require a 4-byte CBOR uint encoding",
    );
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
    msg[21] = 0x1a; // uint32
    for i in 0..4 {
        msg[22 + i] = aud_bytes[i];
    }
    msg[26] = 0x04; // exp (4):
    msg[27] = 0x1a; // uint32
    for i in 0..4 {
        msg[28 + i] = exp_bytes[i];
    }
    msg[32] = 0x0a; // nonce (10):
    msg[33] = 0x58; // bytes(1-byte length)
    msg[34] = 0x20; // 32
    for i in 0..32 {
        msg[35 + i] = nonce_bytes[i];
    }
    msg[67] = 0x19; // eat_profile (265, 2-byte uint):
    msg[68] = 0x01;
    msg[69] = 0x09;
    msg[70] = 0x78; // text(1-byte length)
    msg[71] = 0x1c; // 28
    let profile = "https://world.org/eat/aat/v1".as_bytes();
    for i in 0..28 {
        msg[72 + i] = profile[i];
    }
    msg[100] = 0x3a; // cdh (-80000, 4-byte negative):
    msg[101] = 0x00;
    msg[102] = 0x01;
    msg[103] = 0x38;
    msg[104] = 0x7f;
    msg[105] = 0x58; // bytes(1-byte length)
    msg[106] = 0x20; // 32
    for i in 0..32 {
        msg[107 + i] = cdh_bytes[i];
    }
    msg[139] = 0x3a; // authenticator_meta (-80001):
    msg[140] = 0x00;
    msg[141] = 0x01;
    msg[142] = 0x38;
    msg[143] = 0x80;
    msg[144] = 0x58; // bytes(1-byte length)
    msg[145] = 0x20; // 32
    for i in 0..32 {
        msg[146 + i] = meta_bytes[i];
    }

    msg
}

/// Known-answer test companion to `test_deterministic_takt`: the same TAKT,
/// wrapped in an AAT signed by the assertion key (`ES256`, RFC 6979
/// deterministic, low-S normalized). Values generated by the Rust
/// implementation.
fn test_deterministic_aat() -> AuthenticatorAssertionToken {
    AuthenticatorAssertionToken {
        aud: 1928118,
        exp: 1783446925,
        nonce: 0x11d223ce7b91ac21,
        cdh: 0x9f2c1abc,
        // presence PresentBiometric (0b010) | provider 0b01 << 3
        authenticator_meta: 10,
        takt: super::takt::test_deterministic_takt(),
        signature: [
            0x33, 0x07, 0x2e, 0x05, 0x70, 0x4c, 0x92, 0x7b, 0x97, 0x54, 0xdc, 0x49, 0x4c, 0x0d,
            0x31, 0xbc, 0x87, 0x5e, 0x03, 0xa2, 0x03, 0x35, 0x83, 0xc2, 0xa6, 0x03, 0x46, 0xee,
            0xc5, 0x71, 0x8b, 0xed, 0x0f, 0x3c, 0x9d, 0x76, 0x19, 0x27, 0xda, 0x77, 0x2c, 0x8a,
            0x64, 0x02, 0xaa, 0xe1, 0xcb, 0x5f, 0x13, 0x8e, 0xea, 0xdf, 0xd5, 0xab, 0x33, 0x4d,
            0xa0, 0x0f, 0x0d, 0x4b, 0xee, 0xe7, 0x32, 0xc3,
        ],
    }
}

#[test]
fn test_deterministic_aat_verification() {
    verify_aat(test_deterministic_aat());
}

#[test(should_fail_with = "invalid AAT signature")]
fn test_aat_tampered_claim() {
    let mut aat = test_deterministic_aat();
    aat.nonce += 1;
    verify_aat(aat);
}

#[test(should_fail_with = "invalid AAT signature")]
fn test_aat_key_not_attested() {
    // A valid TAKT attesting a different assertion key must not verify this
    // AAT: the embedded TAKT bytes and the ES256 verification key are both
    // derived from the (wrong) attested key.
    let mut aat = test_deterministic_aat();
    aat.takt = super::takt::test_deterministic_takt_unrelated_key();
    verify_aat(aat);
}

#[test(should_fail_with = "AAT signature r value is zero")]
fn test_aat_zero_r_rejected() {
    // Guards the check `noir_ecdsa` only gained in v0.4.1; we pin v0.2.9, so
    // without our explicit assertion an `r = 0` signature would verify against
    // any public key. Delete this test only if the pin moves to >= v0.4.1.
    let mut aat = test_deterministic_aat();
    for i in 0..32 {
        aat.signature[i] = 0;
    }
    verify_aat(aat);
}

#[test(should_fail_with = "authenticator_meta bits 5+ are reserved")]
fn test_aat_reserved_meta_bits_rejected() {
    let mut aat = test_deterministic_aat();
    aat.authenticator_meta = 32; // bit 5 set
    verify_aat(aat);
}
