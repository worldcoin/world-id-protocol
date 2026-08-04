// Verification of an Authenticator Assertion Token (AAT): a token
// representing integrity of a specific environment through an environment-bound
// key which is attested by a Trust Anchor Key Token (TAKT).
use super::takt::{serialize_takt, TAKT_TOKEN_LEN, TrustAnchorKeyToken, verify_takt};
use bigcurve::curves::secp256r1::{Secp256r1_Fq, Secp256r1_Fr};
use bignum::BigNum;
use noir_ecdsa::ecdsa::verify_secp256r1_ecdsa;

/// Bytes of the COSE `Sig_structure` that are not the embedded TAKT:
/// the `Signature1` framing, protected header, `external_aad`, and the
/// CWT claims map around the `submods.takt` blob.
pub global AAT_SIG_STRUCTURE_OVERHEAD: u32 = 190;

/// Total length of the COSE `Sig_structure` signed by the assertion key.
pub global AAT_SIG_STRUCTURE_LEN: u32 = AAT_SIG_STRUCTURE_OVERHEAD + TAKT_TOKEN_LEN;

pub struct AuthenticatorAssertionToken {
    /// The `rpId` of the requesting RP (CWT `aud`). MUST require a 4-byte
    /// CBOR uint encoding (`2^16 <= aud < 2^32`) so offsets stay constant.
    aud: Field,
    /// Expiration as seconds since the Unix epoch (CWT `exp`). MUST require a
    /// 4-byte CBOR uint encoding (holds for dates between 1971 and 2106).
    exp: Field,
    /// The `ProofRequest` nonce binding the token to a specific request.
    nonce: Field,
    /// Hash of the signal the proof commits to; zero when no signal is present.
    signal: Field,
    /// Structured integrity metadata: user presence (bits 0-2) and
    /// provider-defined bits (3-4); all other bits are reserved (zero).
    authenticator_meta: Field,
    /// The parsed TAKT attesting the assertion key. Its serialized form
    /// (embedded under `submods.takt`) is deduced in-circuit via
    /// `serialize_takt`, so the signed payload provably embeds this exact TAKT.
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
/// and the reserialized TAKT spliced in at fixed offsets.
fn aat_sig_structure(input: AuthenticatorAssertionToken) -> [u8; AAT_SIG_STRUCTURE_LEN] {
    // The payload is everything after the 20-byte Sig_structure prefix.
    let payload_len: u32 = AAT_SIG_STRUCTURE_LEN - 20;

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
    let signal_bytes: [u8; 32] = input.signal.to_be_bytes();
    let meta_bytes: [u8; 32] = input.authenticator_meta.to_be_bytes();
    assert(meta_bytes[31] < 32, "authenticator_meta bits 5+ are reserved");
    for i in 0..31 {
        assert(meta_bytes[i] == 0, "authenticator_meta bits 5+ are reserved");
    }

    let takt_token = serialize_takt(input.takt);

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
    msg[17] = 0x59; // bytes(2-byte length): payload
    msg[18] = (payload_len >> 8) as u8;
    msg[19] = (payload_len & 0xff) as u8;

    // Payload: the CWT claims map in deterministic CBOR map-key order.
    msg[20] = 0xa7; // map(7)
    msg[21] = 0x03; // aud (3):
    msg[22] = 0x1a; // uint32
    for i in 0..4 {
        msg[23 + i] = aud_bytes[i];
    }
    msg[27] = 0x04; // exp (4):
    msg[28] = 0x1a; // uint32
    for i in 0..4 {
        msg[29 + i] = exp_bytes[i];
    }
    msg[33] = 0x0a; // nonce (10):
    msg[34] = 0x58; // bytes(1-byte length)
    msg[35] = 0x20; // 32
    for i in 0..32 {
        msg[36 + i] = nonce_bytes[i];
    }
    msg[68] = 0x19; // eat_profile (265, 2-byte uint):
    msg[69] = 0x01;
    msg[70] = 0x09;
    msg[71] = 0x78; // text(1-byte length)
    msg[72] = 0x1c; // 28
    let profile = "https://world.org/eat/aat/v1".as_bytes();
    for i in 0..28 {
        msg[73 + i] = profile[i];
    }
    msg[101] = 0x19; // submods (266, 2-byte uint):
    msg[102] = 0x01;
    msg[103] = 0x0a;
    msg[104] = 0xa1; // map(1)
    msg[105] = 0x64; // text(4)
    let takt_label = "takt".as_bytes();
    for i in 0..4 {
        msg[106 + i] = takt_label[i];
    }
    msg[110] = 0x58; // bytes(1-byte length): TAKT token (fixed 247 bytes)
    msg[111] = TAKT_TOKEN_LEN as u8;
    for i in 0..TAKT_TOKEN_LEN {
        msg[112 + i] = takt_token[i];
    }
    msg[112 + TAKT_TOKEN_LEN] = 0x3a; // signal (-80000, 4-byte negative):
    msg[113 + TAKT_TOKEN_LEN] = 0x00;
    msg[114 + TAKT_TOKEN_LEN] = 0x01;
    msg[115 + TAKT_TOKEN_LEN] = 0x38;
    msg[116 + TAKT_TOKEN_LEN] = 0x7f;
    msg[117 + TAKT_TOKEN_LEN] = 0x58; // bytes(1-byte length)
    msg[118 + TAKT_TOKEN_LEN] = 0x20; // 32
    for i in 0..32 {
        msg[119 + TAKT_TOKEN_LEN + i] = signal_bytes[i];
    }
    msg[151 + TAKT_TOKEN_LEN] = 0x3a; // authenticator_meta (-80001):
    msg[152 + TAKT_TOKEN_LEN] = 0x00;
    msg[153 + TAKT_TOKEN_LEN] = 0x01;
    msg[154 + TAKT_TOKEN_LEN] = 0x38;
    msg[155 + TAKT_TOKEN_LEN] = 0x80;
    msg[156 + TAKT_TOKEN_LEN] = 0x58; // bytes(1-byte length)
    msg[157 + TAKT_TOKEN_LEN] = 0x20; // 32
    for i in 0..32 {
        msg[158 + TAKT_TOKEN_LEN + i] = meta_bytes[i];
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
        signal: 0x9f2c1abc,
        // presence PresentBiometric (0b010) | provider 0b01 << 3
        authenticator_meta: 10,
        takt: super::takt::test_deterministic_takt(),
        signature: [
            0xb6, 0x49, 0xe1, 0x3d, 0x96, 0xe9, 0x41, 0x83, 0x70, 0xe4, 0xa4, 0xb3, 0xfe, 0x33,
            0x0b, 0xea, 0xbf, 0x8a, 0xc4, 0xbd, 0x87, 0x53, 0x1a, 0x98, 0x22, 0x7b, 0x4e, 0x91,
            0xe9, 0x45, 0x3c, 0xc2, 0x7b, 0x22, 0x5b, 0x10, 0x96, 0x84, 0xfd, 0x4f, 0x8b, 0x26,
            0xa7, 0x98, 0x4e, 0x83, 0xf4, 0xbc, 0xb7, 0xf7, 0x76, 0xad, 0x5c, 0xd4, 0x68, 0xab,
            0x5a, 0x32, 0xa8, 0x1d, 0xe6, 0x48, 0x13, 0xdf,
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
