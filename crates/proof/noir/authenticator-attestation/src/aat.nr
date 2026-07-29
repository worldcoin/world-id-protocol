// Verification of an Authenticator Attestation Token (AAT): a token
// representing integrity of a specific environment through an environment-bound
// key which is attested by a Root of Trust Token (ROT).
use super::rot::{ROT_TOKEN_LEN, RootOfTrustToken, serialize_rot, verify_rot};
use bigcurve::curves::secp256r1::{Secp256r1_Fq, Secp256r1_Fr};
use bignum::BigNum;
use noir_ecdsa::ecdsa::verify_secp256r1_ecdsa;

/// Bytes of the COSE `Sig_structure` that are not the embedded ROT:
/// the `Signature1` framing, protected header, `external_aad`, and the
/// CWT claims map around the `submods.rot` blob.
pub global AAT_SIG_STRUCTURE_OVERHEAD: u32 = 122;

/// Total length of the COSE `Sig_structure` signed by the assertion key.
pub global AAT_SIG_STRUCTURE_LEN: u32 = AAT_SIG_STRUCTURE_OVERHEAD + ROT_TOKEN_LEN;

pub struct AuthenticatorAttestationToken {
    /// The `rpId` of the requesting RP (CWT `aud`). MUST require a 4-byte
    /// CBOR uint encoding (`2^16 <= aud < 2^32`) so offsets stay constant.
    aud: Field,
    /// Expiration as seconds since the Unix epoch (CWT `exp`). MUST require a
    /// 4-byte CBOR uint encoding (holds for dates between 1971 and 2106).
    exp: Field,
    /// The `ProofRequest` nonce binding the token to a specific request.
    nonce: Field,
    /// Provider-defined integrity metadata; at most 2 bits (`authenticator_meta`).
    authenticator_meta: Field,
    /// The parsed ROT attesting the assertion key. Its serialized form
    /// (embedded under `submods.rot`) is deduced in-circuit via
    /// `serialize_rot`, so the signed payload provably embeds this exact ROT.
    rot: RootOfTrustToken,
    /// ES256 signature over the COSE `Sig_structure` (`r || s`, low-S).
    signature: [u8; 64],
}

/// Verifies the full WIP-106 attestation chain:
/// 1. the ROT attests the assertion key (`BabyJubJub-EdDSA-Poseidon2`), and
/// 2. the attested assertion key signs the AAT (`ES256` over the COSE
///    `Sig_structure`).
///
/// This is the primary entrypoint; the ROT digest is computed exactly once
/// along this path (inside `verify_rot`).
pub fn verify_aat(aat: AuthenticatorAttestationToken) {
    verify_rot(aat.rot);

    let message = aat_sig_structure(aat);
    let digest = sha256::digest(message);

    // Pure-Noir ECDSA (bignum/bigcurve). Deliberately NOT the stdlib
    // `ecdsa_secp256r1` black box: provekit does not implement it, so the
    // black box passes `nargo test` but cannot be proven. Only black boxes
    // from provekit's allowlist may be used here; see crates/proof/noir/README.md.
    let public_key_x = Secp256r1_Fq::from_be_bytes(aat.rot.assertion_key_x);
    let public_key_y = Secp256r1_Fq::from_be_bytes(aat.rot.assertion_key_y);
    let r = signature_scalar(aat.signature, 0);
    let s = signature_scalar(aat.signature, 32);
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
/// and the reserialized ROT spliced in at fixed offsets.
fn aat_sig_structure(input: AuthenticatorAttestationToken) -> [u8; AAT_SIG_STRUCTURE_LEN] {
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
    let meta_bytes: [u8; 1] = input.authenticator_meta.to_be_bytes();
    assert(meta_bytes[0] < 4, "authenticator_meta must carry at most 2 bits");

    let rot_token = serialize_rot(input.rot);

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
    msg[20] = 0xa6; // map(6)
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
    msg[72] = 0x20; // 32
    let profile = "https://worldcoin.org/eat/aat/v1".as_bytes();
    for i in 0..32 {
        msg[73 + i] = profile[i];
    }
    msg[105] = 0x19; // submods (266, 2-byte uint):
    msg[106] = 0x01;
    msg[107] = 0x0a;
    msg[108] = 0xa1; // map(1)
    msg[109] = 0x63; // text(3)
    let rot_label = "rot".as_bytes();
    for i in 0..3 {
        msg[110 + i] = rot_label[i];
    }
    msg[113] = 0x59; // bytes(2-byte length): ROT token
    msg[114] = (ROT_TOKEN_LEN >> 8) as u8;
    msg[115] = (ROT_TOKEN_LEN & 0xff) as u8;
    for i in 0..ROT_TOKEN_LEN {
        msg[116 + i] = rot_token[i];
    }
    msg[116 + ROT_TOKEN_LEN] = 0x3a; // authenticator_meta (-80001, 4-byte negative):
    msg[117 + ROT_TOKEN_LEN] = 0x00;
    msg[118 + ROT_TOKEN_LEN] = 0x01;
    msg[119 + ROT_TOKEN_LEN] = 0x38;
    msg[120 + ROT_TOKEN_LEN] = 0x80;
    msg[121 + ROT_TOKEN_LEN] = meta_bytes[0]; // single-byte uint (< 24)

    msg
}

/// Known-answer test companion to `test_deterministic_rot`: the same ROT,
/// wrapped in an AAT signed by the assertion key (`ES256`, RFC 6979
/// deterministic, low-S normalized). Values generated by the Rust
/// implementation.
fn test_deterministic_aat() -> AuthenticatorAttestationToken {
    AuthenticatorAttestationToken {
        aud: 1928118,
        exp: 1783446925,
        nonce: 0x11d223ce7b91ac21,
        authenticator_meta: 1,
        rot: super::rot::test_deterministic_rot(),
        signature: [
            0xf3, 0x1e, 0x74, 0xee, 0xb6, 0xf4, 0x89, 0x04, 0xc5, 0x8f, 0x43, 0x87, 0x34, 0xa9,
            0x93, 0x52, 0x2b, 0xce, 0xe1, 0xd9, 0x8b, 0x3d, 0xad, 0xaf, 0x33, 0xa0, 0x9f, 0x2d,
            0xab, 0x90, 0x29, 0x83, 0x11, 0xbf, 0x2d, 0x7b, 0xb6, 0xde, 0x8c, 0xbf, 0x67, 0x31,
            0x85, 0xcc, 0x76, 0x5b, 0x64, 0x16, 0x33, 0xbf, 0x4d, 0x1b, 0x1b, 0x0e, 0x5d, 0x9d,
            0x95, 0x9a, 0x96, 0xc7, 0x49, 0x84, 0x3c, 0xb6,
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
    // A valid ROT attesting a different assertion key must not verify this
    // AAT: the embedded ROT bytes and the ES256 verification key are both
    // derived from the (wrong) attested key.
    let mut aat = test_deterministic_aat();
    aat.rot = super::rot::test_deterministic_rot_unrelated_key();
    verify_aat(aat);
}
