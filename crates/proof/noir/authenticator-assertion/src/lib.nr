//! WARNING. This library as well as its defining spec (WIP-106) are in active development.
//!
//! Verifies a Trust Anchor Key Token (TAKT) and an Authenticator Assertion Token (AAT). The TAKT
//! is signed by the Authenticator Provider's `trust_anchor_key` (`BabyJubJub-EdDSA-Poseidon2`) over
//! `H_8(DS_TAKT; exp, x_hi, x_lo, y_hi, y_lo, sec_flags)` and attests the `assertion_key`, which
//! signs the AAT (`ES256`) for a single request.

use bigcurve::curves::secp256r1::{Secp256r1_Fq, Secp256r1_Fr};
use bignum::BigNum;
use eddsa_poseidon2::{
    BabyJubJubPoint, BabyJubJubPointInSubgroup, BabyJubJubScalarFieldElement,
    verify_eddsa_poseidon2,
};
use noir_ecdsa::ecdsa::verify_secp256r1_ecdsa;
use poseidon2::bn254::permutation;

mod tests;

/// Maximum remaining lifetime `exp - now` of a TAKT, in seconds.
pub global MAX_TAKT_LIFETIME: Field = 604800;
/// Maximum remaining lifetime `exp - now` of an AAT, in seconds.
pub global MAX_AAT_LIFETIME: Field = 1800;

global DS_TAKT: Field = 127603488023523044162070750169730677970184433650516; // b"WORLD-ID/WIP-106/TAKT"
global DS_KEY: Field = 498451125091886891258088867850510460821032355161; // b"WORLD-ID/WIP-106/KEY"

/// Length of the AAT's COSE `Sig_structure`: 19-byte prefix and 163-byte claims set.
global AAT_SIG_STRUCTURE_LEN: u32 = 182;

/// `(n - 1) / 2` for the P-256 group order `n`, big-endian: the largest low-S scalar.
global HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// The public inputs of WIP-106 section 3.8 verification. The caller MUST expose every field as a
/// public input of its circuit.
pub struct AuthenticatorAssertionPublicInputs {
    /// `H_3(DS_KEY; x, y)` of the Authenticator Provider's key, supplied by the RP.
    pub trust_anchor_key_hash: Field,
    /// Current time as seconds since the Unix epoch.
    pub now: Field,
    /// The `rpId` of the request.
    pub aud: Field,
    /// The nonce of the request.
    pub nonce: Field,
    /// Platform of the Authenticator.
    pub platform: u8,
    /// Where the `assertion_key` is stored.
    pub sec_level: u8,
    /// Provider-defined 4-bit bitmask.
    pub sec_meta: u8,
    /// User presence (bits 0-2) and provider-defined bits (3-4) the Authenticator reports.
    pub authenticator_meta: u8,
    /// Minimum `build_version` the RP accepts.
    pub min_build_version: u32,
}

/// The private inputs of WIP-106 section 3.8 verification: the claims and signatures of both tokens
/// that the public inputs do not fix. How `cdh` is bound to the surrounding proof is the
/// caller's obligation.
pub struct AuthenticatorAssertionPrivateInputs {
    /// The key that signed the TAKT (affine x, y).
    pub trust_anchor_key: [Field; 2],
    /// Expiration of the TAKT, as seconds since the Unix epoch.
    pub takt_exp: Field,
    /// The attested `assertion_key` (big-endian x, y).
    pub assertion_key_x: [u8; 32],
    pub assertion_key_y: [u8; 32],
    /// Packed security attributes of the `assertion_key`.
    pub sec_flags: Field,
    /// The TAKT's EdDSA signature scalar component.
    pub takt_sig_s: Field,
    /// The TAKT's EdDSA signature point component (affine x, y).
    pub takt_sig_r: [Field; 2],
    /// Expiration of the AAT, as seconds since the Unix epoch.
    pub aat_exp: Field,
    /// The AAT's `ES256` signature (`r || s`).
    pub aat_signature: [u8; 64],
    /// Client data hash binding the AAT to its upstream use; `0` is nil.
    pub cdh: Field,
}

/// Verifies a TAKT and an AAT against the public inputs. The AAT's request values and
/// `authenticator_meta` are written into its signed template, so its signature binds them.
pub fn verify_assertion(
    public: AuthenticatorAssertionPublicInputs,
    private: AuthenticatorAssertionPrivateInputs,
) {
    assert(public.nonce != 0, "nonce must not be 0");
    assert(public.authenticator_meta < 32, "authenticator_meta bits 5 and above are reserved");
    assert((public.authenticator_meta & 7) < 5, "user_presence values 5 and above are reserved");

    let key = private.trust_anchor_key;
    assert(
        permutation::t3([DS_KEY, key[0], key[1]])[1] == public.trust_anchor_key_hash,
        "trust_anchor_key does not match its hash",
    );
    assert(
        verify_eddsa_poseidon2(
            BabyJubJubPointInSubgroup::new(key[0], key[1]),
            BabyJubJubScalarFieldElement::new(private.takt_sig_s),
            BabyJubJubPoint::new(private.takt_sig_r[0], private.takt_sig_r[1]),
            takt_message(private),
        ),
        "invalid TAKT signature",
    );
    let aat = aat_sig_structure(public, private);
    assert(
        verify_es256(
            private.assertion_key_x,
            private.assertion_key_y,
            sha256::digest(aat),
            private.aat_signature,
        ),
        "invalid AAT signature",
    );

    now_below_2_32(public.now);
    assert(std::field::bn254::lt(public.now, private.takt_exp), "TAKT is expired");
    assert(
        std::field::bn254::lt(private.takt_exp, public.now + MAX_TAKT_LIFETIME + 1),
        "TAKT lifetime exceeds maximum",
    );
    assert(std::field::bn254::lt(public.now, private.aat_exp), "AAT is expired");
    assert(
        std::field::bn254::lt(private.aat_exp, public.now + MAX_AAT_LIFETIME + 1),
        "AAT lifetime exceeds maximum",
    );

    let build_version = assert_sec_flags(
        private.sec_flags,
        public.platform,
        public.sec_level,
        public.sec_meta,
    );
    assert(build_version >= public.min_build_version, "build_version below minimum");
}

/// Asserts `now < 2^32`. Both `exp` values are bounded by their 4-byte encodings, so
/// `now + MAX_*_LIFETIME + 1` can not wrap.
fn now_below_2_32(now: Field) {
    now.assert_max_bit_size::<32>();
}

/// Verifies an `ES256` signature over a SHA-256 digest. Accepts high-S signatures: platform keys
/// do not normalize `s`, and `(r, s)` and `(r, n - s)` verify alike.
fn verify_es256(key_x: [u8; 32], key_y: [u8; 32], digest: [u8; 32], signature: [u8; 64]) -> bool {
    let r = signature_scalar(signature, 0);
    let s = signature_scalar(signature, 32);
    // Safety: the hint only picks which of `s` and `n - s` to pass on; `noir_ecdsa` rejects the
    // high one, so a wrong hint fails verification and can not make a forgery pass.
    let is_high = unsafe { is_high_s(signature) };
    let s = if is_high { Secp256r1_Fr::zero() - s } else { s };
    // Pure-Noir ECDSA (bignum/bigcurve), not the stdlib `ecdsa_secp256r1` black box: provekit
    // does not implement it.
    verify_secp256r1_ecdsa(
        Secp256r1_Fq::from_be_bytes(key_x),
        Secp256r1_Fq::from_be_bytes(key_y),
        digest,
        (r, s),
    )
}

/// Whether the `s` half of `signature` is above `(n - 1) / 2`.
unconstrained fn is_high_s(signature: [u8; 64]) -> bool {
    let mut result = false;
    let mut decided = false;
    for i in 0..32 {
        if !decided & (signature[32 + i] != HALF_N[i]) {
            result = signature[32 + i] > HALF_N[i];
            decided = true;
        }
    }
    result
}

/// Reads one 32-byte big-endian half of an `r || s` signature as a P-256 scalar.
fn signature_scalar(signature: [u8; 64], offset: u32) -> Secp256r1_Fr {
    let mut bytes = [0; 32];
    for i in 0..32 {
        bytes[i] = signature[offset + i];
    }
    Secp256r1_Fr::from_be_bytes(bytes)
}

/// Writes `bytes` into `msg` at `offset`.
fn write<let N: u32, let M: u32>(msg: &mut [u8; N], offset: u32, bytes: [u8; M]) {
    for i in 0..M {
        msg[offset + i] = bytes[i];
    }
}

/// Splits a 32-byte big-endian P-256 coordinate into its high and low 128-bit limbs.
fn limbs(coordinate: [u8; 32]) -> (Field, Field) {
    let mut hi = [0; 16];
    let mut lo = [0; 16];
    for i in 0..16 {
        hi[i] = coordinate[i];
        lo[i] = coordinate[16 + i];
    }
    (Field::from_be_bytes(hi), Field::from_be_bytes(lo))
}

/// Asserts `exp` takes a 4-byte CBOR uint (`2^16 <= exp < 2^32`) and returns its bytes.
fn exp_bytes(exp: Field) -> [u8; 4] {
    let bytes: [u8; 4] = exp.to_be_bytes();
    assert((bytes[0] != 0) | (bytes[1] != 0), "exp must take a 4-byte CBOR uint");
    bytes
}

/// Computes the TAKT's signed message `H_8(DS_TAKT; exp, x_hi, x_lo, y_hi, y_lo, sec_flags)`.
/// `sec_flags` is range-checked in `assert_sec_flags`.
fn takt_message(private: AuthenticatorAssertionPrivateInputs) -> Field {
    let _ = exp_bytes(private.takt_exp);
    let (x_hi, x_lo) = limbs(private.assertion_key_x);
    let (y_hi, y_lo) = limbs(private.assertion_key_y);
    permutation::t8(
        [DS_TAKT, private.takt_exp, x_hi, x_lo, y_hi, y_lo, private.sec_flags, 0],
    )[1]
}

/// Rebuilds the AAT's `Sig_structure`: protected header `{1: -7}`, empty `external_aad`, and the
/// claims `aud`, `exp`, `nonce`, `eat_profile`, `cdh` and `authenticator_meta`.
fn aat_sig_structure(
    public: AuthenticatorAssertionPublicInputs,
    private: AuthenticatorAssertionPrivateInputs,
) -> [u8; AAT_SIG_STRUCTURE_LEN] {
    let mut msg = [0; AAT_SIG_STRUCTURE_LEN];
    msg[0] = 0x84; // array(4)
    msg[1] = 0x6a; // text(10)
    write(&mut msg, 2, "Signature1".as_bytes());
    write(&mut msg, 12, [0x43, 0xa1, 0x01, 0x26, 0x40, 0x58, 0xa3]);

    // Claims set, in deterministic CBOR key order. The 8-byte decomposition bounds `aud` to `u64`.
    let aud: [u8; 8] = public.aud.to_be_bytes();
    let nonce: [u8; 32] = public.nonce.to_be_bytes();
    let cdh: [u8; 32] = private.cdh.to_be_bytes();
    write(&mut msg, 19, [0xa6, 0x03, 0x48]);
    write(&mut msg, 22, aud);
    write(&mut msg, 30, [0x04, 0x1a]);
    write(&mut msg, 32, exp_bytes(private.aat_exp));
    write(&mut msg, 36, [0x0a, 0x58, 0x20]);
    write(&mut msg, 39, nonce);
    write(&mut msg, 71, [0x19, 0x01, 0x09, 0x78, 0x1c]);
    write(&mut msg, 76, "https://world.org/eat/aat/v1".as_bytes());
    write(&mut msg, 104, [0x3a, 0x00, 0x01, 0x38, 0x7f, 0x58, 0x20]);
    write(&mut msg, 111, cdh);
    // `authenticator_meta` as a 32-byte field element; its upper 31 bytes stay zero.
    write(&mut msg, 143, [0x3a, 0x00, 0x01, 0x38, 0x80, 0x58, 0x20]);
    msg[181] = public.authenticator_meta;
    msg
}

/// Asserts `sec_flags < 2^52` and that it packs LSB-first `platform` (bits 0-7), `sec_level`
/// (8-15), `build_version` (16-47) and `sec_meta` (48-51). Returns `build_version`, which must
/// stay private.
fn assert_sec_flags(sec_flags: Field, platform: u8, sec_level: u8, sec_meta: u8) -> u32 {
    // Constrains `sec_flags < 2^56`; `bytes[0]` holds bits 48-55.
    let bytes: [u8; 7] = sec_flags.to_be_bytes();
    assert(bytes[0] < 16, "sec_flags bits 52 and above are reserved and must be 0");
    assert(
        (bytes[6] == platform) & (bytes[5] == sec_level) & (bytes[0] == sec_meta),
        "sec_flags do not match the public security flags",
    );
    Field::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u32
}
