//! WARNING. This library as well as its defining spec (WIP-106) are in active development.
//!
//! Verifies an Authenticator Assertion Token (AAT): a token signed by an Authenticator
//! Provider's `trust_anchor_key` over `H_4(DS_AAT; exp, req, sec_flags)`, bound to a
//! request through `req = H_8(DS_REQ; aud, nonce, cdh, presence, blind)`.

use eddsa_poseidon2::verify_eddsa_poseidon2;
use poseidon2::bn254::perm;

mod tests;

global DS_AAT: Field = 498451125091886891258088867850510460821031698772; // b"WORLD-ID/WIP-106/AAT"
global DS_REQ: Field = 498451125091886891258088867850510460821032813905; // b"WORLD-ID/WIP-106/REQ"

/// Maximum remaining lifetime `exp - now` of an AAT, in seconds.
pub global MAX_AAT_LIFETIME: Field = 1800;

/// The values of an AAT, as issued by the Authenticator Provider.
pub struct AuthenticatorAssertionToken {
    /// Expiration as seconds since the Unix epoch.
    pub exp: Field,
    /// Packed security attributes (see `SecFlags`).
    pub sec_flags: Field,
    /// EdDSA signature scalar component.
    pub sig_s: Field,
    /// EdDSA signature point component (affine x, y).
    pub sig_r: [Field; 2],
}

/// The unpacked `sec_flags` sub-fields.
pub struct SecFlags {
    pub platform: u8,
    pub sec_level: u8,
    pub sec_meta: u8,
}

/// Verifies an AAT and returns its range-checked security flags.
///
/// The caller MUST expose `trust_anchor_key`, `now`, `aud`, `nonce`, `presence`,
/// `min_build_version` and the returned flags as public inputs, and MUST keep `aat`,
/// `cdh` and `blind` private. How `cdh` is bound to the surrounding proof is the
/// caller's obligation.
pub fn verify_aat(
    aat: AuthenticatorAssertionToken,
    trust_anchor_key: [Field; 2],
    now: Field,
    aud: Field,
    nonce: Field,
    cdh: Field,
    presence: u8,
    min_build_version: Field,
    blind: Field,
) -> SecFlags {
    assert(nonce != 0, "nonce must not be 0");
    assert(presence < 5, "presence values 5 to 7 are reserved");

    let req = request_commitment(aud, nonce, cdh, presence as Field, blind);
    let message = perm::x5_4([DS_AAT, aat.exp, req, aat.sec_flags])[1];
    let is_valid = verify_eddsa_poseidon2(
        trust_anchor_key[0],
        trust_anchor_key[1],
        aat.sig_s,
        aat.sig_r,
        message,
    );
    assert(is_valid, "invalid signature");

    assert_fresh(aat.exp, now);
    let (flags, build_version) = unpack_sec_flags(aat.sec_flags);
    assert(!std::field::bn254::lt(build_version, min_build_version), "build_version below minimum");
    flags
}

fn request_commitment(
    aud: Field,
    nonce: Field,
    cdh: Field,
    presence: Field,
    blind: Field,
) -> Field {
    perm::x5_8([DS_REQ, aud, nonce, cdh, presence, blind, 0, 0])[1]
}

/// Asserts `now < exp` and `exp - now <= MAX_AAT_LIFETIME`, with both below 2^32.
fn assert_fresh(exp: Field, now: Field) {
    exp.assert_max_bit_size::<32>();
    now.assert_max_bit_size::<32>();
    assert(std::field::bn254::lt(now, exp), "token is expired");
    // Both are below 2^32, so `now + MAX_AAT_LIFETIME + 1` can not wrap.
    assert(
        std::field::bn254::lt(exp, now + MAX_AAT_LIFETIME + 1),
        "token lifetime exceeds maximum",
    );
}

/// Unpacks `sec_flags` LSB-first: `platform` (bits 0-7), `sec_level` (8-15),
/// `build_version` (16-47), `sec_meta` (48-50). `build_version` is returned separately
/// as it must stay private.
fn unpack_sec_flags(sec_flags: Field) -> (SecFlags, Field) {
    // Constrains `sec_flags < 2^56`.
    let bytes: [u8; 7] = sec_flags.to_be_bytes();
    assert(bytes[0] < 8, "sec_flags bits 51 and above are reserved and must be 0");
    let build_version = Field::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    (SecFlags { platform: bytes[6], sec_level: bytes[5], sec_meta: bytes[0] }, build_version)
}
