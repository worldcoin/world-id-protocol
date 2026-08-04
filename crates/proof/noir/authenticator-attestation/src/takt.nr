use super::constants::DS_TAKT;
use super::utils::{assert_cbor_uint32, assert_not_expired, p256_be_coord_to_field};
use eddsa_poseidon2::verify_eddsa_poseidon2;
use poseidon2::bn254::perm;

pub struct TrustAnchorKeyToken {
    /// Expiration as seconds since the Unix epoch (CWT `exp`).
    exp: Field,
    /// Big-endian affine x coordinate of the attested assertion key (`cnf`).
    pub(crate) assertion_key_x: [u8; 32],
    /// Big-endian affine y coordinate of the attested assertion key (`cnf`).
    pub(crate) assertion_key_y: [u8; 32],
    /// Packed security attributes (`sec_flags`, LSB-first): platform
    /// (bits 0-7), sec_level (8-15), build_version (16-47), sec_meta (48-51).
    sec_flags: Field,
    /// EdDSA signature scalar component.
    sig_s: Field,
    /// EdDSA signature point component (affine x, y).
    sig_r: [Field; 2],
    /// Affine x coordinate of the Authenticator Provider's `trust_anchor_key`.
    trust_anchor_key_x: Field,
    /// Affine y coordinate of the Authenticator Provider's `trust_anchor_key`.
    trust_anchor_key_y: Field,
}

/// Verifies a Trust Anchor Key Token.
///
/// `now` is the verifier-supplied Unix time (seconds) against which CWT `exp`
/// freshness is checked (`now < exp`). It MUST be a public input of any outer
/// proof that calls this function.
pub fn verify_takt(input: TrustAnchorKeyToken, now: Field) {
    // WIP-106 fixes `exp` to a 4-byte CBOR uint. The circuit no longer
    // serializes the TAKT (it rides in the AAT's unprotected header), so this
    // is the only place that constraint is still enforced -- the Rust
    // constructor only range-checks the CWT numeric date. Must precede the
    // freshness check so an out-of-range `exp` reports the encoding error.
    assert_cbor_uint32(input.exp);
    assert_not_expired(input.exp, now);

    // Range-check the packed sub-fields (reserved bits MUST be 0).
    let _ = unpack_sec_flags(input.sec_flags);

    let digest = takt_digest(input);

    let is_valid = verify_eddsa_poseidon2(
        input.trust_anchor_key_x,
        input.trust_anchor_key_y,
        input.sig_s,
        input.sig_r,
        digest,
    );
    assert(is_valid, "invalid signature");
}

/// Unpacks `sec_flags` into `(platform, sec_level, build_version, sec_meta)`,
/// range-checking every sub-field and that all reserved bits are zero.
pub fn unpack_sec_flags(sec_flags: Field) -> (Field, Field, Field, Field) {
    let bytes: [u8; 8] = sec_flags.to_be_bytes();
    assert(bytes[0] == 0, "sec_flags bits 56-63 are reserved and must be 0");
    assert(bytes[1] < 16, "sec_flags bits 52-55 are reserved and must be 0");
    let platform = bytes[7] as Field;
    let sec_level = bytes[6] as Field;
    let build_version = bytes[5] as Field
        + bytes[4] as Field * 0x100
        + bytes[3] as Field * 0x10000
        + bytes[2] as Field * 0x1000000;
    let sec_meta = bytes[1] as Field;
    (platform, sec_level, build_version, sec_meta)
}

/// Computes the Poseidon2 digest signed by the `trust_anchor_key`.
///
/// The input is the domain separator followed by the claim values in
/// deterministic CBOR map-key order (P-256 coordinates as two 128-bit
/// big-endian limbs each; `sec_flags` as one field element), in the t=8
/// permutation; the digest is element 1 of the permuted state.
fn takt_digest(input: TrustAnchorKeyToken) -> Field {
    let (x_hi, x_lo) = p256_be_coord_to_field(input.assertion_key_x);
    let (y_hi, y_lo) = p256_be_coord_to_field(input.assertion_key_y);

    let state = perm::x5_8([
        DS_TAKT, // [0]
        input.exp, // [1]
        x_hi, // [2]
        x_lo, // [3]
        y_hi, // [4]
        y_lo, // [5]
        input.sec_flags, // [6]
        0, // [7] zero padding
    ]);
    state[1]
}

/// Builds a 32-byte big-endian P-256 coordinate from its two 128-bit limbs.
/// Test-only inverse of `p256_be_coord_to_field`.
fn test_coord_from_limbs(hi: Field, lo: Field) -> [u8; 32] {
    let hi_bytes: [u8; 16] = hi.to_be_bytes();
    let lo_bytes: [u8; 16] = lo.to_be_bytes();
    let mut coord = [0; 32];
    for i in 0..16 {
        coord[i] = hi_bytes[i];
        coord[i + 16] = lo_bytes[i];
    }
    coord
}

/// Known-answer `exp` shared by the deterministic TAKT/AAT fixtures
/// (`1783446925`, around 2026-07-07).
pub(crate) global TEST_EXP: Field = 1783446925;

/// Verifier time used by happy-path tests: strictly before `TEST_EXP`.
pub(crate) global TEST_NOW: Field = 1700000000;

pub(crate) fn test_deterministic_takt() -> TrustAnchorKeyToken {
    // P-256 coordinates as (hi, lo) 128-bit limbs. A whole coordinate cannot
    // be a single Field literal: it may exceed the BN254 modulus (y does here).
    TrustAnchorKeyToken {
        exp: TEST_EXP,
        assertion_key_x: test_coord_from_limbs(
            0x209c317b637935dd3da1c54f63495dfb,
            0x31f97d293df085710320595c9aacb83f,
        ),
        assertion_key_y: test_coord_from_limbs(
            0xdde4c69fc17a0c74c20cc692662f0498,
            0x92ba37a4ba47d2c70cd8a99986391f9b,
        ),
        // platform 2 | sec_level 1 << 8 | build_version 2006 << 16 | sec_meta 3 << 48
        sec_flags: 0x0003000007D60102,
        sig_s: 470068028929166182917067098082253451964722333819896068344928868160891352197,
        sig_r: [
            3038940160993341489764135949086927490288273871352067753480373103236792890019,
            3575406791906717862024209997991679600338512115093140550225375654630093303539,
        ],
        trust_anchor_key_x: 19037598474602150174935475944965340829216795940473064039209388058233204431288,
        trust_anchor_key_y: 3549932221586364715003722955756497910920276078443163728621283280434115857197,
    }
}

/// A second known-answer TAKT signed by the same `trust_anchor_key` but
/// attesting an unrelated assertion key (scalar `[12u8; 32]`); used to test
/// that an AAT must be signed by the key its TAKT attests.
pub(crate) fn test_deterministic_takt_unrelated_key() -> TrustAnchorKeyToken {
    TrustAnchorKeyToken {
        exp: TEST_EXP,
        assertion_key_x: test_coord_from_limbs(
            0x42ad971d037d1ab2bedfce3f17f97dba,
            0xd1205ea7cc75a04ff582ddca56a0bf38,
        ),
        assertion_key_y: test_coord_from_limbs(
            0x1fdba5e5242d51ce760f27c03e12379d,
            0x8372d9c1c9cf9baab1d558b117c7b901,
        ),
        sec_flags: 0x0003000007D60102,
        sig_s: 1349892520413103055939365439804277767462011206099888276450838431845314101031,
        sig_r: [
            2497510479714884033897370712372642880357637781552444460856656911402405468283,
            6160154892924888407590390789330876549069607663319416268142058127129410358139,
        ],
        trust_anchor_key_x: 19037598474602150174935475944965340829216795940473064039209388058233204431288,
        trust_anchor_key_y: 3549932221586364715003722955756497910920276078443163728621283280434115857197,
    }
}

#[test]
fn test_deterministic_takt_verification() {
    let candidate = test_deterministic_takt();
    assert_eq(
        takt_digest(candidate),
        13841652385841404096687877664637984932218603617558109472176126865842396474985,
        "digest mismatch",
    );
    verify_takt(candidate, TEST_NOW);
}

#[test(should_fail_with = "invalid signature")]
fn test_digest_mismatch() {
    let mut candidate = test_deterministic_takt();
    // platform sub-field: 2 -> 4
    candidate.sec_flags = 0x0003000007D60104;
    verify_takt(candidate, TEST_NOW);
}

#[test(should_fail_with = "sec_flags bits 52-55 are reserved and must be 0")]
fn test_reserved_sec_flags_bits_rejected() {
    let mut candidate = test_deterministic_takt();
    candidate.sec_flags = 0x0013000007D60102;
    verify_takt(candidate, TEST_NOW);
}

#[test(should_fail)]
fn test_expired_takt_rejected() {
    // At `exp` the token is already expired (RFC 8392: "on or after").
    verify_takt(test_deterministic_takt(), TEST_EXP);
}

#[test(should_fail_with = "value must require a 4-byte CBOR uint encoding")]
fn test_exp_too_small_for_cbor_uint32_rejected() {
    let mut candidate = test_deterministic_takt();
    // Fits in a 2-byte CBOR uint; violates the WIP-106 encoding profile.
    candidate.exp = 0xffff;
    verify_takt(candidate, TEST_NOW);
}
