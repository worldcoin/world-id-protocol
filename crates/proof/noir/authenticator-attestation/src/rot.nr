use super::constants::DS_ROOT_OF_TRUST;
use super::utils::p256_be_coord_to_field;
use eddsa_poseidon2::verify_eddsa_poseidon2;
use poseidon2::bn254::perm;

pub struct RootOfTrustToken {
    /// Expiration as seconds since the Unix epoch (CWT `exp`).
    exp: Field,
    /// Big-endian affine x coordinate of the attested assertion key (`cnf`).
    assertion_key_x: [u8; 32],
    /// Big-endian affine y coordinate of the attested assertion key (`cnf`).
    assertion_key_y: [u8; 32],
    /// Security level of the assertion key (`sec_level`).
    sec_level: Field,
    /// Host platform where the proof is generated (`platform`).
    platform: Field,
    /// Monotonic build version defined by the Authenticator Provider (`build_version`).
    build_version: Field,
    /// Provider-defined integrity metadata; at most 2 bits (`sec_meta`).
    sec_meta: Field,
    /// EdDSA signature scalar component.
    sig_s: Field,
    /// EdDSA signature point component (affine x, y).
    sig_r: [Field; 2],
    /// Affine x coordinate of the Authenticator Provider's `root_of_trust` key.
    root_of_trust_x: Field,
    /// Affine y coordinate of the Authenticator Provider's `root_of_trust` key.
    root_of_trust_y: Field,
}

pub fn verify_rot(input: RootOfTrustToken) {
    // FIXME: exp verification?

    let digest = rot_digest(input);

    let is_valid = verify_eddsa_poseidon2(
        input.root_of_trust_x,
        input.root_of_trust_y,
        input.sig_s,
        input.sig_r,
        digest,
    );
    assert(is_valid, "invalid signature");
}

/// Computes the Poseidon2 digest signed by the `root_of_trust` key.
///
/// The input is the domain separator followed by the claim values in
/// deterministic CBOR map-key order (P-256 coordinates as two 128-bit
/// big-endian limbs each).
fn rot_digest(input: RootOfTrustToken) -> Field {
    let (x_hi, x_lo) = p256_be_coord_to_field(input.assertion_key_x);
    let (y_hi, y_lo) = p256_be_coord_to_field(input.assertion_key_y);

    let state = perm::x5_16([
        DS_ROOT_OF_TRUST, // [0]
        input.exp, // [1]
        x_hi, // [2]
        x_lo, // [3]
        y_hi, // [4]
        y_lo, // [5]
        input.sec_level, // [6]
        input.platform, // [7]
        input.build_version, // [8]
        input.sec_meta, // [9]
        0, // [10..16] zero padding; reserved for future use
        0,
        0,
        0,
        0,
        0,
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

fn test_deterministic_rot() -> RootOfTrustToken {
    // P-256 coordinates as (hi, lo) 128-bit limbs. A whole coordinate cannot
    // be a single Field literal: it may exceed the BN254 modulus (y does here).
    RootOfTrustToken {
        exp: 1783446925,
        assertion_key_x: test_coord_from_limbs(
            0x209c317b637935dd3da1c54f63495dfb,
            0x31f97d293df085710320595c9aacb83f,
        ),
        assertion_key_y: test_coord_from_limbs(
            0xdde4c69fc17a0c74c20cc692662f0498,
            0x92ba37a4ba47d2c70cd8a99986391f9b,
        ),
        sec_level: 1,
        platform: 2,
        build_version: 2006,
        sec_meta: 3,
        sig_s: 87123941362946713516958050614689998623124046555945510928773898456698810341,
        sig_r: [
            12188356331262277220990847320907430074159104603061841188344456096306551742201,
            14927670491269818484744267881053257209742156439975981685479933944109543983661,
        ],
        root_of_trust_x: 19037598474602150174935475944965340829216795940473064039209388058233204431288,
        root_of_trust_y: 3549932221586364715003722955756497910920276078443163728621283280434115857197,
    }
}

#[test]
fn test_deterministic_rot_verification() {
    let candidate = test_deterministic_rot();
    assert_eq(
        rot_digest(candidate),
        0x2052bb6d5cace96c46dcfbb3d42642be29e2256cbb9046cb5ccee5dccb5daec4,
        "digest mismatch",
    );
    verify_rot(candidate);
}

#[test(should_fail_with = "invalid signature")]
fn test_digest_mismatch() {
    let mut candidate = test_deterministic_rot();
    candidate.sec_level = 2;
    assert(
        rot_digest(candidate) != 0x2052bb6d5cace96c46dcfbb3d42642be29e2256cbb9046cb5ccee5dccb5daec4,
    );
    verify_rot(candidate);
}
