use super::constants::DS_ROOT_OF_TRUST;
use super::utils::p256_be_coord_to_field;
use super::eddsa::verify_eddsa_poseidon2;
use poseidon2::bn254::permutation;

pub struct RootOfTrustToken {
    /// Expiration as seconds since the Unix epoch (CWT `exp`).
    exp: Field,
    /// Big-endian affine x coordinate of the attested assertion key (`cnf`).
    pub(crate) assertion_key_x: [u8; 32],
    /// Big-endian affine y coordinate of the attested assertion key (`cnf`).
    pub(crate) assertion_key_y: [u8; 32],
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

    let state = permutation::t16([
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

/// Length in bytes of a serialized ROT `COSE_Sign1` under this profile.
pub(crate) global ROT_TOKEN_LEN: u32 = 262;

/// `(p - 1) / 2` for the BN254 base field; elements above this are "negative"
/// in ark-serialize's point compression convention.
global FIELD_HALF: Field = 10944121435919637611123202872628637544274182200208017171849102093287904247808;

/// Serializes a BabyJubJub point in ark-serialize compressed form: the y
/// coordinate as 32 little-endian bytes, with the most significant bit of the
/// last byte set when x is "negative" (`x > (p-1)/2`).
fn compress_bjj_point(x: Field, y: Field) -> [u8; 32] {
    let mut bytes: [u8; 32] = y.to_le_bytes();
    // y < p < 2^254, so the top bit of the last byte is always free.
    let x_is_negative = std::field::bn254::lt(FIELD_HALF, x);
    bytes[31] = bytes[31] + (x_is_negative as u8) * 0x80;
    bytes
}

/// Reserializes the ROT `COSE_Sign1` from its parsed attributes.
///
/// The bytes embedded under the AAT's `submods.rot` are deduced from the
/// verified token instead of being provided as a second, independent witness:
/// this keeps the witness minimal and guarantees the AAT's signed payload
/// embeds exactly the ROT whose claims the circuit exposes.
pub(crate) fn serialize_rot(input: RootOfTrustToken) -> [u8; ROT_TOKEN_LEN] {
    // Fixed-width claim encodings so the template offsets are constant.
    let exp_bytes: [u8; 4] = input.exp.to_be_bytes();
    assert(
        (exp_bytes[0] != 0) | (exp_bytes[1] != 0),
        "exp must require a 4-byte CBOR uint encoding",
    );
    let build_version_bytes: [u8; 2] = input.build_version.to_be_bytes();
    assert(
        build_version_bytes[0] != 0,
        "build_version must require a 2-byte CBOR uint encoding",
    );
    let sec_level_bytes: [u8; 1] = input.sec_level.to_be_bytes();
    assert(sec_level_bytes[0] < 24, "sec_level must fit a single-byte CBOR uint");
    let platform_bytes: [u8; 1] = input.platform.to_be_bytes();
    assert(platform_bytes[0] < 24, "platform must fit a single-byte CBOR uint");
    let sec_meta_bytes: [u8; 1] = input.sec_meta.to_be_bytes();
    assert(sec_meta_bytes[0] < 4, "sec_meta must carry at most 2 bits");

    let kid = compress_bjj_point(input.root_of_trust_x, input.root_of_trust_y);
    let sig_r = compress_bjj_point(input.sig_r[0], input.sig_r[1]);
    let sig_s_bytes: [u8; 32] = input.sig_s.to_le_bytes();

    let mut token: [u8; ROT_TOKEN_LEN] = [0; ROT_TOKEN_LEN];

    // COSE_Sign1 = [protected, unprotected, payload, signature]
    token[0] = 0x84; // array(4)
    token[1] = 0x58; // bytes(1-byte length): protected header
    token[2] = 0x2a; // 42
    token[3] = 0xa2; // map(2)
    token[4] = 0x01; // alg:
    token[5] = 0x3a; // BabyJubJub-EdDSA-Poseidon2 (-65537, 4-byte negative)
    token[6] = 0x00;
    token[7] = 0x01;
    token[8] = 0x00;
    token[9] = 0x00;
    token[10] = 0x04; // kid:
    token[11] = 0x58; // bytes(1-byte length)
    token[12] = 0x20; // 32
    for i in 0..32 {
        token[13 + i] = kid[i];
    }
    token[45] = 0xa0; // unprotected: empty map
    token[46] = 0x58; // bytes(1-byte length): payload
    token[47] = 0x94; // 148

    // Payload: the CWT claims map in deterministic CBOR map-key order.
    token[48] = 0xa7; // map(7)
    token[49] = 0x04; // exp (4):
    token[50] = 0x1a; // uint32
    for i in 0..4 {
        token[51 + i] = exp_bytes[i];
    }
    token[55] = 0x08; // cnf (8):
    token[56] = 0xa1; // map(1)
    token[57] = 0x01; // COSE_Key:
    token[58] = 0xa4; // map(4)
    token[59] = 0x01; // kty:
    token[60] = 0x02; // EC2
    token[61] = 0x20; // crv (-1):
    token[62] = 0x01; // P-256
    token[63] = 0x21; // x (-2):
    token[64] = 0x58; // bytes(1-byte length)
    token[65] = 0x20; // 32
    for i in 0..32 {
        token[66 + i] = input.assertion_key_x[i];
    }
    token[98] = 0x22; // y (-3):
    token[99] = 0x58;
    token[100] = 0x20;
    for i in 0..32 {
        token[101 + i] = input.assertion_key_y[i];
    }
    token[133] = 0x19; // eat_profile (265, 2-byte uint):
    token[134] = 0x01;
    token[135] = 0x09;
    token[136] = 0x78; // text(1-byte length)
    token[137] = 0x20; // 32
    let profile = "https://worldcoin.org/eat/rot/v1".as_bytes();
    for i in 0..32 {
        token[138 + i] = profile[i];
    }
    token[170] = 0x3a; // sec_level (-70000, 4-byte negative):
    token[171] = 0x00;
    token[172] = 0x01;
    token[173] = 0x11;
    token[174] = 0x6f;
    token[175] = sec_level_bytes[0];
    token[176] = 0x3a; // platform (-70001):
    token[177] = 0x00;
    token[178] = 0x01;
    token[179] = 0x11;
    token[180] = 0x70;
    token[181] = platform_bytes[0];
    token[182] = 0x3a; // build_version (-70003):
    token[183] = 0x00;
    token[184] = 0x01;
    token[185] = 0x11;
    token[186] = 0x72;
    token[187] = 0x19; // uint16
    token[188] = build_version_bytes[0];
    token[189] = build_version_bytes[1];
    token[190] = 0x3a; // sec_meta (-70005):
    token[191] = 0x00;
    token[192] = 0x01;
    token[193] = 0x11;
    token[194] = 0x74;
    token[195] = sec_meta_bytes[0];

    // Signature: EdDSA (compressed R || S), 64 bytes.
    token[196] = 0x58; // bytes(1-byte length)
    token[197] = 0x40; // 64
    for i in 0..32 {
        token[198 + i] = sig_r[i];
    }
    for i in 0..32 {
        token[230 + i] = sig_s_bytes[i];
    }

    token
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

pub(crate) fn test_deterministic_rot() -> RootOfTrustToken {
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

/// A second known-answer ROT signed by the same `root_of_trust` key but
/// attesting an unrelated assertion key (scalar `[12u8; 32]`); used to test
/// that an AAT must be signed by the key its ROT attests.
pub(crate) fn test_deterministic_rot_unrelated_key() -> RootOfTrustToken {
    RootOfTrustToken {
        exp: 1783446925,
        assertion_key_x: test_coord_from_limbs(
            0x42ad971d037d1ab2bedfce3f17f97dba,
            0xd1205ea7cc75a04ff582ddca56a0bf38,
        ),
        assertion_key_y: test_coord_from_limbs(
            0x1fdba5e5242d51ce760f27c03e12379d,
            0x8372d9c1c9cf9baab1d558b117c7b901,
        ),
        sec_level: 1,
        platform: 2,
        build_version: 2006,
        sec_meta: 3,
        sig_s: 2326074017269111144177606555398948788842611138137480600805829237865067009107,
        sig_r: [
            11208529199184421260062497102262773090160745646707550276440698280354891948292,
            12966874541778944227939133136730232467540585748370170473485901618430275959551,
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

#[test]
fn test_deterministic_rot_serialization() {
    // Expected bytes produced by the Rust implementation
    // (`RootOfTrustToken::sign`) for the same key and claims.
    let expected: [u8; ROT_TOKEN_LEN] = [
        0x84, 0x58, 0x2a, 0xa2, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x04, 0x58, 0x20, 0x2d,
        0x4b, 0xdf, 0x6e, 0xe6, 0x0f, 0xed, 0xa0, 0x97, 0x5c, 0x77, 0x0b, 0xb7, 0xa2, 0x3d,
        0xc6, 0xe4, 0xe0, 0xed, 0x1e, 0x35, 0xff, 0x3c, 0x24, 0x26, 0xcd, 0xed, 0x4e, 0xc0,
        0x30, 0xd9, 0x87, 0xa0, 0x58, 0x94, 0xa7, 0x04, 0x1a, 0x6a, 0x4d, 0x3d, 0x8d, 0x08,
        0xa1, 0x01, 0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20, 0x20, 0x9c, 0x31, 0x7b,
        0x63, 0x79, 0x35, 0xdd, 0x3d, 0xa1, 0xc5, 0x4f, 0x63, 0x49, 0x5d, 0xfb, 0x31, 0xf9,
        0x7d, 0x29, 0x3d, 0xf0, 0x85, 0x71, 0x03, 0x20, 0x59, 0x5c, 0x9a, 0xac, 0xb8, 0x3f,
        0x22, 0x58, 0x20, 0xdd, 0xe4, 0xc6, 0x9f, 0xc1, 0x7a, 0x0c, 0x74, 0xc2, 0x0c, 0xc6,
        0x92, 0x66, 0x2f, 0x04, 0x98, 0x92, 0xba, 0x37, 0xa4, 0xba, 0x47, 0xd2, 0xc7, 0x0c,
        0xd8, 0xa9, 0x99, 0x86, 0x39, 0x1f, 0x9b, 0x19, 0x01, 0x09, 0x78, 0x20, 0x68, 0x74,
        0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x63, 0x6f, 0x69,
        0x6e, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x65, 0x61, 0x74, 0x2f, 0x72, 0x6f, 0x74, 0x2f,
        0x76, 0x31, 0x3a, 0x00, 0x01, 0x11, 0x6f, 0x01, 0x3a, 0x00, 0x01, 0x11, 0x70, 0x02,
        0x3a, 0x00, 0x01, 0x11, 0x72, 0x19, 0x07, 0xd6, 0x3a, 0x00, 0x01, 0x11, 0x74, 0x03,
        0x58, 0x40, 0x2d, 0x0a, 0xac, 0x5c, 0x10, 0xb2, 0x75, 0x48, 0x1c, 0x28, 0x29, 0xff,
        0x04, 0x37, 0x21, 0x4a, 0x76, 0x15, 0x19, 0x9a, 0xea, 0x60, 0x05, 0x61, 0x85, 0x65,
        0x3b, 0x04, 0x18, 0xc3, 0x00, 0xa1, 0xe5, 0x6f, 0x01, 0xe2, 0x15, 0xf5, 0xa2, 0x8b,
        0xac, 0x20, 0x9b, 0xb9, 0xe2, 0x36, 0xd3, 0x0a, 0x7e, 0xdc, 0x68, 0x41, 0x8c, 0x98,
        0x6f, 0xe2, 0x90, 0x4d, 0x7d, 0x97, 0x76, 0x4f, 0x31, 0x00,
    ];
    assert_eq(serialize_rot(test_deterministic_rot()), expected, "serialization mismatch");
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
