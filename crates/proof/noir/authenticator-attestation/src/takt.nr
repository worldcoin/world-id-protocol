use super::constants::DS_TAKT;
use super::utils::p256_be_coord_to_field;
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

pub fn verify_takt(input: TrustAnchorKeyToken) {
    // FIXME: exp verification?

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

/// Length in bytes of a serialized TAKT `COSE_Sign1` under this profile.
pub(crate) global TAKT_TOKEN_LEN: u32 = 247;

/// `(p - 1) / 2` for the BN254 base field; elements above this are "negative"
/// in the compressed point encoding defined by WIP-106.
global FIELD_HALF: Field =
    10944121435919637611123202872628637544274182200208017171849102093287904247808;

/// Serializes a BabyJubJub point in the WIP-106 compressed form: the y
/// coordinate as 32 little-endian bytes, with the most significant bit of the
/// last byte set when x is "negative" (`x > (p-1)/2`).
fn compress_bjj_point(x: Field, y: Field) -> [u8; 32] {
    let mut bytes: [u8; 32] = y.to_le_bytes();
    // y < p < 2^254, so the top bit of the last byte is always free.
    let x_is_negative = std::field::bn254::lt(FIELD_HALF, x);
    bytes[31] = bytes[31] + (x_is_negative as u8) * 0x80;
    bytes
}

/// Reserializes the TAKT `COSE_Sign1` from its parsed attributes.
///
/// The bytes embedded under the AAT's `submods.takt` are deduced from the
/// verified token instead of being provided as a second, independent witness:
/// this keeps the witness minimal and guarantees the AAT's signed payload
/// embeds exactly the TAKT whose claims the circuit exposes.
pub(crate) fn serialize_takt(input: TrustAnchorKeyToken) -> [u8; TAKT_TOKEN_LEN] {
    // Fixed-width claim encodings so the template offsets are constant.
    let exp_bytes: [u8; 4] = input.exp.to_be_bytes();
    assert(
        (exp_bytes[0] != 0) | (exp_bytes[1] != 0),
        "exp must require a 4-byte CBOR uint encoding",
    );
    let sec_flags_bytes: [u8; 8] = input.sec_flags.to_be_bytes();

    let kid = compress_bjj_point(input.trust_anchor_key_x, input.trust_anchor_key_y);
    let sig_r = compress_bjj_point(input.sig_r[0], input.sig_r[1]);
    let sig_s_bytes: [u8; 32] = input.sig_s.to_le_bytes();

    let mut token: [u8; TAKT_TOKEN_LEN] = [0; TAKT_TOKEN_LEN];

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
    token[47] = 0x85; // 133

    // Payload: the CWT claims map in deterministic CBOR map-key order.
    token[48] = 0xa4; // map(4)
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
    token[137] = 0x1d; // 29
    let profile = "https://world.org/eat/takt/v1".as_bytes();
    for i in 0..29 {
        token[138 + i] = profile[i];
    }
    token[167] = 0x3a; // sec_flags (-70000, 4-byte negative):
    token[168] = 0x00;
    token[169] = 0x01;
    token[170] = 0x11;
    token[171] = 0x6f;
    token[172] = 0x48; // bytes(8)
    for i in 0..8 {
        token[173 + i] = sec_flags_bytes[i];
    }

    // Signature: EdDSA (compressed R || S), 64 bytes.
    token[181] = 0x58; // bytes(1-byte length)
    token[182] = 0x40; // 64
    for i in 0..32 {
        token[183 + i] = sig_r[i];
    }
    for i in 0..32 {
        token[215 + i] = sig_s_bytes[i];
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

pub(crate) fn test_deterministic_takt() -> TrustAnchorKeyToken {
    // P-256 coordinates as (hi, lo) 128-bit limbs. A whole coordinate cannot
    // be a single Field literal: it may exceed the BN254 modulus (y does here).
    TrustAnchorKeyToken {
        exp: 1783446925,
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
        exp: 1783446925,
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
    verify_takt(candidate);
}

#[test]
fn test_deterministic_takt_serialization() {
    // Expected bytes produced by the Rust implementation
    // (`TrustAnchorKeyToken::sign`) for the same key and claims.
    let expected: [u8; TAKT_TOKEN_LEN] = [
        0x84, 0x58, 0x2a, 0xa2, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x04, 0x58, 0x20, 0x2d, 0x4b,
        0xdf, 0x6e, 0xe6, 0x0f, 0xed, 0xa0, 0x97, 0x5c, 0x77, 0x0b, 0xb7, 0xa2, 0x3d, 0xc6, 0xe4,
        0xe0, 0xed, 0x1e, 0x35, 0xff, 0x3c, 0x24, 0x26, 0xcd, 0xed, 0x4e, 0xc0, 0x30, 0xd9, 0x87,
        0xa0, 0x58, 0x85, 0xa4, 0x04, 0x1a, 0x6a, 0x4d, 0x3d, 0x8d, 0x08, 0xa1, 0x01, 0xa4, 0x01,
        0x02, 0x20, 0x01, 0x21, 0x58, 0x20, 0x20, 0x9c, 0x31, 0x7b, 0x63, 0x79, 0x35, 0xdd, 0x3d,
        0xa1, 0xc5, 0x4f, 0x63, 0x49, 0x5d, 0xfb, 0x31, 0xf9, 0x7d, 0x29, 0x3d, 0xf0, 0x85, 0x71,
        0x03, 0x20, 0x59, 0x5c, 0x9a, 0xac, 0xb8, 0x3f, 0x22, 0x58, 0x20, 0xdd, 0xe4, 0xc6, 0x9f,
        0xc1, 0x7a, 0x0c, 0x74, 0xc2, 0x0c, 0xc6, 0x92, 0x66, 0x2f, 0x04, 0x98, 0x92, 0xba, 0x37,
        0xa4, 0xba, 0x47, 0xd2, 0xc7, 0x0c, 0xd8, 0xa9, 0x99, 0x86, 0x39, 0x1f, 0x9b, 0x19, 0x01,
        0x09, 0x78, 0x1d, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x6f, 0x72, 0x6c,
        0x64, 0x2e, 0x6f, 0x72, 0x67, 0x2f, 0x65, 0x61, 0x74, 0x2f, 0x74, 0x61, 0x6b, 0x74, 0x2f,
        0x76, 0x31, 0x3a, 0x00, 0x01, 0x11, 0x6f, 0x48, 0x00, 0x03, 0x00, 0x00, 0x07, 0xd6, 0x01,
        0x02, 0x58, 0x40, 0xf3, 0x2e, 0x95, 0xcf, 0x56, 0xfa, 0xf2, 0x61, 0xdb, 0x27, 0xf5, 0x01,
        0xf1, 0xbe, 0x33, 0xd9, 0x1f, 0x5e, 0xcf, 0xc9, 0x1c, 0x1c, 0x21, 0x58, 0xb6, 0x2f, 0x33,
        0xa3, 0xc8, 0x9b, 0xe7, 0x07, 0x85, 0x74, 0xf9, 0xcd, 0xda, 0x58, 0x41, 0xd5, 0xb5, 0x0b,
        0x80, 0x3c, 0xb8, 0x23, 0x36, 0xd5, 0x08, 0x96, 0xce, 0x39, 0xa9, 0x8a, 0x83, 0xe0, 0x6d,
        0x0b, 0xd0, 0x3d, 0x90, 0x0c, 0x0a, 0x01,
    ];
    assert_eq(serialize_takt(test_deterministic_takt()), expected, "serialization mismatch");
}

#[test(should_fail_with = "invalid signature")]
fn test_digest_mismatch() {
    let mut candidate = test_deterministic_takt();
    // platform sub-field: 2 -> 4
    candidate.sec_flags = 0x0003000007D60104;
    verify_takt(candidate);
}

#[test(should_fail_with = "sec_flags bits 52-55 are reserved and must be 0")]
fn test_reserved_sec_flags_bits_rejected() {
    let mut candidate = test_deterministic_takt();
    candidate.sec_flags = 0x0013000007D60102;
    verify_takt(candidate);
}
