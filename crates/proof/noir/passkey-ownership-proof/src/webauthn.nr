use bigcurve::{
    BigCurve,
    curves::secp256r1::{Secp256r1, Secp256r1_Fq, Secp256r1_Fr, Secp256r1Scalar},
};
use bignum::BigNum;

pub global SIGNATURE_LEN: u32 = 64;
global P256_GROUP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
global P256_FIELD_MINUS_ORDER: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x43, 0x19, 0x05, 0x53, 0x58, 0xe8, 0x61, 0x7b, 0x0c, 0x46, 0x35, 0x3d, 0x03, 0x9c, 0xda, 0xae,
];

fn bytes_are_less_than(left: [u8; 32], right: [u8; 32]) -> bool {
    let mut less = false;
    let mut equal = true;
    for i in 0..32 {
        less = less | (equal & (left[i] < right[i]));
        equal = equal & (left[i] == right[i]);
    }
    less
}

fn assert_valid_p256_scalar(bytes: [u8; 32]) {
    let mut non_zero = false;
    for byte in bytes {
        non_zero = non_zero | (byte != 0);
    }
    assert(non_zero, "P-256 signature scalar must not be zero");
    assert(bytes_are_less_than(bytes, P256_GROUP_ORDER), "P-256 signature scalar is out of range");
}

pub fn verify_signature<let CLIENT_DATA_JSON_MAX_LEN: u32, let AUTHENTICATOR_DATA_MAX_LEN: u32>(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; SIGNATURE_LEN],
    client_data_json: BoundedVec<u8, CLIENT_DATA_JSON_MAX_LEN>,
    authenticator_data: BoundedVec<u8, AUTHENTICATOR_DATA_MAX_LEN>,
    challenge: [u8; 32],
    origin_hash: [u8; 32],
    challenge_index: u32,
) {
    assert(authenticator_data.len() >= 37, "authenticatorData is too short");
    assert(authenticator_data.len() <= AUTHENTICATOR_DATA_MAX_LEN);
    assert((authenticator_data.get(32) & 5) == 5, "UP and UV are required");
    assert(challenge_index == 36, "challenge must be the JSON challenge field");
    validate_client_data(client_data_json, challenge, origin_hash);
    let client_data_json_hash =
        sha256::sha256_var(client_data_json.storage(), client_data_json.len() as u64);
    let concatenated: BoundedVec<u8, AUTHENTICATOR_DATA_MAX_LEN + 32> =
        concat(authenticator_data, client_data_json_hash);
    let hashed_message = sha256::sha256_var(concatenated.storage(), concatenated.len() as u64);

    verify_p256_signature(hashed_message, public_key_x, public_key_y, signature);
}

// Deliberately supports the standard compact serialization used by the local
// demo's browsers. Reject unknown/duplicate fields, escaped origins and trailing
// bytes rather than treating a substring in prover-controlled storage as JSON.
// All inspected bytes must be within the length actually covered by the signature.
pub fn validate_client_data<let N: u32>(
    data: BoundedVec<u8, N>,
    challenge: [u8; 32],
    origin_hash: [u8; 32],
) {
    assert(data.len() >= 94, "clientDataJSON is too short");
    assert(data.len() <= N);
    let prefix = "{\"type\":\"webauthn.get\",\"challenge\":\"".as_bytes();
    for i in 0..36 {
        assert(data.get(i) == prefix[i], "invalid clientDataJSON prefix");
    }
    let encoded = encode_challenge_base64_url(challenge);
    for i in 0..43 {
        assert(data.get(36 + i) == encoded[i], "challenge field mismatch");
    }
    let origin_prefix = "\",\"origin\":\"".as_bytes();
    for i in 0..12 {
        assert(data.get(79 + i) == origin_prefix[i], "missing origin field");
    }
    let mut origin = [0 as u8; N - 91];
    let mut origin_len = 0;
    let mut end = 0;
    let mut closed = false;
    for i in 91..N {
        if i < data.len() & !closed {
            let byte = data.get(i);
            if byte == 34 {
                closed = true;
                end = i;
            } else {
                assert((byte >= 33) & (byte <= 126) & (byte != 92), "invalid origin byte");
                // The origin starts at byte 91 and has no skipped bytes.
                // Static indexing avoids a large dynamic-write multiplexer.
                origin[i - 91] = byte;
                origin_len += 1;
            }
        }
    }
    assert(closed & (origin_len > 0), "unterminated or empty origin");
    assert(sha256::sha256_var(origin, origin_len as u64) == origin_hash, "origin mismatch");
    if data.len() == end + 2 {
        assert(data.get(end + 1) == 125, "invalid JSON terminator");
    } else {
        assert(data.len() == end + 22, "unsupported clientDataJSON suffix");
        let suffix = "\",\"crossOrigin\":false}".as_bytes();
        for i in 0..22 {
            assert(data.get(end + i) == suffix[i], "crossOrigin must be false");
        }
    }
}

fn encode_challenge_base64_url(challenge: [u8; 32]) -> [u8; 43] {
    let mut encoded = [0 as u8; 43];
    for i in 0..10 {
        let input = i * 3;
        let output = i * 4;
        let a = challenge[input];
        let b = challenge[input + 1];
        let c = challenge[input + 2];
        encoded[output] = base64_url_char(a >> 2);
        encoded[output + 1] = base64_url_char(((a & 3) << 4) | (b >> 4));
        encoded[output + 2] = base64_url_char(((b & 15) << 2) | (c >> 6));
        encoded[output + 3] = base64_url_char(c & 63);
    }
    let a = challenge[30];
    let b = challenge[31];
    encoded[40] = base64_url_char(a >> 2);
    encoded[41] = base64_url_char(((a & 3) << 4) | (b >> 4));
    encoded[42] = base64_url_char((b & 15) << 2);
    encoded
}

fn base64_url_char(index: u8) -> u8 {
    if index < 26 {
        index + 65
    } else if index < 52 {
        index + 71
    } else if index < 62 {
        index - 4
    } else if index == 62 {
        45
    } else {
        95
    }
}

// Adapted from ProveKit's p256_bigcurve example:
// https://github.com/worldfnd/provekit/tree/main/noir-examples/p256_bigcurve
fn verify_p256_signature(
    hashed_message: [u8; 32],
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; SIGNATURE_LEN],
) {
    let generator = Secp256r1::one();
    let public_key = Secp256r1 {
        x: Secp256r1_Fq::from_be_bytes(public_key_x),
        y: Secp256r1_Fq::from_be_bytes(public_key_y),
        is_infinity: false,
    };
    public_key.validate_on_curve();
    let message = Secp256r1_Fr::from_be_bytes(hashed_message);

    let mut r_bytes: [u8; 32] = [0; 32];
    let mut s_bytes: [u8; 32] = [0; 32];
    for i in 0..32 {
        r_bytes[i] = signature[i];
        s_bytes[i] = signature[i + 32];
    }
    assert_valid_p256_scalar(r_bytes);
    assert_valid_p256_scalar(s_bytes);

    let expected_r_x = Secp256r1_Fq::from_be_bytes(r_bytes);
    let r = Secp256r1_Fr::from_be_bytes(r_bytes);
    let s = Secp256r1_Fr::from_be_bytes(s_bytes);
    let message_over_s = Secp256r1Scalar::from_bignum(message / s);
    let r_over_s = Secp256r1Scalar::from_bignum(r / s);
    let r_point = Secp256r1::evaluate_linear_expression(
        [generator, public_key],
        [message_over_s, r_over_s],
        [],
    );

    assert(!r_point.is_infinity);
    // ECDSA compares r with R.x reduced modulo the group order n. Because the
    // P-256 base-field modulus p is less than 2n, reduction has only two cases.
    let order_as_fq = Secp256r1_Fq::from_be_bytes(P256_GROUP_ORDER);
    let reduced_directly = r_point.x == expected_r_x;
    let reduction_subtracted_n = bytes_are_less_than(r_bytes, P256_FIELD_MINUS_ORDER)
        & (r_point.x == expected_r_x + order_as_fq);
    assert(reduced_directly | reduction_subtracted_n);
}

#[test]
fn accepts_valid_p256_scalar_boundaries() {
    let one: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1,
    ];
    let n_minus_one: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x50,
    ];
    assert_valid_p256_scalar(one);
    assert_valid_p256_scalar(n_minus_one);
}

#[test(should_fail_with = "P-256 signature scalar must not be zero")]
fn rejects_zero_p256_scalar() {
    assert_valid_p256_scalar([0; 32]);
}

#[test(should_fail_with = "P-256 signature scalar is out of range")]
fn rejects_p256_group_order_as_scalar() {
    assert_valid_p256_scalar(P256_GROUP_ORDER);
}

#[test(should_fail_with = "clientDataJSON is too short")]
fn rejects_unsigned_padding_challenge() {
    // The signed data is only '{}'; a valid-looking JSON document in padding
    // must not count as a signed challenge.
    let mut data = policy_test_data(
        "{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"http://localhost\"}"
            .as_bytes(),
    );
    data = BoundedVec::from_parts(data.storage(), 2);
    validate_client_data(data, [0; 32], test_origin_hash());
}

fn policy_test_data<let N: u32>(bytes: [u8; N]) -> BoundedVec<u8, 256> {
    let mut storage = [0 as u8; 256];
    for i in 0..N {
        storage[i] = bytes[i];
    }
    BoundedVec::from_parts(storage, N)
}

fn test_origin_hash() -> [u8; 32] {
    sha256::sha256_var("http://localhost".as_bytes(), 16)
}

#[test]
fn accepts_standard_client_data() {
    validate_client_data(
        policy_test_data(
            "{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"http://localhost\"}"
                .as_bytes(),
        ),
        [0; 32],
        test_origin_hash(),
    );
}

#[test]
fn accepts_explicit_same_origin() {
    validate_client_data(
        policy_test_data(
            "{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"http://localhost\",\"crossOrigin\":false}"
                .as_bytes(),
        ),
        [0; 32],
        test_origin_hash(),
    );
}

#[test(should_fail_with = "invalid clientDataJSON prefix")]
fn rejects_wrong_type() {
    validate_client_data(
        policy_test_data(
            "{\"type\":\"webauthn.foo\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"http://localhost\"}"
                .as_bytes(),
        ),
        [0; 32],
        test_origin_hash(),
    );
}

#[test(should_fail_with = "origin mismatch")]
fn rejects_wrong_origin() {
    validate_client_data(
        policy_test_data(
            "{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"http://evil.test\"}"
                .as_bytes(),
        ),
        [0; 32],
        test_origin_hash(),
    );
}

#[test(should_fail_with = "unsupported clientDataJSON suffix")]
fn rejects_cross_origin() {
    validate_client_data(
        policy_test_data(
            "{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"http://localhost\",\"crossOrigin\":true}"
                .as_bytes(),
        ),
        [0; 32],
        test_origin_hash(),
    );
}

#[test(should_fail_with = "crossOrigin must be false")]
fn rejects_duplicate_challenge() {
    validate_client_data(
        policy_test_data(
            "{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"http://localhost\",\"challenge\":\"decoy\"}"
                .as_bytes(),
        ),
        [0; 32],
        test_origin_hash(),
    );
}

#[test(should_fail_with = "unsupported clientDataJSON suffix")]
fn rejects_trailing_bytes() {
    validate_client_data(
        policy_test_data(
            "{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"http://localhost\"} "
                .as_bytes(),
        ),
        [0; 32],
        test_origin_hash(),
    );
}

fn concat<let N: u32>(a: BoundedVec<u8, N>, b: [u8; 32]) -> BoundedVec<u8, N + 32> {
    let mut result = [0 as u8; N + 32];
    let mut j = 0;
    for i in 0..N {
        if i < a.len() {
            result[j] = a.get(i);
            j += 1;
        }
    }
    for i in 0..b.len() {
        result[j] = b[i];
        j += 1;
    }
    BoundedVec::from_parts(result, j)
}
