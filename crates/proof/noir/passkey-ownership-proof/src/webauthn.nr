use bigcurve::{
    BigCurve,
    curves::secp256r1::{Secp256r1, Secp256r1_Fq, Secp256r1_Fr, Secp256r1Scalar},
};
use bignum::BigNum;

pub global SIGNATURE_LEN: u32 = 64;

pub fn verify_signature<let CLIENT_DATA_JSON_MAX_LEN: u32, let AUTHENTICATOR_DATA_MAX_LEN: u32>(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    signature: [u8; SIGNATURE_LEN],
    client_data_json: BoundedVec<u8, CLIENT_DATA_JSON_MAX_LEN>,
    authenticator_data: BoundedVec<u8, AUTHENTICATOR_DATA_MAX_LEN>,
    challenge: [u8; 32],
    challenge_index: u32,
) {
    let client_data_json_hash =
        sha256::sha256_var(client_data_json.storage(), client_data_json.len() as u64);
    let concatenated: BoundedVec<u8, AUTHENTICATOR_DATA_MAX_LEN + 32> =
        concat(authenticator_data, client_data_json_hash);
    let hashed_message = sha256::sha256_var(concatenated.storage(), concatenated.len() as u64);

    let challenge_base64_url = encode_challenge_base64_url(challenge);
    str_contains_base64_url(
        client_data_json.storage(),
        challenge_base64_url,
        challenge_index,
    );

    verify_p256_signature(hashed_message, public_key_x, public_key_y, signature);
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
    assert(r_point.x == expected_r_x);
}

fn str_contains_base64_url<let N: u32, let H: u32>(haystack: [u8; H], needle: [u8; N], index: u32) {
    for i in 0..needle.len() {
        if needle[i] != 61 {
            assert(haystack[index + i] == needle[i]);
        }
    }
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
