//! Regression vectors for the session derivations, and an independently computed pairing-key
//! vector.
//!
//! Inputs: the pairing secret is the bytes `00..1f` and the X-Wing response key is derived from
//! the seed of 32 bytes of `0x24`.

use sha2::{Digest as _, Sha256};

use super::*;

const REQUEST_ID: &str = "1e52a797a94d90f9de7addf1f9e61dc20033150e725dcc4f0a7947d5df13f7c4";

const RESPONSE_PUBKEY_SHA256: &str =
    "1e837bea0394a1f718a5fe32860f9a2b18fa2473dc8d42ea8a6413fe8f1d3bd7";

fn pairing_secret() -> PairingSecret {
    PairingSecret::from_bytes(std::array::from_fn(|i| u8::try_from(i).unwrap()))
}

#[test]
fn session_derivations_match_vectors() {
    let secret = pairing_secret();
    assert_eq!(secret.request_id().to_string(), REQUEST_ID);
    assert_eq!(secret.request_id().message_id(), REQUEST_ID.to_string());
    // Independently computed with libargon2 and Python cryptography HKDF-SHA256.
    assert_eq!(
        hex::encode(
            secret
                .transport_key(&"QJTWPK".parse().unwrap())
                .unwrap()
                .key()
        ),
        "d54c3095e7243461690e9589eb9c39ebdeafa3f585b0a8586958b5bdb067dc7c"
    );

    let response_pubkey = ResponseSecretKey::from_seed(&[0x24; 32]).public_key();
    assert_eq!(
        hex::encode(Sha256::digest(response_pubkey.to_bytes())),
        RESPONSE_PUBKEY_SHA256
    );
}
