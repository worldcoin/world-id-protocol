//! The normative test vectors of WIP-109 Appendix A.
//!
//! Inputs: the pairing secret is the bytes `00..1f`, the EdDSA signing key is 32 bytes of `0x42`,
//! the X-Wing response key is derived from the seed of 32 bytes of `0x24`, and the Admin
//! Authenticator's management key is `0xabab..ab`.

use alloy::primitives::Address;
use eddsa_babyjubjub::EdDSAPrivateKey;
use sha2::{Digest as _, Sha256};

use super::*;

struct ClassVector {
    class: AuthenticatorClass,
    digest: &'static str,
    signing_message: &'static str,
    registration_sig: &'static str,
    pairing_uri: &'static str,
}

const REQUEST_ID: &str = "1e52a797a94d90f9de7addf1f9e61dc20033150e725dcc4f0a7947d5df13f7c4";
const TRANSPORT_SECRET: &str = "0da9f35aa50d243d41afaca8c8fbc583b43c762976c21947e7c42329dfcff01c";
const NEW_AUTHENTICATOR_PUBKEY: &str =
    "0xe7022bc5049a4df69f8681454fe75af14157890a0f15a9bd8b8252d387c62e4";
const RESPONSE_PUBKEY_SHA256: &str =
    "1e837bea0394a1f718a5fe32860f9a2b18fa2473dc8d42ea8a6413fe8f1d3bd7";

fn class_vectors() -> [ClassVector; 2] {
    [
        ClassVector {
            class: AuthenticatorClass::Proving,
            digest: "cbdf106f16bb216c2683ca74310895eb889373af30e286d9694a5cf6d1c066b4",
            signing_message: "0x268a28e6287640c6934f09becbbf459480ab117829b27aa0ee7c2510e774c7b6",
            registration_sig: "f2e3e6b3388ad468d500fe9236b761fa7a1a8f068e51328e10de4ad8b68b2113\
                               9e418464589fdbbd822d3a6825481eca77391d0213b0b9c92323f83c4a716504",
            pairing_uri: "worldid://auth/v1/register\
                          ?s=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\
                          &d=y98Qbxa7IWwmg8p0MQiV64iTc68w4obZaUpc9tHAZrQ\
                          &b=bridge.example.org",
        },
        ClassVector {
            class: AuthenticatorClass::Admin {
                address: Address::repeat_byte(0xab),
            },
            digest: "e17f1c1d890054d205883b517ff8a789738bc91f1a6c2f5d66437a8f30951866",
            signing_message: "0x23372ab4faf2148f94d16a63bdcc17b69374981d2f63db7e4ed5c3c653a51931",
            registration_sig: "605b968fdd130f6fef1b7a391f090e7bcf67be9cca01c1038e95fe6c2952ca19\
                               dae39db7cf8e098f745c6b498e9652442a4096eb0e3d0dc0fef6dd83df1dd600",
            pairing_uri: "worldid://auth/v1/register\
                          ?s=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\
                          &d=4X8cHYkAVNIFiDtRf_iniXOLyR8abC9dZkN6jzCVGGY\
                          &b=bridge.example.org",
        },
    ]
}

fn pairing_secret() -> PairingSecret {
    PairingSecret::from_bytes(std::array::from_fn(|i| u8::try_from(i).unwrap()))
}

#[test]
fn session_derivations_match_vectors() {
    let secret = pairing_secret();
    assert_eq!(secret.request_id().to_string(), REQUEST_ID);
    assert_eq!(
        hex::encode(secret.transport_key().0.as_ref()),
        TRANSPORT_SECRET
    );

    let response_pubkey = ResponseSecretKey::from_seed(&[0x24; 32]).public_key();
    assert_eq!(
        hex::encode(Sha256::digest(response_pubkey.to_bytes())),
        RESPONSE_PUBKEY_SHA256
    );
}

#[test]
fn registration_request_matches_vectors() {
    let secret = pairing_secret();
    let request_id = secret.request_id();
    let signing_key = EdDSAPrivateKey::from_bytes([0x42; 32]);
    let response_pubkey = ResponseSecretKey::from_seed(&[0x24; 32]).public_key();

    for vector in class_vectors() {
        let (request, digest) = RegistrationRequest::new_signed(
            &signing_key,
            vector.class,
            response_pubkey.clone(),
            None,
            &request_id,
        )
        .unwrap();

        let params = serde_json::to_value(&request).unwrap();
        assert_eq!(params["new_authenticator_pubkey"], NEW_AUTHENTICATOR_PUBKEY);
        assert_eq!(hex::encode(digest.as_bytes()), vector.digest);
        assert_eq!(digest.signing_message().to_string(), vector.signing_message);
        assert_eq!(
            hex::encode(request.registration_sig.to_compressed_bytes().unwrap()),
            vector.registration_sig
        );

        let uri = PairingUri {
            secret: secret.clone(),
            digest,
            bridge: Some("bridge.example.org".parse().unwrap()),
        };
        assert_eq!(uri.to_string(), vector.pairing_uri);
    }
}
