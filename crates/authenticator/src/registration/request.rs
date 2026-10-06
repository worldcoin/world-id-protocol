//! The `worldid_auth_v1_register` request (WIP-109 §3.3.1, §3.3.2 and §3.6.1).

use std::{fmt, str::FromStr};

use alloy::primitives::Address;
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use ruint::aliases::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest as _, Sha256};
use world_id_primitives::{
    FieldElement, PrimitiveError,
    authenticator_message::{MethodName, Request},
    poseidon::{self, ds},
    serde_utils::{hex_array, strict_hex_u256},
};

use super::session::{RESPONSE_PUBLIC_KEY_LEN, RequestId, ResponsePublicKey};
use crate::{account::AuthenticatorClass, traits::OnchainKeyRepresentable as _};

/// The method of the registration request.
pub const REGISTER_METHOD: MethodName = MethodName::from_static("worldid_auth_v1_register");

/// The registration request as sent over the bridge.
pub type RegisterRequestMessage = Request<RegistrationRequest>;

const DIGEST_LABEL: &[u8] = b"WORLD-ID/WIP-109/REGISTER";

/// The maximum length in bytes of an [`AuthenticatorName`].
pub const MAX_NAME_LEN: usize = 64;

/// A self-reported, advisory label for an authenticator, at most [`MAX_NAME_LEN`] bytes of UTF-8.
///
/// The name is not authenticated. Approving Authenticators decide which names they accept and
/// display them as untrusted text.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct AuthenticatorName(String);

impl AuthenticatorName {
    /// Returns the name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AuthenticatorName {
    type Error = NameTooLong;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if name.len() > MAX_NAME_LEN {
            return Err(NameTooLong);
        }
        Ok(Self(name))
    }
}

impl<'de> Deserialize<'de> for AuthenticatorName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl fmt::Display for AuthenticatorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The error returned when an [`AuthenticatorName`] is longer than [`MAX_NAME_LEN`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("authenticator name must be at most {MAX_NAME_LEN} bytes")]
pub struct NameTooLong;

/// The SHA-256 commitment to the registration parameters, carried in the Pairing URI.
///
/// It lets the Approving Authenticator detect a request that was substituted on the way. It
/// covers the [`RequestId`], the new authenticator's keys and the response key, but not the name.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegistrationDigest([u8; 32]);

impl RegistrationDigest {
    /// Computes the digest over the fixed-width encoding of the registration parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if `new_authenticator_pubkey` fails to serialize.
    pub fn compute(
        request_id: &RequestId,
        new_authenticator_pubkey: &EdDSAPublicKey,
        class: &AuthenticatorClass,
        response_pubkey: &ResponsePublicKey,
    ) -> Result<Self, PrimitiveError> {
        let pubkey = new_authenticator_pubkey
            .to_compressed_bytes()
            .map_err(|e| PrimitiveError::Serialization(e.to_string()))?;
        let digest = Sha256::new()
            .chain_update(DIGEST_LABEL)
            .chain_update(request_id.as_bytes())
            .chain_update(pubkey)
            .chain_update(class.onchain_address())
            .chain_update(response_pubkey.to_bytes())
            .finalize();
        Ok(Self(digest.into()))
    }

    /// Wraps raw digest bytes, e.g. ones parsed from a Pairing URI.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowers the digest into the field element signed by the registration signature: the
    /// Poseidon2 hash of its big-endian halves.
    #[must_use]
    pub fn signing_message(&self) -> FieldElement {
        let (hi, lo) = self.0.split_at(16);
        let half = |bytes: &[u8]| {
            FieldElement::from(u128::from_be_bytes(
                bytes.try_into().expect("a digest half is 16 bytes"),
            ))
        };
        poseidon::hash(ds::AUTHENTICATOR_REGISTRATION, [half(hi), half(lo)])
    }
}

impl fmt::Debug for RegistrationDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegistrationDigest({})", hex::encode(self.0))
    }
}

/// The `params` of a `worldid_auth_v1_register` request.
///
/// Deserialization only checks encodings and bounds. The Approving Authenticator still has to
/// compare [`RegistrationRequest::digest`] with the digest from the Pairing URI and verify the
/// signature with [`RegistrationRequest::verify_signature`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationRequest {
    /// The signing key the Requesting Authenticator asks to register.
    pub new_authenticator_pubkey: EdDSAPublicKey,
    /// The class the Requesting Authenticator asks for, with its management key if it is an
    /// Admin Authenticator.
    pub class: AuthenticatorClass,
    /// The key the response must be sealed to.
    pub response_pubkey: ResponsePublicKey,
    /// An optional, unauthenticated label for the new authenticator.
    pub name: Option<AuthenticatorName>,
    /// The signature over the [`RegistrationDigest`] by `new_authenticator_pubkey`.
    pub registration_sig: EdDSASignature,
}

impl RegistrationRequest {
    /// Builds a request for `signing_key` and signs its digest, returning the request together
    /// with the digest to put in the Pairing URI.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key fails to serialize.
    pub fn new_signed(
        signing_key: &EdDSAPrivateKey,
        class: AuthenticatorClass,
        response_pubkey: ResponsePublicKey,
        name: Option<AuthenticatorName>,
        request_id: &RequestId,
    ) -> Result<(Self, RegistrationDigest), PrimitiveError> {
        let new_authenticator_pubkey = signing_key.public();
        let digest = RegistrationDigest::compute(
            request_id,
            &new_authenticator_pubkey,
            &class,
            &response_pubkey,
        )?;
        let registration_sig = signing_key.sign(*digest.signing_message());
        let request = Self {
            new_authenticator_pubkey,
            class,
            response_pubkey,
            name,
            registration_sig,
        };
        Ok((request, digest))
    }

    /// Recomputes the digest of this request for the session identified by `request_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key fails to serialize.
    pub fn digest(&self, request_id: &RequestId) -> Result<RegistrationDigest, PrimitiveError> {
        RegistrationDigest::compute(
            request_id,
            &self.new_authenticator_pubkey,
            &self.class,
            &self.response_pubkey,
        )
    }

    /// Returns whether `registration_sig` is a valid signature of `digest` by the new
    /// authenticator's key.
    #[must_use]
    pub fn verify_signature(&self, digest: &RegistrationDigest) -> bool {
        self.new_authenticator_pubkey
            .verify(*digest.signing_message(), &self.registration_sig)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRegistrationRequest {
    #[serde(with = "strict_hex_u256")]
    new_authenticator_pubkey: U256,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    new_authenticator_address: Option<String>,
    #[serde(with = "hex_array")]
    response_pubkey: [u8; RESPONSE_PUBLIC_KEY_LEN],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<AuthenticatorName>,
    #[serde(with = "hex_array")]
    registration_sig: [u8; 64],
}

impl Serialize for RegistrationRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let address = match self.class {
            AuthenticatorClass::Admin { address } => Some(address.to_checksum(None)),
            AuthenticatorClass::Proving => None,
        };
        let response_pubkey =
            self.response_pubkey.to_bytes().try_into().map_err(|_| {
                serde::ser::Error::custom("response public key has the wrong length")
            })?;
        WireRegistrationRequest {
            new_authenticator_pubkey: self
                .new_authenticator_pubkey
                .to_ethereum_representation()
                .map_err(serde::ser::Error::custom)?,
            new_authenticator_address: address,
            response_pubkey,
            name: self.name.clone(),
            registration_sig: self
                .registration_sig
                .to_compressed_bytes()
                .map_err(serde::ser::Error::custom)?,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RegistrationRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = WireRegistrationRequest::deserialize(deserializer)?;
        let new_authenticator_pubkey =
            EdDSAPublicKey::from_compressed_bytes(wire.new_authenticator_pubkey.to_le_bytes())
                .map_err(|_| D::Error::custom("invalid new_authenticator_pubkey"))?;
        let class = match wire.new_authenticator_address {
            Some(address) => AuthenticatorClass::Admin {
                address: parse_management_address(&address).map_err(D::Error::custom)?,
            },
            None => AuthenticatorClass::Proving,
        };
        let response_pubkey = ResponsePublicKey::from_bytes(&wire.response_pubkey)
            .map_err(|_| D::Error::custom("invalid response_pubkey"))?;
        let registration_sig = EdDSASignature::from_compressed_bytes(wire.registration_sig)
            .map_err(|_| D::Error::custom("invalid registration_sig"))?;
        Ok(Self {
            new_authenticator_pubkey,
            class,
            response_pubkey,
            name: wire.name,
            registration_sig,
        })
    }
}

/// Parses a `0x`-prefixed, 20-byte management key address. A mixed-case address must carry a
/// valid ERC-55 checksum, and the zero address is rejected.
fn parse_management_address(address: &str) -> Result<Address, &'static str> {
    let digits = address
        .strip_prefix("0x")
        .filter(|digits| digits.len() == 40 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("new_authenticator_address must be 0x-prefixed 20-byte hex")?;
    let is_mixed_case = digits.bytes().any(|b| b.is_ascii_uppercase())
        && digits.bytes().any(|b| b.is_ascii_lowercase());
    let parsed = if is_mixed_case {
        Address::parse_checksummed(address, None)
            .map_err(|_| "new_authenticator_address has an invalid ERC-55 checksum")?
    } else {
        Address::from_str(address).map_err(|_| "invalid new_authenticator_address")?
    };
    if parsed.is_zero() {
        return Err("new_authenticator_address must not be the zero address");
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use world_id_primitives::authenticator_message::Id;

    use super::*;
    use crate::registration::{PairingSecret, ResponseSecretKey};

    fn signing_key(seed: u8) -> EdDSAPrivateKey {
        EdDSAPrivateKey::from_bytes([seed; 32])
    }

    fn admin() -> AuthenticatorClass {
        AuthenticatorClass::Admin {
            address: Address::repeat_byte(0x11),
        }
    }

    fn signed_request(
        class: AuthenticatorClass,
    ) -> (RegistrationRequest, RegistrationDigest, RequestId) {
        let request_id = PairingSecret::from_bytes([9; 32]).request_id();
        let response_pubkey = ResponseSecretKey::from_seed(&[4; 32]).public_key();
        let name = AuthenticatorName::try_from("Chrome on MacBook".to_string()).unwrap();
        let (request, digest) = RegistrationRequest::new_signed(
            &signing_key(1),
            class,
            response_pubkey,
            Some(name),
            &request_id,
        )
        .unwrap();
        (request, digest, request_id)
    }

    #[test]
    fn signed_request_verifies_against_its_digest() {
        for class in [admin(), AuthenticatorClass::Proving] {
            let (request, digest, request_id) = signed_request(class);
            assert_eq!(request.digest(&request_id).unwrap(), digest);
            assert!(request.verify_signature(&digest));
        }
    }

    #[test]
    fn digest_binds_every_authenticated_parameter() {
        let (request, digest, request_id) = signed_request(admin());

        let other_request_id = PairingSecret::from_bytes([10; 32]).request_id();
        assert_ne!(request.digest(&other_request_id).unwrap(), digest);

        let mut proving = request.clone();
        proving.class = AuthenticatorClass::Proving;
        assert_ne!(proving.digest(&request_id).unwrap(), digest);

        let mut other_key = request.clone();
        other_key.new_authenticator_pubkey = signing_key(2).public();
        assert_ne!(other_key.digest(&request_id).unwrap(), digest);
        assert!(!other_key.verify_signature(&digest));

        let mut other_response_key = request.clone();
        other_response_key.response_pubkey = ResponseSecretKey::from_seed(&[5; 32]).public_key();
        assert_ne!(other_response_key.digest(&request_id).unwrap(), digest);

        let mut renamed = request;
        renamed.name = None;
        assert_eq!(renamed.digest(&request_id).unwrap(), digest);
    }

    #[test]
    fn request_round_trips_through_json() {
        for class in [admin(), AuthenticatorClass::Proving] {
            let (request, _, request_id) = signed_request(class);
            let message = RegisterRequestMessage::new(
                Id::String(request_id.to_string()),
                REGISTER_METHOD,
                request,
            );
            let json = serde_json::to_value(&message).unwrap();
            assert_eq!(
                json["params"].get("new_authenticator_address").is_some(),
                matches!(class, AuthenticatorClass::Admin { .. })
            );
            let parsed: RegisterRequestMessage = serde_json::from_value(json).unwrap();
            assert_eq!(parsed, message);
        }
    }

    fn params_json() -> serde_json::Value {
        let (request, _, _) = signed_request(admin());
        serde_json::to_value(request).unwrap()
    }

    #[test]
    fn deserialization_rejects_invalid_params() {
        let mutations: Vec<(&str, serde_json::Value)> = vec![
            ("new_authenticator_pubkey", json!("0x0")),
            ("new_authenticator_pubkey", json!("12345")),
            (
                "new_authenticator_address",
                json!("0x0000000000000000000000000000000000000000"),
            ),
            (
                "new_authenticator_address",
                json!("0x11111111111111111111111111111111111111"),
            ),
            (
                "new_authenticator_address",
                json!("0xaAaAaAaAaAaAaAaAaAaAAaAaAaAaAaAaAaAaAaAa"),
            ),
            ("response_pubkey", json!("0x00")),
            (
                "response_pubkey",
                json!(format!("0x{}", "00".repeat(RESPONSE_PUBLIC_KEY_LEN - 1))),
            ),
            ("registration_sig", json!("0x00")),
            ("name", json!("x".repeat(MAX_NAME_LEN + 1))),
            ("unexpected", json!(1)),
        ];
        for (key, value) in mutations {
            let mut params = params_json();
            params[key] = value;
            assert!(
                serde_json::from_value::<RegistrationRequest>(params).is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn deserialization_validates_address_checksums() {
        let checksummed = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let mut params = params_json();
        params["new_authenticator_address"] = json!(checksummed);
        let parsed: RegistrationRequest = serde_json::from_value(params.clone()).unwrap();
        assert_eq!(
            parsed.class,
            AuthenticatorClass::Admin {
                address: Address::from_str(checksummed).unwrap()
            }
        );

        params["new_authenticator_address"] = json!(checksummed.to_lowercase());
        assert!(serde_json::from_value::<RegistrationRequest>(params).is_ok());
    }

    #[test]
    fn missing_address_means_proving() {
        let mut params = params_json();
        params
            .as_object_mut()
            .unwrap()
            .remove("new_authenticator_address");
        let parsed: RegistrationRequest = serde_json::from_value(params).unwrap();
        assert_eq!(parsed.class, AuthenticatorClass::Proving);
    }
}
