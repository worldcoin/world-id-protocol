//! The `worldid_auth_v1_register` request (WIP-109 §3.3.1, §3.3.2 and §3.6.1).

use std::fmt;

use alloy::primitives::Address;
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use sha2::{Digest as _, Sha256};
use world_id_primitives::{
    FieldElement, PrimitiveError,
    authenticator_message::{MessageError, MethodName, Request, Value},
    poseidon::{self, ds},
    serde_utils::deserialize_present,
};

use super::{
    reject_tags,
    session::{RequestId, ResponsePublicKey},
};

/// The method of the registration request.
pub const REGISTER_METHOD: MethodName = MethodName::from_static("worldid_auth_v1_register");

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

const DIGEST_LABEL: &[u8] = b"WORLD-ID/WIP-109/REGISTER";

/// The SHA-256 commitment to the registration parameters, carried in the Pairing URI.
///
/// It lets the Approving Authenticator detect a request that was substituted on the way. It
/// covers the [`RequestId`], the new authenticator's signing key and address, and the response
/// key, but not the name.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegistrationDigest([u8; 32]);

impl RegistrationDigest {
    /// Computes the digest over the fixed-width encoding of the registration parameters. A
    /// Proving Authenticator, without `new_authenticator_address`, is encoded as the zero address.
    fn compute(
        request_id: &RequestId,
        new_authenticator_pubkey: &EdDSAPublicKey,
        new_authenticator_address: Option<Address>,
        response_pubkey: &ResponsePublicKey,
    ) -> Result<Self, PrimitiveError> {
        let pubkey = new_authenticator_pubkey
            .to_compressed_bytes()
            .map_err(|e| PrimitiveError::Serialization(e.to_string()))?;
        let digest = Sha256::new()
            .chain_update(DIGEST_LABEL)
            .chain_update(request_id.as_bytes())
            .chain_update(pubkey)
            .chain_update(new_authenticator_address.unwrap_or(Address::ZERO))
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
/// Decode received params with [`RegistrationRequest::from_params`]. The `Deserialize` impl alone
/// skips CBOR tags, which WIP-109 payloads must not contain.
///
/// Decoding only checks encodings and bounds. The Approving Authenticator still has to compare
/// [`RegistrationRequest::digest`] with the digest from the Pairing URI and verify the signature
/// with [`RegistrationRequest::verify_signature`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    /// The signing key the Requesting Authenticator asks to register.
    #[serde(with = "eddsa_pubkey")]
    pub new_authenticator_pubkey: EdDSAPublicKey,
    /// The management key address of an Admin Authenticator, or `None` for a Proving
    /// Authenticator (WIP-104). Never the zero address.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "authenticator_address"
    )]
    pub new_authenticator_address: Option<Address>,
    /// The key the response must be sealed to.
    #[serde(with = "xwing_pubkey")]
    pub response_pubkey: ResponsePublicKey,
    /// An optional, unauthenticated label for the new authenticator.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub name: Option<AuthenticatorName>,
    /// The signature over the [`RegistrationDigest`] by `new_authenticator_pubkey`.
    #[serde(with = "eddsa_signature")]
    pub registration_sig: EdDSASignature,
}

impl RegistrationRequest {
    /// Builds a request for `signing_key` and signs its digest, returning the request together
    /// with the digest to put in the Pairing URI.
    ///
    /// # Errors
    ///
    /// - [`PrimitiveError::InvalidInput`] if `new_authenticator_address` is the zero address.
    /// - Another [`PrimitiveError`] if the public key fails to serialize.
    pub fn new_signed(
        signing_key: &EdDSAPrivateKey,
        new_authenticator_address: Option<Address>,
        response_pubkey: ResponsePublicKey,
        name: Option<AuthenticatorName>,
        request_id: &RequestId,
    ) -> Result<(Self, RegistrationDigest), PrimitiveError> {
        let new_authenticator_address = new_authenticator_address
            .map(non_zero_address)
            .transpose()
            .map_err(|reason| PrimitiveError::InvalidInput {
                attribute: "new_authenticator_address".to_string(),
                reason: reason.to_string(),
            })?;
        let new_authenticator_pubkey = signing_key.public();
        let digest = RegistrationDigest::compute(
            request_id,
            &new_authenticator_pubkey,
            new_authenticator_address,
            &response_pubkey,
        )?;
        let registration_sig = signing_key.sign(*digest.signing_message());
        let request = Self {
            new_authenticator_pubkey,
            new_authenticator_address,
            response_pubkey,
            name,
            registration_sig,
        };
        Ok((request, digest))
    }

    /// Decodes the `params` of a received registration request.
    ///
    /// The Approving Authenticator decodes the request envelope as a [`Request<Value>`] first, so
    /// that it can answer an invalid request with its `id`, and passes the `params` here once the
    /// `id` and `method` are checked.
    ///
    /// # Errors
    ///
    /// Returns [`MessageError::Deserialize`] if `params` contains a CBOR tag at any depth or does
    /// not match the request schema.
    pub fn from_params(params: &Value) -> Result<Self, MessageError> {
        reject_tags(params)?;
        params
            .deserialized()
            .map_err(|error| MessageError::Deserialize(serde::de::Error::custom(error)))
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
            self.new_authenticator_address,
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

/// The registration request as sent over the bridge.
///
/// The Requesting Authenticator builds and encodes it. A received request is decoded in two
/// steps, as described on [`RegistrationRequest::from_params`].
pub type RegisterRequestMessage = Request<RegistrationRequest>;

/// Returns `address`, unless it is the zero address, which WIP-109 §3.6.1 forbids as
/// `new_authenticator_address`: on-chain, the zero address marks a Proving Authenticator.
fn non_zero_address(address: Address) -> Result<Address, &'static str> {
    if address.is_zero() {
        return Err("new_authenticator_address must not be the zero address");
    }
    Ok(address)
}

/// The compressed public key (WIP-100 §4) as a 32-byte CBOR byte string.
mod eddsa_pubkey {
    use eddsa_babyjubjub::EdDSAPublicKey;
    use serde::{Deserializer, Serializer, de::Error as _, ser::Error as _};
    use world_id_primitives::serde_utils::cbor;

    pub(super) fn serialize<S: Serializer>(
        key: &EdDSAPublicKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let bytes = key.to_compressed_bytes().map_err(S::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EdDSAPublicKey, D::Error> {
        EdDSAPublicKey::from_compressed_bytes(cbor::deserialize_byte_array(deserializer)?)
            .map_err(|_| D::Error::custom("invalid EdDSA public key"))
    }
}

/// The compressed EdDSA signature as a 64-byte CBOR byte string.
mod eddsa_signature {
    use eddsa_babyjubjub::EdDSASignature;
    use serde::{Deserializer, Serializer, de::Error as _, ser::Error as _};
    use world_id_primitives::serde_utils::cbor;

    pub(super) fn serialize<S: Serializer>(
        signature: &EdDSASignature,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let bytes = signature.to_compressed_bytes().map_err(S::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EdDSASignature, D::Error> {
        EdDSASignature::from_compressed_bytes(cbor::deserialize_byte_array(deserializer)?)
            .map_err(|_| D::Error::custom("invalid EdDSA signature"))
    }
}

/// A present `new_authenticator_address` as a 20-byte CBOR byte string, never the zero address.
mod authenticator_address {
    use alloy::primitives::Address;
    use serde::{Deserializer, Serializer, de::Error as _, ser::Error as _};
    use world_id_primitives::serde_utils::cbor;

    use super::non_zero_address;

    pub(super) fn serialize<S: Serializer>(
        address: &Option<Address>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let Some(address) = address else {
            return serializer.serialize_none();
        };
        let address = non_zero_address(*address).map_err(S::Error::custom)?;
        serializer.serialize_bytes(address.as_slice())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Address>, D::Error> {
        let address = Address::from(cbor::deserialize_byte_array(deserializer)?);
        non_zero_address(address)
            .map(Some)
            .map_err(D::Error::custom)
    }
}

/// The X-Wing encapsulation key as a 1216-byte CBOR byte string.
mod xwing_pubkey {
    use serde::{Deserializer, Serializer, de::Error as _};
    use world_id_primitives::serde_utils::cbor;

    use super::ResponsePublicKey;

    pub(super) fn serialize<S: Serializer>(
        key: &ResponsePublicKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&key.to_bytes())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ResponsePublicKey, D::Error> {
        ResponsePublicKey::from_bytes(&cbor::deserialize_byte_string(deserializer)?)
            .map_err(|_| D::Error::custom("invalid X-Wing encapsulation key"))
    }
}

#[cfg(test)]
mod tests {
    use world_id_primitives::authenticator_message;

    use super::*;
    use crate::registration::{MAX_REQUEST_SIZE, PairingSecret, ResponseSecretKey};

    const ADMIN: Option<Address> = Some(Address::repeat_byte(0x11));
    const PROVING: Option<Address> = None;

    fn signing_key(seed: u8) -> EdDSAPrivateKey {
        EdDSAPrivateKey::from_bytes([seed; 32])
    }

    fn signed_request(
        new_authenticator_address: Option<Address>,
    ) -> (RegistrationRequest, RegistrationDigest, RequestId) {
        let request_id = PairingSecret::from_bytes([9; 32]).request_id();
        let response_pubkey = ResponseSecretKey::from_seed(&[4; 32]).public_key();
        let name = AuthenticatorName::try_from("Chrome on MacBook".to_string()).unwrap();
        let (request, digest) = RegistrationRequest::new_signed(
            &signing_key(1),
            new_authenticator_address,
            response_pubkey,
            Some(name),
            &request_id,
        )
        .unwrap();
        (request, digest, request_id)
    }

    #[test]
    fn signed_request_verifies_against_its_digest() {
        for address in [ADMIN, PROVING] {
            let (request, digest, request_id) = signed_request(address);
            assert_eq!(request.digest(&request_id).unwrap(), digest);
            assert!(request.verify_signature(&digest));
        }
    }

    #[test]
    fn digest_binds_every_authenticated_parameter() {
        let (request, digest, request_id) = signed_request(ADMIN);

        let other_request_id = PairingSecret::from_bytes([10; 32]).request_id();
        assert_ne!(request.digest(&other_request_id).unwrap(), digest);

        let mut proving = request.clone();
        proving.new_authenticator_address = PROVING;
        assert_ne!(proving.digest(&request_id).unwrap(), digest);

        let mut other_address = request.clone();
        other_address.new_authenticator_address = Some(Address::repeat_byte(0x22));
        assert_ne!(other_address.digest(&request_id).unwrap(), digest);

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
    fn zero_address_is_neither_signed_nor_encoded() {
        let zero = Some(Address::ZERO);
        let request_id = PairingSecret::from_bytes([9; 32]).request_id();
        let response_pubkey = ResponseSecretKey::from_seed(&[4; 32]).public_key();
        assert!(
            RegistrationRequest::new_signed(
                &signing_key(1),
                zero,
                response_pubkey,
                None,
                &request_id
            )
            .is_err()
        );

        let (mut request, _, request_id) = signed_request(ADMIN);
        request.new_authenticator_address = zero;
        let message = RegisterRequestMessage::builder()
            .id(request_id.message_id())
            .method(REGISTER_METHOD)
            .params(request)
            .build();
        assert!(authenticator_message::encode(&message).is_err());
    }

    #[test]
    fn request_round_trips_through_cbor() {
        for address in [ADMIN, PROVING] {
            let (request, _, request_id) = signed_request(address);
            let message = RegisterRequestMessage::builder()
                .id(request_id.message_id())
                .method(REGISTER_METHOD)
                .params(request.clone())
                .build();
            let encoded = authenticator_message::encode(&message).unwrap();
            let received: Request<Value> =
                authenticator_message::decode(&encoded, MAX_REQUEST_SIZE).unwrap();
            let params = received.params.unwrap();
            assert_eq!(RegistrationRequest::from_params(&params).unwrap(), request);
        }
    }

    #[test]
    fn decode_rejects_malformed_params() {
        let (request, _, _) = signed_request(ADMIN);
        let params = Value::serialized(&request).unwrap();
        let with_field = |field: &str, value: Option<Value>| {
            let Value::Map(mut entries) = params.clone() else {
                unreachable!("params serialize as a map")
            };
            entries.retain(|(key, _)| key.as_text() != Some(field));
            entries.extend(value.map(|value| (Value::from(field), value)));
            Value::Map(entries)
        };

        assert!(RegistrationRequest::from_params(&params).is_ok());
        for (case, invalid) in [
            ("tagged params", Value::Tag(55799, Box::new(params.clone()))),
            (
                "tagged name",
                with_field("name", Some(Value::Tag(0, Box::new("phone".into())))),
            ),
            ("null name", with_field("name", Some(Value::Null))),
            ("long name", with_field("name", Some("x".repeat(65).into()))),
            (
                "null address",
                with_field("new_authenticator_address", Some(Value::Null)),
            ),
            (
                "zero address",
                with_field("new_authenticator_address", Some(Value::Bytes(vec![0; 20]))),
            ),
            (
                "short address",
                with_field("new_authenticator_address", Some(Value::Bytes(vec![1; 19]))),
            ),
            (
                "short pubkey",
                with_field("new_authenticator_pubkey", Some(Value::Bytes(vec![0; 31]))),
            ),
            (
                "text pubkey",
                with_field("new_authenticator_pubkey", Some("0x12".into())),
            ),
            (
                "short response key",
                with_field("response_pubkey", Some(Value::Bytes(vec![1; 1215]))),
            ),
            (
                "short signature",
                with_field("registration_sig", Some(Value::Bytes(vec![1; 63]))),
            ),
            ("missing signature", with_field("registration_sig", None)),
            ("unknown field", with_field("class", Some("admin".into()))),
        ] {
            assert!(
                RegistrationRequest::from_params(&invalid).is_err(),
                "{case}"
            );
        }
    }
}
