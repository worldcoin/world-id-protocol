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
        return Err("must not be the zero address");
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
        let address = non_zero_address(*address).map_err(|reason| {
            S::Error::custom(format_args!("new_authenticator_address {reason}"))
        })?;
        serializer.serialize_bytes(address.as_slice())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Address>, D::Error> {
        let address = Address::from(cbor::deserialize_byte_array(deserializer)?);
        non_zero_address(address)
            .map(Some)
            .map_err(|reason| D::Error::custom(format_args!("new_authenticator_address {reason}")))
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
    use test_case::test_case;

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

    /// The params of an Admin Authenticator's [`signed_request`].
    fn admin_params() -> Value {
        Value::serialized(&signed_request(ADMIN).0).unwrap()
    }

    /// [`admin_params`] with `field` set to `value`, or removed if `value` is `None`.
    fn params_with(field: &str, value: Option<Value>) -> Value {
        let Value::Map(mut entries) = admin_params() else {
            unreachable!("params serialize as a map")
        };
        entries.retain(|(key, _)| key.as_text() != Some(field));
        entries.extend(value.map(|value| (Value::from(field), value)));
        Value::Map(entries)
    }

    #[test_case(ADMIN; "admin")]
    #[test_case(PROVING; "proving")]
    fn signed_request_verifies_against_its_digest(new_authenticator_address: Option<Address>) {
        let (request, digest, request_id) = signed_request(new_authenticator_address);
        assert_eq!(request.digest(&request_id).unwrap(), digest);
        assert!(request.verify_signature(&digest));
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
        let signing = RegistrationRequest::new_signed(
            &signing_key(1),
            zero,
            response_pubkey,
            None,
            &request_id,
        );
        assert_eq!(
            signing.unwrap_err().to_string(),
            "Invalid input at new_authenticator_address: must not be the zero address"
        );

        let (mut request, _, request_id) = signed_request(ADMIN);
        request.new_authenticator_address = zero;
        let message = RegisterRequestMessage::new(
            Some(request_id.message_id()),
            REGISTER_METHOD,
            Some(request),
        );
        let encoding = message.encode().unwrap_err();
        assert!(
            encoding
                .to_string()
                .contains("new_authenticator_address must not be the zero address"),
            "{encoding}"
        );
    }

    #[test]
    fn params_use_the_wip_109_field_names_and_byte_strings() {
        let (request, _, _) = signed_request(ADMIN);
        let pubkey = request
            .new_authenticator_pubkey
            .to_compressed_bytes()
            .unwrap();
        let signature = request.registration_sig.to_compressed_bytes().unwrap();
        let params = Value::Map(vec![
            (
                "new_authenticator_pubkey".into(),
                Value::Bytes(pubkey.to_vec()),
            ),
            (
                "new_authenticator_address".into(),
                Value::Bytes(vec![0x11; 20]),
            ),
            (
                "response_pubkey".into(),
                Value::Bytes(request.response_pubkey.to_bytes()),
            ),
            ("name".into(), "Chrome on MacBook".into()),
            ("registration_sig".into(), Value::Bytes(signature.to_vec())),
        ]);
        assert_eq!(Value::serialized(&request).unwrap(), params);
        assert_eq!(RegistrationRequest::from_params(&params).unwrap(), request);
    }

    #[test_case(ADMIN; "admin")]
    #[test_case(PROVING; "proving")]
    fn request_round_trips_through_cbor(new_authenticator_address: Option<Address>) {
        let (request, _, request_id) = signed_request(new_authenticator_address);
        let message = RegisterRequestMessage::new(
            Some(request_id.message_id()),
            REGISTER_METHOD,
            Some(request.clone()),
        );
        let encoded = message.encode().unwrap();
        let received: Request<Value> = Request::decode(&encoded, MAX_REQUEST_SIZE).unwrap();
        let params = received.params.unwrap();
        assert_eq!(RegistrationRequest::from_params(&params).unwrap(), request);
    }

    #[test]
    fn from_params_rejects_tagged_params() {
        let tagged = Value::Tag(55799, Box::new(admin_params()));
        let rejection = RegistrationRequest::from_params(&tagged).unwrap_err();
        assert!(rejection.to_string().contains("must not contain CBOR tags"));
    }

    #[test_case("name", Some(Value::Tag(0, Box::new("phone".into()))),
                "must not contain CBOR tags"; "tagged name")]
    #[test_case("name", Some(Value::Null), "invalid type: null"; "null name")]
    #[test_case("name", Some("x".repeat(65).into()), "at most 64 bytes"; "long name")]
    #[test_case("new_authenticator_address", Some(Value::Null),
                "expected a CBOR byte string"; "null address")]
    #[test_case("new_authenticator_address", Some(Value::Bytes(vec![0; 20])),
                "must not be the zero address"; "zero address")]
    #[test_case("new_authenticator_address", Some(Value::Bytes(vec![1; 19])),
                "of 20 bytes, got 19"; "short address")]
    #[test_case("new_authenticator_pubkey", Some(Value::Bytes(vec![0; 31])),
                "of 32 bytes, got 31"; "short pubkey")]
    #[test_case("new_authenticator_pubkey", Some("0x12".into()),
                "expected a CBOR byte string"; "text pubkey")]
    #[test_case("response_pubkey", Some(Value::Bytes(vec![1; 1215])),
                "invalid X-Wing encapsulation key"; "short response key")]
    #[test_case("response_pubkey", Some(Value::Bytes(vec![1; 1217])),
                "invalid X-Wing encapsulation key"; "long response key")]
    #[test_case("registration_sig", Some(Value::Bytes(vec![1; 63])),
                "of 64 bytes, got 63"; "short signature")]
    #[test_case("registration_sig", None, "missing field `registration_sig`"; "missing signature")]
    #[test_case("class", Some("admin".into()), "unknown field `class`"; "unknown field")]
    fn from_params_rejects_a_malformed_field(field: &str, value: Option<Value>, error: &str) {
        let rejection = RegistrationRequest::from_params(&params_with(field, value))
            .unwrap_err()
            .to_string();
        assert!(rejection.contains(error), "{rejection}");
    }
}
