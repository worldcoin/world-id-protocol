//! Registering a new authenticator through an existing Admin Authenticator, as defined in
//! [WIP-109](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-109.md).
//!
//! A **Requesting Authenticator** (the new one) generates a [`PairingSecret`] and a
//! [`ResponseSecretKey`], signs a [`RegistrationRequest`] with the key it wants to register,
//! publishes the encrypted request on the bridge and shows a [`PairingUri`]. An **Approving
//! Authenticator** (an existing Admin Authenticator) opens the URI, fetches and checks the
//! request, asks the user for consent, inserts the new authenticator on-chain and answers with a
//! sealed [`RegistrationResult`], which carries the credential vault.
//!
//! This module holds the protocol values and their encodings. Every value derived from the
//! pairing secret is deterministic. Transport encryption additionally requires the independently
//! transferred [`PairingCode`].

mod bytes;
mod pairing_uri;
mod request;
mod response;
mod session;

pub use crate::account::AuthenticatorClass;
pub use pairing_uri::{BridgeDomain, PairingUri, PairingUriError};
pub use request::{
    AuthenticatorName, MAX_NAME_LEN, NameTooLong, REGISTER_METHOD, RegisterRequestMessage,
    RegistrationDigest, RegistrationRequest,
};
pub use response::{
    KnownAuthenticator, RegisterResponseMessage, RegistrationErrorData, RegistrationErrorReason,
    RegistrationResult, Vault, VaultFormat,
};
pub use session::{
    EncryptedPayload, PairingCode, PairingSecret, RESPONSE_PUBLIC_KEY_LEN, RequestId,
    ResponsePublicKey, ResponseSecretKey, TransportError, TransportKey,
};

fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn deserialize_payload<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    use serde::{Deserialize as _, de::Error as _};
    let mut value = ciborium::Value::deserialize(deserializer)?;
    let payload = if !value.is_map() || contains_tag(&value) {
        Err(D::Error::custom(
            "registration payload must be an untagged CBOR map",
        ))
    } else {
        value.deserialized().map_err(D::Error::custom)
    };
    // The intermediate value may hold a copy of the vault.
    wipe_byte_strings(&mut value);
    payload
}

fn wipe_byte_strings(value: &mut ciborium::Value) {
    match value {
        ciborium::Value::Bytes(bytes) => zeroize::Zeroize::zeroize(bytes),
        ciborium::Value::Tag(_, value) => wipe_byte_strings(value),
        ciborium::Value::Array(values) => values.iter_mut().for_each(wipe_byte_strings),
        ciborium::Value::Map(entries) => entries.iter_mut().for_each(|(key, value)| {
            wipe_byte_strings(key);
            wipe_byte_strings(value);
        }),
        _ => {}
    }
}

fn contains_tag(value: &ciborium::Value) -> bool {
    match value {
        ciborium::Value::Tag(..) => true,
        ciborium::Value::Array(values) => values.iter().any(contains_tag),
        ciborium::Value::Map(entries) => entries
            .iter()
            .any(|(key, value)| contains_tag(key) || contains_tag(value)),
        _ => false,
    }
}

#[cfg(test)]
mod vectors;
