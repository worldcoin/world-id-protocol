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
//! [`RegistrationRequester`] drives the requesting side; [`PendingRegistration`] fetches
//! the encrypted request before code entry on the approving side. Authentication with the
//! independently transferred [`PairingCode`] yields an [`IncomingRegistration`] that still
//! requires account checks and explicit consent.

mod approver;
mod bridge;
mod bytes;
mod pairing_uri;
mod request;
mod requester;
mod response;
mod session;

pub use crate::account::AuthenticatorClass;
pub use approver::{
    Approval, ApprovalOutcome, ApproverError, CheckedRegistration, DEFAULT_RESPONSE_DEADLINE,
    IncomingRegistration, MIN_TRACKING_TIME, PendingRegistration, RegistrationPlan,
};
pub use bridge::{BridgeClient, BridgeError, DeliveryOutcome, PublishOutcome, ResponseState};
pub use pairing_uri::{BridgeDomain, PairingUri, PairingUriError};
pub use request::{
    AuthenticatorName, MAX_NAME_LEN, NameTooLong, REGISTER_METHOD, RegisterRequestMessage,
    RegistrationDigest, RegistrationRequest,
};
pub use requester::{RegistrationRequester, RequestedClass, RequesterError, RequesterStatus};
pub use response::{
    KnownAuthenticator, RegisterResponseMessage, RegistrationErrorData, RegistrationErrorReason,
    RegistrationResult, Vault, VaultFormat,
};
pub use session::{
    EncryptedPayload, PairingCode, PairingSecret, RESPONSE_PUBLIC_KEY_LEN, RequestId,
    ResponsePublicKey, ResponseSecretKey, TransportError, TransportKey,
};

/// The largest encoded response a Requesting Authenticator accepts.
const MAX_RESPONSE_SIZE: usize = 16 * 1024 * 1024;

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
    let value = ciborium::Value::deserialize(deserializer)?;
    if !value.is_map() || contains_tag(&value) {
        return Err(D::Error::custom(
            "registration payload must be an untagged CBOR map",
        ));
    }
    value.deserialized().map_err(D::Error::custom)
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
