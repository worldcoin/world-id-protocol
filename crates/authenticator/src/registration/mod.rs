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
//! transferred [`PairingCode`]. Messages are encoded with
//! [`authenticator_message::encode`](world_id_primitives::authenticator_message::encode) and
//! decoded with [`decode_request`] and [`decode_response`], which add the WIP-109 size limits and
//! payload rules to the WIP-105 envelope.

use world_id_primitives::authenticator_message::{MessageError, Value};

mod pairing_uri;
mod request;
mod response;
mod session;

pub use pairing_uri::{BridgeDomain, PairingUri, PairingUriError};
pub use request::{
    AuthenticatorName, MAX_NAME_LEN, NameTooLong, REGISTER_METHOD, RegisterRequestMessage,
    RegistrationDigest, RegistrationRequest, decode_request,
};
pub use response::{
    KnownAuthenticator, MAX_VAULT_SIZE, RegisterResponseMessage, RegistrationErrorData,
    RegistrationErrorReason, RegistrationResult, Vault, VaultFormat, decode_response,
};
pub use session::{
    EncryptedPayload, PairingCode, PairingSecret, RESPONSE_PUBLIC_KEY_LEN, RequestId,
    ResponsePublicKey, ResponseSecretKey, TransportError, TransportKey,
};

/// The largest encoded request (WIP-109 §3.5).
const MAX_REQUEST_SIZE: usize = 4 * 1024;

/// The largest encoded response: a full vault plus 4 KiB for the other fields (WIP-109 §3.5).
const MAX_RESPONSE_SIZE: usize = MAX_VAULT_SIZE + 4 * 1024;

/// Rejects a registration payload that contains a CBOR tag at any depth.
///
/// WIP-109 §3.6 defines every payload field by its CBOR major type, which a tag would wrap.
fn reject_tags(payload: &Value) -> Result<(), MessageError> {
    if contains_tag(payload) {
        return Err(MessageError::Deserialize(serde::de::Error::custom(
            "registration payloads must not contain CBOR tags",
        )));
    }
    Ok(())
}

fn contains_tag(value: &Value) -> bool {
    match value {
        Value::Tag(..) => true,
        Value::Array(values) => values.iter().any(contains_tag),
        Value::Map(entries) => entries
            .iter()
            .any(|(key, value)| contains_tag(key) || contains_tag(value)),
        _ => false,
    }
}

#[cfg(test)]
mod vectors;
