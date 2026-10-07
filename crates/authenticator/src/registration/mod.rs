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
//! [`RegistrationRequester`] drives the Requesting Authenticator's side and
//! [`IncomingRegistration`] the Approving Authenticator's side, over a [`BridgeClient`]. The
//! remaining types are the protocol values and their encodings.

mod approver;
mod bridge;
mod pairing_uri;
mod request;
mod requester;
mod response;
mod session;
#[cfg(test)]
mod vectors;

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
    EncryptedPayload, PairingSecret, RESPONSE_PUBLIC_KEY_LEN, RequestId, ResponsePublicKey,
    ResponseSecretKey, TransportError, TransportKey,
};
