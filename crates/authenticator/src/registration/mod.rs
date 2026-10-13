//! Registering a new authenticator through an existing Admin Authenticator, as defined in
//! [WIP-109](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-109.md).
//!
//! A **Requesting Authenticator** (the new one) generates a [`PairingSecret`] and a
//! [`ResponseSecretKey`]. The pairing secret determines the session's bridge [`RequestId`] and,
//! together with the independently transferred [`PairingCode`], its [`TransportKey`]. An
//! **Approving Authenticator** (an existing Admin Authenticator) that receives the secret and the
//! code derives the same transport key. It seals its response to the Requesting Authenticator's
//! [`ResponsePublicKey`], then encrypts it under the transport key.
//!
//! This module holds the session secrets and the transport encryption. Every value derived from
//! the pairing secret is deterministic.

mod session;

pub use session::{
    EncryptedPayload, PairingCode, PairingSecret, RequestId, ResponsePublicKey, ResponseSecretKey,
    TransportError, TransportKey,
};

/// The largest vault a registration response carries: 3.5 MiB, so that the encrypted response
/// fits the message-bridge's 5 MiB body limit (WIP-109 §3.6.2).
pub const MAX_VAULT_SIZE: usize = 3_670_016;

/// The largest encoded request (WIP-109 §3.5).
const MAX_REQUEST_SIZE: usize = 4 * 1024;

/// The largest encoded response: a full vault plus 4 KiB for the other fields (WIP-109 §3.5).
const MAX_RESPONSE_SIZE: usize = MAX_VAULT_SIZE + 4 * 1024;

#[cfg(test)]
mod vectors;
