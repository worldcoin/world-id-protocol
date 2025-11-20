//! The core library for the World ID Protocol.
//!
//! Read more in: <https://docs.world.org/world-id>

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]
pub use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};

#[cfg(feature = "authenticator")]
pub mod account_registry;

#[cfg(feature = "authenticator")]
mod authenticator;
#[cfg(all(feature = "authenticator", target_arch = "wasm32"))]
pub use crate::authenticator::CircuitAssets;
#[cfg(feature = "authenticator")]
pub use crate::authenticator::{Authenticator, AuthenticatorError, OnchainKeyRepresentable};

pub use world_id_primitives::{Credential, CredentialVersion};

#[cfg(any(feature = "authenticator", feature = "issuer"))]
mod credential;
#[cfg(any(feature = "authenticator", feature = "issuer"))]
pub use credential::HashableCredential;

#[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
mod issuer;
#[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
pub use issuer::Issuer;

pub(crate) mod util;

#[cfg(any(feature = "authenticator", feature = "issuer"))]
mod signer;
#[cfg(any(feature = "authenticator", feature = "issuer"))]
pub(crate) use signer::Signer;

/// Generic re-usable types
pub mod types;
pub use world_id_primitives::FieldElement;

/// Re-export of all the World ID primitives
pub mod primitives {
    pub use world_id_primitives::*;
}
