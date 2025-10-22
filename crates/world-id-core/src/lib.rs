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
#[cfg(feature = "authenticator")]
pub use authenticator::{Authenticator, AuthenticatorError};

/// Global configuration to interact with the different components of the Protocol.
#[cfg(any(feature = "authenticator", feature = "issuer"))]
pub mod config;

mod credential;
pub use credential::{Credential, CredentialVersion};

#[cfg(feature = "issuer")]
mod issuer;
#[cfg(feature = "issuer")]
pub use issuer::Issuer;

#[cfg(any(feature = "authenticator", feature = "issuer"))]
mod signer;
#[cfg(any(feature = "authenticator", feature = "issuer"))]
pub(crate) use signer::Signer;

/// Generic re-usable types
pub mod types;
pub use world_id_types::FieldElement;
