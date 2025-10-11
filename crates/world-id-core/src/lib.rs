//! The core library for the World ID Protocol.
//!
//! Read more in: <https://docs.world.org/world-id>

#![deny(clippy::all, clippy::pedantic, clippy::nursery, missing_docs)]
#![warn(dead_code)] // FIXME: Move to deny once the library has full functionality

pub use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};

#[cfg(feature = "authenticator")]
pub mod account_registry;

#[cfg(feature = "authenticator")]
mod authenticator;
#[cfg(feature = "authenticator")]
pub use authenticator::Authenticator;

/// Global configuration to interact with the different components of the Protocol.
#[cfg(feature = "authenticator")]
pub mod config;

mod credential;
pub use credential::Credential;

/// Generic re-usable types
pub mod types;
pub use types::BaseField;
