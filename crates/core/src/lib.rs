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
pub use crate::authenticator::{Authenticator, AuthenticatorError, OnchainKeyRepresentable};

pub use world_id_primitives::{Credential, CredentialVersion};

#[cfg(any(feature = "authenticator", feature = "issuer"))]
mod credential;
#[cfg(any(feature = "authenticator", feature = "issuer"))]
pub use credential::HashableCredential;

#[cfg(feature = "issuer")]
mod issuer;
#[cfg(feature = "issuer")]
pub use issuer::Issuer;

#[cfg(any(feature = "authenticator", feature = "issuer"))]
mod signer;
#[cfg(any(feature = "authenticator", feature = "issuer"))]
pub(crate) use signer::Signer;

#[cfg(feature = "authenticator")]
pub mod oprf;
#[cfg(feature = "authenticator")]
pub use oprf::ProofError;

#[cfg(feature = "authenticator")]
pub mod proof;

#[cfg(feature = "authenticator")]
pub use oprf_core;
#[cfg(feature = "authenticator")]
pub use oprf_types;

/// Generic re-usable types
pub mod types;
pub use world_id_primitives::FieldElement;

/// Re-export of all the World ID primitives
pub mod primitives {
    pub use world_id_primitives::*;
}
