//! The core library for the World ID Protocol.
//!
//! Read more in: <https://docs.world.org/world-id>

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![deny(clippy::all, clippy::nursery, missing_docs)]
#![allow(clippy::option_if_let_else)]

pub use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};

#[cfg(feature = "authenticator")]
pub use world_id_authenticator::{
    Authenticator, AuthenticatorError, InitializingAuthenticator, OnchainKeyRepresentable,
};

/// Re-export registry from authenticator for convenience
#[cfg(feature = "authenticator")]
pub mod world_id_registry {
    pub use world_id_authenticator::registry::*;
}

pub use world_id_primitives::{Credential, CredentialVersion};

#[cfg(feature = "issuer")]
pub use world_id_issuer::Issuer;

#[cfg(any(feature = "authenticator", feature = "issuer"))]
pub use world_id_signer::Signer;

#[cfg(feature = "authenticator")]
pub use world_id_proof::proof;

#[cfg(feature = "authenticator")]
pub use world_id_proof::nullifier;

#[cfg(any(feature = "authenticator", feature = "rp"))]
pub use world_id_request as requests;

pub use world_id_primitives::FieldElement;

/// Re-export types from authenticator for convenience
#[cfg(feature = "authenticator")]
pub mod api_types {
    pub use world_id_primitives::api_types::*;
}

/// Re-export of all the World ID primitives
pub mod primitives {
    pub use world_id_primitives::*;
}
