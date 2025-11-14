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
pub use crate::authenticator::{
    compress_offchain_pubkey, leaf_hash, Authenticator, AuthenticatorError, Groth16ProofMaterials,
};
#[cfg(feature = "authenticator")]
mod util;

#[cfg(all(feature = "authenticator", target_arch = "wasm32"))]
pub use crate::authenticator::{
    fetch_groth16_materials, fetch_groth16_proof_materials, RemoteGroth16Circuit,
    RemoteGroth16MaterialSources, RemoteGroth16Materials,
};

pub use world_id_primitives::{Credential, CredentialVersion};

#[cfg(any(feature = "authenticator", feature = "issuer"))]
mod credential;
#[cfg(feature = "authenticator")]
pub use credential::credential_to_credentials_signature;
#[cfg(any(feature = "authenticator", feature = "issuer"))]
pub use credential::HashableCredential;

#[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
mod issuer;
#[cfg(all(feature = "issuer", not(target_arch = "wasm32")))]
pub use issuer::Issuer;

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
