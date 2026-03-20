//! Lightweight serde-compatible types for the World ID Protocol.
//!
//! This crate provides wire-format-compatible types that mirror
//! [`world-id-primitives`] but carry no cryptographic dependencies.
//! JSON and CBOR representations are byte-identical to the canonical crate,
//! verified by golden-file tests.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![deny(clippy::all, clippy::nursery, missing_docs, dead_code)]
#![allow(clippy::option_if_let_else)]

mod error;
pub use error::PrimitiveError;

mod field_element;
pub use field_element::FieldElement;

mod public_key_bytes;
pub use public_key_bytes::PublicKeyBytes;

mod signature_bytes;
pub use signature_bytes::SignatureBytes;

mod credential;
pub use credential::{Credential, CredentialVersion};

/// The depth of the Merkle tree used in the World ID Protocol.
pub const TREE_DEPTH: usize = 30;
