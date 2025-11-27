//! vOPRF (Verifiable Threshold Oblivious Pseudorandom Function) client implementation.
//!
//! Provides functionality for performing OPRF queries with multiple nodes,
//! including signing queries, managing sessions, and computing `DLog` equality challenges.
//!
//! The vOPRF protocol is used to generate nullifiers in a privacy-preserving manner while
//! not requiring the user to maintain a single secret that cannot be rotated.

use groth16_material::Groth16Error;

mod query;

pub use query::{sign_oprf_query, SignedOprfQuery};

/// Error type for OPRF operations and proof generation.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    /// Provided public key index is out of valid range.
    #[error("Index in public-key batch must be in range [0..6], but is {0}")]
    InvalidPublicKeyIndex(u64),
    /// Error originating from `oprf_client`.
    #[error(transparent)]
    OprfError(#[from] oprf_client::Error),
    /// Errors originating from Groth16 proof generation or verification.
    #[error(transparent)]
    ZkError(#[from] Groth16Error),
    /// Catch-all for other internal errors.
    #[error(transparent)]
    InternalError(#[from] eyre::Report),
}
