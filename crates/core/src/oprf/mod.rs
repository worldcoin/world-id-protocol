//! vOPRF (Verifiable Threshold Oblivious Pseudorandom Function) client implementation.
//!
//! Provides functionality for performing OPRF queries with multiple nodes,
//! including signing queries, managing sessions, and computing `DLog` equality challenges.
//!
//! The vOPRF protocol is used to generate nullifiers in a privacy-preserving manner while
//! not requiring the user to maintain a single secret that cannot be rotated.

use groth16_material::Groth16Error;
use reqwest::StatusCode;

mod http;
mod query;
pub(crate) mod session;

pub use http::{finish_sessions, init_sessions};
pub use query::{sign_oprf_query, SignedOprfQuery};
pub use session::{compute_challenges, verify_challenges, Challenge, OprfSessions};

/// Error type for OPRF operations and proof generation.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    /// API error returned by the OPRF service.
    #[error("API error {status}: {message}")]
    ApiError {
        /// the HTTP status code
        status: StatusCode,
        /// the error message
        message: String,
    },
    /// HTTP or network errors from OPRF service requests.
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    /// Not enough OPRF responses received to satisfy the required threshold.
    #[error("expected degree {threshold} responses, got {n}")]
    NotEnoughOprfResponses {
        /// actual amount responses
        n: usize,
        /// expected threshold
        threshold: usize,
    },
    /// The `DLog` equality proof failed verification.
    #[error("DLog proof could not be verified")]
    InvalidDLogProof,
    /// Provided public key index is invalid or out of bounds.
    #[error("Index in public key is invalid or out of bounds.")]
    InvalidPublicKeyIndex,
    /// Errors originating from Groth16 proof generation or verification.
    #[error(transparent)]
    ZkError(#[from] Groth16Error),
    /// Catch-all for other internal errors.
    #[error(transparent)]
    InternalError(#[from] eyre::Report),
}
