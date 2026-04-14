use reqwest::StatusCode;
use world_id_primitives::{PrimitiveError, ValidationError};
use world_id_proof::proof::ProofError;

/// Errors that can occur when interacting with the Authenticator.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticatorError {
    /// Primitive error
    #[error(transparent)]
    PrimitiveError(#[from] PrimitiveError),

    /// This operation requires a registered account and an account is not registered
    /// for this authenticator. Call `create_account` first to register it.
    #[error("Account is not registered for this authenticator.")]
    AccountDoesNotExist,

    /// An error occurred while interacting with the EVM contract.
    #[error("Error interacting with EVM contract: {0}")]
    ContractError(#[from] alloy::contract::Error),

    /// Network/HTTP request error.
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),

    /// Public key not found in the Authenticator public key set. Usually indicates the local state is out of sync with the registry.
    #[error("Public key not found.")]
    PublicKeyNotFound,

    /// Gateway returned an error response.
    #[error("Gateway error (status {status}): {body}")]
    GatewayError {
        /// HTTP status code
        status: StatusCode,
        /// Response body
        body: String,
    },

    /// Indexer returned an error response.
    #[error("Indexer error (status {status}): {body}")]
    IndexerError {
        /// HTTP status code
        status: StatusCode,
        /// Response body
        body: String,
    },

    /// Account creation timed out while polling for confirmation.
    #[error("Account creation timed out")]
    Timeout,

    /// Configuration is invalid or missing required values.
    #[error("Invalid configuration for {attribute}: {reason}")]
    InvalidConfig {
        /// The config attribute that is invalid.
        attribute: String,
        /// Description of why it is invalid.
        reason: String,
    },

    /// The provided credential is not valid for the provided proof request.
    #[error("The provided credential is not valid for the provided proof request")]
    InvalidCredentialForProofRequest,

    /// The provided credentials do not satisfy the proof request.
    ///
    /// This usually means the authenticator made an incorrect selection of credentials.
    #[error("Proof request cannot be fulfilled with the provided credentials.")]
    UnfullfilableRequest,

    /// Error during the World ID registration process.
    ///
    /// This usually occurs from an on-chain revert.
    #[error("Registration error ({error_code}): {error_message}")]
    RegistrationError {
        /// Error code from the registration process.
        error_code: String,
        /// Detailed error message.
        error_message: String,
    },

    /// Error on proof generation
    #[error(transparent)]
    ProofError(#[from] ProofError),

    /// Indexer returned an authenticator key slot that exceeds supported key capacity.
    #[error(
        "Invalid indexer authenticator pubkey slot {slot_index}; max supported slot is {max_supported_slot}"
    )]
    InvalidIndexerPubkeySlot {
        /// Slot index returned by the indexer.
        slot_index: usize,
        /// Highest supported slot index.
        max_supported_slot: usize,
    },

    /// OHTTP encapsulation or decapsulation error.
    #[error("OHTTP encapsulation error: {0}")]
    OhttpEncapsulationError(#[from] ohttp::Error),

    /// Binary HTTP framing error.
    #[error("Binary HTTP error: {0}")]
    BhttpError(#[from] bhttp::Error),

    /// The OHTTP relay itself returned a non-success status.
    #[error("OHTTP relay error (status {status}): {body}")]
    OhttpRelayError {
        /// HTTP status code from the relay.
        status: StatusCode,
        /// Response body from the relay.
        body: String,
    },

    /// A service returned a success status but the response body could not be
    /// deserialized into the expected type.
    #[error("Invalid service response: {0}")]
    InvalidServiceResponse(String),

    /// The assembled proof response failed self-validation against the request.
    #[error(transparent)]
    ResponseValidationError(#[from] ValidationError),

    /// Proof materials not loaded. Call `with_proof_materials` before generating proofs.
    #[error("Proof materials not loaded. Call `with_proof_materials` before generating proofs.")]
    ProofMaterialsNotLoaded,

    /// The session ID computed for this proof does not match the expected session ID from the proof request.
    ///
    /// This indicates the `session_id` provided by the RP is invalid or compromised, or
    /// the authenticator cached the wrong `session_id_r_seed` for the `oprf_seed`.
    #[error("the expected session id and the generated session id do not match")]
    SessionIdMismatch,

    /// Generic error for other unexpected issues.
    #[error("{0}")]
    Generic(String),
}

#[derive(Debug)]
pub(crate) enum PollResult {
    Retryable,
    TerminalError(AuthenticatorError),
}
