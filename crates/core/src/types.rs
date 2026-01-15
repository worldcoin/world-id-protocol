#![allow(clippy::option_if_let_else)]
#[cfg(feature = "authenticator")]
use ruint::aliases::U256;

use serde::{Deserialize, Serialize};
#[cfg(feature = "authenticator")]
use strum::EnumString;

#[cfg(feature = "authenticator")]
use alloy::primitives::Address;
#[cfg(feature = "openapi")]
use utoipa::IntoParams;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[cfg(feature = "authenticator")]
use crate::world_id_registry::WorldIdRegistry::{
    AuthenticatorAddressAlreadyInUse, AuthenticatorDoesNotBelongToAccount,
    AuthenticatorDoesNotExist, MismatchedSignatureNonce, PubkeyIdInUse, PubkeyIdOutOfBounds,
};
#[cfg(feature = "authenticator")]
use axum::{http::StatusCode, response::IntoResponse};
#[cfg(feature = "authenticator")]
use world_id_primitives::serde_utils::{
    hex_u256, hex_u256_opt, hex_u256_vec, hex_u32, hex_u32_opt,
};

pub use world_id_primitives::merkle::AccountInclusionProof;

/// The request to create a new World ID account.
#[cfg(feature = "authenticator")]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAccountRequest {
    /// The recovery address.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub recovery_address: Option<Address>,
    /// The addresses of the authenticators.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>, format = "hex"))]
    pub authenticator_addresses: Vec<Address>,
    /// The compressed public keys of the authenticators.
    #[serde(with = "hex_u256_vec")]
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>, format = "hex"))]
    pub authenticator_pubkeys: Vec<U256>,
    /// The offchain signer commitment.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub offchain_signer_commitment: U256,
}

/// The request to update an authenticator.
#[cfg(feature = "authenticator")]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAuthenticatorRequest {
    /// The account index.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub leaf_index: U256,
    /// The old authenticator address.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub old_authenticator_address: Address,
    /// The new authenticator address.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub new_authenticator_address: Address,
    /// The old offchain signer commitment.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    #[serde(with = "hex_u256_vec")]
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>, format = "hex"))]
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<u8>))]
    pub signature: Vec<u8>,
    /// The nonce.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub nonce: U256,
    /// The pubkey id.
    #[serde(with = "hex_u32")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub pubkey_id: u32,
    /// The new authenticator pubkey.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub new_authenticator_pubkey: U256,
}

/// The request to insert an authenticator.
#[cfg(feature = "authenticator")]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct InsertAuthenticatorRequest {
    /// The account index.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub leaf_index: U256,
    /// The new authenticator address.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub new_authenticator_address: Address,
    /// The old offchain signer commitment.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    #[serde(with = "hex_u256_vec")]
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>, format = "hex"))]
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<u8>))]
    pub signature: Vec<u8>,
    /// The nonce.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub nonce: U256,
    /// The pubkey id.
    #[serde(with = "hex_u32")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub pubkey_id: u32,
    /// The new authenticator pubkey.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub new_authenticator_pubkey: U256,
}

/// The request to remove an authenticator.
#[cfg(feature = "authenticator")]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveAuthenticatorRequest {
    /// The account index.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub leaf_index: U256,
    /// The authenticator address.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub authenticator_address: Address,
    /// The old offchain signer commitment.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    #[serde(with = "hex_u256_vec")]
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>, format = "hex"))]
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<u8>))]
    pub signature: Vec<u8>,
    /// The nonce.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub nonce: U256,
    /// The pubkey id.
    #[serde(default, with = "hex_u32_opt")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = "hex"))]
    pub pubkey_id: Option<u32>,
    /// The authenticator pubkey.
    #[serde(default, with = "hex_u256_opt")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = "hex"))]
    pub authenticator_pubkey: Option<U256>,
}

/// The request to recover an account.
#[cfg(feature = "authenticator")]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct RecoverAccountRequest {
    /// The account index.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub leaf_index: U256,
    /// The new authenticator address.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub new_authenticator_address: Address,
    /// The old offchain signer commitment.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    #[serde(with = "hex_u256_vec")]
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>, format = "hex"))]
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<u8>))]
    pub signature: Vec<u8>,
    /// The nonce.
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub nonce: U256,
    /// The new authenticator pubkey.
    #[serde(default, with = "hex_u256_opt")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, format = "hex"))]
    pub new_authenticator_pubkey: Option<U256>,
}

/// Response returned by the registry gateway for state-changing requests.
#[cfg(feature = "authenticator")]
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct GatewayStatusResponse {
    /// Identifier assigned by the gateway to the submitted request.
    pub request_id: String,
    /// The kind of operation that was submitted.
    pub kind: GatewayRequestKind,
    /// The current state of the request.
    pub status: GatewayRequestState,
}

/// Kind of request tracked by the registry gateway.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg(feature = "authenticator")]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GatewayRequestKind {
    /// Account creation request.
    CreateAccount,
    /// Authenticator update request.
    UpdateAuthenticator,
    /// Authenticator insertion request.
    InsertAuthenticator,
    /// Authenticator removal request.
    RemoveAuthenticator,
    /// Account recovery request.
    RecoverAccount,
}

/// Tracking state for a registry gateway request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg(feature = "authenticator")]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GatewayRequestState {
    /// Request queued but not yet batched.
    Queued,
    /// Request currently being batched.
    Batching,
    /// Request submitted on-chain, hash available.
    Submitted {
        /// Transaction hash emitted when the request was submitted.
        tx_hash: String,
    },
    /// Request finalized on-chain.
    Finalized {
        /// Transaction hash emitted when the request was finalized.
        tx_hash: String,
    },
    /// Request failed during processing.
    Failed {
        /// Error message returned by the gateway.
        error: String,
        /// Specific error code, if available.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        error_code: Option<GatewayErrorCode>,
    },
}

#[cfg(feature = "authenticator")]
impl GatewayRequestState {
    /// Creates a failed state with an error message and optional error code.
    pub fn failed(error: impl Into<String>, error_code: Option<GatewayErrorCode>) -> Self {
        Self::Failed {
            error: error.into(),
            error_code,
        }
    }

    /// Creates a failed state from an error code (uses the code's display as the message).
    #[must_use]
    pub fn failed_from_code(code: GatewayErrorCode) -> Self {
        Self::Failed {
            error: code.to_string(),
            error_code: Some(code),
        }
    }
}

/// Request to fetch a packed account index from the indexer.
#[cfg(feature = "authenticator")]
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct IndexerPackedAccountRequest {
    /// The authenticator address to look up
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex", example = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"))]
    pub authenticator_address: Address,
}

/// Response containing the packed account index from the indexer.
#[cfg(feature = "authenticator")]
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct IndexerPackedAccountResponse {
    /// The packed account data [32 bits recoveryCounter][32 bits pubkeyId][192 bits leafIndex]
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex", example = "0x1"))]
    pub packed_account_data: U256,
}

/// Query for the indexer based on a leaf index.
///
/// Used for getting inclusion proofs and signature nonces.
#[cfg(feature = "authenticator")]
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct IndexerQueryRequest {
    /// The leaf index to query (from the `WorldIDRegistry`)
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex", example = "0x1"))]
    pub leaf_index: U256,
}

/// Response containing the signature nonce from the indexer.
#[cfg(feature = "authenticator")]
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct IndexerSignatureNonceResponse {
    /// The signature nonce for the account
    #[serde(with = "hex_u256")]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex", example = "0x0"))]
    pub signature_nonce: U256,
}

/// Health response for an API service (gateway or indexer).
#[cfg(feature = "authenticator")]
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct HealthResponse {
    /// Success value.
    pub success: bool,
}

/// Query params for the `/is-valid-root` endpoint.
#[cfg(feature = "authenticator")]
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(IntoParams, ToSchema))]
pub struct IsValidRootQuery {
    /// Root to validate (hex string).
    #[schema(value_type = String, format = "hex")]
    pub root: String,
}

/// Response payload for root validity checks.
#[cfg(feature = "authenticator")]
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IsValidRootResponse {
    /// Whether the root is currently valid on-chain.
    pub valid: bool,
}

/// Indexer error codes.
#[cfg(feature = "authenticator")]
#[derive(Debug, Clone, EnumString, Serialize, Deserialize, strum::Display)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum IndexerErrorCode {
    /// Internal server error occurred in the indexer.
    InternalServerError,
    /// Requested resource was not found.
    NotFound,
    /// The provided leaf index is invalid.
    InvalidLeafIndex,
    /// The resource is locked and cannot be accessed.
    Locked,
    /// The account does not exist.
    AccountDoesNotExist,
}

/// Gateway error codes.
#[cfg(feature = "authenticator")]
#[derive(Debug, Clone, Deserialize, Serialize, strum::Display)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum GatewayErrorCode {
    /// Internal server error occurred in the gateway.
    InternalServerError,
    /// Requested resource was not found.
    NotFound,
    /// Bad request - invalid input.
    BadRequest,
    /// Batcher service unavailable.
    BatcherUnavailable,
    /// Authenticator address is already in use by another account.
    AuthenticatorAlreadyExists,
    /// Authenticator does not exist on the account.
    AuthenticatorDoesNotExist,
    /// The signature nonce does not match the expected value.
    MismatchedSignatureNonce,
    /// The pubkey ID slot is already in use.
    PubkeyIdInUse,
    /// The pubkey ID is out of bounds (max 7 authenticators).
    PubkeyIdOutOfBounds,
    /// The authenticator does not belong to the specified account.
    AuthenticatorDoesNotBelongToAccount,
    /// Transaction was submitted but reverted on-chain.
    TransactionReverted,
    /// Error while waiting for transaction confirmation.
    ConfirmationError,
    /// Pre-flight simulation failed.
    PreFlightFailed,
    /// Signature length mismatch.
    SignatureLengthMismatch,
    /// Signature all zeros.
    SignatureAllZeros,
    /// Empty authenticators.
    EmptyAuthenticators,
    /// Authenticators addresses pubkeys mismatch
    AuthenticatorsAddressPubkeyMismatch,
    /// Authenticator address cannot be zero.
    AuthenticatorAddressCannotBeZero,
    /// Offchain signer commitment cannot be zero.
    OffchainSignerCommitmentCannotBeZero,
    /// New authenticator address cannot be zero.
    NewAuthenticatorAddressCannotBeZero,
    /// Leaf index cannot be zero.
    LeafIndexCannotBeZero,
}

/// Error object returned by the services APIs (indexer, gateway).
#[cfg(feature = "authenticator")]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct ServiceApiError<T>
where
    T: Clone,
{
    /// The error code.
    pub code: T,
    /// Human-readable error message.
    pub message: String,
}

#[cfg(feature = "authenticator")]
impl<T> ServiceApiError<T>
where
    T: Clone,
{
    /// Creates a new error object.
    pub const fn new(code: T, message: String) -> Self {
        Self { code, message }
    }
}

/// `OpenAPI` schema representation of the `AccountInclusionProof` response.
#[cfg(feature = "authenticator")]
#[derive(serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct AccountInclusionProofSchema {
    /// The root hash of the Merkle tree (hex string)
    #[schema(value_type = String, format = "hex", example = "0x1a2b3c4d5e6f7890")]
    pub root: String,
    /// The World ID's leaf position in the Merkle tree
    #[schema(value_type = String, format = "hex", example = "0x2a")]
    pub leaf_index: String,
    /// The sibling path up to the Merkle root (array of hex strings)
    #[schema(value_type = Vec<String>, format = "hex")]
    pub siblings: Vec<String>,
    /// The compressed authenticator public keys for the account (array of hex strings)
    #[schema(value_type = Vec<String>, format = "hex")]
    pub authenticator_pubkeys: Vec<String>,
}

/// Helper to format a selector as a hex string for matching in error messages.
#[cfg(feature = "authenticator")]
fn selector_hex(selector: [u8; 4]) -> String {
    format!("0x{}", hex::encode(selector))
}

/// Parses a contract error string and returns a specific error code if recognized.
#[cfg(feature = "authenticator")]
#[must_use]
pub fn parse_contract_error(error: &str) -> GatewayErrorCode {
    use alloy::sol_types::SolError;

    if error.contains(&selector_hex(AuthenticatorAddressAlreadyInUse::SELECTOR)) {
        return GatewayErrorCode::AuthenticatorAlreadyExists;
    }
    if error.contains(&selector_hex(AuthenticatorDoesNotExist::SELECTOR)) {
        return GatewayErrorCode::AuthenticatorDoesNotExist;
    }
    if error.contains(&selector_hex(MismatchedSignatureNonce::SELECTOR)) {
        return GatewayErrorCode::MismatchedSignatureNonce;
    }
    if error.contains(&selector_hex(PubkeyIdInUse::SELECTOR)) {
        return GatewayErrorCode::PubkeyIdInUse;
    }
    if error.contains(&selector_hex(PubkeyIdOutOfBounds::SELECTOR)) {
        return GatewayErrorCode::PubkeyIdOutOfBounds;
    }
    if error.contains(&selector_hex(AuthenticatorDoesNotBelongToAccount::SELECTOR)) {
        return GatewayErrorCode::AuthenticatorDoesNotBelongToAccount;
    }

    GatewayErrorCode::BadRequest
}

/// Error response body used by the gateway APIs.
#[cfg(feature = "authenticator")]
pub type GatewayErrorBody = ServiceApiError<GatewayErrorCode>;

/// Error response used by the gateway APIs.
#[cfg(feature = "authenticator")]
#[derive(Debug, Clone)]
pub struct GatewayErrorResponse {
    /// Http status code.
    status: StatusCode,
    /// The specific error.
    error: GatewayErrorBody,
}

#[cfg(feature = "authenticator")]
impl GatewayErrorResponse {
    /// Create a new [`GatewayErrorResponse`] with the provided error and status.
    #[must_use]
    pub const fn new(code: GatewayErrorCode, message: String, status: StatusCode) -> Self {
        Self {
            status,
            error: ServiceApiError::new(code, message),
        }
    }

    #[must_use]
    /// Create a `GatewayErrorCode::InternalServeError`.
    pub fn internal_server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: ServiceApiError::new(
                GatewayErrorCode::InternalServerError,
                "Internal server error. Please try again.".to_string(),
            ),
        }
    }

    #[must_use]
    /// Create a `GatewayErrorCode::NotFound`.
    pub fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error: ServiceApiError::new(GatewayErrorCode::NotFound, "Not found.".to_string()),
        }
    }

    #[must_use]
    /// Create a [`GatewayErrorCode`] with `BAD_REQUEST` http status code.
    pub fn bad_request(code: GatewayErrorCode) -> Self {
        let message = code.to_string();
        Self::new(code, message, StatusCode::BAD_REQUEST)
    }

    #[must_use]
    /// Create a `GatewayErrorCode::BadRequest` with a custom message.
    pub const fn bad_request_message(message: String) -> Self {
        Self::new(
            GatewayErrorCode::BadRequest,
            message,
            StatusCode::BAD_REQUEST,
        )
    }

    #[must_use]
    /// Create a `GatewayErrorCode::BatcherUnavailable`.
    pub fn batcher_unavailable() -> Self {
        Self::new(
            GatewayErrorCode::BatcherUnavailable,
            "Batcher service is unavailable. Please try again.".to_string(),
            StatusCode::SERVICE_UNAVAILABLE,
        )
    }

    /// Creates an error response from a contract simulation error.
    /// Parses the error to extract a specific error code if possible.
    #[must_use]
    pub fn from_simulation_error(e: impl std::fmt::Display) -> Self {
        let error_str = e.to_string();
        let code = parse_contract_error(&error_str);
        let message = if matches!(code, GatewayErrorCode::BadRequest) {
            error_str
        } else {
            code.to_string()
        };
        Self::new(code, message, StatusCode::BAD_REQUEST)
    }
}

#[cfg(feature = "authenticator")]
impl std::fmt::Display for GatewayErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Error Code: `{}`. Message: {}",
            self.error.code, self.error.message,
        )
    }
}

#[cfg(feature = "authenticator")]
impl std::error::Error for GatewayErrorResponse {}

#[cfg(feature = "authenticator")]
impl IntoResponse for GatewayErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (self.status, axum::Json(self.error)).into_response()
    }
}

/// Error response body used by the indexer APIs.
#[cfg(feature = "authenticator")]
pub type IndexerErrorBody = ServiceApiError<IndexerErrorCode>;

/// Error response used by the indexer APIs.
#[cfg(feature = "authenticator")]
#[derive(Debug, Clone)]
pub struct IndexerErrorResponse {
    /// Http status code.
    status: StatusCode,
    /// The specific error.
    error: IndexerErrorBody,
}

#[cfg(feature = "authenticator")]
impl IndexerErrorResponse {
    /// Create a new [`IndexerErrorCode`] with the provided error and status.
    #[must_use]
    pub const fn new(code: IndexerErrorCode, message: String, status: StatusCode) -> Self {
        Self {
            status,
            error: ServiceApiError::new(code, message),
        }
    }

    #[must_use]
    /// Create a `IndexerErrorCode::InternalServeError`.
    pub fn internal_server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: ServiceApiError::new(
                IndexerErrorCode::InternalServerError,
                "Internal server error. Please try again.".to_string(),
            ),
        }
    }

    #[must_use]
    /// Create a `IndexerErrorCode::NotFound`.
    pub fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error: ServiceApiError::new(IndexerErrorCode::NotFound, "Not found.".to_string()),
        }
    }

    #[must_use]
    /// Create a [`IndexerErrorCode`] with `BAD_REQUEST` http status code.
    pub const fn bad_request(code: IndexerErrorCode, message: String) -> Self {
        Self::new(code, message, StatusCode::BAD_REQUEST)
    }
}

#[cfg(feature = "authenticator")]
impl std::fmt::Display for IndexerErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Error Code: `{}`. Message: {}",
            self.error.code, self.error.message,
        )
    }
}

#[cfg(feature = "authenticator")]
impl std::error::Error for IndexerErrorResponse {}

#[cfg(feature = "authenticator")]
impl IntoResponse for IndexerErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (self.status, axum::Json(self.error)).into_response()
    }
}
