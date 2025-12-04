#![allow(clippy::option_if_let_else)]
#[cfg(feature = "authenticator")]
use ruint::aliases::U256;

#[cfg(feature = "authenticator")]
use serde::Serialize;

use serde::Deserialize;

#[cfg(feature = "authenticator")]
use strum::EnumString;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;
pub use world_id_primitives::merkle::AccountInclusionProof;
#[cfg(feature = "authenticator")]
use alloy::primitives::Address;

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
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>, format = "decimal"))]
    pub authenticator_pubkeys: Vec<U256>,
    /// The offchain signer commitment.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub offchain_signer_commitment: U256,
}

/// The request to update an authenticator.
#[cfg(feature = "authenticator")]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAuthenticatorRequest {
    /// The account index.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub account_index: U256,
    /// The old authenticator address.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub old_authenticator_address: Address,
    /// The new authenticator address.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub new_authenticator_address: Address,
    /// The old offchain signer commitment.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>, format = "decimal"))]
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<u8>))]
    pub signature: Vec<u8>,
    /// The nonce.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub nonce: U256,
    /// The pubkey id.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub pubkey_id: Option<u32>,
    /// The new authenticator pubkey.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub new_authenticator_pubkey: Option<U256>,
}

/// The request to insert an authenticator.
#[cfg(feature = "authenticator")]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct InsertAuthenticatorRequest {
    /// The account index.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub account_index: U256,
    /// The new authenticator address.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub new_authenticator_address: Address,
    /// The old offchain signer commitment.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>, format = "decimal"))]
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<u8>))]
    pub signature: Vec<u8>,
    /// The nonce.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub nonce: U256,
    /// The pubkey id.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub pubkey_id: u32,
    /// The new authenticator pubkey.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub new_authenticator_pubkey: U256,
}

/// The request to remove an authenticator.
#[cfg(feature = "authenticator")]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveAuthenticatorRequest {
    /// The account index.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub account_index: U256,
    /// The authenticator address.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub authenticator_address: Address,
    /// The old offchain signer commitment.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>, format = "decimal"))]
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<u8>))]
    pub signature: Vec<u8>,
    /// The nonce.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub nonce: U256,
    /// The pubkey id.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub pubkey_id: Option<u32>,
    /// The authenticator pubkey.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub authenticator_pubkey: Option<U256>,
}

/// The request to recover an account.
#[cfg(feature = "authenticator")]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[derive(Debug, Serialize, Deserialize)]
pub struct RecoverAccountRequest {
    /// The account index.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub account_index: U256,
    /// The new authenticator address.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex"))]
    pub new_authenticator_address: Address,
    /// The old offchain signer commitment.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>, format = "decimal"))]
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<u8>))]
    pub signature: Vec<u8>,
    /// The nonce.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub nonce: U256,
    /// The new authenticator pubkey.
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "decimal"))]
    pub new_authenticator_pubkey: Option<U256>,
}

/// Response returned by the registry gateway for state-changing requests.
#[derive(Debug, Deserialize)]
pub struct GatewayStatusResponse {
    /// Identifier assigned by the gateway to the submitted request.
    pub request_id: String,
    /// The kind of operation that was submitted.
    pub kind: GatewayRequestKind,
    /// The current state of the request.
    pub status: GatewayRequestState,
}

/// Kind of request tracked by the registry gateway.
#[derive(Debug, Deserialize)]
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
#[derive(Debug, Deserialize)]
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
    },
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
    /// The packed account index [32 bits recoveryCounter][32 bits pubkeyId][192 bits accountIndex]
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex", example = "0x1"))]
    pub packed_account_index: U256,
}

/// Request to fetch a signature nonce from the indexer.
#[cfg(feature = "authenticator")]
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct IndexerSignatureNonceRequest {
    /// The account index to look up
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex", example = "0x1"))]
    pub account_index: U256,
}

/// Response containing the signature nonce from the indexer.
#[cfg(feature = "authenticator")]
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct IndexerSignatureNonceResponse {
    /// The signature nonce for the account
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "hex", example = "0x0"))]
    pub signature_nonce: U256,
}

/// Error codes returned by the indexer.
#[cfg(feature = "authenticator")]
#[derive(Debug, Clone, strum::Display, EnumString, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum IndexerErrorCode {
    /// Internal server error occurred in the indexer.
    InternalServerError,
    /// Requested resource was not found.
    NotFound,
    /// The provided account index is invalid.
    InvalidAccountIndex,
    /// The resource is locked and cannot be accessed.
    Locked,
    /// The account does not exist.
    AccountDoesNotExist,
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
