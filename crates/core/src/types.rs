#[cfg(feature = "authenticator")]
use ruint::aliases::U256;

use serde::{self, Deserialize, Serialize};

#[cfg(feature = "openapi")]
use utoipa::ToSchema;
pub use world_id_primitives::merkle::AccountInclusionProof;
#[cfg(any(feature = "authenticator", feature = "rp"))]
use world_id_primitives::FieldElement;

#[cfg(any(feature = "authenticator", feature = "rp"))]
use alloy::signers::k256::ecdsa::Signature;
#[cfg(any(feature = "authenticator", feature = "rp"))]
use oprf_types::crypto::RpNullifierKey;

#[cfg(feature = "authenticator")]
use alloy::primitives::Address;

/// The request to register an action for an RP.
#[cfg(any(feature = "authenticator", feature = "rp"))]
#[derive(Serialize, Deserialize)]
pub struct RpRequest {
    /// The ID of the RP.
    pub rp_id: String,
    /// The nullifier key of the RP.
    pub rp_nullifier_key: RpNullifierKey,
    /// The signature of the RP.
    pub signature: Signature,
    /// The current timestamp.
    pub current_time_stamp: u64,
    /// The action ID.
    pub action_id: FieldElement,
    /// The nonce.
    pub nonce: FieldElement,
}

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
