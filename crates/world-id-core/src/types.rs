use ruint::aliases::U256;
use serde::{self, Deserialize, Serialize};
use world_id_types::BaseField;

#[cfg(any(feature = "authenticator", feature = "rp"))]
use alloy::signers::k256::ecdsa::Signature;
#[cfg(any(feature = "authenticator", feature = "rp"))]
use oprf_types::crypto::RpNullifierKey;

#[cfg(feature = "authenticator")]
use alloy::primitives::Address;

/// The response from an inclusion proof request.
#[derive(Serialize, Deserialize)]
pub struct InclusionProofResponse {
    /// TODO: Add proper documentation.
    pub account_index: u64,
    /// The index of the leaf in the tree.
    pub leaf_index: u64,
    /// The hash root of the tree.
    pub root: U256,
    /// The entire proof of inclusion for all the nodes in the path.
    pub proof: Vec<U256>,
    /// The authenticator public keys for the account.
    pub authenticator_pubkeys: Vec<U256>,
}

impl InclusionProofResponse {
    /// Instantiates a new inclusion proof response.
    #[must_use]
    pub const fn new(
        account_index: u64,
        leaf_index: u64,
        root: U256,
        proof: Vec<U256>,
        authenticator_pubkeys: Vec<U256>,
    ) -> Self {
        Self {
            account_index,
            leaf_index,
            root,
            proof,
            authenticator_pubkeys,
        }
    }
}

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
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base")]
    pub action_id: BaseField,
    /// The nonce.
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_base")]
    #[serde(deserialize_with = "ark_serde_compat::deserialize_babyjubjub_base")]
    pub nonce: BaseField,
}

/// The request to create a new World ID account.
#[cfg(feature = "authenticator")]
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAccountRequest {
    /// The recovery address.
    pub recovery_address: Option<Address>,
    /// The addresses of the authenticators.
    pub authenticator_addresses: Vec<Address>,
    /// The compressed public keys of the authenticators.
    pub authenticator_pubkeys: Vec<U256>,
    /// The offchain signer commitment.
    pub offchain_signer_commitment: U256,
}

/// The request to update an authenticator.
#[cfg(feature = "authenticator")]
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAuthenticatorRequest {
    /// The account index.
    pub account_index: U256,
    /// The old authenticator address.
    pub old_authenticator_address: Address,
    /// The new authenticator address.
    pub new_authenticator_address: Address,
    /// The old offchain signer commitment.
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    pub signature: Vec<u8>,
    /// The nonce.
    pub nonce: U256,
    /// The pubkey id.
    pub pubkey_id: Option<U256>,
    /// The new authenticator pubkey.
    pub new_authenticator_pubkey: Option<U256>,
}

/// The request to insert an authenticator.
#[cfg(feature = "authenticator")]
#[derive(Debug, Serialize, Deserialize)]
pub struct InsertAuthenticatorRequest {
    /// The account index.
    pub account_index: U256,
    /// The new authenticator address.
    pub new_authenticator_address: Address,
    /// The old offchain signer commitment.
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    pub signature: Vec<u8>,
    /// The nonce.
    pub nonce: U256,
    /// The pubkey id.
    pub pubkey_id: U256,
    /// The new authenticator pubkey.
    pub new_authenticator_pubkey: U256,
}

/// The request to remove an authenticator.
#[cfg(feature = "authenticator")]
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveAuthenticatorRequest {
    /// The account index.
    pub account_index: U256,
    /// The authenticator address.
    pub authenticator_address: Address,
    /// The old offchain signer commitment.
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    pub signature: Vec<u8>,
    /// The nonce.
    pub nonce: U256,
    /// The pubkey id.
    pub pubkey_id: Option<U256>,
    /// The authenticator pubkey.
    pub authenticator_pubkey: Option<U256>,
}

/// The request to recover an account.
#[cfg(feature = "authenticator")]
#[derive(Debug, Serialize, Deserialize)]
pub struct RecoverAccountRequest {
    /// The account index.
    pub account_index: U256,
    /// The new authenticator address.
    pub new_authenticator_address: Address,
    /// The old offchain signer commitment.
    pub old_offchain_signer_commitment: U256,
    /// The new offchain signer commitment.
    pub new_offchain_signer_commitment: U256,
    /// The sibling nodes.
    pub sibling_nodes: Vec<U256>,
    /// The signature.
    pub signature: Vec<u8>,
    /// The nonce.
    pub nonce: U256,
    /// The new authenticator pubkey.
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
