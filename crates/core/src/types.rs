use serde::{self, Deserialize, Serialize};
pub use world_id_primitives::merkle::AccountInclusionProof;
#[cfg(any(feature = "authenticator", feature = "rp"))]
use world_id_primitives::FieldElement;

#[cfg(any(feature = "authenticator", feature = "rp"))]
use alloy::signers::k256::ecdsa::Signature;
#[cfg(any(feature = "authenticator", feature = "rp"))]
use oprf_types::crypto::RpNullifierKey;

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
