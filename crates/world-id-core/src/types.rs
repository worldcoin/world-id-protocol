use alloy::signers::k256::ecdsa::Signature;
use oprf_types::crypto::RpNullifierKey;
use ruint::aliases::U256;
use serde;

/// The base field for the credential.
pub type BaseField = ark_bn254::Fr;

/// The response from an inclusion proof request.
#[derive(serde::Serialize, serde::Deserialize)]
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
#[derive(serde::Serialize, serde::Deserialize)]
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
