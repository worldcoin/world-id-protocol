//! The core library for the World ID Protocol.

mod authenticator;
pub use authenticator::Authenticator;
pub mod account_registry;
pub mod account_signer;
pub mod config;
use alloy::primitives::U256;

mod credential;
pub use credential::Credential;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ProofResponse {
    account_index: u64,
    leaf_index: u64,
    root: U256,
    proof: Vec<U256>,
}

impl ProofResponse {
    pub fn new(account_index: u64, leaf_index: u64, root: U256, proof: Vec<U256>) -> Self {
        Self {
            account_index,
            leaf_index,
            root,
            proof,
        }
    }
}
