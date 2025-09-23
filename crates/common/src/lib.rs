mod authenticator;
pub mod authenticator_registry;
pub mod authenticator_signer;
pub mod config;
use alloy::primitives::U256;
pub use authenticator::Authenticator;
pub use authenticator_signer::AuthenticatorSigner;
pub use config::Config;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ProofResponse {
    account_index: u64,
    leaf_index: u64,
    root: U256,
    proof: Vec<U256>,
}

impl ProofResponse {
    pub fn new(account_index: u64, leaf_index: u64, root: U256, proof: Vec<U256>) -> Self {
        Self { account_index, leaf_index, root, proof }
    }
}