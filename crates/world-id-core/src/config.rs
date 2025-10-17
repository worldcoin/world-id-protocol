use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

/// Global configuration to interact with the different components of the Protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    rpc_url: String,
    registry_address: Address,
    indexer_url: String,
    gateway_url: String,
    nullifier_oracle_urls: Vec<String>,
}

impl Config {
    /// Instantiates a new configuration.
    #[must_use]
    pub const fn new(
        rpc_url: String,
        registry_address: Address,
        indexer_url: String,
        gateway_url: String,
        nullifier_oracle_urls: Vec<String>,
    ) -> Self {
        Self {
            rpc_url,
            registry_address,
            indexer_url,
            gateway_url,
            nullifier_oracle_urls,
        }
    }

    /// Loads a configuration from a JSON file.
    ///
    /// # Errors
    /// Will error if the file does not exist or is not valid JSON.
    pub fn from_json(path: &str) -> anyhow::Result<Self> {
        serde_json::from_str(&std::fs::read_to_string(path)?)
            .map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))
    }

    /// The RPC endpoint to perform RPC calls.
    #[must_use]
    pub const fn rpc_url(&self) -> &String {
        &self.rpc_url
    }

    /// The address of the `AccountRegistry` contract.
    #[must_use]
    pub const fn registry_address(&self) -> &Address {
        &self.registry_address
    }

    /// The URL of the `world-id-indexer` service to use. The indexer is used to fetch inclusion proofs from the `AccountRegistry` contract.
    #[must_use]
    pub const fn indexer_url(&self) -> &String {
        &self.indexer_url
    }

    /// The URL of the `world-id-gateway` service to use. The gateway is used to perform operations on the `AccountRegistry` contract
    /// without leaking a wallet address.
    #[must_use]
    pub const fn gateway_url(&self) -> &String {
        &self.gateway_url
    }

    /// The list of URLs of all and each node of the Nullifier Oracle.
    #[must_use]
    pub const fn nullifier_oracle_urls(&self) -> &Vec<String> {
        &self.nullifier_oracle_urls
    }
}
