use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    rpc_url: String,
    registry_address: Address,
    indexer_url: String,
    gateway_url: String,
    nullifier_oracle_urls: Vec<String>,
}

impl Config {
    pub fn new(
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

    pub fn from_json(path: &str) -> anyhow::Result<Self> {
        serde_json::from_str(&std::fs::read_to_string(path)?)
            .map_err(|e| anyhow::anyhow!("failed to parse config: {}", e))
    }

    pub fn rpc_url(&self) -> &String {
        &self.rpc_url
    }

    pub fn registry_address(&self) -> &Address {
        &self.registry_address
    }

    pub fn indexer_url(&self) -> &String {
        &self.indexer_url
    }

    pub fn gateway_url(&self) -> &String {
        &self.gateway_url
    }

    pub fn nullifier_oracle_urls(&self) -> &Vec<String> {
        &self.nullifier_oracle_urls
    }
}
