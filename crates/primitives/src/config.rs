use serde::{Deserialize, Serialize};

use alloy_primitives::Address;

use crate::PrimitiveError;

const fn default_nullifier_oracle_threshold() -> usize {
    2
}

/// Global configuration to interact with the different components of the Protocol.
///
/// Used by Authenticators and RPs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// A fully qualified RPC domain to perform on-chain call functions
    rpc_url: String, // TODO: Make optional
    /// The address of the `AccountRegistry` contract
    registry_address: Address,
    /// Base URL of a deployed `world-id-indexer`. Used to fetch inclusion proofs from the `AccountRegistry`.
    indexer_url: String,
    /// Base URL of a deployed `world-id-gateway`. Used to submit management operations on authenticators.
    gateway_url: String,
    /// The Base URLs of all Nullifier Oracles to use
    nullifier_oracle_urls: Vec<String>,
    /// Minimum number of Nullifier Oracle responses required to build a nullifier.
    #[serde(default = "default_nullifier_oracle_threshold")]
    nullifier_oracle_threshold: usize,
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
        nullifier_oracle_threshold: usize,
    ) -> Self {
        Self {
            rpc_url,
            registry_address,
            indexer_url,
            gateway_url,
            nullifier_oracle_urls,
            nullifier_oracle_threshold: nullifier_oracle_threshold.max(1),
        }
    }

    /// Loads a configuration from JSON.
    ///
    /// # Errors
    /// Will error if the JSON is not valid.
    pub fn from_json(json_str: &str) -> Result<Self, PrimitiveError> {
        serde_json::from_str(json_str)
            .map_err(|e| PrimitiveError::Serialization(format!("failed to parse config: {e}")))
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

    /// The minimum number of Nullifier Oracle responses required to build a nullifier.
    #[must_use]
    pub const fn nullifier_oracle_threshold(&self) -> usize {
        if self.nullifier_oracle_threshold == 0 {
            1
        } else {
            self.nullifier_oracle_threshold
        }
    }
}
