use serde::{Deserialize, Serialize};

use alloy_primitives::Address;
use url::Url;

use crate::PrimitiveError;

const fn default_nullifier_oracle_threshold() -> usize {
    2
}

/// Global configuration to interact with the different components of the Protocol.
///
/// Used by Authenticators and RPs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// A fully qualified RPC domain to perform on-chain call functions.
    ///
    /// When not available, other services will be used (e.g. the indexer to fetch packed account index).
    rpc_url: Option<Url>,
    /// The chain ID of the network where the `WorldIDRegistry` contract is deployed.
    chain_id: u64,
    /// The address of the `WorldIDRegistry` contract
    registry_address: Address,
    /// Base URL of a deployed `world-id-indexer`. Used to fetch inclusion proofs from the `WorldIDRegistry`.
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
    ///
    /// # Errors
    ///
    /// Returns an error if the `rpc_url` is invalid.
    pub fn new(
        rpc_url: Option<String>,
        chain_id: u64,
        registry_address: Address,
        indexer_url: String,
        gateway_url: String,
        nullifier_oracle_urls: Vec<String>,
        nullifier_oracle_threshold: usize,
    ) -> Result<Self, PrimitiveError> {
        let rpc_url = rpc_url
            .map(|url| {
                Url::parse(&url).map_err(|e| PrimitiveError::InvalidInput {
                    reason: e.to_string(),
                    attribute: "rpc_url".to_string(),
                })
            })
            .transpose()?;

        Ok(Self {
            rpc_url,
            chain_id,
            registry_address,
            indexer_url,
            gateway_url,
            nullifier_oracle_urls,
            nullifier_oracle_threshold,
        })
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
    pub const fn rpc_url(&self) -> Option<&Url> {
        self.rpc_url.as_ref()
    }

    /// The chain ID of the network where the `WorldIDRegistry` contract is deployed.
    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The address of the `WorldIDRegistry` contract.
    #[must_use]
    pub const fn registry_address(&self) -> &Address {
        &self.registry_address
    }

    /// The URL of the `world-id-indexer` service to use. The indexer is used to fetch inclusion proofs from the `WorldIDRegistry` contract.
    #[must_use]
    pub const fn indexer_url(&self) -> &String {
        &self.indexer_url
    }

    /// The URL of the `world-id-gateway` service to use. The gateway is used to perform operations on the `WorldIDRegistry` contract
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
        self.nullifier_oracle_threshold
    }
}
