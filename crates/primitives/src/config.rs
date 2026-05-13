use serde::{Deserialize, Serialize};

use alloy_primitives::Address;
use url::Url;

use crate::PrimitiveError;

const fn default_nullifier_oracle_threshold() -> usize {
    2
}

/// Configuration for a protocol service endpoint (indexer or gateway).
///
/// The target URL is required in both variants. The OHTTP variant additionally
/// carries the relay configuration needed to encrypt and route requests through
/// an Oblivious HTTP relay.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServiceEndpoint {
    /// Direct HTTP(S) connection to `url`.
    Direct {
        /// Target service URL.
        url: String,
    },
    /// OHTTP-routed connection: encrypted requests pass through `relay_url` to `url`.
    Ohttp {
        /// Target service URL (placed inside the encrypted BHTTP envelope).
        url: String,
        /// URL of the OHTTP relay that receives encrypted requests.
        relay_url: String,
        /// Base64-encoded `application/ohttp-keys` payload listing the gateway HPKE configs.
        key_config_base64: String,
    },
}

impl ServiceEndpoint {
    /// Convenience constructor for a direct (non-OHTTP) endpoint.
    #[must_use]
    pub const fn direct(url: String) -> Self {
        Self::Direct { url }
    }

    /// Convenience constructor for an OHTTP-routed endpoint.
    #[must_use]
    pub const fn ohttp(url: String, relay_url: String, key_config_base64: String) -> Self {
        Self::Ohttp {
            url,
            relay_url,
            key_config_base64,
        }
    }

    /// Target service URL (works for both variants).
    #[must_use]
    pub fn url(&self) -> &str {
        match self {
            Self::Direct { url } | Self::Ohttp { url, .. } => url,
        }
    }
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
    /// Indexer endpoint (`world-id-indexer`). Used to fetch inclusion proofs from the `WorldIDRegistry`.
    indexer: ServiceEndpoint,
    /// Gateway endpoint (`world-id-gateway`). Used to submit management operations on authenticators.
    gateway: ServiceEndpoint,
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
        indexer: ServiceEndpoint,
        gateway: ServiceEndpoint,
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
            indexer,
            gateway,
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

    /// The indexer endpoint configuration. The indexer is used to fetch inclusion
    /// proofs from the `WorldIDRegistry` contract.
    #[must_use]
    pub const fn indexer(&self) -> &ServiceEndpoint {
        &self.indexer
    }

    /// The gateway endpoint configuration. The gateway is used to perform operations
    /// on the `WorldIDRegistry` contract without leaking a wallet address.
    #[must_use]
    pub const fn gateway(&self) -> &ServiceEndpoint {
        &self.gateway
    }

    /// Convenience accessor for the indexer's target URL.
    #[must_use]
    pub fn indexer_url(&self) -> &str {
        self.indexer.url()
    }

    /// Convenience accessor for the gateway's target URL.
    #[must_use]
    pub fn gateway_url(&self) -> &str {
        self.gateway.url()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_json_direct_endpoints() {
        let json = serde_json::json!({
            "chain_id": 480,
            "registry_address": "0x0000000000000000000000000000000000000001",
            "indexer": { "type": "direct", "url": "http://indexer.example.com" },
            "gateway": { "type": "direct", "url": "http://gateway.example.com" },
            "nullifier_oracle_urls": [],
            "nullifier_oracle_threshold": 2
        });

        let config = Config::from_json(&json.to_string()).unwrap();
        assert!(matches!(config.indexer(), ServiceEndpoint::Direct { .. }));
        assert!(matches!(config.gateway(), ServiceEndpoint::Direct { .. }));
        assert_eq!(config.indexer_url(), "http://indexer.example.com");
        assert_eq!(config.gateway_url(), "http://gateway.example.com");
    }

    #[test]
    fn from_json_ohttp_endpoints() {
        let json = serde_json::json!({
            "chain_id": 480,
            "registry_address": "0x0000000000000000000000000000000000000001",
            "indexer": {
                "type": "ohttp",
                "url": "http://indexer.example.com",
                "relay_url": "https://relay.example.com/gateway",
                "key_config_base64": "dGVzdC1rZXk="
            },
            "gateway": {
                "type": "ohttp",
                "url": "http://gateway.example.com",
                "relay_url": "https://relay.example.com/gateway",
                "key_config_base64": "dGVzdC1rZXk="
            },
            "nullifier_oracle_urls": [],
            "nullifier_oracle_threshold": 2
        });

        let config = Config::from_json(&json.to_string()).unwrap();
        match config.indexer() {
            ServiceEndpoint::Ohttp {
                url,
                relay_url,
                key_config_base64,
            } => {
                assert_eq!(url, "http://indexer.example.com");
                assert_eq!(relay_url, "https://relay.example.com/gateway");
                assert_eq!(key_config_base64, "dGVzdC1rZXk=");
            }
            other => panic!("expected Ohttp variant, got: {other:?}"),
        }
        match config.gateway() {
            ServiceEndpoint::Ohttp {
                url,
                relay_url,
                key_config_base64,
            } => {
                assert_eq!(url, "http://gateway.example.com");
                assert_eq!(relay_url, "https://relay.example.com/gateway");
                assert_eq!(key_config_base64, "dGVzdC1rZXk=");
            }
            other => panic!("expected Ohttp variant, got: {other:?}"),
        }
    }
}
