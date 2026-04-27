//! Configuration types and CLI/environment parsing for the OPRF node.

use std::{num::NonZeroU64, time::Duration};

use alloy::{primitives::Address, transports::http::reqwest::Url};
use serde::Deserialize;
use taceo_nodes_common::web3::{self};
use taceo_oprf::service::{VersionReq, config::OprfNodeServiceConfig};

/// The configuration for the OPRF node.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct WorldOprfNodeConfig {
    /// The address of the `WorldIDRegistry` smart contract
    pub world_id_registry_contract: Address,

    /// The address of the `RpRegistry` smart contract
    pub rp_registry_contract: Address,

    /// The address of the `CredentialSchemaIssuerRegistry` smart contract
    pub credential_schema_issuer_registry_contract: Address,

    /// The OPRF service config
    #[serde(rename = "oprf")]
    pub node_config: OprfNodeServiceConfig,

    /// The blockchain RPC config
    #[serde(rename = "rpc")]
    pub rpc_provider_config: web3::HttpRpcProviderConfig,

    /// Cache configuration for the [`MerkleWatcher`](crate::auth::merkle_watcher::MerkleWatcher)
    #[serde(default)]
    pub merkle_cache_config: WatcherCacheConfig,

    /// Cache configuration for the [`RpRegistryWatcher`](crate::auth::rp_registry_watcher::RpRegistryWatcher)
    #[serde(default)]
    pub rp_cache_config: WatcherCacheConfig,

    /// Cache configuration for the [`SchemaIssuerRegistryWatcher`](crate::auth::schema_issuer_registry_watcher::SchemaIssuerRegistryWatcher)
    #[serde(default)]
    pub issuer_cache_config: WatcherCacheConfig,

    /// Maximum delta between the received `current_time_stamp` and the node's `current_time_stamp`
    #[serde(
        default = "WorldOprfNodeConfig::default_current_time_stamp_max_difference",
        with = "humantime_serde"
    )]
    pub current_time_stamp_max_difference: Duration,

    /// Max time for an `eth_call` to an unknown contract.
    ///
    /// During runtime, the nodes may perform `eth_call`s to unknown contracts (i.e. wip101 verification). To prevent malicious contracts to `DoS` attack, we wrap these calls in a timeout.
    #[serde(
        default = "WorldOprfNodeConfig::default_timeout_external_eth_call",
        with = "humantime_serde"
    )]
    pub timeout_external_eth_call: Duration,
}

/// Cache configuration for a registry watcher.
#[derive(Copy, Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct WatcherCacheConfig {
    /// Maximum size of the cache.
    ///
    /// Will drop old entries if this capacity is reached.
    #[serde(default = "WatcherCacheConfig::default_max_cache_size")]
    pub max_cache_size: NonZeroU64,
    /// TTL of the cache.
    ///
    /// Will drop entries that are older than this time.
    #[serde(default = "WatcherCacheConfig::default_time_to_live")]
    pub time_to_live: Duration,
}

impl WatcherCacheConfig {
    /// Default maximum size of the cache
    const fn default_max_cache_size() -> NonZeroU64 {
        NonZeroU64::new(1000).expect("1000 is non-zero")
    }
    /// Default time-to-live for cache entries
    const fn default_time_to_live() -> Duration {
        Duration::from_mins(10)
    }

    /// Initialize with default values for all fields
    const fn with_default_values() -> Self {
        Self {
            max_cache_size: Self::default_max_cache_size(),
            time_to_live: Self::default_time_to_live(),
        }
    }
}

impl Default for WatcherCacheConfig {
    fn default() -> Self {
        Self::with_default_values()
    }
}

impl WorldOprfNodeConfig {
    /// Default maximum allowed difference between received and node timestamp
    fn default_current_time_stamp_max_difference() -> Duration {
        Duration::from_secs(300) // 5 minutes
    }

    /// Default timeout for an `eth_call` to an unknown contract.
    fn default_timeout_external_eth_call() -> Duration {
        Duration::from_secs(10)
    }

    /// Initialize with default values for all optional fields.
    #[must_use]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "We want to consume the contracts"
    )]
    pub fn with_default_values(
        environment: taceo_oprf::service::Environment,
        contracts: WorldIdNodeContracts,
        version_req: VersionReq,
        rpc_provider_config: web3::HttpRpcProviderConfig,
        ws_rpc_url: Url,
    ) -> Self {
        let WorldIdNodeContracts {
            world_id_registry_contract,
            rp_registry_contract,
            credential_schema_issuer_registry_contract,
            oprf_key_registry_contract,
        } = contracts;
        Self {
            world_id_registry_contract,
            rp_registry_contract,
            credential_schema_issuer_registry_contract,
            rpc_provider_config,
            current_time_stamp_max_difference: Self::default_current_time_stamp_max_difference(),
            timeout_external_eth_call: Self::default_timeout_external_eth_call(),
            node_config: OprfNodeServiceConfig::with_default_values(
                environment,
                oprf_key_registry_contract,
                ws_rpc_url.clone(),
                version_req,
            ),
            rp_cache_config: WatcherCacheConfig::default(),
            issuer_cache_config: WatcherCacheConfig::default(),
            merkle_cache_config: WatcherCacheConfig::default(),
        }
    }
}

/// Holds the Ethereum contract addresses used by the World ID node.
///
/// Each field corresponds to a deployed contract that the node interacts with. This struct is primarily used to provide type-safe access to the contracts when initializing the node configuration.
#[allow(
    clippy::exhaustive_structs,
    reason = "If we add another contract it must be a breaking change anyways"
)]
pub struct WorldIdNodeContracts {
    /// Address of the World ID Registry contract.
    pub world_id_registry_contract: Address,
    /// Address of the `RpRegistry` contract.
    pub rp_registry_contract: Address,
    /// Address of the `CredentialSchemaIssuerRegistry` contract.
    pub credential_schema_issuer_registry_contract: Address,
    /// Address of the OPRF Key Registry contract.
    pub oprf_key_registry_contract: Address,
}
