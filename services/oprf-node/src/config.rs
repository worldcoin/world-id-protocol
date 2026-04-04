//! Configuration types and CLI/environment parsing for the OPRF node.

use std::time::Duration;

use alloy::primitives::Address;
use serde::Deserialize;
use taceo_nodes_common::web3::{self, RpcProviderConfig};
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
    pub rpc_provider_config: web3::RpcProviderConfig,

    /// Maximum size of the Merkle cache
    #[serde(default = "WorldOprfNodeConfig::default_max_merkle_cache_size")]
    pub max_merkle_cache_size: u64,

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

    /// Interval for running maintenance tasks for caches
    ///
    /// This includes removing expired entries from caches (invalidated automatically,
    /// but not removed unless entries are added/removed or maintenance tasks are run)
    /// and running potential eviction listeners to update metrics.
    #[serde(
        default = "WorldOprfNodeConfig::default_cache_maintenance_interval",
        with = "humantime_serde"
    )]
    pub cache_maintenance_interval: Duration,
}

/// Cache configuration for a registry watcher.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct WatcherCacheConfig {
    /// Maximum size of the cache.
    ///
    /// Will drop old entries if this capacity is reached.
    #[serde(default = "WatcherCacheConfig::default_max_cache_size")]
    pub max_cache_size: u64,
    /// TTL of the cache.
    ///
    /// Will drop entries that are older than this time.
    #[serde(default = "WatcherCacheConfig::default_time_to_live")]
    pub time_to_live: Duration,
    /// TTI of the cache.
    ///
    /// Will drop entries that are not used for this amount of time.
    #[serde(default = "WatcherCacheConfig::default_time_to_idle")]
    pub time_to_idle: Duration,
}

impl WatcherCacheConfig {
    /// Default maximum size of the cache
    const fn default_max_cache_size() -> u64 {
        1000
    }
    /// Default time-to-live for cache entries
    const fn default_time_to_live() -> Duration {
        Duration::from_secs(60 * 60 * 24 * 7)
    }

    /// Default time-to-idle for cache entries
    const fn default_time_to_idle() -> Duration {
        Duration::from_secs(60 * 60 * 24)
    }

    /// Initialize with default values for all fields
    const fn with_default_values() -> Self {
        Self {
            max_cache_size: Self::default_max_cache_size(),
            time_to_live: Self::default_time_to_live(),
            time_to_idle: Self::default_time_to_idle(),
        }
    }
}

impl Default for WatcherCacheConfig {
    fn default() -> Self {
        Self::with_default_values()
    }
}

impl WorldOprfNodeConfig {
    /// Default maximum Merkle cache size
    const fn default_max_merkle_cache_size() -> u64 {
        100
    }

    /// Default maximum allowed difference between received and node timestamp
    fn default_current_time_stamp_max_difference() -> Duration {
        Duration::from_secs(300) // 5 minutes
    }

    /// Default interval for cache maintenance tasks
    fn default_cache_maintenance_interval() -> Duration {
        Duration::from_secs(60) // 1 minute
    }

    /// Initialize with default values for all optional fields
    #[must_use]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "We want to consume the contracts"
    )]
    pub fn with_default_values(
        environment: taceo_oprf::service::Environment,
        contracts: WorldIdNodeContracts,
        version_req: VersionReq,
        rpc_provider_config: RpcProviderConfig,
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
            max_merkle_cache_size: Self::default_max_merkle_cache_size(),
            current_time_stamp_max_difference: Self::default_current_time_stamp_max_difference(),
            cache_maintenance_interval: Self::default_cache_maintenance_interval(),
            node_config: OprfNodeServiceConfig::with_default_values(
                environment,
                oprf_key_registry_contract,
                version_req,
            ),
            rp_cache_config: WatcherCacheConfig::with_default_values(),
            issuer_cache_config: WatcherCacheConfig::with_default_values(),
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
