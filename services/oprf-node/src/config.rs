//! Configuration types and CLI/environment parsing for the OPRF node.

use std::time::Duration;

use alloy::primitives::Address;
use secrecy::SecretString;
use serde::Deserialize;
use taceo_oprf::service::{VersionReq, config::OprfNodeServiceConfig};

/// The configuration for the OPRF node.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct WorldOprfNodeConfig {
    /// The address of the WorldIDRegistry smart contract
    pub world_id_registry_contract: Address,

    /// The address of the RpRegistry smart contract
    pub rp_registry_contract: Address,

    /// The address of the CredentialSchemaIssuerRegistry smart contract
    pub credential_schema_issuer_registry_contract: Address,

    /// The OPRF service config
    #[serde(rename = "oprf")]
    pub node_config: OprfNodeServiceConfig,

    /// Maximum size of the Merkle cache
    #[serde(default = "WorldOprfNodeConfig::default_max_merkle_cache_size")]
    pub max_merkle_cache_size: u64,

    /// Maximum size of the RpRegistry store
    ///
    /// Will drop old Rps if this capacity is reached.
    #[serde(default = "WorldOprfNodeConfig::default_max_rp_registry_store_size")]
    pub max_rp_registry_store_size: u64,

    /// Maximum size of the CredentialSchemaIssuerRegistry store
    ///
    /// Will drop old issuers if this capacity is reached.
    #[serde(
        default = "WorldOprfNodeConfig::default_max_credential_schema_issuer_registry_store_size"
    )]
    pub max_credential_schema_issuer_registry_store_size: u64,

    /// Maximum delta between the received current_time_stamp and the node's current_time_stamp
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

impl WorldOprfNodeConfig {
    /// Default maximum Merkle cache size
    const fn default_max_merkle_cache_size() -> u64 {
        100
    }

    /// Default maximum RP registry store size
    const fn default_max_rp_registry_store_size() -> u64 {
        1000
    }

    /// Default maximum CredentialSchemaIssuerRegistry store size
    const fn default_max_credential_schema_issuer_registry_store_size() -> u64 {
        1000
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
        chain_ws_rpc_url: SecretString,
        version_req: VersionReq,
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
            max_merkle_cache_size: Self::default_max_merkle_cache_size(),
            max_rp_registry_store_size: Self::default_max_rp_registry_store_size(),
            max_credential_schema_issuer_registry_store_size:
                Self::default_max_credential_schema_issuer_registry_store_size(),
            current_time_stamp_max_difference: Self::default_current_time_stamp_max_difference(),
            cache_maintenance_interval: Self::default_cache_maintenance_interval(),
            node_config: OprfNodeServiceConfig::with_default_values(
                environment,
                oprf_key_registry_contract,
                chain_ws_rpc_url,
                version_req,
            ),
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
    /// Address of the RpRegistry contract.
    pub rp_registry_contract: Address,
    /// Address of the CredentialSchemaIssuerRegistry contract.
    pub credential_schema_issuer_registry_contract: Address,
    /// Address of the OPRF Key Registry contract.
    pub oprf_key_registry_contract: Address,
}
