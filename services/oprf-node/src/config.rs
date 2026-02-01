//! Configuration types and CLI/environment parsing for the OPRF node.

use std::{net::SocketAddr, time::Duration};

use alloy::primitives::Address;
use clap::Parser;
use taceo_oprf::service::config::OprfNodeConfig;

/// The configuration for the OPRF node.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct WorldOprfNodeConfig {
    /// The bind addr of the AXUM server
    #[clap(long, env = "OPRF_NODE_BIND_ADDR", default_value = "0.0.0.0:4321")]
    pub bind_addr: SocketAddr,

    /// Max wait time the node waits for its workers during shutdown.
    #[clap(
        long,
        env = "OPRF_NODE_MAX_WAIT_TIME_SHUTDOWN",
        default_value = "10s",
        value_parser = humantime::parse_duration
    )]
    pub max_wait_time_shutdown: Duration,

    /// The address of the WorldIDRegistry smart contract
    #[clap(long, env = "OPRF_NODE_WORLD_ID_REGISTRY_CONTRACT")]
    pub world_id_registry_contract: Address,

    /// The address of the RpRegistry smart contract
    #[clap(long, env = "OPRF_NODE_RP_REGISTRY_CONTRACT")]
    pub rp_registry_contract: Address,

    /// The maximum size of the merkle root cache.
    ///
    /// Will drop least recently used merkle roots if this capacity is reached.
    #[clap(long, env = "OPRF_NODE_MERKLE_CACHE_SIZE", default_value = "100")]
    pub max_merkle_cache_size: u64,

    /// The maximum size of the RpRegistry store.
    ///
    /// Will drop old Rps if this capacity is reached.
    #[clap(long, env = "OPRF_NODE_RP_REGISTRY_STORE_SIZE", default_value = "1000")]
    pub max_rp_registry_store_size: u64,

    /// The maximum delta between the received current_time_stamp the node current_time_stamp
    #[clap(
        long,
        env = "OPRF_NODE_CURRENT_TIME_STAMP_MAX_DIFFERENCE",
        default_value = "5min",
        value_parser = humantime::parse_duration
    )]
    pub current_time_stamp_max_difference: Duration,

    /// The interval for running maintenance tasks for caches.
    ///
    /// This includes removing expired entries from caches (invalidated automatically,
    /// but not removed unless entries are added/removed or maintenance task are run)
    /// and running potential eviction listeners to update metrics.
    #[clap(
        long,
        env = "OPRF_NODE_CACHE_MAINTENANCE_INTERVAL",
        default_value = "1min",
        value_parser = humantime::parse_duration
    )]
    pub cache_maintenance_interval: Duration,

    /// The OPRF node config
    #[clap(flatten)]
    pub node_config: OprfNodeConfig,
}
