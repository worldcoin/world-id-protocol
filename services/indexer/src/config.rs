use std::{net::SocketAddr, str::FromStr, sync::Arc};

use alloy::{primitives::Address, providers::DynProvider};
use thiserror::Error;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

use crate::db::DB;

#[derive(Clone)]
pub struct AppState {
    pub db: DB,
    pub registry: Arc<WorldIdRegistryInstance<DynProvider>>,
}

impl AppState {
    pub fn new(db: DB, registry: Arc<WorldIdRegistryInstance<DynProvider>>) -> Self {
        Self { db, registry }
    }
}

#[derive(Debug)]
pub enum RunMode {
    /// Only run the indexer (sync chain data and write to DB)
    IndexerOnly { indexer_config: IndexerConfig },
    /// Only serve HTTP endpoint (requires pre-populated DB)
    HttpOnly { http_config: HttpConfig },
    /// Run both indexer and HTTP server (default)
    Both {
        indexer_config: IndexerConfig,
        http_config: HttpConfig,
    },
}

impl RunMode {
    pub fn from_env() -> Result<Self, ConfigError> {
        let str = std::env::var("RUN_MODE").unwrap_or_else(|_| "both".to_string());

        match str.to_lowercase().as_str() {
            "indexer" | "indexer-only" => Ok(Self::IndexerOnly {
                indexer_config: IndexerConfig::from_env(),
            }),
            "http" | "http-only" => Ok(Self::HttpOnly {
                http_config: HttpConfig::from_env()?,
            }),
            "both" | "all" => Ok(Self::Both {
                indexer_config: IndexerConfig::from_env(),
                http_config: HttpConfig::from_env()?,
            }),
            _ => Err(ConfigError::InvalidRunMode(str)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Production,
    Staging,
    Development,
}

impl FromStr for Environment {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "production" => Ok(Self::Production),
            "staging" => Ok(Self::Staging),
            "development" => Ok(Self::Development),
            _ => Err(format!(
                "Invalid environment: '{s}'. Valid options are: 'production', 'staging', or 'development'"
            )),
        }
    }
}

#[derive(Debug)]
pub struct GlobalConfig {
    pub environment: Environment,
    pub run_mode: RunMode,
    pub db_url: String,
    pub http_rpc_url: String,
    pub ws_rpc_url: String,
    pub registry_address: Address,
}

#[derive(Debug)]
pub struct HttpConfig {
    pub http_addr: SocketAddr,
    pub db_poll_interval_secs: u64,
    /// Optional sanity check interval in seconds. If not set, the sanity check will not be run.
    ///
    /// The sanity check calls the `isValidRoot` function on the `WorldIDRegistry` contract to ensure the local Merkle root is valid.
    pub sanity_check_interval_secs: Option<u64>,
    pub tree_cache: TreeCacheConfig,
}

impl HttpConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let http_addr_str =
            std::env::var("HTTP_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let http_addr = http_addr_str
            .parse()
            .map_err(|e| ConfigError::InvalidHttpAddr(format!("{}: {}", http_addr_str, e)))?;

        let db_poll_interval_str =
            std::env::var("DB_POLL_INTERVAL_SECS").unwrap_or_else(|_| "1".to_string());
        let db_poll_interval_secs = db_poll_interval_str.parse().map_err(|e| {
            ConfigError::InvalidDbPollInterval(format!("{}: {}", db_poll_interval_str, e))
        })?;

        let tree_cache = TreeCacheConfig::from_env()?;

        let config = Self {
            http_addr,
            db_poll_interval_secs,
            sanity_check_interval_secs: std::env::var("SANITY_CHECK_INTERVAL_SECS").ok().and_then(
                |s| {
                    let val = s.parse::<u64>().ok().unwrap_or(0);
                    if val == 0 { None } else { Some(val) }
                },
            ),
            tree_cache,
        };

        if config.http_addr.port() != 8080 {
            tracing::warn!(
                "Indexer is not running on port 8080, this may not work as expected when running dockerized (image exposes port 8080)"
            );
        }

        tracing::info!(
            "✔️ Http config loaded from env. Running on {}",
            config.http_addr
        );
        Ok(config)
    }
}

#[derive(Debug)]
pub struct IndexerConfig {
    pub start_block: u64,
    pub batch_size: u64,
    pub backfill_batch_size: u64,
}

impl IndexerConfig {
    pub fn from_env() -> Self {
        let config = Self {
            start_block: std::env::var("START_BLOCK")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            batch_size: std::env::var("BATCH_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(64),
            backfill_batch_size: std::env::var("BACKFILL_BATCH_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10_000),
        };
        tracing::info!("✔️ Indexer config loaded from env");
        config
    }
}

#[derive(Debug, Clone)]
pub struct TreeCacheConfig {
    /// Path to mmap cache file (mandatory)
    pub cache_file_path: String,

    /// Depth of the Merkle tree (default: 30)
    pub tree_depth: usize,

    /// Depth of dense tree prefix (mandatory, default: 20)
    pub dense_tree_prefix_depth: usize,

    /// HttpOnly mode: interval in seconds to check for cache updates (default: 30)
    pub http_cache_refresh_interval_secs: u64,
}

impl TreeCacheConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let cache_file_path =
            std::env::var("TREE_CACHE_FILE").map_err(|_| ConfigError::MissingTreeCacheFile)?;

        let config = Self {
            cache_file_path,
            tree_depth: std::env::var("TREE_DEPTH")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
            dense_tree_prefix_depth: std::env::var("TREE_DENSE_PREFIX_DEPTH")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(26),
            http_cache_refresh_interval_secs: std::env::var(
                "TREE_HTTP_CACHE_REFRESH_INTERVAL_SECS",
            )
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30),
        };

        tracing::info!(
            "✔️ Tree cache config loaded from env. Cache file: {}",
            config.cache_file_path
        );
        Ok(config)
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("TREE_CACHE_FILE environment variable is required")]
    MissingTreeCacheFile,
    #[error("DATABASE_URL environment variable is required")]
    MissingDatabaseUrl,
    #[error("RPC_URL environment variable is required")]
    MissingRpcUrl,
    #[error("WS_URL environment variable is required")]
    MissingWsUrl,
    #[error("REGISTRY_ADDRESS environment variable is required")]
    MissingRegistryAddress,
    #[error(
        "invalid ENVIRONMENT: '{0}'. Valid options are: 'production', 'staging', or 'development'"
    )]
    InvalidEnvironment(String),
    #[error("invalid REGISTRY_ADDRESS: {0}")]
    InvalidRegistryAddress(String),
    #[error(
        "invalid RUN_MODE: '{0}'. Valid options are: 'indexer', 'indexer-only', 'http', 'http-only', 'both', or 'all'"
    )]
    InvalidRunMode(String),
    #[error("invalid HTTP_ADDR: {0}")]
    InvalidHttpAddr(String),
    #[error("invalid DB_POLL_INTERVAL_SECS: {0}")]
    InvalidDbPollInterval(String),
}

impl GlobalConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let environment_str =
            std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
        let environment = environment_str
            .parse()
            .map_err(|_| ConfigError::InvalidEnvironment(environment_str))?;

        let run_mode = RunMode::from_env()?;

        let db_url = std::env::var("DATABASE_URL").map_err(|_| ConfigError::MissingDatabaseUrl)?;

        let http_rpc_url = std::env::var("RPC_URL").map_err(|_| ConfigError::MissingRpcUrl)?;
        let ws_rpc_url = std::env::var("WS_URL").map_err(|_| ConfigError::MissingWsUrl)?;

        let registry_address_str =
            std::env::var("REGISTRY_ADDRESS").map_err(|_| ConfigError::MissingRegistryAddress)?;
        let registry_address = registry_address_str.parse::<Address>().map_err(|e| {
            ConfigError::InvalidRegistryAddress(format!("{}: {}", registry_address_str, e))
        })?;

        Ok(Self {
            environment,
            run_mode,
            db_url,
            http_rpc_url,
            ws_rpc_url,
            registry_address,
        })
    }
}
