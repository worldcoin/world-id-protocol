use std::{net::SocketAddr, str::FromStr, sync::Arc};

use alloy::{primitives::Address, providers::DynProvider};
use common::ProviderArgs;
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
    pub fn from_env() -> Self {
        let str = std::env::var("RUN_MODE").unwrap_or_else(|_| "both".to_string());

        match str.to_lowercase().as_str() {
            "indexer" | "indexer-only" => Self::IndexerOnly {
                indexer_config: IndexerConfig::from_env(),
            },
            "http" | "http-only" => Self::HttpOnly {
                http_config: HttpConfig::from_env(),
            },
            "both" | "all" => Self::Both {
                indexer_config: IndexerConfig::from_env(),
                http_config: HttpConfig::from_env(),
            },
            _ => panic!(
                "Invalid run mode: '{str}'. Valid options are: 'indexer', 'indexer-only', 'http', 'http-only', 'both', or 'all'",
            ),
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
    pub provider: ProviderArgs,
    pub registry_address: Address,
    pub tree_cache: TreeCacheConfig,
}

#[derive(Debug)]
pub struct HttpConfig {
    pub http_addr: SocketAddr,
    pub db_poll_interval_secs: u64,
    /// Optional sanity check interval in seconds. If not set, the sanity check will not be run.
    ///
    /// The sanity check calls the `isValidRoot` function on the `WorldIDRegistry` contract to ensure the local Merkle root is valid.
    pub sanity_check_interval_secs: Option<u64>,
}

impl HttpConfig {
    pub fn from_env() -> Self {
        let config = Self {
            http_addr: std::env::var("HTTP_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
                .parse()
                .unwrap(),
            db_poll_interval_secs: std::env::var("DB_POLL_INTERVAL_SECS")
                .unwrap_or_else(|_| "1".to_string())
                .parse()
                .unwrap(),
            sanity_check_interval_secs: std::env::var("SANITY_CHECK_INTERVAL_SECS").ok().and_then(
                |s| {
                    let val = s.parse::<u64>().ok().unwrap_or(0);
                    if val == 0 { None } else { Some(val) }
                },
            ),
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
        config
    }
}

#[derive(Debug)]
pub struct IndexerConfig {
    pub start_block: u64,
    pub batch_size: u64,
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
    pub fn from_env() -> anyhow::Result<Self> {
        let cache_file_path = std::env::var("TREE_CACHE_FILE")
            .map_err(|_| anyhow::anyhow!("TREE_CACHE_FILE environment variable is required"))?;

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

impl GlobalConfig {
    pub fn from_env() -> Self {
        let environment = std::env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .parse()
            .unwrap();

        let run_mode = RunMode::from_env();

        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set.");

        // ProviderArgs reads from RPC_URL and WS_URL environment variables automatically
        let provider = ProviderArgs::default();

        let registry_address = std::env::var("REGISTRY_ADDRESS")
            .expect("REGISTRY_ADDRESS must be set.")
            .parse::<Address>()
            .expect("REGISTRY_ADDRESS must be a valid address");

        let tree_cache =
            TreeCacheConfig::from_env().expect("Failed to load tree cache configuration");

        Self {
            environment,
            run_mode,
            db_url,
            provider,
            registry_address,
            tree_cache,
        }
    }
}
