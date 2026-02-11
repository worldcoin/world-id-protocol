use std::{net::SocketAddr, str::FromStr, sync::Arc};

use alloy::{primitives::Address, providers::DynProvider};
use thiserror::Error;
use world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance;

use crate::{db::DB, tree::state::TreeState};

#[derive(Clone)]
pub struct AppState {
    pub db: DB,
    pub registry: Arc<WorldIdRegistryInstance<DynProvider>>,
    pub tree_state: TreeState,
}

impl AppState {
    pub fn new(
        db: DB,
        registry: Arc<WorldIdRegistryInstance<DynProvider>>,
        tree_state: TreeState,
    ) -> Self {
        Self {
            db,
            registry,
            tree_state,
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    /// Helper to set environment variable for test
    fn set_env(key: &str, value: &str) {
        unsafe {
            env::set_var(key, value);
        }
    }

    /// Clear all config-related environment variables
    fn clear_all_config_env() {
        unsafe {
            // Global config
            env::remove_var("ENVIRONMENT");
            env::remove_var("DATABASE_URL");
            env::remove_var("RPC_URL");
            env::remove_var("WS_URL");
            env::remove_var("REGISTRY_ADDRESS");
            env::remove_var("RUN_MODE");

            // HTTP config
            env::remove_var("HTTP_ADDR");
            env::remove_var("DB_POLL_INTERVAL_SECS");
            env::remove_var("SANITY_CHECK_INTERVAL_SECS");

            // Indexer config
            env::remove_var("START_BLOCK");
            env::remove_var("BATCH_SIZE");

            // Tree cache config
            env::remove_var("TREE_CACHE_FILE");
            env::remove_var("TREE_DEPTH");
            env::remove_var("TREE_HTTP_CACHE_REFRESH_INTERVAL_SECS");
        }
    }
    #[test]
    fn test_environment_parsing() {
        let prod: Environment = "production".parse().unwrap();
        assert_eq!(prod, Environment::Production);

        let staging: Environment = "staging".parse().unwrap();
        assert_eq!(staging, Environment::Staging);

        let dev: Environment = "development".parse().unwrap();
        assert_eq!(dev, Environment::Development);
    }

    #[test]
    fn test_environment_parsing_case_insensitive() {
        let prod: Environment = "PRODUCTION".parse().unwrap();
        assert_eq!(prod, Environment::Production);

        let staging: Environment = "StAgInG".parse().unwrap();
        assert_eq!(staging, Environment::Staging);
    }

    #[test]
    fn test_invalid_environment_parsing() {
        let result: Result<Environment, _> = "invalid".parse();
        assert!(result.is_err());
    }

    #[test]
    #[serial]
    fn test_run_mode_from_env_indexer_only() {
        clear_all_config_env();

        set_env("RUN_MODE", "indexer");
        set_env("START_BLOCK", "100");

        let mode = RunMode::from_env().expect("Should load RunMode from env.");
        assert!(matches!(mode, RunMode::IndexerOnly { .. }));
    }

    #[test]
    #[serial]
    fn test_run_mode_from_env_http_only() {
        clear_all_config_env();

        set_env("RUN_MODE", "http");
        set_env("HTTP_ADDR", "127.0.0.1:8080");
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        let mode = RunMode::from_env().expect("Should load RunMode from env.");
        assert!(matches!(mode, RunMode::HttpOnly { .. }));
    }

    #[test]
    #[serial]
    fn test_run_mode_from_env_both() {
        clear_all_config_env();

        set_env("RUN_MODE", "both");
        set_env("START_BLOCK", "100");
        set_env("HTTP_ADDR", "127.0.0.1:8080");
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        let mode = RunMode::from_env().expect("Should load RunMode from env.");
        assert!(matches!(mode, RunMode::Both { .. }));
    }

    #[test]
    #[serial]
    fn test_run_mode_default() {
        clear_all_config_env();
        set_env("START_BLOCK", "100");
        set_env("HTTP_ADDR", "127.0.0.1:8080");
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        let mode = RunMode::from_env().expect("Should load RunMode from env.");
        // Default should be "both"
        assert!(matches!(mode, RunMode::Both { .. }));
    }

    #[test]
    #[serial]
    fn test_run_mode_invalid() {
        clear_all_config_env();
        set_env("RUN_MODE", "invalid_mode");

        let result = RunMode::from_env();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("invalid RUN_MODE") || err_msg.contains("Invalid"));
    }

    #[test]
    #[serial]
    fn test_http_config_defaults() {
        clear_all_config_env();

        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        let config = HttpConfig::from_env().expect("Should load HttpConfig from env.");

        assert_eq!(config.http_addr.to_string(), "0.0.0.0:8080");
        assert_eq!(config.db_poll_interval_secs, 1);
        assert_eq!(config.sanity_check_interval_secs, None);
        assert_eq!(config.tree_cache.cache_file_path, "/tmp/test_cache");
        assert_eq!(config.tree_cache.tree_depth, 30); // default
    }

    #[test]
    #[serial]
    fn test_http_config_custom_values() {
        clear_all_config_env();

        set_env("TREE_CACHE_FILE", "/tmp/test_cache");
        set_env("HTTP_ADDR", "127.0.0.1:9000");
        set_env("DB_POLL_INTERVAL_SECS", "5");
        set_env("SANITY_CHECK_INTERVAL_SECS", "60");

        let config = HttpConfig::from_env().expect("Should load HttpConfig from env.");

        assert_eq!(config.http_addr.to_string(), "127.0.0.1:9000");
        assert_eq!(config.db_poll_interval_secs, 5);
        assert_eq!(config.sanity_check_interval_secs, Some(60));
        assert_eq!(config.tree_cache.cache_file_path, "/tmp/test_cache");
    }

    #[test]
    #[serial]
    fn test_http_config_sanity_check_disabled_on_zero() {
        clear_all_config_env();

        set_env("TREE_CACHE_FILE", "/tmp/test_cache");
        set_env("SANITY_CHECK_INTERVAL_SECS", "0");

        let config = HttpConfig::from_env().expect("Should load HttpConfig from env.");
        assert_eq!(config.sanity_check_interval_secs, None);
    }

    #[test]
    #[serial]
    fn test_indexer_config_defaults() {
        clear_all_config_env();

        let config = IndexerConfig::from_env();

        assert_eq!(config.start_block, 0);
        assert_eq!(config.batch_size, 64);
    }

    #[test]
    #[serial]
    fn test_indexer_config_custom_values() {
        clear_all_config_env();

        set_env("START_BLOCK", "12345");
        set_env("BATCH_SIZE", "128");

        let config = IndexerConfig::from_env();

        assert_eq!(config.start_block, 12345);
        assert_eq!(config.batch_size, 128);
    }

    #[test]
    #[serial]
    fn test_indexer_config_invalid_values_use_defaults() {
        clear_all_config_env();

        set_env("START_BLOCK", "invalid");
        set_env("BATCH_SIZE", "not_a_number");

        let config = IndexerConfig::from_env();

        // Invalid values should fall back to defaults
        assert_eq!(config.start_block, 0);
        assert_eq!(config.batch_size, 64);
    }

    #[test]
    #[serial]
    fn test_global_config_environment_default() {
        clear_all_config_env();
        set_env("DATABASE_URL", "postgresql://localhost/test");
        set_env("RPC_URL", "http://localhost:8545");
        set_env("WS_URL", "ws://localhost:8545");
        set_env(
            "REGISTRY_ADDRESS",
            "0x0000000000000000000000000000000000000001",
        );
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");
        set_env("HTTP_ADDR", "127.0.0.1:8080");
        set_env("START_BLOCK", "0");

        let config = GlobalConfig::from_env().expect("Should load GlobalConfig from env.");

        // Verify all environment variables were loaded correctly
        assert_eq!(config.environment, Environment::Development);
        assert_eq!(config.db_url, "postgresql://localhost/test");
        assert_eq!(config.http_rpc_url, "http://localhost:8545");
        assert_eq!(config.ws_rpc_url, "ws://localhost:8545");
        assert_eq!(
            config.registry_address.to_string(),
            "0x0000000000000000000000000000000000000001"
        );
        assert!(matches!(config.run_mode, RunMode::Both { .. }));
    }

    #[test]
    #[serial]
    fn test_global_config_missing_database_url() {
        clear_all_config_env();
        set_env("RPC_URL", "http://localhost:8545");
        set_env("WS_URL", "ws://localhost:8545");
        set_env(
            "REGISTRY_ADDRESS",
            "0x0000000000000000000000000000000000000001",
        );
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        let result = GlobalConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DATABASE_URL"));
    }

    #[test]
    #[serial]
    fn test_global_config_missing_rpc_url() {
        clear_all_config_env();
        set_env("DATABASE_URL", "postgresql://localhost/test");
        set_env("WS_URL", "ws://localhost:8545");
        set_env(
            "REGISTRY_ADDRESS",
            "0x0000000000000000000000000000000000000001",
        );
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        let result = GlobalConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("RPC_URL"));
    }

    #[test]
    #[serial]
    fn test_global_config_missing_ws_url() {
        clear_all_config_env();
        set_env("DATABASE_URL", "postgresql://localhost/test");
        set_env("RPC_URL", "http://localhost:8545");
        set_env(
            "REGISTRY_ADDRESS",
            "0x0000000000000000000000000000000000000001",
        );
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        let result = GlobalConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("WS_URL"));
    }

    #[test]
    #[serial]
    fn test_global_config_missing_registry_address() {
        clear_all_config_env();
        set_env("DATABASE_URL", "postgresql://localhost/test");
        set_env("RPC_URL", "http://localhost:8545");
        set_env("WS_URL", "ws://localhost:8545");
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        let result = GlobalConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("REGISTRY_ADDRESS"));
    }

    #[test]
    #[serial]
    fn test_global_config_invalid_registry_address() {
        clear_all_config_env();
        set_env("DATABASE_URL", "postgresql://localhost/test");
        set_env("RPC_URL", "http://localhost:8545");
        set_env("WS_URL", "ws://localhost:8545");
        set_env("REGISTRY_ADDRESS", "invalid_address");
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        let result = GlobalConfig::from_env();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("REGISTRY_ADDRESS") || err_msg.contains("Invalid"));
    }

    #[test]
    #[serial]
    fn test_tree_cache_config_defaults() {
        clear_all_config_env();

        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        let config = super::TreeCacheConfig::from_env().unwrap();

        assert_eq!(config.cache_file_path, "/tmp/test_cache");
        assert_eq!(config.tree_depth, 30);
        assert_eq!(config.http_cache_refresh_interval_secs, 30);
    }

    #[test]
    #[serial]
    fn test_tree_cache_config_custom_values() {
        clear_all_config_env();

        set_env("TREE_CACHE_FILE", "/custom/path/cache");
        set_env("TREE_DEPTH", "20");
        set_env("TREE_HTTP_CACHE_REFRESH_INTERVAL_SECS", "60");

        let config = super::TreeCacheConfig::from_env().unwrap();

        assert_eq!(config.cache_file_path, "/custom/path/cache");
        assert_eq!(config.tree_depth, 20);
        assert_eq!(config.http_cache_refresh_interval_secs, 60);
    }

    #[test]
    #[serial]
    fn test_tree_cache_config_missing_required_field() {
        clear_all_config_env();

        let result = super::TreeCacheConfig::from_env();
        assert!(
            result.is_err(),
            "Should fail when TREE_CACHE_FILE is missing"
        );
    }

    #[test]
    #[serial]
    fn test_http_addr_parsing() {
        clear_all_config_env();

        // Valid formats
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");
        set_env("HTTP_ADDR", "0.0.0.0:8080");
        let config = HttpConfig::from_env().expect("Should load HttpConfig from env.");
        assert_eq!(config.http_addr.to_string(), "0.0.0.0:8080");

        set_env("HTTP_ADDR", "127.0.0.1:3000");
        let config = HttpConfig::from_env().expect("Should load HttpConfig from env.");
        assert_eq!(config.http_addr.to_string(), "127.0.0.1:3000");
    }

    #[test]
    #[serial]
    fn test_http_addr_invalid_format() {
        clear_all_config_env();
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");
        set_env("HTTP_ADDR", "invalid:address:format");

        let result = HttpConfig::from_env();
        assert!(result.is_err());
    }

    #[test]
    #[serial]
    fn test_batch_size_validation() {
        clear_all_config_env();

        // Very small batch size
        set_env("BATCH_SIZE", "1");
        let config = IndexerConfig::from_env();
        assert_eq!(config.batch_size, 1);

        // Very large batch size
        set_env("BATCH_SIZE", "10000");
        let config = IndexerConfig::from_env();
        assert_eq!(config.batch_size, 10000);
    }

    #[test]
    #[serial]
    fn test_zero_start_block() {
        clear_all_config_env();

        set_env("START_BLOCK", "0");
        let config = IndexerConfig::from_env();
        assert_eq!(config.start_block, 0);
    }
}
