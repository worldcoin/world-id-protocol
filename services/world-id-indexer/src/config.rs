use std::net::SocketAddr;
use std::str::FromStr;

use alloy::primitives::Address;

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
            "indexer" | "indexer-only" => Self::IndexerOnly { indexer_config: IndexerConfig::from_env() },
            "http" | "http-only" => Self::HttpOnly { http_config: HttpConfig::from_env() },
            "both" | "all" => Self::Both { indexer_config: IndexerConfig::from_env(), http_config: HttpConfig::from_env() },
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
            _ => Err(format!("Invalid environment: '{s}'. Valid options are: 'production', 'staging', or 'development'")),
        }
    }
}

#[derive(Debug)]
pub struct GlobalConfig {
    pub environment: Environment,
    pub run_mode: RunMode,
    pub db_url: String,
}

#[derive(Debug)]
pub struct HttpConfig {
    pub http_addr: SocketAddr,
    pub db_poll_interval_secs: u64,
}

impl HttpConfig {
    pub fn from_env() -> Self {
        Self {
            http_addr: std::env::var("HTTP_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
                .parse()
                .unwrap(),
            db_poll_interval_secs: std::env::var("DB_POLL_INTERVAL_SECS")
                .unwrap_or_else(|_| "1".to_string())
                .parse()
                .unwrap(),
        }
    }
}

#[derive(Debug)]
pub struct IndexerConfig {
    pub rpc_url: String,
    pub ws_url: String,
    pub registry_address: Address,
    pub start_block: u64,
    pub batch_size: u64,
}

impl IndexerConfig {
    pub fn from_env() -> Self {
        Self {
            rpc_url: std::env::var("RPC_URL")
                .unwrap_or_else(|_| "http://localhost:8545".to_string()),
            ws_url: std::env::var("WS_URL").unwrap_or_else(|_| "ws://localhost:8545".to_string()),
            registry_address: std::env::var("REGISTRY_ADDRESS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap(),
            start_block: std::env::var("START_BLOCK")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            batch_size: std::env::var("BATCH_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(64),
        }
    }
}

impl GlobalConfig {
    pub fn from_env() -> Self {
        let environment = std::env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .parse()
            .unwrap();
        let run_mode = RunMode::from_env();

        let db_url = std::env::var("DATABASE_URL").unwrap();

        Self {
            environment,
            run_mode,
            db_url,
        }
    }
}
