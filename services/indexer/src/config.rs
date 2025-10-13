use std::net::SocketAddr;
use std::str::FromStr;

use alloy::primitives::Address;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunMode {
    /// Only run the indexer (sync chain data and write to DB)
    IndexerOnly,
    /// Only serve HTTP endpoint (requires pre-populated DB)
    HttpOnly,
    /// Run both indexer and HTTP server (default)
    Both,
}

impl FromStr for RunMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "indexer" | "indexer-only" => Ok(Self::IndexerOnly),
            "http" | "http-only" => Ok(Self::HttpOnly),
            "both" | "all" => Ok(Self::Both),
            _ => Err(format!(
                "Invalid run mode: '{s}'. Valid options are: 'indexer', 'indexer-only', 'http', 'http-only', 'both', or 'all'",
            )),
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
    pub rpc_url: String,
    pub ws_url: String,
    pub registry_address: Address,
    pub db_url: String,
    pub start_block: u64,
    pub batch_size: u64,
    pub http_addr: SocketAddr,
    pub db_poll_interval_secs: u64,
}

impl GlobalConfig {
    pub fn from_env() -> Self {
        let environment = std::env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .parse()
            .unwrap();
        let run_mode = std::env::var("RUN_MODE")
            .unwrap_or_else(|_| "both".to_string())
            .parse()
            .unwrap();
        let rpc_url =
            std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string());
        let registry_address = std::env::var("REGISTRY_ADDRESS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap();
        let db_url = std::env::var("DATABASE_URL").unwrap();
        let start_block: u64 = std::env::var("START_BLOCK")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let batch_size: u64 = std::env::var("BATCH_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(64);
        let ws_url = std::env::var("WS_URL").unwrap_or_else(|_| "ws://localhost:8545".to_string());
        let http_addr = std::env::var("HTTP_ADDR")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "0.0.0.0:8080".parse().unwrap());
        let db_poll_interval_secs: u64 = std::env::var("DB_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        Self {
            environment,
            run_mode,
            rpc_url,
            ws_url,
            registry_address,
            db_url,
            start_block,
            batch_size,
            http_addr,
            db_poll_interval_secs,
        }
    }
}
