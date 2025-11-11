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
    /// Optional sanity check interval in seconds. If not set, the sanity check will not be run.
    ///
    /// The sanity check calls the `isValidRoot` function on the `AccountRegistry` contract to ensure the local Merkle root is valid.
    pub sanity_check_interval_secs: Option<u64>,

    /// Optional RPC URL to use for the sanity check. If not set, the sanity check will not be run.
    pub rpc_url: Option<String>,

    /// Optional registry address to use for the sanity check. If not set, the sanity check will not be run.
    pub registry_address: Option<Address>,
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
                    if val == 0 {
                        None
                    } else {
                        Some(val)
                    }
                },
            ),
            rpc_url: std::env::var("RPC_URL").ok().map(|s| s.to_string()),
            registry_address: std::env::var("REGISTRY_ADDRESS")
                .ok()
                .map(|s| s.parse::<Address>().ok())
                .unwrap_or(None),
        };

        if config.http_addr.port() != 8080 {
            tracing::warn!("Indexer is not running on port 8080, this may not work as expected when running dockerized (image exposes port 8080)");
        }

        if config.sanity_check_interval_secs.is_some() {
            if config.rpc_url.is_none() {
                tracing::warn!("⚠️ Misconfiguration: SANITY_CHECK_INTERVAL_SECS is set but RPC_URL is not set. Sanity check will not be run.");
            }
            if config.registry_address.is_none() {
                tracing::warn!("⚠️ Misconfiguration: SANITY_CHECK_INTERVAL_SECS is set but REGISTRY_ADDRESS is not set. Sanity check will not be run.");
            }
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
    pub rpc_url: String,
    pub ws_url: String,
    pub registry_address: Address,
    pub start_block: u64,
    pub batch_size: u64,
}

impl IndexerConfig {
    pub fn from_env() -> Self {
        let config = Self {
            rpc_url: std::env::var("RPC_URL").expect("RPC_URL must be set."),
            ws_url: std::env::var("WS_URL").expect("WS_URL must be set."),
            registry_address: std::env::var("REGISTRY_ADDRESS")
                .ok()
                .and_then(|s| s.parse().ok())
                .expect("REGISTRY_ADDRESS must be set."),
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

impl GlobalConfig {
    pub fn from_env() -> Self {
        let environment = std::env::var("ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string())
            .parse()
            .unwrap();

        let run_mode = RunMode::from_env();

        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set.");

        Self {
            environment,
            run_mode,
            db_url,
        }
    }
}
