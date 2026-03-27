use std::{
    collections::BTreeSet,
    env,
    path::{Path, PathBuf},
    str::FromStr,
};

use alloy::primitives::Address;
use config as config_rs;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub chain_name: String,
    pub chain_id: u64,
    pub ws_rpc_url: String,
    pub explorer: ExplorerConfig,
    pub service: ServiceConfig,
    pub subscriptions: Vec<SubscriptionConfig>,
}

#[derive(Debug, Clone)]
pub struct ExplorerConfig {
    pub url: String,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub reconnect_initial_backoff_ms: u64,
    pub reconnect_max_backoff_ms: u64,
}

#[derive(Debug, Clone)]
pub struct SubscriptionConfig {
    pub contract_address: Address,
    pub event_signature: String,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    #[serde(default)]
    subscriptions: Vec<RawSubscriptionConfig>,
}

#[derive(Debug, Deserialize)]
struct RawSubscriptionConfig {
    contract_address: String,
    event_signature: String,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required env var {0}")]
    MissingEnv(&'static str),
    #[error("failed to load WATCHER_CONFIG from {path}: {message}")]
    LoadConfigFile { path: String, message: String },
    #[error("invalid WATCHER_CHAIN_ID: {0}")]
    InvalidChainId(String),
    #[error("invalid WATCHER_RECONNECT_INITIAL_BACKOFF_MS: {0}")]
    InvalidReconnectInitial(String),
    #[error("invalid WATCHER_RECONNECT_MAX_BACKOFF_MS: {0}")]
    InvalidReconnectMax(String),
    #[error("duplicate event signature: {0}")]
    DuplicateEventSignature(String),
    #[error("subscription for {event_signature} has invalid contract address: {value}")]
    InvalidSubscriptionAddress {
        event_signature: String,
        value: String,
    },
    #[error("subscription has empty event signature")]
    EmptyEventSignature,
    #[error("subscription for {0} has zero contract address")]
    ZeroContractAddress(String),
    #[error("no subscriptions found in WATCHER_CONFIG")]
    EmptySubscriptions,
    #[error("WATCHER_RECONNECT_INITIAL_BACKOFF_MS must be <= WATCHER_RECONNECT_MAX_BACKOFF_MS")]
    InvalidReconnectRange,
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let chain_name = env::var("WATCHER_CHAIN_NAME")
            .map_err(|_| ConfigError::MissingEnv("WATCHER_CHAIN_NAME"))?;
        let chain_id_raw = env::var("WATCHER_CHAIN_ID")
            .map_err(|_| ConfigError::MissingEnv("WATCHER_CHAIN_ID"))?;
        let chain_id = chain_id_raw
            .parse()
            .map_err(|_| ConfigError::InvalidChainId(chain_id_raw.clone()))?;

        let ws_rpc_url = env::var("WATCHER_WS_RPC_URL")
            .map_err(|_| ConfigError::MissingEnv("WATCHER_WS_RPC_URL"))?;

        let explorer = ExplorerConfig {
            url: env::var("WATCHER_EXPLORER_URL")
                .map_err(|_| ConfigError::MissingEnv("WATCHER_EXPLORER_URL"))?,
            api_key: env::var("WATCHER_EXPLORER_API_KEY")
                .ok()
                .filter(|s| !s.is_empty()),
        };

        let reconnect_initial_backoff_ms = env::var("WATCHER_RECONNECT_INITIAL_BACKOFF_MS")
            .unwrap_or_else(|_| "1000".to_owned())
            .parse()
            .map_err(|_| {
                ConfigError::InvalidReconnectInitial(
                    env::var("WATCHER_RECONNECT_INITIAL_BACKOFF_MS")
                        .unwrap_or_else(|_| "1000".to_owned()),
                )
            })?;
        let reconnect_max_backoff_ms = env::var("WATCHER_RECONNECT_MAX_BACKOFF_MS")
            .unwrap_or_else(|_| "30000".to_owned())
            .parse()
            .map_err(|_| {
                ConfigError::InvalidReconnectMax(
                    env::var("WATCHER_RECONNECT_MAX_BACKOFF_MS")
                        .unwrap_or_else(|_| "30000".to_owned()),
                )
            })?;
        if reconnect_initial_backoff_ms > reconnect_max_backoff_ms {
            return Err(ConfigError::InvalidReconnectRange);
        }

        let config_path =
            env::var("WATCHER_CONFIG").map_err(|_| ConfigError::MissingEnv("WATCHER_CONFIG"))?;
        let file_config = load_file_config(&config_path)?;
        let subscriptions = validate_subscriptions(file_config.subscriptions)?;

        Ok(Self {
            chain_name,
            chain_id,
            ws_rpc_url,
            explorer,
            service: ServiceConfig {
                reconnect_initial_backoff_ms,
                reconnect_max_backoff_ms,
            },
            subscriptions,
        })
    }
}

fn load_file_config(path: &str) -> Result<FileConfig, ConfigError> {
    let resolved = expand_config_path(path);
    let settings = config_rs::Config::builder()
        .add_source(config_rs::File::from(resolved.as_path()))
        .build()
        .map_err(|e| ConfigError::LoadConfigFile {
            path: resolved.display().to_string(),
            message: e.to_string(),
        })?;

    settings
        .try_deserialize::<FileConfig>()
        .map_err(|e| ConfigError::LoadConfigFile {
            path: resolved.display().to_string(),
            message: e.to_string(),
        })
}

fn expand_config_path(path: &str) -> PathBuf {
    let input = Path::new(path);
    if input.is_absolute() {
        return input.to_path_buf();
    }

    if let Ok(cwd) = env::current_dir() {
        cwd.join(input)
    } else {
        input.to_path_buf()
    }
}

fn validate_subscriptions(
    raw_subscriptions: Vec<RawSubscriptionConfig>,
) -> Result<Vec<SubscriptionConfig>, ConfigError> {
    if raw_subscriptions.is_empty() {
        return Err(ConfigError::EmptySubscriptions);
    }

    let mut seen_signatures = BTreeSet::new();
    let mut subscriptions = Vec::with_capacity(raw_subscriptions.len());

    for raw in raw_subscriptions {
        if raw.event_signature.trim().is_empty() {
            return Err(ConfigError::EmptyEventSignature);
        }
        if !seen_signatures.insert(raw.event_signature.clone()) {
            return Err(ConfigError::DuplicateEventSignature(raw.event_signature));
        }

        let address = Address::from_str(&raw.contract_address).map_err(|_| {
            ConfigError::InvalidSubscriptionAddress {
                event_signature: raw.event_signature.clone(),
                value: raw.contract_address.clone(),
            }
        })?;
        if address.is_zero() {
            return Err(ConfigError::ZeroContractAddress(raw.event_signature));
        }

        subscriptions.push(SubscriptionConfig {
            contract_address: address,
            event_signature: raw.event_signature,
        });
    }

    Ok(subscriptions)
}
