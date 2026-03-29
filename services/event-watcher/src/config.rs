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
    pub contracts: Vec<ContractConfig>,
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
pub struct ContractConfig {
    pub name: String,
    pub contract_address: Address,
    pub enabled: bool,
    pub event_names: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    #[serde(default)]
    contracts: Vec<RawContractConfig>,
}

#[derive(Debug, Deserialize)]
struct RawContractConfig {
    name: String,
    contract_address: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    event_names: Option<Vec<String>>,
}

fn default_enabled() -> bool {
    true
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
    #[error("duplicate contract name: {0}")]
    DuplicateContractName(String),
    #[error("contract {name} has invalid contract address: {value}")]
    InvalidContractAddress { name: String, value: String },
    #[error("contract has empty name")]
    EmptyContractName,
    #[error("contract {0} has zero contract address")]
    ZeroContractAddress(String),
    #[error("no contracts found in WATCHER_CONFIG")]
    EmptyContracts,
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
        let contracts = validate_contracts(file_config.contracts)?;

        Ok(Self {
            chain_name,
            chain_id,
            ws_rpc_url,
            explorer,
            service: ServiceConfig {
                reconnect_initial_backoff_ms,
                reconnect_max_backoff_ms,
            },
            contracts,
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

fn validate_contracts(
    raw_contracts: Vec<RawContractConfig>,
) -> Result<Vec<ContractConfig>, ConfigError> {
    if raw_contracts.is_empty() {
        return Err(ConfigError::EmptyContracts);
    }

    let mut seen_names = BTreeSet::new();
    let mut contracts = Vec::with_capacity(raw_contracts.len());

    for raw in raw_contracts {
        if raw.name.trim().is_empty() {
            return Err(ConfigError::EmptyContractName);
        }
        if !seen_names.insert(raw.name.clone()) {
            return Err(ConfigError::DuplicateContractName(raw.name));
        }

        let address = Address::from_str(&raw.contract_address).map_err(|_| {
            ConfigError::InvalidContractAddress {
                name: raw.name.clone(),
                value: raw.contract_address.clone(),
            }
        })?;
        if address.is_zero() {
            return Err(ConfigError::ZeroContractAddress(raw.name));
        }

        contracts.push(ContractConfig {
            name: raw.name,
            contract_address: address,
            enabled: raw.enabled,
            event_names: raw.event_names,
        });
    }

    Ok(contracts)
}
