//! Common utilities and types shared across multiple services.

mod provider;
mod provider_layers;
mod provider_metrics;
mod server_layers;
mod tx_fillers;

pub use provider::{ProviderArgs, ProviderError, ProviderResult, SignerArgs, SignerConfig};
pub use provider_metrics::{
    METRICS_RPC_ENDPOINT_LATENCY_MS, METRICS_RPC_ENDPOINT_REQUESTS, describe_provider_metrics,
};

// Re-export alloy NonceManager trait so downstream crates can implement it
// without taking a direct alloy dependency on the filler internals.
pub use alloy::providers::fillers::NonceManager;
pub use provider_layers::RetryConfig;
pub use server_layers::{timeout_layer, trace_layer};
