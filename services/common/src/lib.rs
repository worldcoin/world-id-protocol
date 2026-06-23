//! Common utilities and types shared across multiple services.

mod provider;
mod provider_layers;
mod server_layers;
mod tx_fillers;

pub use provider::{ProviderArgs, ProviderError, ProviderResult, SignerArgs, SignerConfig};

// Re-export alloy NonceManager trait so downstream crates can implement it
// without taking a direct alloy dependency on the filler internals.
pub use alloy::providers::fillers::NonceManager;
pub use provider_layers::{
    METRICS_RPC_ENDPOINT_LATENCY_MS, METRICS_RPC_ENDPOINT_REQUESTS, RetryConfig,
    describe_provider_transport_metrics,
};
pub use server_layers::{
    METRICS_HTTP_LATENCY_MS, request_latency_middleware, timeout_layer, trace_layer,
};
