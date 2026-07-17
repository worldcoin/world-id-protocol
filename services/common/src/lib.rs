//! Common utilities and types shared across multiple services.

pub mod alloy;
pub mod axum;

pub use self::{
    alloy::{
        provider::{ProviderArgs, ProviderError, ProviderResult, SignerArgs, SignerConfig},
        provider_layers::{
            METRICS_RPC_ENDPOINT_LATENCY_MS, METRICS_RPC_ENDPOINT_REQUESTS, RetryConfig,
            describe_provider_transport_metrics,
        },
    },
    axum::server_layers::{
        METRICS_HTTP_LATENCY_MS, describe_http_request_metrics, request_latency_middleware,
        timeout_layer, trace_layer,
    },
};

// Re-export alloy NonceManager trait so downstream crates can implement it
// without taking a direct alloy dependency on the filler internals.
pub use ::alloy::providers::fillers::NonceManager;
