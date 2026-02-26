//! Common utilities and types shared across multiple services.

mod provider;
mod provider_layers;
mod server_layers;

// TODO: FIXME: Provider Metrics

pub use provider::{ProviderArgs, ProviderError, ProviderResult, SignerArgs, SignerConfig};

// Re-export alloy NonceManager trait so downstream crates can implement it
// without taking a direct alloy dependency on the filler internals.
pub use alloy::providers::fillers::NonceManager;
pub use provider_layers::RetryConfig;
pub use server_layers::{timeout_layer, trace_layer};
