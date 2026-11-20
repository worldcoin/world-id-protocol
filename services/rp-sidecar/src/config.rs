//! Command-line and environment configuration.

use std::{net::SocketAddr, num::NonZeroUsize, path::PathBuf};

use alloy::primitives::Address;
use clap::Parser;
use url::Url;
use world_id_services_common::RetryConfig;

/// Defaults for [`Config`].
pub mod defaults {
    /// Loopback only: the sidecar has no authentication, so only its own pod may reach it.
    pub const LISTEN_ADDR: &str = "127.0.0.1:9202";
    /// How long one request may take, including the registry reads and the proof verification.
    pub const REQUEST_TIMEOUT_SECS: u64 = 30;
    /// The largest request body accepted, in bytes.
    pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
}

/// The sidecar's configuration.
#[derive(Debug, Parser)]
#[command(name = "world-id-rp-sidecar", about)]
pub struct Config {
    /// The address to listen on.
    #[arg(long, env = "LISTEN_ADDR", default_value = defaults::LISTEN_ADDR)]
    pub listen_addr: SocketAddr,

    /// The RP's policy file, see `policy.example.json`.
    #[arg(long, env = "POLICY_PATH")]
    pub policy_path: PathBuf,

    /// World Chain JSON-RPC endpoints, in priority order.
    #[arg(
        long = "rpc-url",
        env = "RPC_URL",
        value_delimiter = ',',
        required = true
    )]
    pub rpc_urls: Vec<Url>,

    /// Timeouts and retries of the JSON-RPC calls.
    #[command(flatten)]
    pub rpc_retry: RetryConfig,

    /// The `WorldIDRegistry` proxy, which roots are checked against.
    #[arg(long, env = "WORLD_ID_REGISTRY_ADDRESS")]
    pub world_id_registry: Address,

    /// The `CredentialSchemaIssuerRegistry` proxy, which Issuer keys are checked against.
    #[arg(long, env = "CREDENTIAL_SCHEMA_ISSUER_REGISTRY_ADDRESS")]
    pub credential_schema_issuer_registry: Address,

    /// How many proofs may be verified at once. Defaults to the available CPUs; a request beyond
    /// it is answered `503 overloaded` instead of queueing.
    #[arg(long, env = "MAX_CONCURRENT_VERIFICATIONS")]
    pub max_concurrent_verifications: Option<NonZeroUsize>,

    /// How long one request may take, in seconds.
    #[arg(long, env = "REQUEST_TIMEOUT_SECS", default_value_t = defaults::REQUEST_TIMEOUT_SECS)]
    pub request_timeout_secs: u64,

    /// The largest request body accepted, in bytes.
    #[arg(long, env = "MAX_BODY_BYTES", default_value_t = defaults::MAX_BODY_BYTES)]
    pub max_body_bytes: usize,
}
