//! Command-line and environment configuration.

use std::{
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};

use alloy::primitives::Address;
use clap::Parser;
use url::Url;
use world_id_services_common::RetryConfig;

/// Defaults for [`Config`].
pub mod defaults {
    use std::num::{NonZeroU64, NonZeroUsize};

    /// Loopback only: the sidecar has no authentication, so nothing outside its pod may reach it.
    pub const LISTEN_ADDR: &str = "127.0.0.1:9202";
    pub const REQUEST_TIMEOUT_SECS: NonZeroU64 = NonZeroU64::new(30).unwrap();
    pub const MAX_BODY_BYTES: NonZeroUsize = NonZeroUsize::new(8 * 1024 * 1024).unwrap();

    // The registry reads run one after the other. With these values both fit in
    // `REQUEST_TIMEOUT_SECS` even when every attempt times out:
    // 2 reads × (3 attempts × 3 s + ~0.6 s backoff) ≈ 19 s.
    pub const RPC_TIMEOUT_SECS: NonZeroU64 = NonZeroU64::new(3).unwrap();
    pub const RPC_MAX_RETRIES: u32 = 2;
    pub const RPC_INITIAL_BACKOFF_MS: u64 = 100;
    pub const RPC_MAX_BACKOFF_MS: u64 = 1_000;
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

    /// World Chain JSON-RPC endpoints. Every call goes to all of them and takes the first
    /// answer.
    #[arg(
        long = "rpc-url",
        env = "RPC_URL",
        value_delimiter = ',',
        required = true
    )]
    pub rpc_urls: Vec<Url>,

    /// The timeout of one JSON-RPC attempt, in seconds.
    #[arg(long, env = "RPC_TIMEOUT_SECS", default_value_t = defaults::RPC_TIMEOUT_SECS)]
    pub rpc_timeout_secs: NonZeroU64,

    /// How many times a failed JSON-RPC call is retried, with exponential backoff and jitter.
    #[arg(long, env = "RPC_MAX_RETRIES", default_value_t = defaults::RPC_MAX_RETRIES)]
    pub rpc_max_retries: u32,

    /// The backoff before the first retry, in milliseconds. It doubles with every retry.
    #[arg(long, env = "RPC_INITIAL_BACKOFF_MS", default_value_t = defaults::RPC_INITIAL_BACKOFF_MS)]
    pub rpc_initial_backoff_ms: u64,

    /// The longest backoff between retries, in milliseconds.
    #[arg(long, env = "RPC_MAX_BACKOFF_MS", default_value_t = defaults::RPC_MAX_BACKOFF_MS)]
    pub rpc_max_backoff_ms: u64,

    /// The `WorldIDRegistry` proxy, which roots are checked against.
    #[arg(long, env = "WORLD_ID_REGISTRY_ADDRESS")]
    pub world_id_registry: Address,

    /// The `CredentialSchemaIssuerRegistry` proxy, which Issuer keys are checked against.
    #[arg(long, env = "CREDENTIAL_SCHEMA_ISSUER_REGISTRY_ADDRESS")]
    pub credential_schema_issuer_registry: Address,

    /// How many verifications may run at once, each holding its slot from the registry reads to
    /// the proof verification. Defaults to the available CPUs; a request beyond it is answered
    /// `503 overloaded` instead of queueing.
    #[arg(long, env = "MAX_CONCURRENT_VERIFICATIONS")]
    pub max_concurrent_verifications: Option<NonZeroUsize>,

    /// How long one verification may take, in seconds. At the deadline the registry reads are
    /// cancelled and the request is answered; CPU-bound work already running keeps its slot until
    /// it finishes.
    #[arg(long, env = "REQUEST_TIMEOUT_SECS", default_value_t = defaults::REQUEST_TIMEOUT_SECS)]
    pub request_timeout_secs: NonZeroU64,

    /// The largest request body accepted, in bytes.
    #[arg(long, env = "MAX_BODY_BYTES", default_value_t = defaults::MAX_BODY_BYTES)]
    pub max_body_bytes: NonZeroUsize,
}

impl Config {
    /// The timeouts and retries of the registry reads.
    pub const fn rpc_retry(&self) -> RetryConfig {
        RetryConfig {
            max_retries: self.rpc_max_retries,
            initial_backoff_ms: self.rpc_initial_backoff_ms,
            max_backoff_ms: self.rpc_max_backoff_ms,
            timeout_secs: self.rpc_timeout_secs.get(),
        }
    }

    /// How long one verification may take.
    pub const fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs.get())
    }
}
