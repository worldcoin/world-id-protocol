use std::{
    num::{NonZeroU32, NonZeroUsize},
    path::Path,
    sync::Arc,
    time::Duration,
};

use alloy::{
    network::EthereumWallet,
    providers::{DynProvider, Provider, ProviderBuilder, fillers::CachedNonceManager},
    rpc::{
        client::RpcClient,
        json_rpc::{RequestPacket, RpcError},
    },
    signers::{
        Signer,
        aws::{AwsSigner, AwsSignerError, aws_config::BehaviorVersion},
        local::{LocalSignerError, PrivateKeySigner},
    },
    transports::{
        TransportError, TransportErrorKind,
        http::{Http, reqwest},
        layers::{FallbackLayer, RateLimitRetryPolicy, RetryBackoffLayer},
    },
};
use clap::Args;
use config::ConfigError;
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use serde::Deserialize;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use thiserror::Error;
use tower::{Layer, Service, ServiceBuilder};
use url::Url;

pub type ProviderResult<T> = Result<T, ProviderError>;

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(#[from] LocalSignerError),
    #[error("failed to initialize AWS KMS signer: {0}")]
    AwsKmsSigner(#[from] Box<AwsSignerError>),
    #[error("exactly one of wallet_private_key or aws_kms_key_id must be provided")]
    SignerConfigMissing,
    #[error("no HTTP URLs provided")]
    NoHttpUrls,
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    #[error("transport error while trying to fetch chain id: {0}")]
    ChainId(TransportError),
}

#[derive(Debug, Clone, Args, Deserialize)]
#[command(next_help_heading = "Rpc Configuration")]
#[derive(Default)]
pub struct ProviderArgs {
    /// HTTP RPC endpoints (in priority order).
    #[arg(long = "rpc-url", value_delimiter = ',', env = "RPC_URL")]
    #[serde(default)]
    pub http: Option<Vec<Url>>,

    #[command(flatten)]
    #[serde(default)]
    pub signer: Option<SignerArgs>,

    #[command(flatten)]
    #[serde(default)]
    pub throttle: Option<ThrottleConfig>,

    #[command(flatten)]
    #[serde(default)]
    pub retry: Option<RetryConfig>,
}

#[derive(Args, Debug, Clone, Deserialize)]
pub struct ThrottleConfig {
    /// Requests per second rate limit.
    #[arg(long = "rps", default_value_t = 100, env = "RPC_REQUESTS_PER_SECOND")]
    #[serde(default = "defaults::default_requests_per_second")]
    pub requests_per_second: u32,

    /// Burst size for rate limiting.
    #[arg(long = "burst-size", default_value_t = 10, env = "RPC_BURST_SIZE")]
    #[serde(default = "defaults::default_burst_size")]
    pub burst_size: u32,
}

#[derive(Args, Debug, Clone, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts for failed RPC requests.
    #[arg(long = "rpc-max-retries", default_value_t = defaults::MAX_RETRIES, env = "RPC_MAX_RETRIES")]
    #[serde(default = "defaults::default_max_retries")]
    pub max_retries: u32,

    /// Initial backoff delay in milliseconds before the first retry.
    #[arg(long = "rpc-initial-backoff-ms", default_value_t = defaults::INITIAL_BACKOFF_MS, env = "RPC_INITIAL_BACKOFF_MS")]
    #[serde(default = "defaults::default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,

    /// Per-RPC request timeout in seconds.
    #[arg(long = "rpc-timeout-secs", default_value_t = defaults::TIMEOUT_SECS, env = "RPC_TIMEOUT_SECS")]
    #[serde(default = "defaults::default_timeout_secs")]
    pub timeout_secs: u64,

    /// Compute units per second budget used for backoff scaling under concurrent load.
    #[arg(long = "rpc-compute-units-per-second", default_value_t = defaults::COMPUTE_UNITS_PER_SECOND, env = "RPC_COMPUTE_UNITS_PER_SECOND")]
    #[serde(default = "defaults::default_compute_units_per_second")]
    pub compute_units_per_second: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: defaults::MAX_RETRIES,
            initial_backoff_ms: defaults::INITIAL_BACKOFF_MS,
            timeout_secs: defaults::TIMEOUT_SECS,
            compute_units_per_second: defaults::COMPUTE_UNITS_PER_SECOND,
        }
    }
}

/// Secrets for the signer.
/// Exactly one of `wallet_private_key` or `aws_kms_key_id` must be provided.
#[derive(Args, Debug, Clone, Deserialize)]
#[group(required = true, multiple = false)]
pub struct SignerArgs {
    /// The signer wallet private key (hex) that will submit transactions (pays for gas)
    #[arg(long, env = "WALLET_PRIVATE_KEY")]
    wallet_private_key: Option<String>,

    /// AWS KMS Key ID for signing transactions
    #[arg(long, env = "AWS_KMS_KEY_ID")]
    aws_kms_key_id: Option<String>,
}

impl SignerArgs {
    pub async fn signer(&self, rpc_url: &Url) -> ProviderResult<EthereumWallet> {
        match (&self.wallet_private_key, &self.aws_kms_key_id) {
            (Some(s), None) => {
                // PrivateKey: No RPC call needed
                let signer = s.parse::<PrivateKeySigner>()?;
                Ok(EthereumWallet::from(signer))
            }
            (None, Some(key_id)) => {
                tracing::info!("Initializing AWS KMS signer with key_id: {}", key_id);

                let temp_provider = ProviderBuilder::new().connect_http(rpc_url.clone());
                let chain_id = temp_provider
                    .get_chain_id()
                    .await
                    .map_err(ProviderError::ChainId)?;
                tracing::info!("Fetched chain_id: {}", chain_id);

                let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
                let kms_client = aws_sdk_kms::Client::new(&config);
                let aws_signer = AwsSigner::new(kms_client, key_id.to_string(), Some(chain_id))
                    .await
                    .map_err(|err| ProviderError::AwsKmsSigner(Box::new(err)))?;
                tracing::info!(
                    "AWS KMS signer initialized with address: {}",
                    aws_signer.address()
                );
                Ok(EthereumWallet::from(aws_signer))
            }
            _ => Err(ProviderError::SignerConfigMissing),
        }
    }

    /// Create a new `SignerArgs` with the provided wallet private key.
    pub fn from_wallet(wallet_private_key: String) -> Self {
        Self {
            wallet_private_key: Some(wallet_private_key),
            aws_kms_key_id: None,
        }
    }

    /// Create a new `SignerArgs` with the provided aws kms key id
    pub fn from_aws(aws_kms_key_id: String) -> Self {
        Self {
            wallet_private_key: None,
            aws_kms_key_id: Some(aws_kms_key_id),
        }
    }

    /// Create and return a `SignerConfig`.
    pub fn signer_config(&self) -> SignerConfig {
        match (&self.wallet_private_key, &self.aws_kms_key_id) {
            (Some(pk), None) => SignerConfig::PrivateKey(pk.clone()),
            (None, Some(key_id)) => SignerConfig::AwsKms(key_id.clone()),
            // Clap's group constraint enforces exactly one of these is set
            _ => unreachable!("clap enforces exactly one of wallet_private_key or aws_kms_key_id"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SignerConfig {
    PrivateKey(String),
    AwsKms(String),
}

mod defaults {
    pub const BURST_SIZE: u32 = 10;
    pub const REQUESTS_PER_SECOND: u32 = 100;
    pub const MAX_RETRIES: u32 = 10;
    pub const INITIAL_BACKOFF_MS: u64 = 1000;
    pub const TIMEOUT_SECS: u64 = 10;
    pub const COMPUTE_UNITS_PER_SECOND: u64 = 10_000;

    pub const fn default_burst_size() -> u32 {
        BURST_SIZE
    }
    pub const fn default_requests_per_second() -> u32 {
        REQUESTS_PER_SECOND
    }
    pub const fn default_max_retries() -> u32 {
        MAX_RETRIES
    }
    pub const fn default_initial_backoff_ms() -> u64 {
        INITIAL_BACKOFF_MS
    }
    pub const fn default_timeout_secs() -> u64 {
        TIMEOUT_SECS
    }
    pub const fn default_compute_units_per_second() -> u64 {
        COMPUTE_UNITS_PER_SECOND
    }
}

impl ProviderArgs {
    /// Create a new provider configuration with sensible defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> ProviderResult<Self> {
        let settings = config::Config::builder()
            .add_source(config::File::from(path.as_ref()))
            .build()?;

        Ok(settings
            .get::<Self>("provider")
            .or_else(|_| settings.try_deserialize::<Self>())?)
    }

    /// Add multiple HTTP RPC endpoints.
    pub fn with_http_urls(mut self, urls: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.http.get_or_insert_with(Vec::new).extend(
            urls.into_iter()
                .map(|u| Url::parse(u.as_ref()).expect("invalid URL")),
        );
        self
    }

    /// Build a dynamic provider from the configuration.
    pub async fn http(self) -> ProviderResult<DynProvider> {
        let Some(http) = self.http else {
            return Err(ProviderError::NoHttpUrls);
        };

        // Save first URL for signer (needed for AWS KMS chain_id lookup)
        let first_url = http.first().cloned().ok_or(ProviderError::NoHttpUrls)?;

        // Configure the fallback layer
        let fallback_layer = FallbackLayer::default()
            .with_active_transport_count(NonZeroUsize::new(http.len()).unwrap());

        let throttle = self.throttle.map(|throttle_config| {
            ThrottleLayer::new_with_config(
                throttle_config.requests_per_second,
                throttle_config.burst_size,
            )
        });

        let retry_cfg = self.retry.unwrap_or_default();

        // Per-request timeout configured at the HTTP client level so that
        // hanging connections surface errors for the retry layer to act on.
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(retry_cfg.timeout_secs))
            .build()
            .expect("failed to build HTTP client");

        let transports = http
            .into_iter()
            .map(|url| Http::with_client(http_client.clone(), url))
            .collect::<Vec<_>>();

        // Extended retry policy built on [`RateLimitRetryPolicy`] (which already handles 429, 503,
        // null responses, missing batch responses, and retryable JSON-RPC error codes).
        // The `.or()` extension adds coverage for transient transport failures.
        let transport_retry_policy =
            RateLimitRetryPolicy::default().or(|error: &TransportError| match error {
                // Connection drops, DNS failures, TLS errors, reqwest timeouts
                RpcError::Transport(TransportErrorKind::Custom(_)) => true,
                // Request timeout, bad gateway, gateway timeout
                RpcError::Transport(TransportErrorKind::HttpError(e)) => {
                    matches!(e.status, 408 | 502 | 504)
                }
                _ => false,
            });

        let retry_layer = RetryBackoffLayer::new_with_policy(
            retry_cfg.max_retries,
            retry_cfg.initial_backoff_ms,
            retry_cfg.compute_units_per_second,
            transport_retry_policy,
        );

        let client = if let Some(throttle) = throttle {
            let transport = ServiceBuilder::new()
                .layer(throttle)
                .layer(fallback_layer)
                .service(transports);
            RpcClient::builder()
                .layer(retry_layer)
                .transport(transport, false)
        } else {
            let transport = ServiceBuilder::new()
                .layer(fallback_layer)
                .service(transports);
            RpcClient::builder()
                .layer(retry_layer)
                .transport(transport, false)
        };

        let maybe_signer = if let Some(signer) = &self.signer {
            // Pass the first URL to the signer - it will only make RPC calls if needed (AWS KMS)
            Some(signer.signer(&first_url).await?)
        } else {
            None
        };

        let provider = if let Some(signer) = maybe_signer {
            let provider = ProviderBuilder::new()
                .with_nonce_management(CachedNonceManager::default())
                .wallet(signer)
                .connect_client(client);

            provider.erased()
        } else {
            let provider = ProviderBuilder::new().connect_client(client);
            provider.erased()
        };

        Ok(provider)
    }
}

/// Rate limiting for RPC requests.
type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

#[derive(Clone)]
/// A Tower layer that applies rate limiting to RPC requests.
struct ThrottleLayer {
    limiter: Arc<Limiter>,
}

impl ThrottleLayer {
    /// Creates a new [`ThrottleLayer`] with specified RPS and burst size.
    pub fn new_with_config(rps: u32, burst: u32) -> Self {
        let rps = NonZeroU32::new(rps).expect("RPS must be non-zero");
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        Self {
            limiter: RateLimiter::direct(Quota::per_second(rps).allow_burst(burst)).into(),
        }
    }
}

impl<S> Layer<S> for ThrottleLayer {
    type Service = ThrottleService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ThrottleService {
            inner,
            limiter: self.limiter.clone(),
        }
    }
}

#[derive(Clone)]
/// A Tower service that applies rate limiting to RPC requests.
struct ThrottleService<S> {
    inner: S,
    limiter: Arc<Limiter>,
}

impl<S> Service<RequestPacket> for ThrottleService<S>
where
    S: Service<RequestPacket> + Clone + Send + Sync + 'static,
    S::Response: Send + Sync + 'static,
    S::Error: Send + Sync + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let limiter = self.limiter.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            limiter.until_ready().await;
            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::io::Write;

    #[test]
    fn from_file_loads_http_with_multiple_endpoints() {
        let config = r#"
            [provider]
            http = ["https://rpc1.example.com", "https://rpc2.example.com", "https://rpc3.example.com"]
        "#;

        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        file.write_all(config.as_bytes()).unwrap();

        let args = ProviderArgs::from_file(file.path()).unwrap();
        let urls = args.http.unwrap();
        assert_eq!(urls.len(), 3);
        assert_eq!(urls[0].as_str(), "https://rpc1.example.com/");
        assert_eq!(urls[1].as_str(), "https://rpc2.example.com/");
        assert_eq!(urls[2].as_str(), "https://rpc3.example.com/");
    }

    #[test]
    fn from_file_loads_with_private_key_signer() {
        let config = r#"
            [provider]
            http = ["https://rpc.example.com"]

            [provider.signer]
            wallet_private_key = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        "#;

        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        file.write_all(config.as_bytes()).unwrap();

        let args = ProviderArgs::from_file(file.path()).unwrap();
        let signer = args.signer.unwrap();
        assert!(matches!(
            signer.signer_config(),
            SignerConfig::PrivateKey(_)
        ));
    }

    #[test]
    fn from_file_loads_with_aws_kms_signer() {
        let config = r#"
            [provider]
            http = ["https://rpc.example.com"]

            [provider.signer]
            aws_kms_key_id = "arn:aws:kms:us-east-1:123456789:key/abc-123"
        "#;

        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        file.write_all(config.as_bytes()).unwrap();

        let args = ProviderArgs::from_file(file.path()).unwrap();
        let signer = args.signer.unwrap();
        assert!(matches!(signer.signer_config(), SignerConfig::AwsKms(_)));
    }

    #[test]
    fn from_file_loads_retry_config() {
        let config = r#"
            [provider]
            http = ["https://rpc.example.com"]

            [provider.retry]
            max_retries = 3
            initial_backoff_ms = 500
            timeout_secs = 5
            compute_units_per_second = 5000
        "#;

        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        file.write_all(config.as_bytes()).unwrap();

        let args = ProviderArgs::from_file(file.path()).unwrap();
        let retry = args.retry.unwrap();
        assert_eq!(retry.max_retries, 3);
        assert_eq!(retry.initial_backoff_ms, 500);
        assert_eq!(retry.timeout_secs, 5);
        assert_eq!(retry.compute_units_per_second, 5000);
    }
}
