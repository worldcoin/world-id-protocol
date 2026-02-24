use std::{num::NonZeroUsize, path::Path, time::Duration};

use alloy::{
    network::EthereumWallet,
    providers::{DynProvider, Provider, ProviderBuilder, fillers::CachedNonceManager},
    rpc::{client::RpcClient, json_rpc::RpcError},
    signers::{
        Signer,
        aws::{AwsSigner, AwsSignerError, aws_config::BehaviorVersion},
        local::{LocalSignerError, PrivateKeySigner},
    },
    transports::{
        TransportError, TransportErrorKind,
        http::{Http, reqwest},
        layers::{FallbackLayer, RateLimitRetryPolicy},
    },
};
use clap::Args;
use config::ConfigError;
use serde::Deserialize;
use thiserror::Error;
use tower::ServiceBuilder;
use url::Url;

use crate::provider_layers::{RetryConfig, RetryLayer, ThrottleConfig, ThrottleLayer};

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

/// Secrets for the signer.
/// At most one of `wallet_private_key` or `aws_kms_key_id` may be provided.
/// When neither is set, no signer is configured.
#[derive(Args, Debug, Clone, Deserialize)]
#[group(required = false, multiple = false)]
pub struct SignerArgs {
    /// The signer wallet private key (hex) that will submit transactions (pays for gas)
    #[arg(long, env = "WALLET_PRIVATE_KEY")]
    wallet_private_key: Option<String>,

    /// AWS KMS Key ID for signing transactions
    #[arg(long, env = "AWS_KMS_KEY_ID")]
    aws_kms_key_id: Option<String>,
}

impl SignerArgs {
    async fn signer(&self, rpc_url: &Url) -> ProviderResult<EthereumWallet> {
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

    /// Create and return a `SignerConfig`, if a signer key is configured.
    pub fn signer_config(&self) -> Option<SignerConfig> {
        match (&self.wallet_private_key, &self.aws_kms_key_id) {
            (Some(pk), None) => Some(SignerConfig::PrivateKey(pk.clone())),
            (None, Some(key_id)) => Some(SignerConfig::AwsKms(key_id.clone())),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SignerConfig {
    PrivateKey(String),
    AwsKms(String),
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

    /// Set the maximum number of RPC retries. Set to 0 to disable retries.
    pub fn with_max_rpc_retries(mut self, max_retries: u32) -> Self {
        self.retry
            .get_or_insert_with(RetryConfig::default)
            .max_retries = max_retries;
        self
    }

    /// Build a dynamic provider from the configuration.
    pub async fn http(self) -> ProviderResult<DynProvider> {
        let Some(http) = self.http else {
            return Err(ProviderError::NoHttpUrls);
        };

        // Save first URL for signer (needed for AWS KMS chain_id lookup)
        let first_url = http.first().cloned().ok_or(ProviderError::NoHttpUrls)?;

        let retry_cfg = self.retry.unwrap_or_default();

        // Per-request timeout configured at the HTTP client level so that
        // hanging connections surface errors for the retry layer to act on.
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(retry_cfg.timeout_secs))
            .build()
            .expect("failed to build HTTP client");

        let num_urls = http.len();

        let transports = http
            .into_iter()
            .map(|url| Http::with_client(http_client.clone(), url))
            .collect::<Vec<_>>();

        // Configure the fallback layer (always)
        let fallback_layer = FallbackLayer::default()
            .with_active_transport_count(NonZeroUsize::new(num_urls).unwrap());

        // Extended retry policy built on [`RateLimitRetryPolicy`] (which already handles 429,
        // 503, null responses, missing batch responses, and retryable JSON-RPC error codes).
        // The `.or()` extension adds coverage for transient transport failures.
        let retry_policy =
            RateLimitRetryPolicy::default().or(|error: &TransportError| match error {
                RpcError::Transport(TransportErrorKind::Custom(_)) => true,
                RpcError::Transport(TransportErrorKind::HttpError(e)) => {
                    matches!(e.status, 408 | 502 | 504)
                }
                _ => false,
            });
        let retry_layer = RetryLayer::new(retry_policy, &retry_cfg);

        // Flow is: RetryLayer calls ThrottleLayer calls FallbackLayer calls transports
        // I.e. if throttling is enabled retries count into the request budget
        // NOTE: Retries can be disabled by setting max_retries to 0 in the retry config. Layer could be made optional as well.
        let client = if let Some(throttle_cfg) = self.throttle {
            let throttle_layer = ThrottleLayer::new_with_config(
                throttle_cfg.requests_per_second,
                throttle_cfg.burst_size,
            );

            let transport = ServiceBuilder::new()
                .layer(retry_layer)
                .layer(throttle_layer)
                .layer(fallback_layer)
                .service(transports);

            RpcClient::builder().transport(transport, false)
        } else {
            let transport = ServiceBuilder::new()
                .layer(retry_layer)
                .layer(fallback_layer)
                .service(transports);

            RpcClient::builder().transport(transport, false)
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
            Some(SignerConfig::PrivateKey(_))
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
        assert!(matches!(
            signer.signer_config(),
            Some(SignerConfig::AwsKms(_))
        ));
    }

    #[test]
    fn from_file_loads_retry_config() {
        let config = r#"
            [provider]
            http = ["https://rpc.example.com"]

            [provider.retry]
            max_retries = 3
            initial_backoff_ms = 500
            max_backoff_ms = 30000
            timeout_secs = 5
        "#;

        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        file.write_all(config.as_bytes()).unwrap();

        let args = ProviderArgs::from_file(file.path()).unwrap();
        let retry = args.retry.unwrap();
        assert_eq!(retry.max_retries, 3);
        assert_eq!(retry.initial_backoff_ms, 500);
        assert_eq!(retry.max_backoff_ms, 30000);
        assert_eq!(retry.timeout_secs, 5);
    }
}
