use std::{num::NonZeroUsize, path::Path, time::Duration};

use ::alloy::{
    network::{Ethereum, EthereumWallet, NetworkWallet},
    primitives::Address,
    providers::{
        DynProvider, Provider, ProviderBuilder,
        fillers::{NonceManager, SimpleNonceManager},
    },
    rpc::{client::RpcClient, json_rpc::RpcError, types::TransactionRequest},
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

use crate::alloy::{
    provider_layers::{
        EndpointMetricsLayer, RetryConfig, RetryLayer, ThrottleConfig, ThrottleLayer,
    },
    tx_fillers::GasEstimateWithFallbackFiller,
};

pub type ProviderResult<T> = Result<T, ProviderError>;

#[derive(Clone, Debug)]
struct ConfiguredProvider {
    provider: DynProvider,
    wallet: Option<EthereumWallet>,
}

impl ConfiguredProvider {
    fn into_provider(self) -> DynProvider {
        self.provider
    }

    fn try_into_wallet(self) -> ProviderResult<ProviderWallet> {
        let wallet = self.wallet.ok_or(ProviderError::SignerConfigMissing)?;
        let address = <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(&wallet);
        Ok(ProviderWallet::new(address, self.provider, wallet))
    }
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(#[from] LocalSignerError),
    #[error("failed to initialize AWS KMS signer: {0}")]
    AwsKmsSigner(#[from] Box<AwsSignerError>),
    #[error(
        "exactly one of wallet_private_key, aws_kms_key_id, or aws_kms_key_ids must be provided"
    )]
    SignerConfigMissing,
    #[error(
        "pod ordinal {ordinal} is out of range: AWS_KMS_KEY_IDS contains {key_count} gateway slot(s)"
    )]
    OrdinalOutOfRange { ordinal: usize, key_count: usize },
    #[error("AWS_KMS_KEY_IDS gateway slot {ordinal} contains an empty KMS key ID")]
    EmptyKmsKeyId { ordinal: usize },
    #[error(
        "AWS_KMS_KEY_IDS is set but pod ordinal could not be resolved from HOSTNAME \
         (got: {hostname:?}); ensure the pod hostname follows the StatefulSet convention \
         '<name>-<ordinal>'"
    )]
    OrdinalUnresolvable { hostname: Option<String> },
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
    pub http: Vec<Url>,

    #[command(flatten)]
    #[serde(default)]
    pub signer: SignerArgs,

    #[command(flatten)]
    #[serde(default)]
    pub throttle: Option<ThrottleConfig>,

    #[command(flatten)]
    #[serde(default)]
    pub retry: RetryConfig,
}

/// Secrets for the signer.
/// Exactly one of `wallet_private_key`, `aws_kms_key_id`, or `aws_kms_key_ids` may be
/// provided. When none is set, no signer is configured.
#[derive(Args, Debug, Clone, Default, Deserialize)]
#[group(required = false, multiple = false)]
pub struct SignerArgs {
    /// The signer wallet private key (hex) that will submit transactions (pays for gas)
    #[arg(long, env = "WALLET_PRIVATE_KEY")]
    wallet_private_key: Option<String>,

    /// AWS KMS Key ID for signing transactions (shared across all replicas).
    /// Mutually exclusive with `AWS_KMS_KEY_IDS`.
    #[arg(long, env = "AWS_KMS_KEY_ID")]
    aws_kms_key_id: Option<String>,

    /// AWS KMS keys grouped by StatefulSet replica.
    ///
    /// Commas separate pod ordinals and semicolons separate wallets assigned to
    /// one pod. For example, `key-a1;key-a2,key-b1;key-b2` assigns two wallets
    /// to pod 0 and two to pod 1. The legacy `key-a,key-b` form still assigns
    /// exactly one wallet to each pod.
    /// Mutually exclusive with `AWS_KMS_KEY_ID`.
    #[arg(long, env = "AWS_KMS_KEY_IDS")]
    aws_kms_key_ids: Option<String>,
}

/// Parse the pod ordinal from the trailing numeric suffix of a StatefulSet
/// hostname (e.g. `"world-id-gateway-2"` → `Some(2)`).  Returns `None` when
/// the string has no `-` separator or the last segment is not an integer.
fn parse_ordinal(hostname: &str) -> Option<usize> {
    hostname.rsplit('-').next()?.parse().ok()
}

fn pod_ordinal() -> Option<usize> {
    parse_ordinal(&std::env::var("HOSTNAME").ok()?)
}

fn kms_keys_for_ordinal(key_ids: &str, ordinal: usize) -> ProviderResult<Vec<String>> {
    let groups: Vec<&str> = key_ids.split(',').collect();
    let group = groups
        .get(ordinal)
        .ok_or(ProviderError::OrdinalOutOfRange {
            ordinal,
            key_count: groups.len(),
        })?;
    let keys: Vec<String> = group.split(';').map(|key| key.trim().to_string()).collect();
    if keys.is_empty() || keys.iter().any(String::is_empty) {
        return Err(ProviderError::EmptyKmsKeyId { ordinal });
    }
    Ok(keys)
}

/// Strips the url to leave only the host & port
fn endpoint_label(url: &Url) -> String {
    let host = url.host_str().unwrap_or("unknown");
    // `Url::port()` is `None` when the port matches the scheme default.
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

impl SignerArgs {
    /// Build every signer assigned to this process.
    pub async fn signers(&self, rpc_url: &Url) -> ProviderResult<Vec<EthereumWallet>> {
        match (
            &self.wallet_private_key,
            &self.aws_kms_key_id,
            &self.aws_kms_key_ids,
        ) {
            (Some(s), None, None) => {
                // PrivateKey: No RPC call needed
                let signer = s.parse::<PrivateKeySigner>()?;
                Ok(vec![EthereumWallet::from(signer)])
            }
            (None, Some(key_id), None) => {
                tracing::info!("Initializing AWS KMS signer with key_id: {}", key_id);
                Ok(vec![Self::aws_kms_wallet(key_id, rpc_url).await?])
            }
            (None, None, Some(key_ids)) => {
                let ordinal = pod_ordinal().ok_or_else(|| ProviderError::OrdinalUnresolvable {
                    hostname: std::env::var("HOSTNAME").ok(),
                })?;
                let keys = kms_keys_for_ordinal(key_ids, ordinal)?;
                let mut wallets = Vec::with_capacity(keys.len());
                for key_id in keys {
                    tracing::info!(ordinal, key_id, "Initializing per-replica AWS KMS signer");
                    wallets.push(Self::aws_kms_wallet(&key_id, rpc_url).await?);
                }
                Ok(wallets)
            }
            (None, None, None) => Ok(Vec::new()),
            // Any multi-field combo is prevented at parse time by the clap
            // `#[group(multiple = false)]` attribute. Direct construction that
            // reaches here is a programming error.
            _ => Err(ProviderError::SignerConfigMissing),
        }
    }

    async fn aws_kms_wallet(key_id: &str, rpc_url: &Url) -> ProviderResult<EthereumWallet> {
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

    /// Returns `true` when per-replica key selection is active (`AWS_KMS_KEY_IDS` is set).
    ///
    /// When `true`, each pod uses its own Ethereum address derived from its
    /// ordinal slot in the key list, so nonces are independent and a
    /// nonce streams are independent across replicas.
    pub fn is_per_replica_signer(&self) -> bool {
        self.aws_kms_key_ids.is_some()
    }

    /// Create a new `SignerArgs` with the provided wallet private key.
    pub fn from_wallet(wallet_private_key: String) -> Self {
        Self {
            wallet_private_key: Some(wallet_private_key),
            aws_kms_key_id: None,
            aws_kms_key_ids: None,
        }
    }

    /// Create a new `SignerArgs` with the provided aws kms key id
    pub fn from_aws(aws_kms_key_id: String) -> Self {
        Self {
            wallet_private_key: None,
            aws_kms_key_id: Some(aws_kms_key_id),
            aws_kms_key_ids: None,
        }
    }

    /// Create `SignerArgs` with comma-separated replica slots and optional
    /// semicolon-separated wallets inside each slot (`AWS_KMS_KEY_IDS`).
    pub fn from_aws_per_replica(aws_kms_key_ids: String) -> Self {
        Self {
            wallet_private_key: None,
            aws_kms_key_id: None,
            aws_kms_key_ids: Some(aws_kms_key_ids),
        }
    }

    /// Create and return a `SignerConfig`, if a signer key is configured.
    pub fn signer_config(&self) -> Option<SignerConfig> {
        match (
            &self.wallet_private_key,
            &self.aws_kms_key_id,
            &self.aws_kms_key_ids,
        ) {
            (Some(pk), None, None) => Some(SignerConfig::PrivateKey(pk.clone())),
            (None, Some(key_id), None) => Some(SignerConfig::AwsKms(key_id.clone())),
            (None, None, Some(key_ids)) => Some(SignerConfig::AwsKmsPerReplica(key_ids.clone())),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SignerConfig {
    PrivateKey(String),
    AwsKms(String),
    /// Per-replica KMS signing: comma-separated list of key ARNs, one per pod ordinal.
    AwsKmsPerReplica(String),
}

/// A transaction signer paired with the provider stack that fills its transactions.
#[derive(Clone, Debug)]
pub struct ProviderWallet {
    pub address: Address,
    pub provider: DynProvider,
    wallet: EthereumWallet,
}

impl ProviderWallet {
    /// Creates a provider wallet from its provider and signer.
    pub fn new(address: Address, provider: DynProvider, wallet: EthereumWallet) -> Self {
        Self {
            address,
            provider,
            wallet,
        }
    }

    /// Fills and signs a transaction without broadcasting it.
    ///
    /// This reconstructs the filler stack as a workaround until
    /// <https://github.com/alloy-rs/alloy/issues/4150> is resolved.
    pub async fn sign_transaction(
        &self,
        transaction: TransactionRequest,
    ) -> Result<::alloy::consensus::TxEnvelope, TransportError> {
        ProviderBuilder::default()
            .with_gas_estimation()
            .filler(GasEstimateWithFallbackFiller)
            .with_blob_gas_estimation()
            .with_nonce_management(SimpleNonceManager::default())
            .fetch_chain_id()
            .wallet(self.wallet.clone())
            .connect_provider(self.provider.clone())
            .fill(transaction)
            .await?
            .try_into_envelope()
            .map_err(|_| {
                RpcError::local_usage_str("wallet provider did not produce a signed transaction")
            })
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
        self.http.extend(
            urls.into_iter()
                .map(|u| Url::parse(u.as_ref()).expect("invalid URL")),
        );
        self
    }

    /// Set the signer configuration.
    pub fn with_signer(mut self, signer: SignerArgs) -> Self {
        self.signer = signer;
        self
    }

    /// Set the maximum number of RPC retries. Set to 0 to disable retries.
    pub fn with_max_rpc_retries(mut self, max_retries: u32) -> Self {
        self.retry.max_retries = max_retries;
        self
    }

    /// Build a provider for each signer assigned to this process using the
    /// default [`SimpleNonceManager`]. Configurations without a signer return
    /// one read-only provider.
    ///
    /// The simple manager fetches the pending transaction count for each
    /// transaction instead of incrementing a process-local nonce cache.
    pub async fn http(self) -> ProviderResult<Vec<DynProvider>> {
        self.http_with_nonce_manager(SimpleNonceManager::default())
            .await
    }

    /// Builds one provider wallet for each signer assigned to this process.
    pub async fn http_wallets(self) -> ProviderResult<Vec<ProviderWallet>> {
        self.http_with_nonce_manager_and_address(SimpleNonceManager::default())
            .await?
            .into_iter()
            .map(ConfiguredProvider::try_into_wallet)
            .collect()
    }

    /// Build a provider for each signer using a caller-supplied [`NonceManager`].
    /// Configurations without a signer return one read-only provider.
    pub async fn http_with_nonce_manager<M: NonceManager + Clone + 'static>(
        self,
        nonce_manager: M,
    ) -> ProviderResult<Vec<DynProvider>> {
        self.http_with_nonce_manager_and_address(nonce_manager)
            .await
            .map(|providers| {
                providers
                    .into_iter()
                    .map(ConfiguredProvider::into_provider)
                    .collect()
            })
    }

    async fn http_with_nonce_manager_and_address<M: NonceManager + Clone + 'static>(
        self,
        nonce_manager: M,
    ) -> ProviderResult<Vec<ConfiguredProvider>> {
        if self.http.is_empty() {
            return Err(ProviderError::NoHttpUrls);
        }

        // Save first URL for signer (needed for AWS KMS chain_id lookup)
        let first_url = self.http[0].clone();
        let http = self.http;

        let retry_cfg = self.retry;

        // Per-request timeout configured at the HTTP client level so that
        // hanging connections surface errors for the retry layer to act on.
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(retry_cfg.timeout_secs))
            .build()
            .expect("failed to build HTTP client");

        let num_urls = http.len();

        let labeled_transports = http
            .into_iter()
            .map(|url| {
                // Leaks a static str to avoid per-request metric-label allocs.
                let label: &'static str = Box::leak(endpoint_label(&url).into_boxed_str());
                let transport = Http::with_client(http_client.clone(), url.clone());
                (label, transport)
            })
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

        // NOTE: Retries can be disabled by setting max_retries to 0 in the retry config.
        let client = if let Some(throttle_cfg) = self.throttle {
            let throttle_layer = ThrottleLayer::new_with_config(
                throttle_cfg.requests_per_second,
                throttle_cfg.burst_size,
            );

            let transport = ServiceBuilder::new()
                .layer(retry_layer)
                .layer(throttle_layer)
                .layer(fallback_layer)
                .layer(EndpointMetricsLayer)
                .service(labeled_transports);

            RpcClient::builder().transport(transport, false)
        } else {
            let transport = ServiceBuilder::new()
                .layer(retry_layer)
                .layer(fallback_layer)
                .layer(EndpointMetricsLayer)
                .service(labeled_transports);

            RpcClient::builder().transport(transport, false)
        };

        // Pass the first URL to the signers - it will only make RPC calls if needed (AWS KMS)
        let signers = self.signer.signers(&first_url).await?;

        if signers.is_empty() {
            let provider = ProviderBuilder::default().connect_client(client);
            return Ok(vec![ConfiguredProvider {
                provider: provider.erased(),
                wallet: None,
            }]);
        }

        Ok(signers
            .into_iter()
            .map(|wallet| {
                let provider = ProviderBuilder::default()
                    .with_gas_estimation()
                    .filler(GasEstimateWithFallbackFiller)
                    .with_blob_gas_estimation()
                    .with_nonce_management(nonce_manager.clone())
                    .fetch_chain_id()
                    .wallet(wallet.clone())
                    .connect_client(client.clone());

                ConfiguredProvider {
                    provider: provider.erased(),
                    wallet: Some(wallet),
                }
            })
            .collect())
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
        let urls = args.http;
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
        assert!(matches!(
            args.signer.signer_config(),
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
        assert!(matches!(
            args.signer.signer_config(),
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
        let retry = args.retry;
        assert_eq!(retry.max_retries, 3);
        assert_eq!(retry.initial_backoff_ms, 500);
        assert_eq!(retry.max_backoff_ms, 30000);
        assert_eq!(retry.timeout_secs, 5);
    }

    // ── parse_ordinal() ──────────────────────────────────────────────────────

    #[test]
    fn parse_ordinal_standard_statefulset_names() {
        assert_eq!(parse_ordinal("world-id-gateway-0"), Some(0));
        assert_eq!(parse_ordinal("world-id-gateway-1"), Some(1));
        assert_eq!(parse_ordinal("world-id-gateway-12"), Some(12));
    }

    #[test]
    fn parse_ordinal_simple_name() {
        assert_eq!(parse_ordinal("gateway-3"), Some(3));
    }

    #[test]
    fn parse_ordinal_non_numeric_suffix() {
        assert_eq!(parse_ordinal("world-id-gateway-abc123def"), None);
    }

    #[test]
    fn parse_ordinal_no_dash() {
        assert_eq!(parse_ordinal("gateway"), None);
    }

    #[test]
    fn kms_keys_for_ordinal_supports_multiple_wallets_per_slot() {
        assert_eq!(
            kms_keys_for_ordinal("key-a1; key-a2,key-b1;key-b2", 0).unwrap(),
            ["key-a1", "key-a2"]
        );
        assert_eq!(
            kms_keys_for_ordinal("key-a1; key-a2,key-b1;key-b2", 1).unwrap(),
            ["key-b1", "key-b2"]
        );
    }

    #[test]
    fn kms_keys_for_ordinal_rejects_invalid_slots() {
        assert!(matches!(
            kms_keys_for_ordinal("key-a1;;key-a2,key-b", 0),
            Err(ProviderError::EmptyKmsKeyId { ordinal: 0 })
        ));
        assert!(matches!(
            kms_keys_for_ordinal("key-a,key-b", 2),
            Err(ProviderError::OrdinalOutOfRange {
                ordinal: 2,
                key_count: 2
            })
        ));
    }

    // ── SignerArgs::is_per_replica_signer() ──────────────────────────────────

    #[test]
    fn is_per_replica_signer_false_for_single_key() {
        let args = SignerArgs::from_aws("arn:aws:kms:us-east-1:123:key/abc".to_string());
        assert!(!args.is_per_replica_signer());
    }

    #[test]
    fn is_per_replica_signer_false_for_private_key() {
        let args = SignerArgs::from_wallet("0xdeadbeef".to_string());
        assert!(!args.is_per_replica_signer());
    }

    #[test]
    fn is_per_replica_signer_true_when_key_ids_set() {
        let args = SignerArgs::from_aws_per_replica(
            "arn:aws:kms:us-east-1:123:key/a,arn:aws:kms:us-east-1:123:key/b".to_string(),
        );
        assert!(args.is_per_replica_signer());
    }

    // ── key-selection by ordinal (via signer_config) ─────────────────────────

    #[test]
    fn signer_config_per_replica_variant() {
        let ids = "arn:aws:kms:us-east-1:123:key/a,arn:aws:kms:us-east-1:123:key/b";
        let args = SignerArgs::from_aws_per_replica(ids.to_string());
        assert!(matches!(
            args.signer_config(),
            Some(SignerConfig::AwsKmsPerReplica(_))
        ));
    }

    #[test]
    fn signer_config_single_key_variant() {
        let args = SignerArgs::from_aws("arn:aws:kms:us-east-1:123:key/abc".to_string());
        assert!(matches!(
            args.signer_config(),
            Some(SignerConfig::AwsKms(_))
        ));
    }

    #[tokio::test]
    async fn http_wallet_exposes_signer_address() {
        let private_key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
        let signer: PrivateKeySigner = private_key.parse().unwrap();
        let wallets = ProviderArgs::new()
            .with_http_urls(["http://127.0.0.1:8545"])
            .with_signer(SignerArgs::from_wallet(private_key.to_string()))
            .http_wallets()
            .await
            .unwrap();

        assert_eq!(wallets[0].address, signer.address());
    }

    #[tokio::test]
    async fn http_wallet_requires_signer() {
        let result = ProviderArgs::new()
            .with_http_urls(["http://127.0.0.1:8545"])
            .http_wallets()
            .await;

        assert!(matches!(result, Err(ProviderError::SignerConfigMissing)));
    }

    #[test]
    fn endpoint_label_is_correct() {
        // Default port for the scheme is elided.
        let alchemy: Url = "https://worldchain-mainnet.g.alchemy.com/v2/secret-api-key"
            .parse()
            .unwrap();
        assert_eq!(endpoint_label(&alchemy), "worldchain-mainnet.g.alchemy.com");

        // Non-default port is kept.
        let internal: Url = "http://worldchain-rpc.internal.worldcoin.dev:9545"
            .parse()
            .unwrap();
        assert_eq!(
            endpoint_label(&internal),
            "worldchain-rpc.internal.worldcoin.dev:9545"
        );
    }
}
