use std::num::{NonZeroU32, NonZeroUsize};
use std::path::Path;
use std::sync::Arc;

use alloy::network::{Ethereum, EthereumWallet};
use alloy::providers::fillers::CachedNonceManager;
use alloy::providers::{DynProvider, Provider, ProviderBuilder, RootProvider, WsConnect};
use alloy::rpc::client::RpcClient;
use alloy::rpc::json_rpc::RequestPacket;
use alloy::signers::aws::aws_config::BehaviorVersion;
use alloy::signers::aws::AwsSigner;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::transports::http::Http;
use alloy::transports::layers::FallbackLayer;
use clap::Args;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service, ServiceBuilder};
use url::Url;

#[derive(Debug, Clone, Args, Deserialize)]
#[command(next_help_heading = "Rpc Configuration")]
pub struct ProviderArgs {
    /// HTTP RPC endpoints (in priority order).
    #[arg(long = "http", value_delimiter = ',', env = "RPC_URL")]
    #[serde(default)]
    pub http: Option<Vec<Url>>,

    /// WebSocket RPC endpoints (in priority order).
    #[arg(long = "ws", value_delimiter = ',', env = "WS_URL")]
    #[serde(default)]
    pub ws: Option<String>,

    #[command(flatten)]
    #[serde(default)]
    pub signer: Option<SignerArgs>,

    #[command(flatten)]
    #[serde(default)]
    pub throttle: Option<ThrottleConfig>,
}

#[derive(Args, Debug, Clone, Deserialize)]
pub struct ThrottleConfig {
    /// Requests per second rate limit (0 = unlimited).
    #[arg(long = "rps", default_value_t = 100, env = "RPC_REQUESTS_PER_SECOND")]
    #[serde(default = "defaults::default_requests_per_second")]
    pub requests_per_second: u32,

    /// Burst size for rate limiting.
    #[arg(long = "burst-size", default_value_t = 10, env = "RPC_BURST_SIZE")]
    #[serde(default = "defaults::default_burst_size")]
    pub burst_size: u32,
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
    pub async fn signer(&self, chain: u64) -> anyhow::Result<EthereumWallet> {
        match (&self.wallet_private_key, &self.aws_kms_key_id) {
            (Some(s), None) => {
                let signer = s
                    .parse::<PrivateKeySigner>()
                    .map_err(|e| anyhow::anyhow!("invalid private key: {e}"))?;
                Ok(EthereumWallet::from(signer))
            }
            (None, Some(key_id)) => {
                tracing::info!("Initializing AWS KMS signer with key_id: {}", key_id);

                // Initialize AWS KMS signer with the chain ID
                let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
                let client = aws_sdk_kms::Client::new(&config);
                let aws_signer = AwsSigner::new(client, key_id.to_string(), Some(chain))
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to initialize AWS KMS signer: {e}"))?;
                tracing::info!(
                    "AWS KMS signer initialized with address: {}",
                    aws_signer.address()
                );
                Ok(EthereumWallet::from(aws_signer))
            }
            _ => Err(anyhow::anyhow!(
                "exactly one of wallet_private_key or aws_kms_key_id must be provided"
            )),
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
    pub const REQUESTS_PER_SECOND: u32 = 50;

    pub const fn default_burst_size() -> u32 {
        BURST_SIZE
    }
    pub const fn default_requests_per_second() -> u32 {
        REQUESTS_PER_SECOND
    }
}

impl Default for ProviderArgs {
    fn default() -> Self {
        Self {
            http: Some(vec![]),
            ws: None,
            signer: None,
            throttle: None,
        }
    }
}

impl ProviderArgs {
    /// Create a new provider configuration with sensible defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
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

    /// Add multiple WebSocket RPC endpoints.
    pub fn with_ws_urls(mut self, url: String) -> Self {
        self.ws = Some(url);
        self
    }
    /// Build a dynamic provider from the configuration.
    pub async fn http(self) -> anyhow::Result<DynProvider> {
        let Some(http) = self.http else {
            return Err(anyhow::anyhow!("No HTTP URLs provided"));
        };

        // Configure the fallback layer
        let fallback_layer = FallbackLayer::default()
            .with_active_transport_count(NonZeroUsize::new(http.len()).unwrap());

        let throttle = self.throttle.map(|throttle_config| {
            ThrottleLayer::new_with_config(
                throttle_config.requests_per_second,
                throttle_config.burst_size,
            )
        });

        let transports = http.into_iter().map(Http::new).collect::<Vec<_>>();

        let client = if let Some(throttle) = throttle {
            let transport = ServiceBuilder::new()
                .layer(throttle)
                .layer(fallback_layer)
                .service(transports);

            RpcClient::builder().transport(transport, false)
        } else {
            let transport = ServiceBuilder::new()
                .layer(fallback_layer)
                .service(transports);

            RpcClient::builder().transport(transport, false)
        };

        let chain_id = {
            let provider: RootProvider<Ethereum> =
                ProviderBuilder::default().connect_client(client.clone());
            provider.get_chain_id().await?
        };

        let maybe_signer = if let Some(signer) = &self.signer {
            Some(signer.signer(chain_id).await?)
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

    pub async fn ws(self) -> anyhow::Result<DynProvider> {
        let Some(ws) = self.ws else {
            return Err(anyhow::anyhow!("No WS URLs provided"));
        };

        let provider = ProviderBuilder::new()
            .connect_ws(WsConnect::new(ws))
            .await?
            .erased();

        Ok(provider)
    }

    pub async fn build_providers(self) -> anyhow::Result<(DynProvider, DynProvider)> {
        let http_provider = self.clone().http().await?;
        let ws_provider = self.ws().await?;

        Ok((http_provider, ws_provider))
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
            chain_id = 1
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
    fn from_file_loads_http_and_ws() {
        let config = r#"
            [provider]
            http = ["https://rpc.example.com"]
            ws = "wss://ws.example.com"
            chain_id = 42161
        "#;

        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        file.write_all(config.as_bytes()).unwrap();

        let args = ProviderArgs::from_file(file.path()).unwrap();
        assert_eq!(args.http.unwrap().len(), 1);
        assert_eq!(args.ws.unwrap(), "wss://ws.example.com");
    }

    #[test]
    fn from_file_loads_with_private_key_signer() {
        let config = r#"
            [provider]
            http = ["https://rpc.example.com"]
            chain_id = 1

            [provider.signer]
            wallet_private_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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
            chain_id = 1

            [provider.signer]
            aws_kms_key_id = "arn:aws:kms:us-east-1:123456789:key/abc-123"
        "#;

        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        file.write_all(config.as_bytes()).unwrap();

        let args = ProviderArgs::from_file(file.path()).unwrap();
        let signer = args.signer.unwrap();
        assert!(matches!(signer.signer_config(), SignerConfig::AwsKms(_)));
    }
}
