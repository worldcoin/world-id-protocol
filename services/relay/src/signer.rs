//! Relay transaction signers: one AWS KMS key per network, or one raw private
//! key shared by every network.
//!
//! KMS keys are provisioned per network so a disabled key stops signing for
//! that chain only. Each key is an independent identity with its own address,
//! funding and on-chain authorisation.

use std::time::Duration;

use alloy::{
    network::{Ethereum, EthereumWallet, NetworkWallet},
    signers::{
        aws::{AwsSigner, aws_config::BehaviorVersion},
        local::PrivateKeySigner,
    },
};
use alloy_primitives::Address;
use aws_config::{SdkConfig, retry::RetryConfig, timeout::TimeoutConfig};

/// Per-attempt cap on a KMS call. `Sign` is a sub-second operation, so this is
/// generous enough never to fire on a healthy path.
const KMS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Total cap across all retries of one KMS call, bounding how long a satellite
/// task can block on signing.
const KMS_OPERATION_TIMEOUT: Duration = Duration::from_secs(15);

/// Which signing backend to use. Exactly one is required; clap enforces that at
/// parse time via `group(required = true, multiple = false)`.
#[derive(clap::Args, Debug, Clone, Default)]
#[group(required = true, multiple = false)]
pub struct SignerArgs {
    /// Sign with AWS KMS, reading one key per network from
    /// `{NETWORK}_AWS_KMS_KEY_ID` (same naming as `{NETWORK}_RPC_URL`).
    #[arg(long, env = "AWS_KMS_SIGNING")]
    pub aws_kms_signing: bool,

    /// Hex private key used for *every* network (legacy, local development).
    #[arg(long, env = "WALLET_PRIVATE_KEY", hide_env_values = true)]
    pub wallet_private_key: Option<String>,
}

/// The env var holding a network's KMS key id, e.g. `BASE_AWS_KMS_KEY_ID`.
fn kms_key_env_var(network: &str) -> String {
    format!("{}_AWS_KMS_KEY_ID", network.to_uppercase())
}

/// A wallet for one network, with its resolved signing address.
#[derive(Debug, Clone)]
pub struct RelayWallet {
    pub wallet: EthereumWallet,
    pub address: Address,
}

/// Builds per-network wallets from whichever backend is configured.
#[derive(Debug, Clone)]
pub enum RelaySigners {
    /// One key for every network; all wallets share an address.
    PrivateKey(PrivateKeySigner),
    /// One KMS key per network, resolved lazily per chain. The SDK config is
    /// loaded once so credentials are not re-resolved per network.
    AwsKms(Box<SdkConfig>),
}

impl RelaySigners {
    /// Resolves the configured backend, loading AWS config once up front.
    pub async fn init(args: &SignerArgs) -> eyre::Result<Self> {
        match (args.aws_kms_signing, &args.wallet_private_key) {
            (true, None) => Ok(Self::AwsKms(Box::new(Self::aws_config().await))),
            (false, Some(key)) => {
                let signer: PrivateKeySigner = key
                    .parse()
                    .map_err(|e| eyre::eyre!("failed to parse WALLET_PRIVATE_KEY: {e}"))?;
                tracing::warn!(
                    signer = "private_key",
                    wallet = %signer.address(),
                    "signing every network with a raw private key from the \
                     environment; migrate this deployment to AWS_KMS_SIGNING"
                );
                Ok(Self::PrivateKey(signer))
            }
            (true, Some(_)) => Err(eyre::eyre!(
                "AWS_KMS_SIGNING and WALLET_PRIVATE_KEY are mutually exclusive; set exactly one"
            )),
            (false, None) => Err(eyre::eyre!(
                "no signer configured: set AWS_KMS_SIGNING=true (preferred) or WALLET_PRIVATE_KEY"
            )),
        }
    }

    /// Every relay transaction costs a KMS round trip, and the SDK sets no
    /// operation timeout by default, so a hung `Sign` would stall a satellite
    /// task indefinitely. `standard` retries are bounded with jitter.
    async fn aws_config() -> SdkConfig {
        aws_config::defaults(BehaviorVersion::latest())
            .timeout_config(
                TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(3))
                    .operation_attempt_timeout(KMS_ATTEMPT_TIMEOUT)
                    .operation_timeout(KMS_OPERATION_TIMEOUT)
                    .build(),
            )
            .retry_config(RetryConfig::standard().with_max_attempts(3))
            .load()
            .await
    }

    /// Builds the wallet that signs for `network`.
    ///
    /// KMS signers are pinned to `chain_id`, so a key id wired to the wrong
    /// network fails at signing time instead of submitting on the wrong chain.
    pub async fn wallet_for(&self, network: &str, chain_id: u64) -> eyre::Result<RelayWallet> {
        match self {
            Self::PrivateKey(signer) => Ok(RelayWallet {
                wallet: EthereumWallet::from(signer.clone()),
                address: signer.address(),
            }),
            Self::AwsKms(config) => {
                let env_var = kms_key_env_var(network);
                let key_id = std::env::var(&env_var).map_err(|_| {
                    eyre::eyre!(
                        "{env_var} is required to sign for {network} when AWS_KMS_SIGNING is set"
                    )
                })?;
                let client = aws_sdk_kms::Client::new(config);
                let signer = AwsSigner::new(client, key_id.clone(), Some(chain_id))
                    .await
                    .map_err(|e| {
                        eyre::eyre!("failed to initialize AWS KMS signer for {network}: {e}")
                    })?;
                let wallet = EthereumWallet::from(signer);
                let address =
                    <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(&wallet);
                tracing::info!(
                    signer = "aws_kms",
                    %network,
                    chain_id,
                    %key_id,
                    wallet = %address,
                    "initialized AWS KMS relay signer"
                );
                Ok(RelayWallet { wallet, address })
            }
        }
    }
}
