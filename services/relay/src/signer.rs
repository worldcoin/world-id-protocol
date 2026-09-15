//! Relay transaction signer: raw private key or AWS KMS.
//!
//! Mirrors `world-id-services-common`'s `SignerArgs` (used by the gateway) but
//! builds a **chain-agnostic** signer: the relay signs on World Chain plus every
//! satellite chain with the same wallet, so the signer must not be pinned to one
//! chain id.

use std::time::Duration;

use alloy::{
    network::{Ethereum, EthereumWallet, NetworkWallet},
    signers::{
        aws::{AwsSigner, aws_config::BehaviorVersion},
        local::PrivateKeySigner,
    },
};
use alloy_primitives::Address;
use aws_config::{retry::RetryConfig, timeout::TimeoutConfig};

/// Per-attempt cap on a KMS call. `Sign` is a p99-sub-second operation, so this
/// is generous enough never to fire on a healthy path.
const KMS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Total cap across all retries of one KMS call, bounding how long a satellite
/// task can block on signing.
const KMS_OPERATION_TIMEOUT: Duration = Duration::from_secs(15);

/// Signing credentials. Exactly one of the two may be set; clap enforces
/// mutual exclusion at parse time via `group(multiple = false)`.
#[derive(clap::Args, Debug, Clone, Default)]
#[group(required = true, multiple = false)]
pub struct SignerArgs {
    /// Hex private key of the relay wallet that submits transactions.
    ///
    /// Legacy path: the key is stored in AWS Secrets Manager and injected as an
    /// env var. Prefer `--aws-kms-key-id`, which keeps the key non-exportable.
    #[arg(long, env = "WALLET_PRIVATE_KEY", hide_env_values = true)]
    pub wallet_private_key: Option<String>,

    /// AWS KMS key id (or ARN) of an `ECC_SECG_P256K1` / `SIGN_VERIFY` key.
    ///
    /// Credentials come from the ambient AWS provider chain (EKS Pod Identity
    /// in-cluster), so no secret material reaches the pod.
    #[arg(long, env = "AWS_KMS_KEY_ID")]
    pub aws_kms_key_id: Option<String>,
}

/// Which signer is in use. Logged at startup so operators can confirm a
/// migrated deployment is really on KMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerKind {
    PrivateKey,
    AwsKms,
}

impl SignerKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrivateKey => "private_key",
            Self::AwsKms => "aws_kms",
        }
    }
}

/// A built relay wallet: the signing wallet plus its resolved address.
#[derive(Debug)]
pub struct RelayWallet {
    pub wallet: EthereumWallet,
    pub address: Address,
    pub signer: SignerKind,
}

impl SignerArgs {
    /// Builds the relay wallet, failing fast when neither (or both) inputs are set.
    ///
    /// KMS initialisation performs one `GetPublicKey` call to derive the address;
    /// a failure here aborts startup rather than surfacing later as unsigned
    /// transactions.
    pub async fn build(&self) -> eyre::Result<RelayWallet> {
        match (&self.wallet_private_key, &self.aws_kms_key_id) {
            (Some(key), None) => {
                let signer: PrivateKeySigner = key
                    .parse()
                    .map_err(|e| eyre::eyre!("failed to parse WALLET_PRIVATE_KEY: {e}"))?;
                let address = signer.address();
                tracing::warn!(
                    signer = SignerKind::PrivateKey.as_str(),
                    wallet = %address,
                    "signing with a raw private key from the environment; \
                     migrate this deployment to AWS_KMS_KEY_ID"
                );
                Ok(RelayWallet {
                    wallet: EthereumWallet::from(signer),
                    address,
                    signer: SignerKind::PrivateKey,
                })
            }
            (None, Some(key_id)) => {
                let config = aws_config::defaults(BehaviorVersion::latest())
                    // Every relay transaction now costs a KMS round trip. The SDK
                    // sets no operation timeout by default, so a hung `Sign` would
                    // stall the satellite task indefinitely.
                    .timeout_config(
                        TimeoutConfig::builder()
                            .connect_timeout(Duration::from_secs(3))
                            .operation_attempt_timeout(KMS_ATTEMPT_TIMEOUT)
                            .operation_timeout(KMS_OPERATION_TIMEOUT)
                            .build(),
                    )
                    // `standard` is exponential backoff with jitter, capped at
                    // 3 attempts. Signing is idempotent, so retries are safe.
                    .retry_config(RetryConfig::standard().with_max_attempts(3))
                    .load()
                    .await;
                let client = aws_sdk_kms::Client::new(&config);
                // `chain_id: None` keeps the signer usable across every chain the
                // relay bridges to; a `Some(..)` here rejects txs for other chains.
                let signer = AwsSigner::new(client, key_id.to_string(), None)
                    .await
                    .map_err(|e| eyre::eyre!("failed to initialize AWS KMS signer: {e}"))?;
                let wallet = EthereumWallet::from(signer);
                let address =
                    <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(&wallet);
                tracing::info!(
                    signer = SignerKind::AwsKms.as_str(),
                    %key_id,
                    wallet = %address,
                    "initialized AWS KMS relay signer"
                );
                Ok(RelayWallet {
                    wallet,
                    address,
                    signer: SignerKind::AwsKms,
                })
            }
            (None, None) => Err(eyre::eyre!(
                "no signer configured: set AWS_KMS_KEY_ID (preferred) or WALLET_PRIVATE_KEY"
            )),
            (Some(_), Some(_)) => Err(eyre::eyre!(
                "WALLET_PRIVATE_KEY and AWS_KMS_KEY_ID are mutually exclusive; set exactly one"
            )),
        }
    }
}
