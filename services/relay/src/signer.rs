//! Relay transaction signer: raw private key or AWS KMS.
//!
//! Mirrors `world-id-services-common`'s `SignerArgs` (used by the gateway) but
//! builds a **chain-agnostic** signer: the relay signs on World Chain plus every
//! satellite chain with the same wallet, so the signer must not be pinned to one
//! chain id.

use alloy::{
    network::{Ethereum, EthereumWallet, NetworkWallet},
    signers::{
        aws::{AwsSigner, aws_config::BehaviorVersion},
        local::PrivateKeySigner,
    },
};
use alloy_primitives::Address;

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

/// Which signing backend is in use. Logged at startup so operators can
/// confirm a migrated deployment is really on KMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerBackend {
    PrivateKey,
    AwsKms,
}

impl SignerBackend {
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
    pub backend: SignerBackend,
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
                    wallet = %address,
                    "signing with a raw private key from the environment; \
                     migrate this deployment to AWS_KMS_KEY_ID"
                );
                Ok(RelayWallet {
                    wallet: EthereumWallet::from(signer),
                    address,
                    backend: SignerBackend::PrivateKey,
                })
            }
            (None, Some(key_id)) => {
                let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
                let client = aws_sdk_kms::Client::new(&config);
                // `chain_id: None` keeps the signer usable across every chain the
                // relay bridges to; a `Some(..)` here rejects txs for other chains.
                let signer = AwsSigner::new(client, key_id.to_string(), None)
                    .await
                    .map_err(|e| eyre::eyre!("failed to initialize AWS KMS signer: {e}"))?;
                let wallet = EthereumWallet::from(signer);
                let address =
                    <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(&wallet);
                tracing::info!(%key_id, wallet = %address, "initialized AWS KMS relay signer");
                Ok(RelayWallet {
                    wallet,
                    address,
                    backend: SignerBackend::AwsKms,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(pk: Option<&str>, kms: Option<&str>) -> SignerArgs {
        SignerArgs {
            wallet_private_key: pk.map(str::to_string),
            aws_kms_key_id: kms.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn private_key_backend_resolves_address() {
        let key = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
        let built = args(Some(key), None).build().await.unwrap();
        assert_eq!(built.backend, SignerBackend::PrivateKey);
        assert_eq!(
            built.address,
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
                .parse::<Address>()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn rejects_missing_signer() {
        let err = args(None, None).build().await.unwrap_err().to_string();
        assert!(err.contains("no signer configured"), "{err}");
    }

    #[tokio::test]
    async fn rejects_both_signers() {
        let err = args(Some("0x1"), Some("key")).build().await.unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[tokio::test]
    async fn rejects_malformed_private_key() {
        let err = args(Some("not-a-key"), None).build().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("failed to parse WALLET_PRIVATE_KEY")
        );
    }
}
