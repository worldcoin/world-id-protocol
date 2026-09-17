//! Per-network signer selection for the relay.
//!
//! Signer construction itself lives in `world-id-services-common`; this module
//! only decides *which* key signs for a given network and delegates. Keys are
//! provisioned per network, so each has its own address, funding and on-chain
//! authorisation.

use alloy::network::{Ethereum, EthereumWallet, NetworkWallet};
use alloy_primitives::Address;
use world_id_services_common::alloy::provider::SignerArgs as CommonSignerArgs;

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

impl From<EthereumWallet> for RelayWallet {
    fn from(wallet: EthereumWallet) -> Self {
        let address = <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(&wallet);
        Self { wallet, address }
    }
}

/// Resolves the wallet that signs for each network.
#[derive(Debug, Clone)]
pub enum RelaySigners {
    /// One unpinned key shared by every network; all wallets share an address.
    Shared(RelayWallet),
    /// One KMS key per network, resolved from the environment per chain.
    AwsKmsPerNetwork,
}

impl RelaySigners {
    /// Resolves the configured backend, building the shared wallet up front so a
    /// bad private key fails before any provider work.
    pub async fn init(args: &SignerArgs) -> eyre::Result<Self> {
        match (args.aws_kms_signing, &args.wallet_private_key) {
            (true, None) => Ok(Self::AwsKmsPerNetwork),
            (false, Some(key)) => {
                let wallet: RelayWallet = CommonSignerArgs::from_wallet(key.clone())
                    .chain_agnostic_wallet()
                    .await?
                    .into();
                tracing::warn!(
                    signer = "private_key",
                    wallet = %wallet.address,
                    "signing every network with a raw private key from the \
                     environment; migrate this deployment to AWS_KMS_SIGNING"
                );
                Ok(Self::Shared(wallet))
            }
            (true, Some(_)) => Err(eyre::eyre!(
                "AWS_KMS_SIGNING and WALLET_PRIVATE_KEY are mutually exclusive; set exactly one"
            )),
            (false, None) => Err(eyre::eyre!(
                "no signer configured: set AWS_KMS_SIGNING=true (preferred) or WALLET_PRIVATE_KEY"
            )),
        }
    }

    /// Builds the wallet that signs for `network`.
    ///
    /// KMS signers are pinned to `chain_id`, so a key id wired to the wrong
    /// network fails at signing time instead of submitting on the wrong chain.
    pub async fn wallet_for(&self, network: &str, chain_id: u64) -> eyre::Result<RelayWallet> {
        match self {
            Self::Shared(wallet) => Ok(wallet.clone()),
            Self::AwsKmsPerNetwork => {
                let env_var = kms_key_env_var(network);
                let key_id = std::env::var(&env_var).map_err(|_| {
                    eyre::eyre!(
                        "{env_var} is required to sign for {network} when AWS_KMS_SIGNING is set"
                    )
                })?;
                let wallet: RelayWallet = CommonSignerArgs::from_aws(key_id.clone())
                    .wallet_for_chain(Some(chain_id))
                    .await?
                    .into();
                tracing::info!(
                    signer = "aws_kms",
                    %network,
                    chain_id,
                    %key_id,
                    wallet = %wallet.address,
                    "resolved per-network AWS KMS relay signer"
                );
                Ok(wallet)
            }
        }
    }
}
