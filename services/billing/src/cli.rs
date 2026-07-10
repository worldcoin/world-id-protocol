use alloy_primitives::Address;
use clap::{Parser, ValueEnum};
use eyre::Context as _;

use crate::finalizer::{Finalizer, FinalizerArgs};
use world_id_services_common::ProviderArgs;

/// Worker role this process should run.
///
/// The service is a modular monolith: each role can be deployed as its own
/// process from the same image, keeping signing keys and blast radius isolated.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Role {
    /// Drive epoch finalization by calling the Billing Contract's
    /// permissionless `finalizeEpochs` once voting windows close.
    Finalizer,
    /// Settle finalized epoch fees in WLD on behalf of relying parties.
    Payer,
}

/// World ID billing service — off-chain operator for WIP-107 transactional fees.
#[derive(Debug, Parser)]
#[command(name = "world-id-billing", version, about)]
pub struct Cli {
    /// Worker role to run.
    #[arg(long, env = "BILLING_ROLE", value_enum)]
    pub role: Role,

    /// Address of the on-chain Billing Contract.
    #[arg(long, env = "BILLING_CONTRACT_ADDRESS")]
    pub billing_contract_address: Address,

    #[command(flatten)]
    pub provider: ProviderArgs,

    #[command(flatten)]
    pub finalizer: FinalizerArgs,
}

impl Cli {
    pub async fn run(self) -> eyre::Result<()> {
        match self.role {
            Role::Finalizer => {
                // `finalizeEpochs` is permissionless but state-changing: fail fast at
                // startup on a missing signer instead of on the first transaction.
                if self
                    .provider
                    .signer
                    .as_ref()
                    .and_then(|s| s.signer_config())
                    .is_none()
                {
                    eyre::bail!(
                        "the finalizer submits transactions and requires a signer; \
                         set WALLET_PRIVATE_KEY, AWS_KMS_KEY_ID, or AWS_KMS_KEY_IDS"
                    );
                }

                let provider = self
                    .provider
                    .http()
                    .await
                    .wrap_err("failed to build the RPC provider")?;

                Finalizer::new(provider, self.billing_contract_address, &self.finalizer)
                    .run(shutdown_signal())
                    .await?;
            }
            Role::Payer => tracing::warn!("payer worker is not yet implemented"),
        }

        Ok(())
    }
}

/// Resolves on SIGINT (ctrl-c) or SIGTERM, for graceful shutdown under Kubernetes.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}
