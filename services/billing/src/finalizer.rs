//! Finalizer worker: drives on-chain epoch finalization of the Billing Contract.
use std::{
    future::Future,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::providers::{DynProvider, PendingTransactionError, WatchTxError};
use alloy_primitives::{Address, U256};
use clap::Args;
use eyre::{Context, Result};

use crate::{
    bindings::IBillingContract::{self, IBillingContractInstance},
    metrics::{self, tx_outcome},
};

/// Configuration for the finalizer worker.
#[derive(Debug, Clone, Args)]
#[command(next_help_heading = "Finalizer Configuration")]
pub struct FinalizerArgs {
    /// Maximum finalization steps per transaction (bounds gas per transaction, defined by the Billing Contract).
    #[arg(
        long,
        env = "FINALIZER_MAX_STEPS_PER_TX",
        default_value = "500",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub max_steps_per_tx: u64,

    /// Deadline for a submitted transaction to confirm, in seconds.
    #[arg(
        long,
        env = "FINALIZER_RECEIPT_TIMEOUT_SECS",
        default_value = "60",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub receipt_timeout_secs: u64,

    /// Extra buffer added after an epoch's computed voting-window-close time before waking to check it, in seconds.
    #[arg(long, env = "FINALIZER_CLOSE_LAG_SECS", default_value = "3")]
    pub close_lag_secs: u64,
}

/// The finalizer worker. Construct with [`Finalizer::new`], then drive it with
/// [`Finalizer::run`].
pub struct Finalizer {
    contract: IBillingContractInstance<DynProvider>,
    max_steps_per_tx: u64,
    receipt_timeout: Duration,
    wake_buffer: Duration,
}

impl Finalizer {
    pub fn new(provider: DynProvider, billing_contract: Address, args: &FinalizerArgs) -> Self {
        Self {
            contract: IBillingContract::new(billing_contract, provider),
            max_steps_per_tx: args.max_steps_per_tx,
            receipt_timeout: Duration::from_secs(args.receipt_timeout_secs),
            wake_buffer: Duration::from_secs(args.close_lag_secs),
        }
    }

    pub async fn run(&self, shutdown: impl Future<Output = ()>) -> Result<()> {
        tracing::info!(
            contract = %self.contract.address(),
            max_steps_per_tx = self.max_steps_per_tx,
            close_lag_secs = self.wake_buffer.as_secs(),
            "starting finalizer worker"
        );

        tokio::select! {
            result = self.run_ticker() => result?,
            () = shutdown => {
                tracing::info!("shutdown signal received, stopping finalizer worker");
            }
        }
        Ok(())
    }

    async fn run_ticker(&self) -> Result<()> {
        loop {
            let (latest_finalized_epoch, latest_closed_epoch) =
                match self.get_epoch_watermarks().await {
                    Ok(res) => res,
                    Err(e) => {
                        tracing::error!(error = ?e, "failed to get epoch watermarks");
                        continue;
                    }
                };

            let is_fully_caught_up = latest_finalized_epoch == latest_closed_epoch;

            if is_fully_caught_up {
                // If latest_closed_epoch is None, there is no closed epoch yet, and the next closing epoch is 0.
                let next_closing_epoch = latest_closed_epoch.map(|e| e + 1).unwrap_or(0);

                if let Err(e) = self.wait_next_closed_epoch(next_closing_epoch).await {
                    tracing::error!(error = ?e, "failed to wait for next closed epoch");
                }
                // After waiting, we start the next iteration of the loop
                continue;
            }

            if let Some(latest_closed_epoch) = latest_closed_epoch {
                if let Err(e) = self.send_finalize_tx(latest_closed_epoch).await {
                    tracing::error!(error = ?e, "failed to send finalizeEpochs transaction");
                    continue;
                }
            }
        }
    }

    /// Send one bounded `finalizeEpochs` transaction and wait for its receipt.
    async fn send_finalize_tx(&self, upto_epoch: u32) -> Result<()> {
        let call = self
            .contract
            .finalizeEpochs(upto_epoch, U256::from(self.max_steps_per_tx));

        let pending = match call.send().await {
            Err(err) => {
                self.record_finalize_tx_outcome(tx_outcome::RPC_ERROR);
                return Err(err).wrap_err("failed to submit finalizeEpochs transaction");
            }
            Ok(pending) => pending.with_timeout(Some(self.receipt_timeout)),
        };
        let tx_hash = *pending.tx_hash();
        tracing::debug!(%tx_hash, upto_epoch, "finalizeEpochs transaction sent");

        let receipt = match pending.get_receipt().await {
            // Transaction was not confirmed on chain within the receipt timeout.
            Err(PendingTransactionError::TxWatcher(WatchTxError::Timeout)) => {
                self.record_finalize_tx_outcome(tx_outcome::TIMEOUT);
                eyre::bail!(
                    "finalizeEpochs receipt for {tx_hash} timed out after {:?}",
                    self.receipt_timeout
                );
            }
            Err(err) => {
                self.record_finalize_tx_outcome(tx_outcome::RPC_ERROR);
                return Err(err).wrap_err_with(|| {
                    format!("failed while waiting for finalizeEpochs receipt of {tx_hash}")
                });
            }
            Ok(receipt) => receipt,
        };

        if !receipt.status() {
            self.record_finalize_tx_outcome(tx_outcome::REVERT_ON_CHAIN);
            eyre::bail!("finalizeEpochs transaction reverted: {tx_hash}");
        }

        self.record_finalize_tx_outcome(tx_outcome::SUCCESS);
        tracing::info!(%tx_hash, upto_epoch, "finalizeEpochs transaction confirmed");
        Ok(())
    }

    async fn get_epoch_watermarks(&self) -> Result<(Option<u32>, Option<u32>)> {
        let res = self.contract.epochWatermarks().call().await?;

        Ok((
            res.finalizedExists.then_some(res.finalizedEpoch),
            res.closedExists.then_some(res.closedEpoch),
        ))
    }

    async fn wait_next_closed_epoch(&self, next_closing_epoch: u32) -> Result<()> {
        let voting_window_closed_next_epoch = self
            .contract
            .votingWindowEnd(next_closing_epoch)
            .call()
            .await?;

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the unix epoch")
            .as_secs();

        let wait_duration =
            Duration::from_secs(voting_window_closed_next_epoch.saturating_sub(now_unix))
                + self.wake_buffer;

        tokio::time::sleep(wait_duration).await;
        Ok(())
    }

    fn record_finalize_tx_outcome(&self, outcome: &'static str) {
        ::metrics::counter!(
            metrics::METRICS_FINALIZER_FINALIZE_ATTEMPTS,
            metrics::LABEL_OUTCOME => outcome
        )
        .increment(1);
    }
}
