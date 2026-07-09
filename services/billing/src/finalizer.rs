//! Finalizer worker: drives on-chain epoch finalization of the Billing Contract.
//!
//! Finalization is keeper-driven: the permissionless `finalizeEpochs` call is
//! the *only* path that advances the contract's finalization cursor (neither
//! `pay` nor `submitBillingVotes` finalize as a side effect), and an epoch
//! becomes finalizable purely by wall-clock time, once its voting window
//! closes. No contract event signals this — vote-less epochs emit nothing at
//! all but still need the cursor advanced past them.
//!
//! Rather than polling on a fixed interval, the worker computes the exact
//! wall-clock moment the current finalization frontier (derived from the
//! contract's `latestFinalizedEpoch` watermark) becomes closeable —
//! `epochEnd(cursor) + votingWindow`, both already exposed by the contract —
//! and sleeps to it. After waking, a short bounded retry
//! loop confirms the chain actually reflects the close (bridging RPC lag /
//! clock drift) before draining via `tick`, which submits `finalizeEpochs`
//! transactions until the backlog is caught up. Work per transaction is
//! bounded by `--max-steps-per-tx` (the contract resumes mid-epoch across
//! calls); `tick` itself always drains fully or errors, since each call makes
//! guaranteed forward progress while backlog remains.

use std::{
    future::Future,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::providers::{DynProvider, PendingTransactionError, WatchTxError};
use alloy_primitives::{Address, U256};
use backon::{ConstantBuilder, Retryable as _};
use clap::Args;
use eyre::{Context, Result, eyre};

use crate::{
    bindings::IBillingContract::{self, IBillingContractInstance},
    metrics::{self, outcome},
};

/// Configuration for the finalizer worker.
#[derive(Debug, Clone, Args)]
#[command(next_help_heading = "Finalizer Configuration")]
pub struct FinalizerArgs {
    /// Maximum finalization steps per transaction (bounds gas per transaction;
    /// the contract resumes mid-epoch across calls).
    #[arg(
        long,
        env = "FINALIZER_MAX_STEPS_PER_TX",
        default_value = "500",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub max_steps_per_tx: u64,

    /// Deadline for a submitted transaction to confirm, in seconds. This is
    /// the only worker-level timeout: waiting for a receipt is otherwise
    /// unbounded (a dropped or underpriced transaction never mines), whereas
    /// plain RPC reads and submissions are already bounded by the provider's
    /// per-request timeout and retry budget.
    #[arg(
        long,
        env = "FINALIZER_RECEIPT_TIMEOUT_SECS",
        default_value = "60",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub receipt_timeout_secs: u64,

    /// Extra buffer added after an epoch's computed voting-window-close time
    /// before waking to check it, in seconds. Absorbs ordinary clock drift
    /// between this worker and the chain so the confirm-retry loop below
    /// rarely needs more than its first attempt. Zero is a legitimate
    /// "no buffer" choice.
    #[arg(long, env = "FINALIZER_CLOSE_LAG_SECS", default_value = "3")]
    pub close_lag_secs: u64,

    /// Interval between confirm-loop retries after waking, in seconds. The
    /// worker wakes at a computed deadline and re-checks on-chain state; if
    /// the chain doesn't yet reflect the close (RPC lag, clock drift), it
    /// retries at this constant interval rather than backing off — it's
    /// bridging a short, expected gap, not backing off from a failure.
    #[arg(
        long,
        env = "FINALIZER_CONFIRM_RETRY_INTERVAL_SECS",
        default_value = "2",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub confirm_retry_interval_secs: u64,

    /// Maximum confirm-loop retry attempts before giving up. Exhausting this
    /// is fatal (the worker exits with an error, see `Finalizer::run`) rather
    /// than degrading to a silent poll loop: it means either persistent RPC
    /// degradation or a systematically wrong computed deadline, both of which
    /// deserve loud, infra-visible failure (a pod restart) instead of running
    /// on unnoticed.
    #[arg(
        long,
        env = "FINALIZER_CONFIRM_MAX_ATTEMPTS",
        default_value = "30",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub confirm_max_attempts: u32,
}

/// The finalizer worker. Construct with [`Finalizer::new`], then drive it with
/// [`Finalizer::run`].
pub struct Finalizer {
    contract: IBillingContractInstance<DynProvider>,
    max_steps_per_tx: u64,
    receipt_timeout: Duration,
    close_lag: Duration,
    confirm_retry_interval: Duration,
    confirm_max_attempts: usize,
}

impl Finalizer {
    /// Create a finalizer against `billing_contract` using `provider`.
    ///
    /// The provider must have a signer configured: `finalizeEpochs` is a
    /// state-changing call (any gas-funded key works — the call is
    /// permissionless).
    pub fn new(provider: DynProvider, billing_contract: Address, args: &FinalizerArgs) -> Self {
        Self {
            contract: IBillingContract::new(billing_contract, provider),
            max_steps_per_tx: args.max_steps_per_tx,
            receipt_timeout: Duration::from_secs(args.receipt_timeout_secs),
            close_lag: Duration::from_secs(args.close_lag_secs),
            confirm_retry_interval: Duration::from_secs(args.confirm_retry_interval_secs),
            confirm_max_attempts: args.confirm_max_attempts as usize,
        }
    }

    /// Run the deadline-scheduled finalizer loop until `shutdown` resolves.
    ///
    /// Each cycle computes the wall-clock moment the current finalization
    /// frontier (derived from `latestFinalizedEpoch`) becomes closeable and
    /// sleeps to it instead of polling on a fixed interval (see module docs).
    /// Non-fatal
    /// failures (a failed cursor/deadline fetch, a failed `tick`) are logged
    /// and counted, then retried next cycle from fresh on-chain state —
    /// self-healing without a retry storm. Exhausting the confirm-retry bound
    /// in [`Self::wait_for_close_confirmed`] is the one fatal condition: it
    /// propagates out of this loop and `run` returns `Err`, deliberately
    /// crashing the worker rather than degrading to a silent poll loop.
    pub async fn run(&self, shutdown: impl Future<Output = ()>) -> Result<()> {
        tracing::info!(
            contract = %self.contract.address(),
            max_steps_per_tx = self.max_steps_per_tx,
            close_lag_secs = self.close_lag.as_secs(),
            confirm_retry_interval_secs = self.confirm_retry_interval.as_secs(),
            confirm_max_attempts = self.confirm_max_attempts,
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

    /// The deadline-scheduled cycle loop driving `run`. Never returns `Ok` —
    /// only resolves (with `Err`) when [`Self::wait_for_close_confirmed`]
    /// exhausts its confirm-retry bound; every other failure is caught and
    /// retried in place.
    async fn run_ticker(&self) -> Result<()> {
        loop {
            let cursor = match self.next_epoch_to_finalize().await {
                Ok(cursor) => cursor,
                Err(err) => {
                    self.count_cycle_failure(err, "failed to read finalization cursor");
                    tokio::time::sleep(self.confirm_retry_interval).await;
                    continue;
                }
            };
            let target_close = match self.next_deadline(cursor).await {
                Ok(target) => target,
                Err(err) => {
                    self.count_cycle_failure(err, "failed to compute finalizer deadline");
                    tokio::time::sleep(self.confirm_retry_interval).await;
                    continue;
                }
            };

            tokio::time::sleep(sleep_duration(target_close, self.close_lag)?).await;

            self.wait_for_close_confirmed(cursor).await?;

            if let Err(err) = self.tick().await {
                self.count_cycle_failure(err, "finalizer tick failed");
            }
        }
    }

    /// One drain: work off however much of the finalization backlog is
    /// currently closed, submitting `finalizeEpochs` transactions until fully
    /// caught up. No-ops if nothing has closed yet. Always either fully
    /// drains or errors — each call is guaranteed forward progress by the
    /// contract while backlog remains, bounded only by `max_steps_per_tx`
    /// (gas) and the receipt timeout per transaction.
    pub async fn tick(&self) -> Result<()> {
        let Some(closed) = self.latest_closed_epoch().await? else {
            // No epoch's voting window has closed yet — nothing can finalize.
            ::metrics::gauge!(metrics::METRICS_FINALIZER_EPOCH_LAG).set(0.0);
            return Ok(());
        };
        let mut cursor = self.next_epoch_to_finalize().await?;
        self.record_lag(cursor, closed);

        let mut txs_sent = 0u32;
        while cursor <= closed {
            self.send_finalize_tx(closed).await?;
            txs_sent += 1;
            cursor = self.next_epoch_to_finalize().await?;
        }
        self.record_lag(cursor, closed);

        if txs_sent > 0 {
            tracing::info!(finalized_up_to = closed, txs_sent, "finalization caught up");
        }

        Ok(())
    }

    /// The wall-clock unix timestamp at which `cursor`'s voting window
    /// closes, i.e. when it becomes eligible to finalize.
    ///
    /// Reads `votingWindow` from the *current* timing era (`getTiming`), not
    /// necessarily the era that governs `cursor`'s own window — this only
    /// differs right at a `setTiming` transition boundary. Deliberately not
    /// replicating the contract's era-lookup logic client-side to avoid
    /// duplicating it; [`Self::wait_for_close_confirmed`] is the general
    /// backstop that absorbs this imprecision the same way it absorbs RPC lag.
    pub async fn next_deadline(&self, cursor: u32) -> Result<u64> {
        let end = self.epoch_end(cursor).await?;
        let voting_window = self.voting_window().await?;
        Ok(end + voting_window)
    }

    /// Polls `latest_closed_epoch` every `confirm_retry_interval` until it
    /// covers `cursor`, up to `confirm_max_attempts`. Bridges the short,
    /// expected gap between waking at a computed deadline and the chain
    /// actually reflecting it (RPC lag, clock drift, or the `voting_window`
    /// era-lookup simplification in [`Self::next_deadline`]) — a constant,
    /// not exponential, delay, since this isn't backing off from a failure.
    ///
    /// Exhausting the bound is treated as fatal by the caller (see `run`): it
    /// signals persistent RPC degradation or a systematically wrong
    /// deadline, not routine noise.
    pub async fn wait_for_close_confirmed(&self, cursor: u32) -> Result<()> {
        (|| async {
            match self.latest_closed_epoch().await {
                Ok(Some(closed)) if closed >= cursor => Ok(()),
                Ok(_) => Err(eyre!("epoch {cursor} not yet reflected as closed")),
                Err(err) => Err(err),
            }
        })
        .retry(
            ConstantBuilder::new()
                .with_delay(self.confirm_retry_interval)
                .with_max_times(self.confirm_max_attempts),
        )
        .notify(|_err, _dur| {
            ::metrics::counter!(metrics::METRICS_FINALIZER_CONFIRM_RETRIES).increment(1);
        })
        .sleep(tokio::time::sleep)
        .await
        .wrap_err_with(|| {
            format!(
                "epoch {cursor} still not reflected as closed after {} attempts",
                self.confirm_max_attempts
            )
        })
    }

    /// Logs and counts a non-fatal cycle failure (cursor/deadline read or a
    /// failed `tick`) before the caller retries next cycle from fresh
    /// on-chain state.
    fn count_cycle_failure(&self, err: eyre::Report, context: &'static str) {
        ::metrics::counter!(metrics::METRICS_FINALIZER_TICK_FAILURES).increment(1);
        tracing::error!(error = ?err, "{context}; retrying next cycle");
    }

    /// Send one bounded `finalizeEpochs` transaction and wait for its receipt.
    ///
    /// Submission (like all plain RPC calls) relies on the provider's
    /// per-request timeout and retry budget; only the receipt wait carries a
    /// worker-level deadline, because a transaction that never mines would
    /// otherwise block forever.
    async fn send_finalize_tx(&self, upto_epoch: u32) -> Result<()> {
        let call = self
            .contract
            .finalizeEpochs(upto_epoch, U256::from(self.max_steps_per_tx));

        let pending = match call.send().await {
            Err(err) => {
                self.count_attempt(outcome::RPC_ERROR);
                return Err(err).wrap_err("failed to submit finalizeEpochs transaction");
            }
            Ok(pending) => pending.with_timeout(Some(self.receipt_timeout)),
        };
        let tx_hash = *pending.tx_hash();
        tracing::debug!(%tx_hash, upto_epoch, "finalizeEpochs transaction sent");

        let receipt = match pending.get_receipt().await {
            Err(PendingTransactionError::TxWatcher(WatchTxError::Timeout)) => {
                self.count_attempt(outcome::TIMEOUT);
                return Err(eyre!(
                    "finalizeEpochs receipt for {tx_hash} timed out after {:?}",
                    self.receipt_timeout
                ));
            }
            Err(err) => {
                self.count_attempt(outcome::RPC_ERROR);
                return Err(err).wrap_err_with(|| {
                    format!("failed while waiting for finalizeEpochs receipt of {tx_hash}")
                });
            }
            Ok(receipt) => receipt,
        };

        if !receipt.status() {
            self.count_attempt(outcome::REVERT_ON_CHAIN);
            return Err(eyre!("finalizeEpochs transaction reverted: {tx_hash}"));
        }

        self.count_attempt(outcome::SUCCESS);
        tracing::info!(%tx_hash, upto_epoch, "finalizeEpochs transaction confirmed");
        Ok(())
    }

    async fn latest_closed_epoch(&self) -> Result<Option<u32>> {
        let ret = self
            .contract
            .latestClosedEpoch()
            .call()
            .await
            .wrap_err("failed to read latestClosedEpoch")?;
        Ok(ret.exists.then_some(ret.epoch))
    }

    /// The lowest epoch not yet finalized (the finalization cursor), derived
    /// from the contract's latest-finalized watermark: `latest + 1`, or 0 when
    /// nothing has been finalized yet.
    async fn next_epoch_to_finalize(&self) -> Result<u32> {
        let ret = self
            .contract
            .latestFinalizedEpoch()
            .call()
            .await
            .wrap_err("failed to read latestFinalizedEpoch")?;
        Ok(if ret.exists { ret.epoch + 1 } else { 0 })
    }

    /// The timestamp at which `epoch` ends (and its voting window opens).
    /// Like the other plain reads above, relies on the provider layer's own
    /// per-request timeout/retry budget rather than a manual timeout wrapper.
    async fn epoch_end(&self, epoch: u32) -> Result<u64> {
        self.contract
            .epochEnd(epoch)
            .call()
            .await
            .wrap_err("failed to read epochEnd")
    }

    /// The current timing era's voting window, in seconds.
    async fn voting_window(&self) -> Result<u64> {
        Ok(self
            .contract
            .getTiming()
            .call()
            .await
            .wrap_err("failed to read getTiming")?
            .votingWindow)
    }

    /// Record the finalization backlog: closed-but-unfinalized epochs. 0 means
    /// fully caught up; sustained growth means finalization is falling behind.
    fn record_lag(&self, cursor: u32, closed: u32) {
        let lag = (u64::from(closed) + 1).saturating_sub(u64::from(cursor));
        ::metrics::gauge!(metrics::METRICS_FINALIZER_EPOCH_LAG).set(lag as f64);
    }

    fn count_attempt(&self, outcome: &'static str) {
        ::metrics::counter!(
            metrics::METRICS_FINALIZER_FINALIZE_ATTEMPTS,
            metrics::LABEL_OUTCOME => outcome
        )
        .increment(1);
    }
}

/// How long to sleep before `target_close_unix` (plus `lag`), computed
/// against the current wall clock. Saturates to zero if the target has
/// already passed (an already-closed epoch, e.g. backlog or startup), so the
/// caller's sleep resolves immediately rather than underflowing.
fn sleep_duration(target_close_unix: u64, lag: Duration) -> Result<Duration> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("system clock is before the unix epoch")?
        .as_secs();
    Ok(wait_duration(target_close_unix, now_unix, lag))
}

/// Pure arithmetic behind [`sleep_duration`], split out for unit testing
/// without touching the real clock.
fn wait_duration(target_close_unix: u64, now_unix: u64, lag: Duration) -> Duration {
    Duration::from_secs(target_close_unix.saturating_sub(now_unix)) + lag
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_duration_is_zero_plus_lag_when_target_already_passed() {
        assert_eq!(
            wait_duration(100, 200, Duration::from_secs(3)),
            Duration::from_secs(3)
        );
    }

    #[test]
    fn wait_duration_counts_down_to_target_plus_lag() {
        assert_eq!(
            wait_duration(200, 100, Duration::from_secs(3)),
            Duration::from_secs(103)
        );
    }
}
