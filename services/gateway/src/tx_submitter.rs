//! Transaction submission with gateway-owned nonces.
//!
//! The gateway is the sole submitter for its signer: production provisions one
//! KMS key per replica ordinal, so each replica owns an independent nonce
//! stream and can allocate nonces in-process.
//!
//! Owning the nonce is what makes "retry until it lands" safe. A retained batch
//! is re-broadcast at the *same* nonce with an escalating priority fee until it
//! is mined; re-deriving the nonce from `eth_getTransactionCount(pending)` on a
//! retry could pick a different nonce and execute the same batch twice.
//!
//! Because a reserved nonce blocks every later nonce until it is consumed,
//! every reservation must end in exactly one of two states:
//!
//! - **mined** — a receipt arrived (success or revert; both consume the nonce)
//! - **released** — the batch is abandoned and a minimal self-transfer is sent
//!   at that nonce so the transactions queued behind it become executable
//!
//! Escalation can create its own permanent rejection: each bump raises
//! `max_fee_per_gas * gas_limit`, which eventually exceeds the signer balance or
//! the node's transaction fee cap. Those errors are classified as terminal, so
//! the nonce is released instead of being retried forever.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use alloy::{
    network::{Ethereum, TransactionBuilder},
    primitives::{Address, U256},
    providers::{DynProvider, PendingTransactionBuilder, Provider},
    rpc::types::TransactionRequest,
};
use tokio::{sync::Mutex, time::Instant};
use world_id_primitives::api_types::{GatewayErrorCode, GatewayRequestState};
use world_id_services_common::estimate_gas_with_fallback;

use crate::{RequestTracker, config::TxSubmitterConfig, error::parse_contract_error, metrics};

/// Gas limit of the transaction used to release a nonce. A plain value transfer
/// to self costs nothing beyond the 21k intrinsic gas.
const RELEASE_TX_GAS_LIMIT: u64 = 21_000;

/// Shared in-flight registry, keyed by nonce so the blocking nonce is first.
type Inflight = Arc<Mutex<BTreeMap<u64, InflightTx>>>;

/// Why a reserved nonce was given up on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TerminalReason {
    /// The node rejected the transaction for a reason that will not change.
    PermanentRejection,
    /// The escalation budget was exhausted without the transaction landing.
    EscalationExhausted,
    /// The signer balance is below the configured floor.
    BalanceFloor,
}

impl TerminalReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PermanentRejection => "permanent_rejection",
            Self::EscalationExhausted => "escalation_exhausted",
            Self::BalanceFloor => "balance_floor",
        }
    }
}

/// Whether a send error means the transaction can never be included.
///
/// Only causes that cannot change with time or with a higher fee belong here.
/// Everything else — `already known`, `replacement transaction underpriced`,
/// transport failures, timeouts — is transient and left to the escalation loop.
fn is_permanent_rejection(error: &str) -> bool {
    const PERMANENT: [&str; 6] = [
        "insufficient funds",
        "exceeds block gas limit",
        "oversized data",
        "exceeds the configured cap",
        "intrinsic gas too low",
        "negative value",
    ];
    let lowered = error.to_ascii_lowercase();
    PERMANENT.iter().any(|needle| lowered.contains(needle))
}

/// Whether the node already holds this exact transaction.
///
/// Not a failure: the transaction is in the pool, so the nonce is occupied and
/// must not be released.
fn is_already_known(error: &str) -> bool {
    let lowered = error.to_ascii_lowercase();
    lowered.contains("already known") || lowered.contains("already imported")
}

/// Whether the nonce has already been consumed by some other transaction.
fn is_nonce_too_low(error: &str) -> bool {
    error.to_ascii_lowercase().contains("nonce too low")
}

/// A batch transaction that has been broadcast but not yet mined.
struct InflightTx {
    /// Fully populated request; escalation rewrites only the fee fields.
    request: TransactionRequest,
    /// Gateway request ids carried by this batch.
    ids: Vec<String>,
    batch_type: &'static str,
    /// Priority fee of the most recent broadcast.
    priority_fee: u128,
    /// Number of escalations performed so far.
    escalations: u32,
    /// When the most recent broadcast happened.
    last_sent_at: Instant,
    /// When the batch was first submitted, for end-to-end latency.
    submitted_at: Instant,
}

/// Owns the signer's nonce stream and every unconfirmed batch transaction.
pub struct TxSubmitter {
    provider: Arc<DynProvider>,
    signer: Address,
    config: TxSubmitterConfig,
    tracker: RequestTracker,
    /// Next nonce to hand out. Seeded from the pending count, then owned here.
    next_nonce: AtomicU64,
    inflight: Inflight,
}

impl TxSubmitter {
    /// Creates a submitter and seeds the nonce counter.
    ///
    /// Seeded from the *pending* count rather than `latest`, so a replica that
    /// restarts while its own earlier transactions are still in the mempool
    /// does not hand out a nonce that collides with them.
    ///
    /// # Errors
    ///
    /// Returns the transport error if the initial transaction count cannot be
    /// read — the gateway cannot submit anything without it.
    pub async fn new(
        provider: Arc<DynProvider>,
        signer: Address,
        config: TxSubmitterConfig,
        tracker: RequestTracker,
    ) -> Result<Self, alloy::transports::TransportError> {
        let seed = provider.get_transaction_count(signer).pending().await?;

        tracing::info!(
            signer = %signer,
            seed_nonce = seed,
            "tx submitter seeded nonce counter from pending transaction count"
        );

        Ok(Self {
            provider,
            signer,
            config,
            tracker,
            next_nonce: AtomicU64::new(seed),
            inflight: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    /// Whether another batch may be submitted right now.
    ///
    /// Checked before a batch is drained from the policy queue, so a refused
    /// batch is never lost. Two conditions gate submission: the in-flight cap,
    /// which bounds how much piles up behind a nonce that is not progressing,
    /// and the balance floor, so escalation cannot drain the signer.
    pub async fn can_submit(&self) -> bool {
        let inflight = self.inflight.lock().await.len();
        metrics::set_nonce_inflight(inflight);

        // A cap of 0 disables the check.
        if self.config.max_inflight_txs > 0 && inflight >= self.config.max_inflight_txs {
            tracing::warn!(
                inflight,
                max_inflight_txs = self.config.max_inflight_txs,
                "in-flight transaction cap reached, applying backpressure"
            );
            metrics::record_inflight_cap_reached();
            return false;
        }

        self.has_sufficient_balance().await
    }

    /// Reads the signer balance and compares it against the configured floor.
    ///
    /// An RPC failure counts as sufficient: refusing to submit because a
    /// balance read failed would turn a telemetry problem into an outage. The
    /// gauge goes stale instead, and the RPC error metrics fire.
    async fn has_sufficient_balance(&self) -> bool {
        match self.provider.get_balance(self.signer).await {
            Ok(balance) => {
                metrics::set_signer_balance_wei(f64::from(balance));
                if balance < U256::from(self.config.min_balance_wei) {
                    tracing::error!(
                        signer = %self.signer,
                        balance = %balance,
                        min_balance_wei = self.config.min_balance_wei,
                        "signer balance below floor, refusing to submit transactions"
                    );
                    metrics::record_balance_floor_hit();
                    return false;
                }
                true
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to read signer balance");
                true
            }
        }
    }

    /// Submits a batch transaction at a gateway-owned nonce.
    ///
    /// Sets `nonce`, `gas_limit` and both fee fields explicitly. That is
    /// required rather than cosmetic: alloy's `GasFiller` overwrites both fee
    /// fields unless `gas_limit` is also set, which would make the fee used on a
    /// re-broadcast unpredictable and could fail to clear the replacement price
    /// bump.
    ///
    /// Both estimation calls happen *before* a nonce is reserved, so an
    /// estimation failure can never consume one — the failure mode behind
    /// PROTO-4494.
    pub async fn submit(
        &self,
        mut request: TransactionRequest,
        ids: Vec<String>,
        batch_type: &'static str,
        submitted_at: Instant,
    ) {
        request.set_from(self.signer);

        let gas_limit =
            match estimate_gas_with_fallback(self.provider.as_ref(), request.clone()).await {
                Ok(gas_limit) => gas_limit,
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        batch_type,
                        "gas estimation failed with a transport error, dropping batch"
                    );
                    metrics::record_batch_send_failed(batch_type, 0.0);
                    self.fail_requests(&ids, &format!("gas estimation failed: {err}"))
                        .await;
                    return;
                }
            };

        let fees = match self.provider.estimate_eip1559_fees().await {
            Ok(fees) => fees,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    batch_type,
                    "fee estimation failed, dropping batch"
                );
                metrics::record_batch_send_failed(batch_type, 0.0);
                self.fail_requests(&ids, &format!("fee estimation failed: {err}"))
                    .await;
                return;
            }
        };

        request.set_gas_limit(gas_limit);
        request.set_max_fee_per_gas(fees.max_fee_per_gas);
        request.set_max_priority_fee_per_gas(fees.max_priority_fee_per_gas);

        let nonce = self.next_nonce.fetch_add(1, Ordering::SeqCst);
        request.set_nonce(nonce);
        metrics::set_nonce_owned(nonce);

        let send_started = Instant::now();
        let result = self.provider.send_transaction(request.clone()).await;

        let entry = InflightTx {
            request,
            ids: ids.clone(),
            batch_type,
            priority_fee: fees.max_priority_fee_per_gas,
            escalations: 0,
            last_sent_at: Instant::now(),
            submitted_at,
        };

        match result {
            Ok(pending) => {
                let send_latency_ms = send_started.elapsed().as_millis() as f64;
                metrics::record_batch_send_latency(batch_type, send_latency_ms);

                let tx_hash = format!("0x{:x}", pending.tx_hash());
                tracing::info!(
                    tx_hash = %tx_hash,
                    batch_type,
                    nonce,
                    batch_size = ids.len(),
                    send_latency_ms,
                    "batch transaction submitted to RPC node"
                );

                self.tracker
                    .set_status_batch(
                        &ids,
                        GatewayRequestState::Submitted {
                            tx_hash: tx_hash.clone(),
                        },
                    )
                    .await;

                self.inflight.lock().await.insert(nonce, entry);
                spawn_receipt_watch(
                    Arc::clone(&self.inflight),
                    self.tracker.clone(),
                    nonce,
                    pending,
                    tx_hash,
                    batch_type,
                    submitted_at,
                );
            }
            Err(err) => {
                let send_latency_ms = send_started.elapsed().as_millis() as f64;
                metrics::record_batch_send_failed(batch_type, send_latency_ms);
                let error_str = err.to_string();

                if is_already_known(&error_str) {
                    // The node holds this exact transaction. The nonce is
                    // occupied, so keep it in flight and let the escalation
                    // loop drive it to a receipt.
                    tracing::warn!(
                        batch_type,
                        nonce,
                        "node reports transaction already known, retaining nonce"
                    );
                    self.inflight.lock().await.insert(nonce, entry);
                    return;
                }

                tracing::error!(
                    error = %error_str,
                    batch_type,
                    nonce,
                    send_latency_ms,
                    "{batch_type} batch failed to submit to RPC node"
                );

                let code = parse_contract_error(&error_str);
                self.tracker
                    .set_status_batch(
                        &ids,
                        GatewayRequestState::failed(error_str.clone(), Some(code)),
                    )
                    .await;

                if is_nonce_too_low(&error_str) {
                    // Something else consumed this nonce; nothing to release.
                    return;
                }

                // The node never accepted the transaction, so this nonce is
                // unoccupied — but later nonces have already been handed out,
                // so it still has to be filled.
                self.release_nonce(
                    nonce,
                    fees.max_priority_fee_per_gas,
                    TerminalReason::PermanentRejection,
                )
                .await;
            }
        }
    }

    /// Marks a batch's requests as failed.
    async fn fail_requests(&self, ids: &[String], reason: &str) {
        self.tracker
            .set_status_batch(
                ids,
                GatewayRequestState::failed(
                    reason.to_owned(),
                    Some(GatewayErrorCode::InternalServerError),
                ),
            )
            .await;
    }

    /// One escalation pass over the in-flight set.
    ///
    /// Public so tests can drive it directly without managing task lifetime,
    /// mirroring [`crate::orphan_sweeper::sweep_once`].
    pub async fn escalate_once(&self) {
        let latest = match self.provider.get_transaction_count(self.signer).await {
            Ok(latest) => latest,
            Err(err) => {
                tracing::warn!(error = %err, "escalation: failed to read latest nonce, skipping pass");
                return;
            }
        };
        metrics::set_nonce_latest(latest);

        let due: Vec<u64> = {
            let inflight = self.inflight.lock().await;
            metrics::set_nonce_inflight(inflight.len());
            inflight
                .iter()
                .filter(|(nonce, tx)| {
                    **nonce >= latest
                        && tx.last_sent_at.elapsed()
                            >= Duration::from_secs(self.config.escalation_interval_secs)
                })
                .map(|(nonce, _)| *nonce)
                .collect()
        };

        // Entries below `latest` were mined; the receipt watcher finalizes them
        // and removes them. Nothing to do here.
        for nonce in due {
            self.escalate_one(nonce).await;
        }
    }

    /// Re-broadcasts a single in-flight transaction at its original nonce with a
    /// higher priority fee, or gives up and releases the nonce.
    async fn escalate_one(&self, nonce: u64) {
        let Some((mut request, batch_type, ids, escalations, prev_priority_fee, submitted_at)) = ({
            let inflight = self.inflight.lock().await;
            inflight.get(&nonce).map(|tx| {
                (
                    tx.request.clone(),
                    tx.batch_type,
                    tx.ids.clone(),
                    tx.escalations,
                    tx.priority_fee,
                    tx.submitted_at,
                )
            })
        }) else {
            return;
        };

        if escalations >= self.config.max_escalations {
            self.go_terminal(
                nonce,
                prev_priority_fee,
                TerminalReason::EscalationExhausted,
            )
            .await;
            return;
        }

        if !self.has_sufficient_balance().await {
            self.go_terminal(nonce, prev_priority_fee, TerminalReason::BalanceFloor)
                .await;
            return;
        }

        let fees = match self.provider.estimate_eip1559_fees().await {
            Ok(fees) => fees,
            Err(err) => {
                tracing::warn!(error = %err, nonce, "escalation: fee estimation failed, retrying next pass");
                return;
            }
        };

        // Bump the priority fee, and keep the base-fee component of the fresh
        // estimate rather than compounding it, so `max_fee * gas_limit` does not
        // inflate faster than necessary and walk into `insufficient funds`.
        let priority_fee = prev_priority_fee
            .saturating_mul(u128::from(self.config.escalation_factor_percent))
            / 100;
        let priority_fee = priority_fee.max(fees.max_priority_fee_per_gas);
        let base_component = fees
            .max_fee_per_gas
            .saturating_sub(fees.max_priority_fee_per_gas);
        let max_fee = base_component.saturating_add(priority_fee);

        request.set_max_priority_fee_per_gas(priority_fee);
        request.set_max_fee_per_gas(max_fee);

        tracing::warn!(
            nonce,
            batch_type,
            escalation = escalations + 1,
            priority_fee,
            max_fee,
            age_secs = submitted_at.elapsed().as_secs(),
            "escalating unconfirmed batch transaction"
        );

        match self.provider.send_transaction(request.clone()).await {
            Ok(pending) => {
                let tx_hash = format!("0x{:x}", pending.tx_hash());
                metrics::record_escalation(batch_type, "sent");

                self.tracker
                    .set_status_batch(
                        &ids,
                        GatewayRequestState::Submitted {
                            tx_hash: tx_hash.clone(),
                        },
                    )
                    .await;

                if let Some(tx) = self.inflight.lock().await.get_mut(&nonce) {
                    tx.request = request;
                    tx.priority_fee = priority_fee;
                    tx.escalations += 1;
                    tx.last_sent_at = Instant::now();
                }

                spawn_receipt_watch(
                    Arc::clone(&self.inflight),
                    self.tracker.clone(),
                    nonce,
                    pending,
                    tx_hash,
                    batch_type,
                    submitted_at,
                );
            }
            Err(err) => {
                let error_str = err.to_string();

                if is_already_known(&error_str) || is_nonce_too_low(&error_str) {
                    // Either the replacement is redundant or the nonce is gone.
                    // Both resolve on their own; do not burn an escalation.
                    tracing::info!(
                        nonce,
                        error = %error_str,
                        "escalation: no-op response from node"
                    );
                    return;
                }

                metrics::record_escalation(batch_type, "failed");

                if is_permanent_rejection(&error_str) {
                    tracing::error!(
                        error = %error_str,
                        nonce,
                        batch_type,
                        "escalation hit a permanent rejection, releasing nonce"
                    );
                    self.go_terminal(nonce, prev_priority_fee, TerminalReason::PermanentRejection)
                        .await;
                    return;
                }

                tracing::warn!(
                    error = %error_str,
                    nonce,
                    batch_type,
                    "escalation send failed, retrying next pass"
                );

                if let Some(tx) = self.inflight.lock().await.get_mut(&nonce) {
                    tx.escalations += 1;
                    tx.last_sent_at = Instant::now();
                }
            }
        }
    }

    /// Abandons the batch at `nonce`: fails its requests, then releases the
    /// nonce so later transactions become executable.
    async fn go_terminal(&self, nonce: u64, priority_fee: u128, reason: TerminalReason) {
        let Some(tx) = self.inflight.lock().await.remove(&nonce) else {
            return;
        };

        tracing::error!(
            nonce,
            batch_type = tx.batch_type,
            reason = reason.as_str(),
            escalations = tx.escalations,
            request_count = tx.ids.len(),
            age_secs = tx.submitted_at.elapsed().as_secs(),
            "abandoning batch transaction, requests will be failed"
        );
        metrics::record_terminal(tx.batch_type, reason.as_str());

        self.tracker
            .set_status_batch(
                &tx.ids,
                GatewayRequestState::failed(
                    format!(
                        "transaction abandoned after {} escalation(s) ({})",
                        tx.escalations,
                        reason.as_str()
                    ),
                    Some(GatewayErrorCode::ConfirmationError),
                ),
            )
            .await;

        self.release_nonce(nonce, priority_fee, reason).await;
    }

    /// Sends a minimal self-transfer at `nonce` so transactions queued behind it
    /// become executable.
    ///
    /// The replacement price bump is cleared by doubling the priority fee of the
    /// transaction being displaced. If the nonce was never occupied — a send the
    /// node rejected outright — there is nothing to replace and the transfer
    /// simply lands.
    async fn release_nonce(
        &self,
        nonce: u64,
        displaced_priority_fee: u128,
        reason: TerminalReason,
    ) {
        match self.provider.get_transaction_count(self.signer).await {
            Ok(latest) if latest > nonce => {
                tracing::info!(
                    nonce,
                    latest,
                    "nonce already consumed on-chain, no release needed"
                );
                metrics::record_nonce_release("already_consumed");
                return;
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err, nonce, "failed to read latest nonce before release");
                metrics::record_nonce_release("rpc_error");
                return;
            }
        }

        let fees = match self.provider.estimate_eip1559_fees().await {
            Ok(fees) => fees,
            Err(err) => {
                tracing::error!(error = %err, nonce, "failed to estimate fees for nonce release");
                metrics::record_nonce_release("fee_estimation_failed");
                return;
            }
        };

        let priority_fee = displaced_priority_fee
            .saturating_mul(2)
            .max(fees.max_priority_fee_per_gas);
        let base_component = fees
            .max_fee_per_gas
            .saturating_sub(fees.max_priority_fee_per_gas);
        let max_fee = base_component.saturating_add(priority_fee);

        let request = TransactionRequest::default()
            .with_from(self.signer)
            .with_to(self.signer)
            .with_value(U256::ZERO)
            .with_nonce(nonce)
            .with_gas_limit(RELEASE_TX_GAS_LIMIT)
            .with_max_fee_per_gas(max_fee)
            .with_max_priority_fee_per_gas(priority_fee);

        tracing::warn!(
            nonce,
            reason = reason.as_str(),
            priority_fee,
            "releasing blocked nonce with a self-transfer"
        );

        match self.provider.send_transaction(request).await {
            Ok(pending) => {
                tracing::warn!(
                    nonce,
                    reason = reason.as_str(),
                    tx_hash = %format!("0x{:x}", pending.tx_hash()),
                    "nonce release transaction submitted"
                );
                metrics::record_nonce_release("sent");
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    nonce,
                    reason = reason.as_str(),
                    "nonce release transaction failed to submit, submission remains blocked"
                );
                metrics::record_nonce_release("failed");
            }
        }
    }
}

/// Watches for a receipt and drops the in-flight entry once the nonce is
/// consumed. A revert consumes the nonce just as a success does.
///
/// A watcher that ends without a receipt is not terminal: the escalation loop
/// still owns the nonce and will re-broadcast or release it.
fn spawn_receipt_watch(
    inflight: Inflight,
    tracker: RequestTracker,
    nonce: u64,
    pending: PendingTransactionBuilder<Ethereum>,
    tx_hash: String,
    batch_type: &'static str,
    submitted_at: Instant,
) {
    tokio::spawn(async move {
        match pending.get_receipt().await {
            Ok(receipt) => {
                let confirmed = receipt.status();
                let latency_ms = submitted_at.elapsed().as_millis() as f64;
                metrics::record_batch_confirmed(batch_type, confirmed, latency_ms);

                if confirmed {
                    tracing::info!(
                        tx_hash = %tx_hash,
                        batch_type,
                        nonce,
                        latency_ms,
                        "batch transaction confirmed on-chain"
                    );
                } else {
                    tracing::error!(
                        tx_hash = %tx_hash,
                        batch_type,
                        nonce,
                        "batch transaction reverted on-chain"
                    );
                }

                let ids = inflight.lock().await.remove(&nonce).map(|tx| tx.ids);
                if let Some(ids) = ids {
                    tracker
                        .finalize_from_receipt(&ids, confirmed, &tx_hash)
                        .await;
                }
            }
            Err(err) => {
                tracing::warn!(
                    tx_hash = %tx_hash,
                    batch_type,
                    nonce,
                    error = %err,
                    "receipt watch ended without a receipt, escalation loop retains the nonce"
                );
            }
        }
    });
}

/// Runs the escalation loop indefinitely.
pub async fn run_escalation_loop(submitter: Arc<TxSubmitter>) {
    let interval = Duration::from_secs(submitter.config.escalation_interval_secs);
    loop {
        tokio::time::sleep(interval).await;
        submitter.escalate_once().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_rejections_are_classified() {
        assert!(is_permanent_rejection(
            "insufficient funds for gas * price + value"
        ));
        assert!(is_permanent_rejection("exceeds block gas limit"));
        assert!(is_permanent_rejection("oversized data"));
        assert!(is_permanent_rejection(
            "tx fee (2.10 ether) exceeds the configured cap (1.00 ether)"
        ));
        assert!(is_permanent_rejection("intrinsic gas too low"));
    }

    #[test]
    fn transient_errors_are_not_permanent() {
        assert!(!is_permanent_rejection(
            "replacement transaction underpriced"
        ));
        assert!(!is_permanent_rejection("already known"));
        assert!(!is_permanent_rejection(
            "nonce too low: next nonce 82, tx nonce 81"
        ));
        assert!(!is_permanent_rejection("request timed out"));
        assert!(!is_permanent_rejection("connection reset by peer"));
    }

    #[test]
    fn already_known_and_nonce_too_low_are_recognised() {
        assert!(is_already_known("already known"));
        assert!(is_already_known("Transaction ALREADY IMPORTED"));
        assert!(!is_already_known("replacement transaction underpriced"));

        assert!(is_nonce_too_low(
            "nonce too low: next nonce 82, tx nonce 81"
        ));
        assert!(!is_nonce_too_low("already known"));
    }

    #[test]
    fn terminal_reason_labels_are_stable() {
        assert_eq!(
            TerminalReason::PermanentRejection.as_str(),
            "permanent_rejection"
        );
        assert_eq!(
            TerminalReason::EscalationExhausted.as_str(),
            "escalation_exhausted"
        );
        assert_eq!(TerminalReason::BalanceFloor.as_str(), "balance_floor");
    }
}
