//! Durable wallet leasing, transaction broadcast and receipt resolution.
//!
//! One transaction per wallet at a time. A batch is signed, committed to
//! [`WalletStore`] and only then broadcast; the wallet stays out of the pool
//! until the transaction's fate is known. The committed record is what makes
//! that survive a restart, and the stored signed bytes are what let an
//! ambiguous broadcast be retried with identical input instead of guessed at.
//!
//! This replaces the per-batch receipt task. Receipt polling for requests that
//! a wallet record owns now happens here; the orphan sweeper keeps only the
//! requests no wallet record owns.
//!
//! See `WALLET_POOL_PLAN.md` §5.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use alloy::{
    consensus::Transaction as _,
    eips::eip2718::Encodable2718,
    primitives::{Address, Bytes, TxHash},
    providers::{DynProvider, Provider},
    rpc::types::{TransactionReceipt, TransactionRequest},
};
use futures::StreamExt as _;
use tokio::sync::Notify;
use uuid::Uuid;
use world_id_primitives::api_types::{GatewayErrorCode, GatewayRequestState};
use world_id_services_common::ProviderWallet;

use crate::{
    batch_policy::BacklogUrgencyStats,
    batch_type::BatchType,
    config::WalletConfig,
    error::{GatewayError, GatewayResult},
    metrics,
    request_tracker::{BacklogScope, RequestTracker, now_unix_secs},
    storage::{
        request_store::{StatusGuard, StatusWriteOutcome},
        wallet_store::{CasOutcome, Submission, WalletRecord, WalletState, WalletStore},
    },
};

/// Wallets probed concurrently by one resolver pass, so a single slow RPC
/// cannot stall resolution of the rest of the pool.
const RESOLVER_CONCURRENCY: usize = 4;

/// What the resolver learned about one outstanding transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe {
    /// No definitive answer yet.
    Wait,
    /// The transaction is on chain, with a canonical receipt.
    Included {
        /// Whether the transaction succeeded rather than reverted.
        success: bool,
        /// Blocks mined on top of the inclusion block.
        confirmations: u64,
    },
    /// The nonce was consumed by a different transaction, so ours will not land.
    Replaced,
    /// The transaction is in no mempool and its nonce is untouched.
    Absent,
}

/// Whether a batch may be broadcast after its requests were guarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BroadcastGuard {
    /// The requests were still awaiting submission, so the transaction may be sent.
    Proceed,
    /// Another owner resolved the requests, so the transaction must be discarded.
    Abandon,
}

/// Result of one submission attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubmitOutcome {
    /// The transaction was committed and a broadcast was attempted.
    Submitted,
    /// No wallet became available in time. Nothing was changed, so the caller
    /// should retry the batch rather than fail its requests.
    NoWalletAvailable,
}

/// A configured wallet and the provider stack that signs and sends for it.
#[derive(Clone)]
struct WalletEntry {
    wallet: ProviderWallet,
}

/// Signs, commits, broadcasts and resolves one transaction per wallet at a time.
pub(crate) struct TransactionSubmitter {
    wallets: Vec<WalletEntry>,
    /// Indices into `wallets` that may be handed out for new work.
    ///
    /// A draining wallet is deliberately still in `wallets` so the resolver
    /// keeps deciding its outstanding transaction, but it is never acquired.
    acquirable: Vec<usize>,
    /// Read-only providers, one per configured RPC URL.
    ///
    /// A resolver pass is pinned to a single one, because the provider fans
    /// every call out across all URLs: a receipt, a block and a nonce answered
    /// by different nodes would make "the nonce is mined but the transaction is
    /// not" an unsound conclusion. Passes rotate, so a failing endpoint costs
    /// one pass rather than stalling resolution.
    resolver_providers: Vec<DynProvider>,
    wallet_store: WalletStore,
    tracker: RequestTracker,
    config: WalletConfig,
    next_wallet: AtomicUsize,
    resolver_pass: AtomicUsize,
    wallet_released: Notify,
}

impl TransactionSubmitter {
    /// Connects to Redis and prepares the wallet pool.
    ///
    /// # Errors
    ///
    /// Returns an error when no wallet is configured, when two wallets share an
    /// address, when a drained address is not configured, when every configured
    /// wallet is draining, or when Redis cannot be reached.
    pub(crate) async fn connect(
        wallets: Vec<ProviderWallet>,
        resolver_providers: Vec<DynProvider>,
        tracker: RequestTracker,
        redis_url: &str,
        config: WalletConfig,
    ) -> GatewayResult<Arc<Self>> {
        if resolver_providers.is_empty() {
            return Err(GatewayError::Config(
                "at least one RPC endpoint is required to resolve wallet transactions".to_string(),
            ));
        }

        if wallets.is_empty() {
            return Err(GatewayError::Config(
                "at least one transaction wallet must be configured".to_string(),
            ));
        }

        let unique: std::collections::HashSet<Address> =
            wallets.iter().map(|wallet| wallet.address).collect();
        if unique.len() != wallets.len() {
            return Err(GatewayError::Config(
                "transaction wallet addresses must be unique; two wallets would share a nonce stream"
                    .to_string(),
            ));
        }

        // A drained address that is not configured is a typo, and silently
        // ignoring it would leave a wallet in service that the operator
        // believed was retired.
        for address in &config.draining_addresses {
            if !unique.contains(address) {
                return Err(GatewayError::Config(format!(
                    "WALLET_DRAINING_ADDRESSES names {address}, which is not a configured wallet"
                )));
            }
        }

        let acquirable: Vec<usize> = wallets
            .iter()
            .enumerate()
            .filter(|(_, wallet)| !config.draining_addresses.contains(&wallet.address))
            .map(|(index, _)| index)
            .collect();

        if acquirable.is_empty() {
            return Err(GatewayError::Config(
                "every configured wallet is draining, so no batch could ever be submitted"
                    .to_string(),
            ));
        }

        metrics::record_wallet_pool_size(wallets.len());
        if !config.draining_addresses.is_empty() {
            tracing::info!(
                draining = config.draining_addresses.len(),
                acquirable = acquirable.len(),
                "wallet pool prepared with draining wallets; they are resolved but not reused"
            );
        }

        let wallets = wallets
            .into_iter()
            .map(|wallet| WalletEntry { wallet })
            .collect();

        Ok(Arc::new(Self {
            wallets,
            acquirable,
            resolver_providers,
            wallet_store: WalletStore::connect(redis_url).await?,
            tracker,
            config,
            next_wallet: AtomicUsize::new(0),
            resolver_pass: AtomicUsize::new(0),
            wallet_released: Notify::new(),
        }))
    }

    /// Number of configured wallets, including draining ones.
    #[must_use]
    pub(crate) fn pool_size(&self) -> usize {
        self.wallets.len()
    }

    /// Number of wallets currently available for new work.
    #[must_use]
    pub(crate) fn acquirable_size(&self) -> usize {
        self.acquirable.len()
    }

    /// Signs, durably records and broadcasts one batch transaction.
    ///
    /// An `Ok` return means the transaction was committed to Redis and a
    /// broadcast was attempted; it does not mean the transaction was accepted
    /// by the node, because that outcome is ambiguous and is resolved by the
    /// background resolver instead.
    ///
    /// # Errors
    ///
    /// Returns an error when no wallet became available, when signing failed,
    /// or when the transaction could not be committed before broadcast. In the
    /// last two cases nothing was broadcast, so the wallet is immediately
    /// reusable.
    pub(crate) async fn submit(
        &self,
        transaction: TransactionRequest,
        request_ids: Vec<String>,
        batch_type: BatchType,
    ) -> GatewayResult<SubmitOutcome> {
        let Some((entry, lease_id)) = self.acquire().await? else {
            // Capacity, not failure: the batch is untouched and stays queued.
            return Ok(SubmitOutcome::NoWalletAvailable);
        };
        let wallet = entry.wallet.address;

        let sign_started = tokio::time::Instant::now();
        let signed = match entry.wallet.sign_transaction(transaction).await {
            Ok(signed) => signed,
            Err(error) => {
                self.release_lease(wallet, lease_id).await;
                return Err(GatewayError::Submission(format!("signing failed: {error}")));
            }
        };
        let sign_latency_ms = sign_started.elapsed().as_secs_f64() * 1000.0;

        let submission = Submission {
            nonce: signed.nonce(),
            tx_hash: *signed.tx_hash(),
            raw_tx: Some(Bytes::from(signed.encoded_2718())),
            request_ids: request_ids.clone(),
            batch_type,
            submitted_at: now_unix_secs(),
            last_attempt_at: 0,
            attempts: 0,
        };
        let tx_hash = submission.tx_hash;
        let formatted_tx_hash = format!("0x{tx_hash:x}");

        // Write-ahead commit. A conflict means the signing lease was lost, so
        // the signature must be discarded rather than broadcast: broadcasting
        // now could collide with whoever holds the wallet.
        match self
            .wallet_store
            .mark_in_flight(wallet, lease_id, submission, self.state_ttl())
            .await
        {
            Ok(CasOutcome::Applied) => {}
            Ok(outcome) => {
                tracing::error!(
                    %wallet, ?outcome, %batch_type,
                    "wallet lease lost before the transaction could be committed; discarding signature"
                );
                return Err(GatewayError::Submission(
                    "wallet lease lost before broadcast".to_string(),
                ));
            }
            Err(error) => {
                // A connection can fail after the script applied. Treat a record
                // that is ours as committed, or the requests would be failed
                // while the resolver could still find the record and broadcast
                // the transaction.
                if !self.wallet_record_is_ours(wallet, lease_id).await {
                    tracing::error!(
                        %error, %wallet, %batch_type,
                        "failed to commit signed transaction"
                    );
                    return Err(error);
                }
                tracing::warn!(
                    %error, %wallet, %batch_type,
                    "commit reported an error but the record is present; continuing"
                );
            }
        }

        if self
            .guard_broadcast(&request_ids, tx_hash, wallet)
            .await
            .is_abandon()
        {
            // Nothing was broadcast, so the nonce is untouched and the wallet is
            // safe to reuse immediately.
            self.release_lease(wallet, lease_id).await;
            return Err(GatewayError::Submission(
                "requests were resolved by another owner before broadcast".to_string(),
            ));
        }

        tracing::info!(
            tx_hash = %formatted_tx_hash,
            %wallet,
            %batch_type,
            batch_size = request_ids.len(),
            sign_latency_ms,
            "batch transaction committed before broadcast"
        );

        let send_started = tokio::time::Instant::now();
        match entry.wallet.provider.send_tx_envelope(signed).await {
            Ok(_) => {
                let send_latency_ms = send_started.elapsed().as_secs_f64() * 1000.0;
                metrics::record_batch_send_latency(batch_type.as_str(), send_latency_ms);
                tracing::info!(
                    tx_hash = %formatted_tx_hash,
                    %wallet,
                    %batch_type,
                    send_latency_ms,
                    "batch transaction broadcast to the RPC node"
                );
            }
            Err(error) => {
                // The RPC outcome is ambiguous: the transaction may be in the
                // mempool even though the call failed. The record is kept and
                // the resolver decides, rather than guessing here.
                let send_latency_ms = send_started.elapsed().as_secs_f64() * 1000.0;
                metrics::record_batch_send_failed(batch_type.as_str(), send_latency_ms);
                tracing::warn!(
                    %error,
                    tx_hash = %formatted_tx_hash,
                    %wallet,
                    %batch_type,
                    "broadcast failed after the transaction was committed; the resolver will decide its fate"
                );
            }
        }

        self.record_attempt(wallet, lease_id).await;
        Ok(SubmitOutcome::Submitted)
    }

    /// Marks a batch as owned by a batcher.
    ///
    /// Guarded on `Queued` and applied per request, so a batch that is
    /// re-dispatched after waiting for a wallet does not refresh the age the
    /// orphan sweeper uses to decide whether a request was abandoned.
    pub(crate) async fn mark_batching(&self, ids: &[String]) {
        for id in ids {
            let result = self
                .tracker
                .set_status_if(
                    id,
                    &[StatusGuard::Queued],
                    GatewayRequestState::Batching,
                    None,
                )
                .await;
            if let Err(error) = result {
                tracing::warn!(%error, %id, "failed to mark a request as batching");
            }
        }
    }

    /// Writes a status for several requests without a guard.
    ///
    /// Used only where this process is the sole owner: failures detected before
    /// any transaction exists.
    pub(crate) async fn set_status_batch(&self, ids: &[String], status: GatewayRequestState) {
        self.tracker.set_status_batch(ids, status).await;
    }

    /// Queued-backlog urgency for one batch stream, from the shared request store.
    ///
    /// # Errors
    ///
    /// Returns an error when the request store cannot be read.
    pub(crate) async fn queued_backlog_stats(
        &self,
        scope: BacklogScope,
    ) -> GatewayResult<BacklogUrgencyStats> {
        self.tracker.queued_backlog_stats_for_scope(scope).await
    }

    /// Runs the resolution loop until the process exits.
    ///
    /// Errors are handled per wallet and per pass: the loop never returns an
    /// error, because a supervisor that treats an unexpected task exit as fatal
    /// would turn a Redis or RPC blip into a fleet-wide restart.
    pub(crate) async fn run_resolver(self: Arc<Self>) {
        let interval = Duration::from_secs(self.config.tracker_interval_secs);
        loop {
            self.resolve_all().await;
            tokio::time::sleep(interval).await;
        }
    }

    /// One resolution pass over every configured wallet.
    pub(crate) async fn resolve_all(&self) {
        let addresses: Vec<Address> = self
            .wallets
            .iter()
            .map(|entry| entry.wallet.address)
            .collect();

        let records = match self.wallet_store.get_many(&addresses).await {
            Ok(records) => records,
            Err(error) => {
                metrics::increment_wallet_tracker_error();
                tracing::error!(%error, "failed to load wallet records");
                return;
            }
        };

        let in_flight = records
            .iter()
            .flatten()
            .filter(|record| record.state == WalletState::InFlight)
            .count();
        let parked = records
            .iter()
            .flatten()
            .filter(|record| record.state == WalletState::Parked)
            .count();
        metrics::record_wallet_pool_state(in_flight, parked);

        let active: Vec<(usize, WalletRecord)> = records
            .into_iter()
            .enumerate()
            .filter_map(|(index, record)| record.map(|record| (index, record)))
            .filter(|(_, record)| record.state != WalletState::Signing)
            .collect();

        // One provider for the whole pass, so every read it makes is answered by
        // the same node.
        let pass = self.resolver_pass.fetch_add(1, Ordering::Relaxed);
        let provider = self.resolver_providers[pass % self.resolver_providers.len()].clone();

        futures::stream::iter(active)
            .map(|(index, record)| {
                let provider = provider.clone();
                async move {
                    self.resolve_wallet(index, &record, &provider).await;
                }
            })
            .buffer_unordered(RESOLVER_CONCURRENCY)
            .collect::<Vec<()>>()
            .await;
    }

    /// Resolves one wallet record.
    ///
    /// A `Signing` record is skipped: its lease carries a short TTL and nothing
    /// has been broadcast, so the TTL expiring is the correct reclamation path.
    async fn resolve_wallet(&self, index: usize, record: &WalletRecord, provider: &DynProvider) {
        let Some(entry) = self.wallets.get(index) else {
            return;
        };
        let wallet = entry.wallet.address;
        let lease_id = record.lease_id;

        let Some(submission) = record.submission() else {
            tracing::error!(
                %wallet,
                "wallet record has no signed transaction; it cannot be resolved automatically"
            );
            return;
        };

        // Keep the record alive while we are still deciding its fate.
        if let Err(error) = self
            .wallet_store
            .touch(wallet, lease_id, self.state_ttl())
            .await
        {
            tracing::warn!(%error, %wallet, "failed to refresh wallet record lifetime");
        }

        let age = now_unix_secs().saturating_sub(submission.submitted_at);
        let parked = record.state == WalletState::Parked;

        // Nothing may be touched while a submitter could still be inside its own
        // sign/commit/guard sequence. Adopting its requests there would flip them
        // out from under the guard that authorises its broadcast, and it would
        // abandon a batch it was about to send.
        if !parked && age < self.config.first_probe_delay_secs {
            return;
        }

        // Adopt the requests. By now no submitter is mid-sequence, so a batch
        // still in `Batching` was left behind by a process that died between
        // committing the record and writing the statuses.
        if !parked {
            self.adopt_requests(wallet, submission).await;
        }

        match self.probe(entry, submission, provider).await {
            Probe::Wait => {}
            Probe::Included {
                success,
                confirmations,
            } => {
                self.settle(entry, record, submission, success, confirmations)
                    .await;
                // Resolved: the record is released or retried on its own terms.
                // Falling through to the timeout check below would park a wallet
                // whose transaction is already accounted for.
                return;
            }
            Probe::Replaced => {
                tracing::error!(
                    wallet = %wallet,
                    tx_hash = %format!("0x{:x}", submission.tx_hash),
                    nonce = submission.nonce,
                    "wallet transaction was replaced; its requests cannot be confirmed"
                );
                self.fail_replaced(entry, record, submission).await;
                return;
            }
            Probe::Absent => {
                if !parked {
                    self.rebroadcast(entry, record, submission, provider).await;
                }
            }
        }

        if !parked && age >= self.config.resolution_timeout_secs {
            self.park(entry, record, submission).await;
        }
    }

    /// Marks a batch's requests as submitted so the resolver owns them.
    ///
    /// Guarded on `Batching`, so this is a no-op once the submitter has already
    /// written the status and cannot disturb a request another owner resolved.
    async fn adopt_requests(&self, wallet: Address, submission: &Submission) {
        let status = GatewayRequestState::Submitted {
            tx_hash: format!("0x{:x}", submission.tx_hash),
        };
        match self
            .tracker
            .set_status_batch_if(
                &submission.request_ids,
                &[StatusGuard::Batching],
                status,
                Some(wallet),
            )
            .await
        {
            Ok(StatusWriteOutcome::Applied | StatusWriteOutcome::Guarded) => {}
            Ok(StatusWriteOutcome::Missing) => {}
            Err(error) => {
                tracing::warn!(%error, "failed to adopt requests for an outstanding transaction");
            }
        }
    }

    /// Probes the chain for one outstanding transaction.
    ///
    /// The receipt lookup is treated as the source of truth. An RPC failure is
    /// never evidence of anything, so it always yields [`Probe::Wait`].
    async fn probe(
        &self,
        entry: &WalletEntry,
        submission: &Submission,
        provider: &DynProvider,
    ) -> Probe {
        let tx_hash = submission.tx_hash;

        let receipt = match provider.get_transaction_receipt(tx_hash).await {
            Ok(receipt) => receipt,
            Err(error) => {
                metrics::increment_wallet_tracker_error();
                tracing::warn!(%error, %tx_hash, "failed to fetch transaction receipt");
                return Probe::Wait;
            }
        };

        if let Some(receipt) = receipt {
            return self.classify_receipt(provider, submission, &receipt).await;
        }

        // No receipt. Distinguish "never landed" from "landed then reorged out"
        // by asking where the transaction and its nonce are.
        match provider.get_transaction_by_hash(tx_hash).await {
            Ok(Some(_)) => return Probe::Wait,
            Ok(None) => {}
            Err(error) => {
                metrics::increment_wallet_tracker_error();
                tracing::warn!(%error, %tx_hash, "failed to look up transaction by hash");
                return Probe::Wait;
            }
        }

        let latest = match provider
            .get_transaction_count(entry.wallet.address)
            .latest()
            .await
        {
            Ok(count) => count,
            Err(error) => {
                metrics::increment_wallet_tracker_error();
                tracing::warn!(%error, "failed to read latest transaction count");
                return Probe::Wait;
            }
        };

        if latest > submission.nonce {
            // The nonce is mined. If it were ours we would have a receipt, but a
            // load-balanced RPC fleet can answer these two calls from different
            // nodes, so re-read the receipt before drawing a conclusion.
            return match provider.get_transaction_receipt(tx_hash).await {
                Ok(Some(receipt)) => self.classify_receipt(provider, submission, &receipt).await,
                Ok(None) => Probe::Replaced,
                Err(error) => {
                    metrics::increment_wallet_tracker_error();
                    tracing::warn!(%error, %tx_hash, "failed to re-read receipt; not concluding replacement");
                    Probe::Wait
                }
            };
        }

        let pending = match provider
            .get_transaction_count(entry.wallet.address)
            .pending()
            .await
        {
            Ok(count) => count,
            Err(error) => {
                metrics::increment_wallet_tracker_error();
                tracing::warn!(%error, "failed to read pending transaction count");
                return Probe::Wait;
            }
        };

        if pending > submission.nonce {
            // The nonce is occupied in a mempool, so the transaction may still
            // land whether or not the entry is ours.
            Probe::Wait
        } else {
            Probe::Absent
        }
    }

    /// Turns a receipt into a probe outcome, verifying it is still canonical.
    async fn classify_receipt(
        &self,
        provider: &DynProvider,
        submission: &Submission,
        receipt: &TransactionReceipt,
    ) -> Probe {
        let Some(block_number) = receipt.block_number else {
            return Probe::Wait;
        };

        // A receipt without a block hash cannot be checked against the chain.
        // Waiting is the only answer that neither re-broadcasts on a false
        // reorganisation nor releases the wallet below the configured
        // confirmation floor.
        let Some(receipt_block_hash) = receipt.block_hash else {
            tracing::warn!(
                tx_hash = %submission.tx_hash,
                "receipt has no block hash; cannot verify inclusion yet"
            );
            return Probe::Wait;
        };

        match provider.get_block_by_number(block_number.into()).await {
            Ok(Some(block)) if block.header.hash == receipt_block_hash => {}
            // The block that included this transaction is no longer canonical,
            // so the transaction is no longer included.
            Ok(Some(_) | None) => return Probe::Absent,
            Err(error) => {
                metrics::increment_wallet_tracker_error();
                tracing::warn!(
                    %error,
                    tx_hash = %submission.tx_hash,
                    "failed to check whether the inclusion block is still canonical"
                );
                return Probe::Wait;
            }
        }

        let head = match provider.get_block_number().await {
            Ok(head) => head,
            Err(error) => {
                metrics::increment_wallet_tracker_error();
                tracing::warn!(%error, "failed to read the chain head");
                return Probe::Wait;
            }
        };

        let confirmations = head.saturating_sub(block_number);
        if confirmations < self.config.release_confirmations {
            return Probe::Wait;
        }

        Probe::Included {
            success: receipt.status(),
            confirmations,
        }
    }

    /// Resolves a batch whose transaction is on chain, and releases the wallet.
    async fn settle(
        &self,
        entry: &WalletEntry,
        record: &WalletRecord,
        submission: &Submission,
        success: bool,
        confirmations: u64,
    ) {
        let wallet = entry.wallet.address;
        let formatted_tx_hash = format!("0x{:x}", submission.tx_hash);
        let latency_ms = now_unix_secs()
            .saturating_sub(submission.submitted_at)
            .saturating_mul(1_000) as f64;

        metrics::record_batch_confirmed(submission.batch_type.as_str(), success, latency_ms);
        metrics::record_wallet_time_in_flight(latency_ms);
        metrics::record_wallet_confirmations_at_release(confirmations);

        if success {
            tracing::info!(
                tx_hash = %formatted_tx_hash,
                %wallet,
                batch_type = %submission.batch_type,
                confirmations,
                latency_ms,
                "batch transaction confirmed on-chain"
            );
        } else {
            tracing::error!(
                tx_hash = %formatted_tx_hash,
                %wallet,
                batch_type = %submission.batch_type,
                "batch transaction reverted on-chain"
            );
        }

        let status = if success {
            GatewayRequestState::Finalized {
                tx_hash: formatted_tx_hash.clone(),
            }
        } else {
            GatewayRequestState::failed(
                format!("transaction reverted on-chain (tx: {formatted_tx_hash})"),
                Some(GatewayErrorCode::TransactionReverted),
            )
        };

        if self
            .mark_terminal(&submission.request_ids, &status, wallet)
            .await
        {
            metrics::record_wallet_outcome(if success { "confirmed" } else { "reverted" });
            self.release_lease(wallet, record.lease_id).await;
        }
    }

    /// Fails a batch whose nonce was consumed by a different transaction.
    async fn fail_replaced(
        &self,
        entry: &WalletEntry,
        record: &WalletRecord,
        submission: &Submission,
    ) {
        let wallet = entry.wallet.address;
        let status = GatewayRequestState::failed(
            format!(
                "transaction replaced by another transaction with the same nonce (nonce {})",
                submission.nonce
            ),
            Some(GatewayErrorCode::ConfirmationError),
        );

        metrics::record_wallet_outcome("replaced");
        if self
            .mark_terminal(&submission.request_ids, &status, wallet)
            .await
        {
            self.release_lease(wallet, record.lease_id).await;
        }
    }

    /// Parks a wallet whose transaction fate could not be decided.
    ///
    /// The requests are failed so clients get a bounded answer, but the lease is
    /// deliberately kept: releasing the wallet could reuse a nonce whose
    /// transaction still exists. Parking is a capacity loss, not a correctness
    /// risk, and it stops the wallet until the chain settles or an operator acts.
    async fn park(&self, entry: &WalletEntry, record: &WalletRecord, submission: &Submission) {
        let wallet = entry.wallet.address;
        let status = GatewayRequestState::failed(
            format!(
                "transaction fate undecided after {}s (tx: 0x{:x})",
                self.config.resolution_timeout_secs, submission.tx_hash
            ),
            Some(GatewayErrorCode::ConfirmationError),
        );

        if !self
            .mark_terminal(&submission.request_ids, &status, wallet)
            .await
        {
            // Do not park on a failed write: the wallet would be out of the pool
            // with its requests still non-terminal, and nothing would retry the
            // write. Leaving the record in flight lets the next pass retry.
            tracing::warn!(
                %wallet,
                "could not resolve the batch's requests; leaving the wallet in flight to retry"
            );
            return;
        }

        let next = WalletRecord::parked(record.lease_id, submission.clone());
        match self
            .wallet_store
            .replace(
                wallet,
                record.lease_id,
                WalletState::InFlight,
                Some(submission.last_attempt_at),
                &next,
                self.state_ttl(),
            )
            .await
        {
            Ok(CasOutcome::Applied) => {
                metrics::record_wallet_outcome("parked");
                tracing::error!(
                    %wallet,
                    tx_hash = %format!("0x{:x}", submission.tx_hash),
                    nonce = submission.nonce,
                    attempts = submission.attempts,
                    "wallet parked: transaction fate could not be decided; it will not be reused until resolved"
                );
            }
            Ok(outcome) => {
                tracing::warn!(%wallet, ?outcome, "wallet record changed before it could be parked");
            }
            Err(error) => {
                tracing::error!(%error, %wallet, "failed to park wallet");
            }
        }
    }

    /// Re-broadcasts the exact signed bytes when the transaction is still absent.
    ///
    /// Re-sending identical bytes is safe: the hash and nonce are unchanged, and
    /// a node that already has the transaction answers `already known`, which is
    /// evidence of liveness rather than a failure.
    async fn rebroadcast(
        &self,
        entry: &WalletEntry,
        record: &WalletRecord,
        submission: &Submission,
        provider: &DynProvider,
    ) {
        let wallet = entry.wallet.address;

        let Some(raw_tx) = submission.raw_tx.clone() else {
            // A record rebuilt from request state has no signed bytes, so it can
            // only be resolved by observing the chain.
            tracing::debug!(
                %wallet,
                "wallet record has no signed bytes; it can only be resolved by observing the chain"
            );
            return;
        };

        if submission.attempts >= self.config.rebroadcast_max_attempts {
            return;
        }

        let now = now_unix_secs();
        if now.saturating_sub(submission.last_attempt_at) < self.config.rebroadcast_interval_secs {
            return;
        }

        // Claim the attempt before sending. The compare-and-set is what stops two
        // resolver passes from each issuing a re-broadcast, and from losing an
        // increment of the cap.
        if !self
            .advance_attempt(wallet, record.lease_id, submission, now)
            .await
        {
            return;
        }

        match provider.send_raw_transaction(&raw_tx).await {
            Ok(_) => {
                tracing::info!(
                    tx_hash = %format!("0x{:x}", submission.tx_hash),
                    %wallet,
                    attempts = submission.attempts + 1,
                    "re-broadcast transaction that had not been included"
                );
            }
            Err(error) => {
                // `already known` and friends prove the transaction is in a
                // mempool, so this is not treated as a failure and does not stop
                // the wallet from resolving.
                tracing::warn!(
                    %error,
                    tx_hash = %format!("0x{:x}", submission.tx_hash),
                    %wallet,
                    "re-broadcast attempt did not succeed"
                );
            }
        }
        metrics::increment_wallet_rebroadcast();
    }

    /// Advances the broadcast attempt counter under a compare-and-set.
    ///
    /// Returns whether this caller claimed the attempt. Only an `InFlight` record
    /// may be advanced, because the replacement is written back as `InFlight`.
    async fn advance_attempt(
        &self,
        wallet: Address,
        lease_id: Uuid,
        submission: &Submission,
        now: u64,
    ) -> bool {
        let mut next = submission.clone();
        next.attempts = next.attempts.saturating_add(1);
        next.last_attempt_at = now;

        let replacement = WalletRecord::in_flight(lease_id, next);
        match self
            .wallet_store
            .replace(
                wallet,
                lease_id,
                WalletState::InFlight,
                Some(submission.last_attempt_at),
                &replacement,
                self.state_ttl(),
            )
            .await
        {
            Ok(CasOutcome::Applied) => true,
            Ok(outcome) => {
                tracing::debug!(%wallet, ?outcome, "another resolver pass advanced this record");
                false
            }
            Err(error) => {
                tracing::warn!(%error, %wallet, "failed to record a broadcast attempt");
                false
            }
        }
    }

    /// Writes a terminal status for a batch, returning whether the wallet may be
    /// released.
    ///
    /// The lease is released only once every request is resolved. If a request
    /// has already been resolved by another owner the write is refused, so the
    /// records are re-read: a batch whose requests are all terminal is still
    /// safe to release, while one that is only partly resolved is retried on the
    /// next pass.
    async fn mark_terminal(
        &self,
        ids: &[String],
        status: &GatewayRequestState,
        wallet: Address,
    ) -> bool {
        let allowed = [StatusGuard::Batching, StatusGuard::Submitted];
        match self
            .tracker
            .set_status_batch_if(ids, &allowed, status.clone(), Some(wallet))
            .await
        {
            Ok(StatusWriteOutcome::Applied | StatusWriteOutcome::Missing) => true,
            Ok(StatusWriteOutcome::Guarded) => self.all_resolved(ids).await,
            Err(error) => {
                tracing::error!(%error, "failed to write terminal status for a batch");
                false
            }
        }
    }

    /// Whether every request in a batch is already in a terminal state.
    async fn all_resolved(&self, ids: &[String]) -> bool {
        match self.tracker.snapshot_batch(ids).await {
            Ok(records) => records.iter().all(|(_, record)| {
                record.as_ref().is_none_or(|record| {
                    matches!(
                        record.status,
                        GatewayRequestState::Finalized { .. } | GatewayRequestState::Failed { .. }
                    )
                })
            }),
            Err(error) => {
                tracing::error!(%error, "failed to re-read request states");
                false
            }
        }
    }

    /// Guards the transition of a batch's requests to `Submitted`.
    ///
    /// The transaction is broadcast only if every request was still awaiting
    /// submission at that instant, so a request another owner has already
    /// resolved is never executed on chain.
    async fn guard_broadcast(
        &self,
        ids: &[String],
        tx_hash: TxHash,
        wallet: Address,
    ) -> BroadcastGuard {
        let status = GatewayRequestState::Submitted {
            tx_hash: format!("0x{tx_hash:x}"),
        };
        let allowed = [StatusGuard::Batching];

        match self
            .tracker
            .set_status_batch_if(ids, &allowed, status, Some(wallet))
            .await
        {
            Ok(StatusWriteOutcome::Applied) => BroadcastGuard::Proceed,
            // A missing record means the request is gone, so broadcasting would
            // execute work nobody is tracking; `Guarded` means another owner
            // already resolved it. Neither may be broadcast.
            Ok(StatusWriteOutcome::Guarded | StatusWriteOutcome::Missing) => {
                BroadcastGuard::Abandon
            }
            Err(error) => {
                // Ambiguous: the write may or may not have landed. Re-read before
                // deciding, because a request another owner resolved must stop
                // the broadcast.
                tracing::warn!(%error, "guarded status write failed; re-reading request states");
                if self.any_resolved(ids).await {
                    BroadcastGuard::Abandon
                } else {
                    BroadcastGuard::Proceed
                }
            }
        }
    }

    /// Whether any request in a batch has already been resolved.
    async fn any_resolved(&self, ids: &[String]) -> bool {
        match self.tracker.snapshot_batch(ids).await {
            Ok(records) => records.iter().any(|(_, record)| {
                record.as_ref().is_some_and(|record| {
                    matches!(
                        record.status,
                        GatewayRequestState::Finalized { .. } | GatewayRequestState::Failed { .. }
                    )
                })
            }),
            Err(error) => {
                tracing::error!(%error, "failed to re-read request states");
                // Treat an unreadable batch as resolved: refusing to broadcast
                // risks a retry, while broadcasting risks executing a request
                // that was already answered.
                true
            }
        }
    }

    /// Whether a wallet record exists and is still owned by this lease.
    async fn wallet_record_is_ours(&self, wallet: Address, lease_id: Uuid) -> bool {
        match self.wallet_store.get(wallet).await {
            Ok(Some(record)) => record.lease_id == lease_id,
            Ok(None) | Err(_) => false,
        }
    }

    /// Records that a broadcast was attempted, so the resolver does not race it.
    async fn record_attempt(&self, wallet: Address, lease_id: Uuid) {
        let Some(record) = self
            .wallet_store
            .get(wallet)
            .await
            .ok()
            .flatten()
            .filter(|record| record.lease_id == lease_id)
        else {
            return;
        };
        if record.state != WalletState::InFlight {
            return;
        }
        let Some(submission) = record.submission() else {
            return;
        };

        let _ = self
            .advance_attempt(wallet, lease_id, submission, now_unix_secs())
            .await;
    }

    /// Acquires a free wallet, waiting up to the configured timeout.
    ///
    /// Returns `Ok(None)` when the pool stayed busy for the whole timeout. That
    /// is a capacity signal, not an error: the caller should retry the batch
    /// rather than fail its requests.
    ///
    /// # Errors
    ///
    /// Returns an error when Redis cannot be reached.
    async fn acquire(&self) -> GatewayResult<Option<(WalletEntry, Uuid)>> {
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_secs(self.config.acquire_timeout_secs);
        let lease = Duration::from_secs(self.config.sign_lease_secs);

        loop {
            let start = self.next_wallet.fetch_add(1, Ordering::Relaxed);

            for offset in 0..self.acquirable.len() {
                let index = self.acquirable[start.wrapping_add(offset) % self.acquirable.len()];
                let entry = self.wallets[index].clone();
                let lease_id = Uuid::new_v4();

                if self
                    .wallet_store
                    .reserve(entry.wallet.address, lease_id, lease)
                    .await?
                {
                    metrics::record_wallet_acquire_wait(started.elapsed().as_secs_f64() * 1000.0);
                    return Ok(Some((entry, lease_id)));
                }
            }

            metrics::increment_wallet_acquire_empty();

            if tokio::time::Instant::now() >= deadline {
                return Ok(None);
            }

            // A release notification is process-local, so it cannot report a
            // wallet freed by another replica. Recheck every tracker interval as
            // well, or a shared pool would only pick those up after the whole
            // acquire timeout.
            let recheck = tokio::time::Instant::now()
                + Duration::from_secs(self.config.tracker_interval_secs);
            let notified = self.wallet_released.notified();
            let _ = tokio::time::timeout_at(deadline.min(recheck), notified).await;
        }
    }

    /// Releases a lease and wakes anything waiting for a wallet.
    async fn release_lease(&self, wallet: Address, lease_id: Uuid) {
        match self.wallet_store.release(wallet, lease_id).await {
            Ok(CasOutcome::Applied | CasOutcome::Missing) => self.wallet_released.notify_waiters(),
            Ok(CasOutcome::Conflict) => {
                tracing::error!(
                    %wallet,
                    "wallet lease changed before it could be released; leaving it for the resolver"
                );
            }
            Err(error) => {
                tracing::error!(%error, %wallet, "failed to release wallet lease");
            }
        }
    }

    /// Lifetime of a committed wallet record.
    fn state_ttl(&self) -> Duration {
        Duration::from_secs(self.config.state_ttl_secs)
    }
}

impl BroadcastGuard {
    /// Whether the batch must be abandoned rather than broadcast.
    const fn is_abandon(self) -> bool {
        matches!(self, Self::Abandon)
    }
}
