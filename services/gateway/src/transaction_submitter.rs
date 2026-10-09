//! Durable wallet leasing, transaction broadcast and receipt resolution.
//!
//! One transaction per wallet at a time. A batch is signed, committed to
//! [`WalletStore`] and only then broadcast; the wallet stays out of the pool
//! until the transaction's fate is known. The committed record, which holds
//! the nonce and hash, is what makes that survive a restart: the resolver
//! probes the chain for that hash and nonce rather than trusting the outcome
//! of the broadcast call.
//!
//! Receipt polling for requests a wallet record owns lives here; the orphan
//! sweeper keeps only the requests no wallet record owns.

mod probe;
mod resolver;
#[cfg(test)]
mod tests;

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use alloy::{
    consensus::{Transaction as _, TxEnvelope},
    primitives::{Address, TxHash},
    providers::{DynProvider, Provider},
    rpc::types::TransactionRequest,
    transports::TransportError,
};
use tokio::sync::Notify;
use uuid::Uuid;
use world_id_primitives::api_types::{GatewayErrorCode, GatewayRequestState};
use world_id_services_common::ProviderWallet;

use crate::{
    batch_policy::BacklogUrgencyStats,
    batch_type::BatchType,
    config::{WalletConfig, defaults},
    error::{GatewayError, GatewayResult},
    metrics,
    request_tracker::{BacklogScope, RequestTracker, now_unix_secs},
    storage::{
        request_store::{StatusGuard, StatusWriteOutcome},
        wallet_store::{CasOutcome, Submission, WalletState, WalletStore},
    },
};

/// Wallets probed concurrently by one resolver pass, so a single slow RPC
/// cannot stall resolution of the rest of the pool.
const RESOLVER_CONCURRENCY: usize = 4;

/// Upper bound on the time from commit to the end of the broadcast call,
/// retries included.
///
/// The resolver must not conclude [`probe::Probe::Absent`] while a broadcast
/// may still be in progress, so `WALLET_ABSENT_GRACE_SECS` is validated to
/// exceed this.
const BROADCAST_TIMEOUT: Duration = Duration::from_secs(defaults::BROADCAST_TIMEOUT_SECS);

/// Whether a batch may be broadcast after its requests were guarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BroadcastGuard {
    /// The requests were still awaiting submission, so the transaction may be sent.
    Proceed,
    /// Another owner resolved the requests, so the transaction must be discarded.
    Abandon,
}

impl BroadcastGuard {
    /// Whether the batch must be abandoned rather than broadcast.
    const fn is_abandon(self) -> bool {
        matches!(self, Self::Abandon)
    }
}

/// Result of one submission attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubmitOutcome {
    /// The transaction was committed and a broadcast was attempted.
    Submitted,
    /// No wallet could be held through signing: none became free in time, or
    /// the signing lease lapsed before the commit. Nothing was broadcast, so
    /// the caller should retry the batch rather than fail its requests.
    NoWalletAvailable,
    /// Another owner resolved some of the batch's requests before broadcast,
    /// so the signature was discarded. The remaining requests were failed.
    Abandoned,
}

/// Signs, commits, broadcasts and resolves one transaction per wallet at a time.
pub(crate) struct TransactionSubmitter {
    wallets: Vec<ProviderWallet>,
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
    /// Capacity problems (no free wallet, a lease lost while signing) and a
    /// batch resolved elsewhere before broadcast are outcomes, not errors; see
    /// [`SubmitOutcome`].
    ///
    /// # Errors
    ///
    /// Returns an error when signing failed, or when the commit failed and the
    /// record does not hold this transaction. Nothing was broadcast in either
    /// case. After a failed signature the lease is released at once; after a
    /// failed commit it expires with the signing lease.
    pub(crate) async fn submit(
        &self,
        transaction: TransactionRequest,
        request_ids: Vec<String>,
        batch_type: BatchType,
    ) -> GatewayResult<SubmitOutcome> {
        let Some((entry, lease_id)) = self.acquire().await else {
            // Capacity, not failure: the batch is untouched and stays queued.
            return Ok(SubmitOutcome::NoWalletAvailable);
        };
        let wallet = entry.address;

        let sign_started = tokio::time::Instant::now();
        let signed = match self.sign(&entry, transaction).await {
            Ok(signed) => signed,
            Err(error) => {
                self.release_lease(wallet, lease_id).await;
                return Err(GatewayError::Submission(format!("signing failed: {error}")));
            }
        };
        let sign_latency_ms = sign_started.elapsed().as_secs_f64() * 1000.0;

        // One deadline for the whole post-commit sequence, taken with
        // `submitted_at`: the resolver's grace counts from that moment, so a
        // broadcast must never start, or still be running, after it.
        let broadcast_deadline = tokio::time::Instant::now() + BROADCAST_TIMEOUT;
        let submission = Submission {
            nonce: signed.nonce(),
            tx_hash: *signed.tx_hash(),
            request_ids: request_ids.clone(),
            batch_type,
            submitted_at: now_unix_secs(),
        };
        let tx_hash = submission.tx_hash;
        let formatted_tx_hash = format!("{tx_hash:#x}");

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
                // Signing outlived the lease. Nothing was broadcast, so this is
                // a capacity problem rather than a reason to fail the requests.
                metrics::record_wallet_outcome("lease_lost");
                tracing::warn!(
                    %wallet, ?outcome, %batch_type,
                    "wallet lease lost before the transaction could be committed; discarding signature"
                );
                return Ok(SubmitOutcome::NoWalletAvailable);
            }
            Err(error) => {
                // A connection can fail after the script applied. Only a record
                // that holds this very transaction counts as committed: a record
                // still `Signing` is skipped by the resolver and would expire
                // while the transaction might be in flight.
                if !self.is_committed(wallet, lease_id, tx_hash).await {
                    tracing::error!(
                        %error, %wallet, %batch_type,
                        "failed to commit signed transaction"
                    );
                    return Err(GatewayError::Submission(format!("commit failed: {error}")));
                }
                tracing::warn!(
                    %error, %wallet, %batch_type,
                    "commit reported an error but the transaction is recorded; continuing"
                );
            }
        }

        if self
            .guard_broadcast(&request_ids, tx_hash, wallet)
            .await
            .is_abandon()
        {
            // Nothing was broadcast, so the nonce is untouched and the wallet is
            // safe to reuse immediately. The requests nobody else resolved still
            // need an answer, or they would sit in `Batching` until the sweeper.
            metrics::record_wallet_outcome("abandoned");
            tracing::warn!(
                %wallet, %batch_type,
                "requests were resolved by another owner before broadcast; discarding signature"
            );
            // `Submitted` too: an ambiguous guard write may have applied before
            // the batch was abandoned, and nothing will broadcast it now.
            self.set_each_if(
                &request_ids,
                &[StatusGuard::Batching, StatusGuard::Submitted],
                &GatewayRequestState::failed(
                    "batch was abandoned before broadcast because another request in it was resolved",
                    Some(GatewayErrorCode::InternalServerError),
                ),
                None,
            )
            .await;
            self.release_lease(wallet, lease_id).await;
            return Ok(SubmitOutcome::Abandoned);
        }

        tracing::debug!(
            tx_hash = %formatted_tx_hash,
            %wallet,
            %batch_type,
            batch_size = request_ids.len(),
            sign_latency_ms,
            "batch transaction committed before broadcast"
        );

        let send_started = tokio::time::Instant::now();
        if send_started >= broadcast_deadline {
            // Skipping is always safe: nothing was sent, so the resolver finds
            // the transaction absent after the grace and frees the nonce.
            metrics::record_batch_send_failed(batch_type.as_str(), 0.0);
            tracing::warn!(
                tx_hash = %formatted_tx_hash,
                %wallet,
                %batch_type,
                "broadcast deadline passed before sending; leaving the transaction to the resolver"
            );
            return Ok(SubmitOutcome::Submitted);
        }
        let sent =
            tokio::time::timeout_at(broadcast_deadline, entry.provider.send_tx_envelope(signed))
                .await
                .unwrap_or_else(|_| {
                    Err(alloy::transports::TransportErrorKind::custom_str(
                        "broadcast timed out",
                    ))
                });
        match sent {
            Ok(_) => {
                let send_latency_ms = send_started.elapsed().as_secs_f64() * 1000.0;
                metrics::record_batch_send_latency(batch_type.as_str(), send_latency_ms);
                tracing::debug!(
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

        Ok(SubmitOutcome::Submitted)
    }

    /// Signs `transaction`, never below the wallet's recorded nonce floor.
    ///
    /// The filler takes the pending nonce from whichever RPC node answers
    /// first. A node that has not yet seen the wallet's last transaction hands
    /// back its consumed nonce, and the new transaction would then be reported
    /// as replaced; the floor recorded at release prevents that. An unreadable
    /// floor only loses that protection, so it does not fail the batch.
    async fn sign(
        &self,
        entry: &ProviderWallet,
        transaction: TransactionRequest,
    ) -> Result<TxEnvelope, TransportError> {
        let floor = match self.wallet_store.nonce_floor(entry.address).await {
            Ok(floor) => floor,
            Err(error) => {
                metrics::increment_wallet_error("acquire", "redis");
                tracing::warn!(%error, wallet = %entry.address, "failed to read the nonce floor; signing without it");
                None
            }
        };

        let signed = entry.sign_transaction(transaction.clone()).await?;
        match floor {
            Some(floor) if signed.nonce() < floor => {
                tracing::warn!(
                    wallet = %entry.address,
                    filled = signed.nonce(),
                    floor,
                    "RPC node returned a consumed nonce; signing at the recorded floor"
                );
                entry.sign_transaction(transaction.nonce(floor)).await
            }
            _ => Ok(signed),
        }
    }

    /// Claims a batch's requests for a batcher, returning the ids it claimed.
    ///
    /// Guarded on `Queued`, so a request another owner already resolved (the
    /// sweeper, typically) is left out and never put on chain. When the write
    /// errors it may still have applied, so the request is re-read and kept
    /// only if it is now `Batching`.
    pub(crate) async fn mark_batching(&self, ids: &[String]) -> Vec<String> {
        let mut claimed = Vec::with_capacity(ids.len());
        for id in ids {
            match self
                .tracker
                .set_status_if(
                    id,
                    &[StatusGuard::Queued],
                    GatewayRequestState::Batching,
                    None,
                )
                .await
            {
                Ok(StatusWriteOutcome::Applied) => claimed.push(id.clone()),
                Ok(StatusWriteOutcome::Guarded | StatusWriteOutcome::Missing) => {}
                Err(error) => {
                    tracing::warn!(%error, request_id = %id, "claim for batching failed; re-reading the request");
                    let now_batching = self.tracker.snapshot(id).await.is_some_and(|record| {
                        matches!(record.status, GatewayRequestState::Batching)
                    });
                    if now_batching {
                        claimed.push(id.clone());
                    }
                }
            }
        }
        claimed
    }

    /// Fails a batch that could not be submitted before any broadcast.
    ///
    /// Guarded on `Batching` and applied per request, so a request the sweeper
    /// or another owner already resolved keeps its status, while the rest of
    /// the batch still gets an answer.
    pub(crate) async fn fail_batching(&self, ids: &[String], status: GatewayRequestState) {
        self.set_each_if(ids, &[StatusGuard::Batching], &status, None)
            .await;
    }

    /// Applies `status` to each request still in one of `allowed`, one request
    /// at a time, returning whether every write reached Redis.
    ///
    /// A refused or missing request is not an error: it is already resolved,
    /// or gone, and either way needs no write from this caller.
    async fn set_each_if(
        &self,
        ids: &[String],
        allowed: &[StatusGuard],
        status: &GatewayRequestState,
        wallet: Option<Address>,
    ) -> bool {
        let mut all_written = true;
        for id in ids {
            let result = self
                .tracker
                .set_status_if(id, allowed, status.clone(), wallet)
                .await;
            if let Err(error) = result {
                tracing::error!(%error, request_id = %id, ?allowed, "guarded status write failed");
                all_written = false;
            }
        }
        all_written
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
            tx_hash: format!("{tx_hash:#x}"),
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
                // Ambiguous: the write may or may not have landed. Broadcast only
                // if it demonstrably did; a batch left in `Batching` could be
                // failed by the sweeper while its transaction executes.
                tracing::warn!(%error, "guarded status write failed; re-reading request states");
                if self.all_submitted_as(ids, tx_hash).await {
                    BroadcastGuard::Proceed
                } else {
                    BroadcastGuard::Abandon
                }
            }
        }
    }

    /// Whether every request in a batch is recorded as submitted in `tx_hash`.
    ///
    /// An unreadable batch counts as not submitted: refusing to broadcast costs
    /// a retry, while broadcasting risks executing a request nobody owns.
    async fn all_submitted_as(&self, ids: &[String], tx_hash: TxHash) -> bool {
        let expected = format!("{tx_hash:#x}");
        match self.tracker.snapshot_batch(ids).await {
            Ok(records) => records.iter().all(|(_, record)| {
                record.as_ref().is_some_and(|record| {
                    matches!(&record.status, GatewayRequestState::Submitted { tx_hash } if *tx_hash == expected)
                })
            }),
            Err(error) => {
                tracing::error!(%error, "failed to re-read request states");
                false
            }
        }
    }

    /// Whether this lease's record holds `tx_hash` in flight, i.e. whether an
    /// ambiguous commit actually landed.
    async fn is_committed(&self, wallet: Address, lease_id: Uuid, tx_hash: TxHash) -> bool {
        match self.wallet_store.get(wallet).await {
            Ok(Some(record)) => {
                record.lease_id == lease_id
                    && record.state == WalletState::InFlight
                    && record
                        .submission()
                        .is_some_and(|submission| submission.tx_hash == tx_hash)
            }
            Ok(None) => false,
            Err(error) => {
                tracing::error!(%error, %wallet, "failed to re-read the wallet record after an ambiguous commit");
                false
            }
        }
    }

    /// Acquires a free wallet, waiting up to the configured timeout.
    ///
    /// Returns `None` when no wallet could be reserved for the whole timeout,
    /// whether because the pool was busy or because Redis failed. Either way it
    /// is a capacity signal, not a reason to fail the batch's requests.
    async fn acquire(&self) -> Option<(ProviderWallet, Uuid)> {
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_secs(self.config.acquire_timeout_secs);
        let lease = Duration::from_secs(self.config.sign_lease_secs);

        loop {
            let start = self.next_wallet.fetch_add(1, Ordering::Relaxed);

            for offset in 0..self.acquirable.len() {
                let index = self.acquirable[start.wrapping_add(offset) % self.acquirable.len()];
                let entry = self.wallets[index].clone();
                let lease_id = Uuid::new_v4();

                match self
                    .wallet_store
                    .reserve(entry.address, lease_id, lease)
                    .await
                {
                    Ok(true) => {
                        metrics::record_wallet_acquire_wait(
                            started.elapsed().as_secs_f64() * 1000.0,
                        );
                        return Some((entry, lease_id));
                    }
                    Ok(false) => {}
                    Err(error) => {
                        // If the reservation applied anyway, its short signing
                        // lease expires on its own.
                        metrics::increment_wallet_error("acquire", "redis");
                        tracing::warn!(%error, wallet = %entry.address, "failed to reserve wallet");
                    }
                }
            }

            metrics::increment_wallet_acquire_empty();

            if tokio::time::Instant::now() >= deadline {
                // Record the tail as well as the successes: a pool that is
                // saturated for the whole timeout is exactly the case the wait
                // histogram exists to show.
                metrics::record_wallet_acquire_wait(started.elapsed().as_secs_f64() * 1000.0);
                return None;
            }

            // A release notification is process-local, so it cannot report a
            // wallet freed by another replica. Recheck every resolver interval as
            // well, or a shared pool would only pick those up after the whole
            // acquire timeout.
            let recheck = tokio::time::Instant::now()
                + Duration::from_secs(self.config.resolver_interval_secs);
            let notified = self.wallet_released.notified();
            let _ = tokio::time::timeout_at(deadline.min(recheck), notified).await;
        }
    }

    /// Releases a lease and wakes anything waiting for a wallet, returning
    /// whether this call deleted the record.
    ///
    /// `Missing` and `Conflict` mean another replica released it first (and
    /// possibly re-leased the wallet), which is a normal race, not an error.
    async fn release_lease(&self, wallet: Address, lease_id: Uuid) -> bool {
        match self.wallet_store.release(wallet, lease_id).await {
            Ok(CasOutcome::Applied) => {
                self.wallet_released.notify_waiters();
                true
            }
            Ok(CasOutcome::Missing | CasOutcome::Conflict) => false,
            Err(error) => {
                metrics::increment_wallet_error("release", "redis");
                tracing::error!(%error, %wallet, "failed to release wallet lease");
                false
            }
        }
    }

    /// Lifetime of a committed wallet record.
    fn state_ttl(&self) -> Duration {
        Duration::from_secs(self.config.state_ttl_secs)
    }
}
