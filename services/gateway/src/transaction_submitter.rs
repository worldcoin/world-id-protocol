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
use futures::StreamExt as _;
use rand::Rng as _;
use tokio::sync::Notify;
use uuid::Uuid;
use world_id_primitives::api_types::{GatewayErrorCode, GatewayRequestState};
use world_id_services_common::ProviderWallet;

use self::probe::Probe;
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

/// Upper bound on one broadcast call, retries included.
///
/// The resolver must not conclude [`Probe::Absent`] while a broadcast may still
/// be in progress, so `WALLET_ABSENT_GRACE_SECS` is validated to exceed this.
pub(crate) const BROADCAST_TIMEOUT: Duration = Duration::from_secs(20);

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

        let submission = Submission {
            nonce: signed.nonce(),
            tx_hash: *signed.tx_hash(),
            request_ids: request_ids.clone(),
            batch_type,
            submitted_at: now_unix_secs(),
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
                    return Err(error);
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
            self.fail_batching(
                &request_ids,
                GatewayRequestState::failed(
                    "batch was abandoned before broadcast because another request in it was resolved",
                    Some(GatewayErrorCode::InternalServerError),
                ),
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
        let sent = tokio::time::timeout(BROADCAST_TIMEOUT, entry.provider.send_tx_envelope(signed))
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
    /// sweeper, typically) is left out and never put on chain. A request whose
    /// write failed is kept: the write may have landed, and `guard_broadcast`
    /// re-checks every request before anything is sent.
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
                    tracing::error!(%error, request_id = %id, "failed to claim a request for batching");
                    claimed.push(id.clone());
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

    /// Runs the resolution loop until the process exits.
    ///
    /// Errors are handled per wallet and per pass, so the loop never returns
    /// one. Passes are spaced by the resolver interval with ±20% jitter, so
    /// replicas started together do not probe in lockstep.
    pub(crate) async fn run_resolver(self: Arc<Self>) {
        let interval = Duration::from_secs(self.config.resolver_interval_secs);
        // Bounded so a Redis or RPC call that accepts a connection and never
        // answers cannot wedge the pass: supervision only restarts a task that
        // exits, and a hanging loop never exits.
        let pass_timeout = interval.max(Duration::from_secs(60));

        loop {
            if tokio::time::timeout(pass_timeout, self.resolve_all())
                .await
                .is_err()
            {
                metrics::increment_wallet_error("resolve", "timeout");
                tracing::error!(
                    timeout_secs = pass_timeout.as_secs(),
                    "resolution pass did not finish in time; abandoning it"
                );
            }
            let pause = interval.mul_f64(rand::thread_rng().gen_range(0.8..1.2));
            tokio::time::sleep(pause).await;
        }
    }

    /// One resolution pass over every wallet that has a record.
    ///
    /// That is the configured wallets plus any other record in Redis: a pool
    /// key removed without draining, or the per-replica key of a replica that
    /// was scaled down, still has a transaction someone must decide. Resolving
    /// needs only the address, never the signer.
    pub(crate) async fn resolve_all(&self) {
        let mut addresses: Vec<Address> = self.wallets.iter().map(|entry| entry.address).collect();
        match self.wallet_store.addresses().await {
            Ok(stored) => {
                let unconfigured: Vec<Address> = stored
                    .into_iter()
                    .filter(|address| !addresses.contains(address))
                    .collect();
                metrics::record_wallet_unconfigured(unconfigured.len());
                addresses.extend(unconfigured);
            }
            Err(error) => {
                // The configured wallets can still be resolved without the scan.
                metrics::increment_wallet_error("resolve", "redis");
                tracing::warn!(%error, "failed to list wallet records; resolving configured wallets only");
            }
        }

        let records = match self.wallet_store.get_many(&addresses).await {
            Ok(records) => records,
            Err(error) => {
                metrics::increment_wallet_error("resolve", "redis");
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

        let active: Vec<(Address, WalletRecord)> = addresses
            .into_iter()
            .zip(records)
            .filter_map(|(address, record)| record.map(|record| (address, record)))
            .filter(|(_, record)| record.state != WalletState::Signing)
            .collect();

        // One provider for the whole pass, so every read it makes is answered by
        // the same node.
        let pass = self.resolver_pass.fetch_add(1, Ordering::Relaxed);
        let provider = self.resolver_providers[pass % self.resolver_providers.len()].clone();
        let claim = Duration::from_secs(self.config.resolver_interval_secs);

        futures::stream::iter(active)
            .map(|(wallet, record)| {
                let provider = provider.clone();
                async move {
                    match self.wallet_store.claim_resolution(wallet, claim).await {
                        Ok(true) => self.resolve_wallet(wallet, &record, &provider).await,
                        // Another replica resolves this wallet in this interval.
                        Ok(false) => {}
                        Err(error) => {
                            metrics::increment_wallet_error("resolve", "redis");
                            tracing::warn!(%error, %wallet, "failed to claim a wallet for resolution");
                        }
                    }
                }
            })
            .buffer_unordered(RESOLVER_CONCURRENCY)
            .collect::<Vec<()>>()
            .await;
    }

    /// Resolves one committed wallet record (`InFlight` or `Parked`).
    async fn resolve_wallet(&self, wallet: Address, record: &WalletRecord, provider: &DynProvider) {
        let lease_id = record.lease_id;

        let Some(submission) = record.submission() else {
            metrics::increment_wallet_error("resolve", "invalid_record");
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
        // Within the grace a submitter may still be inside its commit, guard and
        // broadcast sequence. Adopting its requests there would flip them out
        // from under the guard that authorises the broadcast, and concluding
        // `Absent` would fail a transaction that is still on its way. Inclusion
        // and replacement are evidence either way, so probing starts at once.
        let submitter_done = age >= self.config.absent_grace_secs;

        // A batch still in `Batching` after the grace was left behind by a
        // process that died between committing the record and writing the
        // statuses.
        if !parked && submitter_done {
            self.adopt_requests(wallet, submission).await;
        }

        match probe::probe(
            provider,
            wallet,
            submission,
            self.config.release_confirmations,
            submission.submitted_at + self.config.absent_grace_secs,
        )
        .await
        {
            Probe::Wait => {}
            Probe::Included {
                success,
                confirmations,
            } => {
                self.settle(wallet, record, submission, success, confirmations)
                    .await;
                // Resolved: the record is released or retried on its own terms.
                // Falling through to the timeout check below would park a wallet
                // whose transaction is already accounted for.
                return;
            }
            Probe::Replaced => {
                self.fail_replaced(wallet, record, submission).await;
                return;
            }
            Probe::Absent if submitter_done => {
                self.fail_absent(wallet, record, submission).await;
                // Resolved: the transaction never landed, so its wallet is free.
                return;
            }
            // Possibly still being broadcast; decide on a later pass.
            Probe::Absent => {}
        }

        if !parked && age >= self.config.resolution_timeout_secs {
            self.park(wallet, record, submission).await;
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

    /// Resolves a batch whose transaction is on chain, and releases the wallet.
    async fn settle(
        &self,
        wallet: Address,
        record: &WalletRecord,
        submission: &Submission,
        success: bool,
        confirmations: u64,
    ) {
        let tx_hash = format!("{:#x}", submission.tx_hash);
        let parked = record.state == WalletState::Parked;
        if parked {
            // The requests were already failed when the wallet was parked, and a
            // terminal answer is not taken back. Make the contradiction loud.
            tracing::error!(
                %tx_hash,
                %wallet,
                success,
                "a parked wallet's transaction landed after its requests were reported failed"
            );
        }
        let (status, outcome) = if success {
            (
                GatewayRequestState::Finalized {
                    tx_hash: tx_hash.clone(),
                },
                if parked { "parked_landed" } else { "confirmed" },
            )
        } else {
            tracing::error!(
                %tx_hash,
                %wallet,
                batch_type = %submission.batch_type,
                "batch transaction reverted on-chain"
            );
            (
                GatewayRequestState::failed(
                    format!("transaction reverted on-chain (tx: {tx_hash})"),
                    Some(GatewayErrorCode::TransactionReverted),
                ),
                if parked { "parked_landed" } else { "reverted" },
            )
        };

        if self
            .resolve_batch(wallet, record, submission, &status, outcome)
            .await
        {
            let latency_ms = now_unix_secs()
                .saturating_sub(submission.submitted_at)
                .saturating_mul(1_000) as f64;
            metrics::record_batch_confirmed(submission.batch_type.as_str(), success, latency_ms);
            metrics::record_wallet_time_in_flight(latency_ms);
            metrics::record_wallet_confirmations_at_release(confirmations);
        }
    }

    /// Fails a batch whose nonce was consumed by a different transaction.
    async fn fail_replaced(&self, wallet: Address, record: &WalletRecord, submission: &Submission) {
        tracing::error!(
            %wallet,
            tx_hash = %format!("{:#x}", submission.tx_hash),
            nonce = submission.nonce,
            "wallet transaction was replaced; its requests cannot be confirmed"
        );
        let status = GatewayRequestState::failed(
            format!(
                "transaction replaced by another transaction with the same nonce (nonce {})",
                submission.nonce
            ),
            Some(GatewayErrorCode::ConfirmationError),
        );
        self.resolve_batch(wallet, record, submission, &status, "replaced")
            .await;
    }

    /// Parks a wallet whose transaction fate could not be decided.
    ///
    /// The requests are failed so clients get a bounded answer, but the lease is
    /// deliberately kept: releasing the wallet could reuse a nonce whose
    /// transaction still exists. Parking is a capacity loss, not a correctness
    /// risk, and it stops the wallet until the chain settles or an operator acts.
    async fn park(&self, wallet: Address, record: &WalletRecord, submission: &Submission) {
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
                // The lease and state guards already ensure this is the record we
                // decided about.
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

    /// Fails a batch whose transaction is neither on chain nor pending.
    ///
    /// [`Probe::Absent`] established that the nonce is unconsumed and the signed
    /// hash is unknown to the endpoint after the broadcast grace, so the
    /// transaction never landed and the wallet's nonce is free to reuse.
    /// Nothing is retried: the requests are answered and the wallet returns to
    /// the pool.
    async fn fail_absent(&self, wallet: Address, record: &WalletRecord, submission: &Submission) {
        let status = GatewayRequestState::failed(
            format!(
                "transaction was not accepted by the network (tx: {:#x})",
                submission.tx_hash
            ),
            Some(GatewayErrorCode::ConfirmationError),
        );
        self.resolve_batch(wallet, record, submission, &status, "absent")
            .await;
    }

    /// Writes a batch's terminal status and releases its wallet.
    ///
    /// Returns whether this caller released the wallet. Two replicas can still
    /// resolve the same wallet when a resolution claim lapses mid-pass, so only
    /// the one whose release applied records the outcome.
    async fn resolve_batch(
        &self,
        wallet: Address,
        record: &WalletRecord,
        submission: &Submission,
        status: &GatewayRequestState,
        outcome: &'static str,
    ) -> bool {
        if !self
            .mark_terminal(&submission.request_ids, status, wallet)
            .await
        {
            return false;
        }
        // Every outcome but `absent` consumed the nonce. Recorded before the
        // release, so the next holder of the wallet sees it.
        if outcome != "absent"
            && let Err(error) = self
                .wallet_store
                .raise_nonce_floor(wallet, submission.nonce + 1, self.state_ttl())
                .await
        {
            metrics::increment_wallet_error("release", "redis");
            tracing::warn!(%error, %wallet, "failed to record the nonce floor");
        }
        let released = self.release_lease(wallet, record.lease_id).await;
        if released {
            metrics::record_wallet_outcome(outcome);
        }
        released
    }

    /// Writes a terminal status for a batch, returning whether the wallet may be
    /// released.
    ///
    /// The batch write is all-or-nothing, so it refuses the whole batch when any
    /// request was already resolved by another owner or has expired. The
    /// remaining requests are then resolved one by one: leaving them for the
    /// next pass would refuse again forever, and the sweeper does not touch
    /// requests a wallet owns. The wallet is released only once every write has
    /// reached Redis.
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
            Ok(StatusWriteOutcome::Applied) => true,
            Ok(StatusWriteOutcome::Guarded | StatusWriteOutcome::Missing) => {
                self.set_each_if(ids, &allowed, status, Some(wallet)).await
            }
            Err(error) => {
                tracing::error!(%error, %wallet, "failed to write terminal status for a batch");
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

impl BroadcastGuard {
    /// Whether the batch must be abandoned rather than broadcast.
    const fn is_abandon(self) -> bool {
        matches!(self, Self::Abandon)
    }
}
