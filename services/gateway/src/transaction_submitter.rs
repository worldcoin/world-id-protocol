use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::{Address, TxHash},
    providers::Provider,
    rpc::types::TransactionRequest,
};
use tokio::sync::Notify;
use uuid::Uuid;
use world_id_primitives::api_types::{GatewayErrorCode, GatewayRequestKind, GatewayRequestState};
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;
use world_id_services_common::ProviderWallet;

pub use crate::storage::request_store::RequestRecord;
use crate::{
    batch_policy::BacklogUrgencyStats,
    batch_type::BatchType,
    config::RateLimitConfig,
    error::{GatewayError, GatewayErrorResponse, GatewayResult},
    metrics,
    storage::{
        request_store::{CreateRequestOutcome, RateLimitOutcome, RequestStore},
        wallet_store::{WalletStore, WalletTransaction},
    },
};

const WALLET_RECHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Signs, persists, broadcasts, and tracks transactions for the configured wallets.
pub(crate) struct TransactionSubmitter {
    wallets: Vec<WalletEntry>,
    wallet_store: WalletStore,
    request_store: RequestStore,
    rate_limit: Option<RateLimitConfig>,
    next_wallet: AtomicUsize,
    wallet_released: Notify,
    receipt_timeout: Duration,
    tracker_interval: Duration,
}

#[derive(Clone)]
struct WalletEntry {
    wallet: ProviderWallet,
    registry: Arc<WorldIdRegistryInstance<Arc<alloy::providers::DynProvider>>>,
}

impl TransactionSubmitter {
    /// Creates a submitter and starts its persistent receipt tracker.
    pub(crate) async fn connect(
        registry_address: Address,
        wallets: Vec<ProviderWallet>,
        redis_url: &str,
        rate_limit: Option<RateLimitConfig>,
        tracker_interval: Duration,
        receipt_timeout: Duration,
    ) -> GatewayResult<Arc<Self>> {
        if wallets.is_empty() {
            return Err(GatewayError::Config(
                "at least one transaction wallet must be configured".to_string(),
            ));
        }

        let addresses: HashSet<Address> = wallets.iter().map(|wallet| wallet.address).collect();
        if addresses.len() != wallets.len() {
            return Err(GatewayError::Config(
                "transaction wallet addresses must be unique".to_string(),
            ));
        }

        let wallets = wallets
            .into_iter()
            .map(|wallet| WalletEntry {
                registry: Arc::new(WorldIdRegistryInstance::new(
                    registry_address,
                    Arc::new(wallet.provider.clone()),
                )),
                wallet,
            })
            .collect();

        let submitter = Arc::new(Self {
            wallets,
            wallet_store: WalletStore::connect(redis_url).await?,
            request_store: RequestStore::connect(redis_url).await,
            rate_limit,
            next_wallet: AtomicUsize::new(0),
            wallet_released: Notify::new(),
            receipt_timeout,
            tracker_interval,
        });

        // TODO: We should move task spawning to app initialization
        //       and track each task's JoinHandle to catch panics
        tokio::spawn(submitter.clone().run_tracker());

        Ok(submitter)
    }

    /// Records a terminal request with a specific ID without adding it to the
    /// pending set or acquiring in-flight locks.
    ///
    /// This is intended for compatibility no-op endpoints that should be
    /// visible through `/status/{request_id}` even though there is no batcher or
    /// on-chain transaction to track.
    pub async fn new_terminal_request_with_id(
        &self,
        id: String,
        kind: GatewayRequestKind,
        status: GatewayRequestState,
    ) -> Result<(), GatewayErrorResponse> {
        debug_assert!(
            matches!(
                &status,
                GatewayRequestState::Finalized { .. } | GatewayRequestState::Failed { .. }
            ),
            "new_terminal_request_with_id should only be used with terminal states"
        );

        self.request_store
            .create_terminal_request(&id, kind, status, now_unix_secs())
            .await
            .map_err(|error| {
                tracing::error!(%error, request_id = id, "Error creating terminal request");
                GatewayErrorResponse::internal_server_error()
            })
    }

    /// Creates a new request with a specific ID, atomically acquiring in-flight
    /// lock keys.
    ///
    /// If any in-flight key already exists, the operation is aborted and a
    /// `DuplicateRequestInFlight` error is returned.
    pub async fn new_request_with_id(
        &self,
        id: String,
        kind: GatewayRequestKind,
        inflight_keys: Vec<String>,
    ) -> Result<(), GatewayErrorResponse> {
        match self
            .request_store
            .create_request(&id, kind, &inflight_keys, now_unix_secs())
            .await
        {
            Ok(CreateRequestOutcome::Created) => Ok(()),
            Ok(CreateRequestOutcome::DuplicateInflight(key)) => {
                tracing::info!(%key, "Duplicate in-flight request detected");
                metrics::increment_request_rejected("duplicate_inflight");
                Err(GatewayErrorResponse::bad_request(
                    GatewayErrorCode::DuplicateRequestInFlight,
                ))
            }
            Err(error) => {
                tracing::error!(%error, request_id = id, "Error creating request");
                Err(GatewayErrorResponse::internal_server_error())
            }
        }
    }

    /// Updates the status of a single request.
    pub async fn set_status(&self, id: &str, status: GatewayRequestState) {
        self.set_status_batch(&[id.to_string()], status).await;
    }

    /// Returns a snapshot of the current state of a request, if it exists.
    pub async fn snapshot(&self, id: &str) -> Option<RequestRecord> {
        match self.request_store.request(id).await {
            Ok(record) => record,
            Err(error) => {
                tracing::error!(%error, request_id = id, "Failed to get request");
                None
            }
        }
    }

    /// Computes queued-backlog urgency statistics for a batch type.
    ///
    /// The stats include requests currently in `Queued` state whose
    /// [`GatewayRequestKind`] belongs to `batch_type`.
    pub async fn queued_backlog_stats(
        &self,
        batch_type: BatchType,
    ) -> GatewayResult<BacklogUrgencyStats> {
        let ids = self.request_store.pending_request_ids().await?;
        if ids.is_empty() {
            return Ok(BacklogUrgencyStats::default());
        }

        let records = self.request_store.requests(&ids).await?;
        let now = now_unix_secs();
        let mut queued_count = 0usize;
        let mut oldest_age_secs = 0u64;
        for (_, maybe_record) in records {
            let Some(record) = maybe_record else {
                continue;
            };

            if !matches_batch_type(record.kind, batch_type) {
                continue;
            }

            if matches!(record.status, GatewayRequestState::Queued) {
                let age = now.saturating_sub(record.updated_at);
                queued_count += 1;
                oldest_age_secs = oldest_age_secs.max(age);
            }
        }

        if queued_count == 0 {
            return Ok(BacklogUrgencyStats::default());
        }

        Ok(BacklogUrgencyStats {
            queued_count,
            oldest_age_secs,
        })
    }

    // =========================================================================
    // Rate limiting
    // =========================================================================

    /// Checks if a request for the given leaf_index should be allowed.
    ///
    /// Returns `Ok(())` if the request is allowed.
    /// Returns `Err(GatewayErrorResponse)` with rate limit error if exceeded.
    ///
    /// If rate limiting is not configured, always returns `Ok(())`.
    pub async fn check_rate_limit(
        &self,
        leaf_index: u64,
        request_id: &str,
    ) -> Result<(), GatewayErrorResponse> {
        let Some(ref rl) = self.rate_limit else {
            return Ok(());
        };
        let (window_secs, max_requests) = (rl.window_secs, rl.max_requests);

        let result = self
            .request_store
            .check_rate_limit(
                leaf_index,
                request_id,
                now_unix_secs(),
                window_secs,
                max_requests,
            )
            .await;

        match result {
            Ok(RateLimitOutcome::Exceeded) => {
                tracing::warn!(
                    leaf_index = leaf_index,
                    request_id = request_id,
                    "Rate limit exceeded"
                );
                metrics::increment_request_rejected("rate_limited");
                Err(GatewayErrorResponse::rate_limit_exceeded(
                    window_secs,
                    max_requests,
                ))
            }
            Ok(RateLimitOutcome::Allowed(count)) => {
                tracing::debug!(
                    leaf_index,
                    request_id,
                    count,
                    max = max_requests,
                    "Rate limit check passed"
                );
                Ok(())
            }
            Err(error) => {
                tracing::error!(%error, "Storage error during rate limit check");
                tracing::warn!("Rate limit check failed due to storage error, allowing request");
                Ok(())
            }
        }
    }

    /// Signs and durably records a transaction before broadcasting it.
    ///
    /// An error means submission failed before the transaction was persisted.
    /// Broadcast errors after persistence are handled by the background tracker.
    pub(crate) async fn submit(
        &self,
        transaction: TransactionRequest,
        request_ids: Vec<String>,
        batch_type: BatchType,
    ) -> GatewayResult<()> {
        let (entry, reservation_id) = match self.acquire().await {
            Ok(reservation) => reservation,
            Err(error) => {
                tracing::error!(%error, %batch_type, "failed to reserve a transaction wallet");
                return Err(error);
            }
        };

        let wallet = entry.wallet.address;
        let started_at = tokio::time::Instant::now();

        // NOTE: We sign and persist the transaction hash BEFORE broadcasting it.
        //       This ensures that we don't end up broadcasting a tx without persisting it
        //       which could result in nonce gaps or transaction overwrites.
        let signed = match entry.wallet.sign_transaction(transaction).await {
            Ok(signed) => signed,
            Err(error) => {
                tracing::error!(%error, %wallet, %batch_type, "failed to sign batch transaction");
                self.release_reservation(wallet, reservation_id).await;
                return Err(error.into());
            }
        };
        let tx_hash = *signed.tx_hash();
        let formatted_tx_hash = format!("0x{tx_hash:x}");
        let submitted_at = now_unix_secs();

        match self
            .wallet_store
            .mark_submitted(
                wallet,
                reservation_id,
                tx_hash,
                request_ids.clone(),
                batch_type,
                submitted_at,
            )
            .await
        {
            Ok(_) => {}
            Err(error) => {
                tracing::error!(%error, %wallet, tx_hash = %formatted_tx_hash, %batch_type, "failed to persist signed batch transaction");
                self.release_reservation(wallet, reservation_id).await;
                return Err(error);
            }
        };

        self.set_status_batch(
            &request_ids,
            GatewayRequestState::Submitted {
                tx_hash: formatted_tx_hash.clone(),
            },
        )
        .await;

        tracing::info!(
            tx_hash = %formatted_tx_hash,
            %wallet,
            %batch_type,
            batch_size = request_ids.len(),
            "batch transaction persisted before broadcast"
        );

        match entry.registry.provider().send_tx_envelope(signed).await {
            Ok(pending) => {
                debug_assert_eq!(*pending.tx_hash(), tx_hash);
                let send_latency_ms = started_at.elapsed().as_millis() as f64;
                metrics::record_batch_send_latency(batch_type, send_latency_ms);
                tracing::info!(
                    tx_hash = %formatted_tx_hash,
                    %wallet,
                    %batch_type,
                    batch_size = request_ids.len(),
                    send_latency_ms,
                    "batch transaction broadcast to RPC node"
                );
            }
            Err(error) => {
                let send_latency_ms = started_at.elapsed().as_millis() as f64;
                metrics::record_batch_send_failed(batch_type, send_latency_ms);
                tracing::warn!(
                    %error,
                    tx_hash = %formatted_tx_hash,
                    %wallet,
                    %batch_type,
                    send_latency_ms,
                    "batch transaction persisted but RPC broadcast failed; tracker will await receipt timeout"
                );
                // The RPC outcome may be ambiguous. Keep the durable submission
                // and let the tracker resolve it by receipt or timeout.
            }
        }

        Ok(())
    }

    async fn run_tracker(self: Arc<Self>) {
        loop {
            if let Err(error) = self.track_transactions().await {
                tracing::error!(%error, "failed to track persisted wallet transactions");
            }
            tokio::time::sleep(self.tracker_interval).await;
        }
    }

    async fn track_transactions(&self) -> GatewayResult<()> {
        let addresses: Vec<Address> = self
            .wallets
            .iter()
            .map(|entry| entry.wallet.address)
            .collect();
        let transactions = self.wallet_store.transactions(&addresses).await?;

        for (entry, transaction) in self.wallets.iter().zip(transactions) {
            let Some(transaction @ WalletTransaction::Submitted { .. }) = transaction else {
                continue;
            };
            self.track_transaction(entry, transaction).await;
        }

        Ok(())
    }

    async fn track_transaction(&self, entry: &WalletEntry, transaction: WalletTransaction) {
        let WalletTransaction::Submitted {
            reservation_id,
            tx_hash,
            request_ids,
            batch_type,
            submitted_at,
        } = transaction
        else {
            return;
        };

        let wallet = &entry.wallet;
        let formatted_tx_hash = format!("0x{tx_hash:x}");

        // TODO: This will suffice for now - but in practice we may want to wait until we have a
        //       receipt from a safe or even finalized block
        let receipt = wallet.provider.get_transaction_receipt(tx_hash).await;
        let receipt_timed_out =
            now_unix_secs().saturating_sub(submitted_at) >= self.receipt_timeout.as_secs();

        match receipt {
            Ok(Some(receipt)) => {
                let confirmed = receipt.status();
                let latency_ms = now_unix_secs().saturating_sub(submitted_at) as f64 * 1_000.0;
                metrics::record_batch_confirmed(batch_type, confirmed, latency_ms);

                if confirmed {
                    tracing::info!(
                        tx_hash = %formatted_tx_hash,
                        wallet = %wallet.address,
                        %batch_type,
                        latency_ms,
                        "batch transaction confirmed on-chain"
                    );
                } else {
                    tracing::error!(
                        tx_hash = %formatted_tx_hash,
                        wallet = %wallet.address,
                        %batch_type,
                        "batch transaction reverted on-chain"
                    );
                }

                // TODO: finalize_from_receipt calls under RequestStore::update_status under the hood
                //       which can fail and only log an error. So there's a chance we release a
                //       submission without actually finalizing the requests - we should be smarter
                //       about error handling here.
                self.finalize_from_receipt(&request_ids, confirmed, &formatted_tx_hash)
                    .await;
                self.release_submission(wallet.address, reservation_id, tx_hash)
                    .await;
            }
            Ok(None) | Err(_) if receipt_timed_out => {
                tracing::error!(
                    tx_hash = %formatted_tx_hash,
                    wallet = %wallet.address,
                    %batch_type,
                    timeout_secs = self.receipt_timeout.as_secs(),
                    "batch transaction receipt timed out"
                );

                self.set_status_batch(
                    &request_ids,
                    GatewayRequestState::failed(
                        format!(
                            "transaction receipt timed out after {}s (tx: {formatted_tx_hash})",
                            self.receipt_timeout.as_secs()
                        ),
                        Some(GatewayErrorCode::ConfirmationError),
                    ),
                )
                .await;

                // TODO: Very unlikely but possible that the transaction is still sitting in the
                //       transaction pool.
                self.release_submission(wallet.address, reservation_id, tx_hash)
                    .await;
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    tx_hash = %formatted_tx_hash,
                    wallet = %wallet.address,
                    %batch_type,
                    "failed to poll tracked batch transaction"
                );
            }
            Ok(None) => {
                // do nothing - we're still waiting for the receipt
            }
        }
    }

    /// Resolves a batch of requests based on a transaction receipt outcome.
    ///
    /// If the receipt indicates success, marks all requests as `Finalized`.
    /// If the receipt indicates a revert, marks all requests as `Failed`.
    pub async fn finalize_from_receipt(
        &self,
        ids: &[String],
        receipt_succeeded: bool,
        tx_hash: &str,
    ) {
        let status = if receipt_succeeded {
            GatewayRequestState::Finalized {
                tx_hash: tx_hash.to_string(),
            }
        } else {
            GatewayRequestState::failed(
                format!("transaction reverted on-chain (tx: {tx_hash})"),
                Some(GatewayErrorCode::TransactionReverted),
            )
        };
        self.set_status_batch(ids, status).await;
    }

    /// Acquires a wallet reservation from one of the available wallets
    ///
    /// this function cycles through wallets and returns the first one that has no reservations
    async fn acquire(&self) -> GatewayResult<(WalletEntry, Uuid)> {
        loop {
            let start = self.next_wallet.fetch_add(1, Ordering::Relaxed);
            for offset in 0..self.wallets.len() {
                let index = start.wrapping_add(offset) % self.wallets.len();
                let entry = self.wallets[index].clone();
                let reservation_id = Uuid::new_v4();
                if self
                    .wallet_store
                    .reserve(entry.wallet.address, reservation_id)
                    .await?
                {
                    return Ok((entry, reservation_id));
                }
            }

            let notified = self.wallet_released.notified();
            let _ = tokio::time::timeout(WALLET_RECHECK_INTERVAL, notified).await;
        }
    }

    async fn release_reservation(&self, wallet: Address, reservation_id: Uuid) {
        if let Err(error) = self
            .wallet_store
            .release_reservation(wallet, reservation_id)
            .await
        {
            tracing::error!(%error, %wallet, "failed to release wallet reservation");
        } else {
            self.wallet_released.notify_one();
        }
    }

    async fn release_submission(&self, wallet: Address, reservation_id: Uuid, tx_hash: TxHash) {
        if let Err(error) = self
            .wallet_store
            .release_submission(wallet, reservation_id, tx_hash)
            .await
        {
            tracing::error!(%error, %wallet, "failed to release tracked wallet transaction");
        } else {
            self.wallet_released.notify_one();
        }
    }

    /// Updates the status of multiple requests in a batch.
    pub async fn set_status_batch(&self, ids: &[String], status: GatewayRequestState) {
        for id in ids {
            if let Err(error) = self
                .request_store
                .update_status(id, &status, now_unix_secs())
                .await
            {
                tracing::error!(%error, request_id = id, "failed to update request status");
            }
        }
    }
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

fn matches_batch_type(kind: GatewayRequestKind, batch_type: BatchType) -> bool {
    match batch_type {
        BatchType::Create => matches!(kind, GatewayRequestKind::CreateAccount),
        BatchType::Ops => matches!(
            kind,
            GatewayRequestKind::InsertAuthenticator
                | GatewayRequestKind::UpdateAuthenticator
                | GatewayRequestKind::RemoveAuthenticator
                | GatewayRequestKind::UpdateRecoveryAgent
                | GatewayRequestKind::CancelRecoveryAgentUpdate
                | GatewayRequestKind::ExecuteRecoveryAgentUpdate
                | GatewayRequestKind::RecoverAccount
        ),
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        network::EthereumWallet,
        primitives::{TxHash, address},
        providers::ProviderBuilder,
        signers::local::PrivateKeySigner,
    };
    use testcontainers_modules::{
        redis::{REDIS_PORT, Redis},
        testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _},
    };
    use world_id_primitives::api_types::GatewayRequestKind;

    use super::*;

    async fn start_redis() -> (String, ContainerAsync<Redis>) {
        let container = Redis::default()
            .with_tag("latest")
            .start()
            .await
            .expect("failed to start Redis container");
        let host = container.get_host().await.unwrap();
        let port = container.get_host_port_ipv4(REDIS_PORT).await.unwrap();
        (format!("redis://{host}:{port}"), container)
    }

    fn provider_wallet(address: Address) -> ProviderWallet {
        let signer: PrivateKeySigner =
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
                .parse()
                .unwrap();
        ProviderWallet::new(
            address,
            ProviderBuilder::new()
                .connect_http("http://127.0.0.1:8545".parse().unwrap())
                .erased(),
            EthereumWallet::from(signer),
        )
    }

    #[tokio::test]
    async fn submitter_cycles_through_available_wallets() {
        let (url, _redis) = start_redis().await;
        let first = address!("1111111111111111111111111111111111111111");
        let second = address!("2222222222222222222222222222222222222222");
        let submitter = TransactionSubmitter::connect(
            Address::ZERO,
            vec![provider_wallet(first), provider_wallet(second)],
            &url,
            None,
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

        let (first_entry, first_reservation) = submitter.acquire().await.unwrap();
        let (second_entry, second_reservation) = submitter.acquire().await.unwrap();
        assert_eq!(first_entry.wallet.address, first);
        assert_eq!(second_entry.wallet.address, second);

        submitter
            .release_reservation(first, first_reservation)
            .await;
        let (next_entry, next_reservation) = submitter.acquire().await.unwrap();
        assert_eq!(next_entry.wallet.address, first);
        submitter.release_reservation(first, next_reservation).await;
        submitter
            .release_reservation(second, second_reservation)
            .await;
    }

    #[tokio::test]
    async fn submitter_fails_timed_out_transaction_and_releases_wallet() {
        let (url, _redis) = start_redis().await;
        let wallet = address!("1111111111111111111111111111111111111111");
        let submitter = TransactionSubmitter::connect(
            Address::ZERO,
            vec![provider_wallet(wallet)],
            &url,
            None,
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        submitter
            .new_request_with_id(
                "request-1".to_string(),
                GatewayRequestKind::CreateAccount,
                Vec::new(),
            )
            .await
            .unwrap();
        let reservation_id = Uuid::new_v4();
        submitter
            .wallet_store
            .reserve(wallet, reservation_id)
            .await
            .unwrap();
        submitter
            .wallet_store
            .mark_submitted(
                wallet,
                reservation_id,
                TxHash::repeat_byte(0x22),
                vec!["request-1".to_string()],
                BatchType::Create,
                now_unix_secs() - 11,
            )
            .await
            .unwrap();

        submitter.track_transactions().await.unwrap();

        let request = submitter.snapshot("request-1").await.unwrap();
        assert!(matches!(request.status, GatewayRequestState::Failed { .. }));
        assert_eq!(
            submitter
                .wallet_store
                .transactions(&[wallet])
                .await
                .unwrap(),
            [None]
        );
    }
}
