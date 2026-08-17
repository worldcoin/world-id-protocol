use std::{sync::Arc, time::Duration};

use alloy::{primitives::Address, providers::Provider, rpc::types::TransactionRequest};
use uuid::Uuid;
use world_id_primitives::api_types::{GatewayErrorCode, GatewayRequestState};
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;
use world_id_services_common::ProviderWallet;

use crate::{
    error::GatewayResult,
    metrics,
    request_tracker::{RequestTracker, now_unix_secs},
    storage::wallet_store::{WalletStore, WalletTransaction},
};

const WALLET_RECHECK_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone)]
struct WalletEntry {
    wallet: ProviderWallet,
    registry: Arc<WorldIdRegistryInstance<Arc<alloy::providers::DynProvider>>>,
}

struct TransactionSubmitterInner {
    wallet: WalletEntry,
    store: WalletStore,
    tracker: RequestTracker,
    receipt_timeout: Duration,
    tracker_interval: Duration,
}

/// Signs, persists, broadcasts, and tracks transactions for the configured wallet.
#[derive(Clone)]
pub(crate) struct TransactionSubmitter {
    inner: Arc<TransactionSubmitterInner>,
}

impl TransactionSubmitter {
    /// Creates a submitter and starts its persistent receipt tracker.
    pub(crate) async fn connect(
        registry_address: Address,
        wallet: ProviderWallet,
        redis_url: &str,
        tracker: RequestTracker,
        tracker_interval: Duration,
        receipt_timeout: Duration,
    ) -> GatewayResult<Self> {
        let wallet = WalletEntry {
            registry: Arc::new(WorldIdRegistryInstance::new(
                registry_address,
                Arc::new(wallet.provider.clone()),
            )),
            wallet,
        };
        let submitter = Self {
            inner: Arc::new(TransactionSubmitterInner {
                wallet,
                store: WalletStore::connect(redis_url).await?,
                tracker,
                receipt_timeout,
                tracker_interval,
            }),
        };
        tokio::spawn(submitter.clone().run_tracker());
        Ok(submitter)
    }

    /// Signs and durably records a transaction before broadcasting it.
    ///
    /// An error means submission failed before the transaction was persisted.
    /// Broadcast errors after persistence are handled by the background tracker.
    pub(crate) async fn submit(
        &self,
        transaction: TransactionRequest,
        request_ids: Vec<String>,
        batch_type: &'static str,
    ) -> GatewayResult<()> {
        let lease = match self.acquire().await {
            Ok(lease) => lease,
            Err(error) => {
                tracing::error!(%error, batch_type, "failed to reserve a transaction wallet");
                return Err(error);
            }
        };
        let wallet = lease.entry.wallet.address;
        let started_at = tokio::time::Instant::now();

        let signed = match lease.entry.wallet.sign_transaction(transaction).await {
            Ok(signed) => signed,
            Err(error) => {
                tracing::error!(%error, %wallet, batch_type, "failed to sign batch transaction");
                lease.release_reservation().await;
                return Err(error.into());
            }
        };
        let tx_hash = *signed.tx_hash();
        let formatted_tx_hash = format!("0x{tx_hash:x}");
        let submitted_at = now_unix_secs();

        match self
            .inner
            .store
            .mark_submitted(
                wallet,
                lease.reservation_id,
                tx_hash,
                request_ids.clone(),
                batch_type,
                submitted_at,
            )
            .await
        {
            Ok(_) => {}
            Err(error) => {
                tracing::error!(%error, %wallet, tx_hash = %formatted_tx_hash, batch_type, "failed to persist signed batch transaction");
                lease.release_reservation().await;
                return Err(error);
            }
        };

        self.inner
            .tracker
            .set_status_batch(
                &request_ids,
                GatewayRequestState::Submitted {
                    tx_hash: formatted_tx_hash.clone(),
                },
            )
            .await;

        tracing::info!(
            tx_hash = %formatted_tx_hash,
            %wallet,
            batch_type,
            batch_size = request_ids.len(),
            "batch transaction persisted before broadcast"
        );

        match lease
            .entry
            .registry
            .provider()
            .send_tx_envelope(signed)
            .await
        {
            Ok(pending) => {
                debug_assert_eq!(*pending.tx_hash(), tx_hash);
                let send_latency_ms = started_at.elapsed().as_millis() as f64;
                metrics::record_batch_send_latency(batch_type, send_latency_ms);
                tracing::info!(
                    tx_hash = %formatted_tx_hash,
                    %wallet,
                    batch_type,
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
                    batch_type,
                    send_latency_ms,
                    "batch transaction persisted but RPC broadcast failed; tracker will await receipt timeout"
                );
                // The RPC outcome may be ambiguous. Keep the durable submission
                // and let the tracker resolve it by receipt or timeout.
            }
        }

        Ok(())
    }

    async fn acquire(&self) -> GatewayResult<TransactionLease> {
        loop {
            let entry = self.inner.wallet.clone();
            let reservation_id = Uuid::new_v4();
            if self
                .inner
                .store
                .reserve(entry.wallet.address, reservation_id)
                .await?
            {
                return Ok(TransactionLease {
                    submitter: self.clone(),
                    entry,
                    reservation_id,
                });
            }

            tokio::time::sleep(WALLET_RECHECK_INTERVAL).await;
        }
    }

    async fn run_tracker(self) {
        loop {
            if let Err(error) = self.track_transactions().await {
                tracing::error!(%error, "failed to track persisted wallet transactions");
            }
            tokio::time::sleep(self.inner.tracker_interval).await;
        }
    }

    async fn track_transactions(&self) -> GatewayResult<()> {
        let entry = &self.inner.wallet;
        let transactions = self
            .inner
            .store
            .transactions(&[entry.wallet.address])
            .await?;
        if let Some(Some(transaction @ WalletTransaction::Submitted { .. })) =
            transactions.into_iter().next()
        {
            self.track_transaction(entry, transaction).await;
        }
        Ok(())
    }

    async fn track_transaction(&self, entry: &WalletEntry, transaction: WalletTransaction) {
        let WalletTransaction::Submitted {
            tx_hash,
            ref request_ids,
            ref batch_type,
            submitted_at,
            ..
        } = transaction
        else {
            return;
        };
        let formatted_tx_hash = format!("0x{tx_hash:x}");
        let receipt = entry
            .registry
            .provider()
            .get_transaction_receipt(tx_hash)
            .await;

        if let Ok(Some(receipt)) = &receipt {
            let confirmed = receipt.status();
            let latency_ms = now_unix_secs().saturating_sub(submitted_at) as f64 * 1_000.0;
            let metric_batch_type = if batch_type == "create" {
                "create"
            } else {
                "ops"
            };
            metrics::record_batch_confirmed(metric_batch_type, confirmed, latency_ms);
            if confirmed {
                tracing::info!(
                    tx_hash = %formatted_tx_hash,
                    wallet = %entry.wallet.address,
                    batch_type,
                    latency_ms,
                    "batch transaction confirmed on-chain"
                );
            } else {
                tracing::error!(
                    tx_hash = %formatted_tx_hash,
                    wallet = %entry.wallet.address,
                    batch_type,
                    "batch transaction reverted on-chain"
                );
            }
            if request_ids.is_empty() {
                self.inner
                    .tracker
                    .finalize_submitted_transaction(confirmed, &formatted_tx_hash)
                    .await;
            } else {
                self.inner
                    .tracker
                    .finalize_from_receipt(request_ids, confirmed, &formatted_tx_hash)
                    .await;
            }
            self.release_submission(entry.wallet.address, &transaction)
                .await;
            return;
        }

        if submitted_at != 0
            && now_unix_secs().saturating_sub(submitted_at) >= self.inner.receipt_timeout.as_secs()
        {
            tracing::error!(
                tx_hash = %formatted_tx_hash,
                wallet = %entry.wallet.address,
                batch_type,
                timeout_secs = self.inner.receipt_timeout.as_secs(),
                "batch transaction receipt timed out"
            );
            self.inner
                .tracker
                .set_status_batch(
                    request_ids,
                    GatewayRequestState::failed(
                        format!(
                            "transaction receipt timed out after {}s (tx: {formatted_tx_hash})",
                            self.inner.receipt_timeout.as_secs()
                        ),
                        Some(GatewayErrorCode::ConfirmationError),
                    ),
                )
                .await;
            self.release_submission(entry.wallet.address, &transaction)
                .await;
            return;
        }

        if let Err(error) = receipt {
            tracing::warn!(
                %error,
                tx_hash = %formatted_tx_hash,
                wallet = %entry.wallet.address,
                batch_type,
                "failed to poll tracked batch transaction"
            );
        }
    }

    async fn release_submission(&self, wallet: Address, transaction: &WalletTransaction) {
        let WalletTransaction::Submitted {
            reservation_id,
            tx_hash,
            ..
        } = transaction
        else {
            return;
        };
        if let Err(error) = self
            .inner
            .store
            .release_submission(wallet, *reservation_id, *tx_hash)
            .await
        {
            tracing::error!(%error, %wallet, "failed to release tracked wallet transaction");
        }
    }
}

struct TransactionLease {
    submitter: TransactionSubmitter,
    entry: WalletEntry,
    reservation_id: Uuid,
}

impl TransactionLease {
    async fn release_reservation(&self) {
        if let Err(error) = self
            .submitter
            .inner
            .store
            .release_reservation(self.entry.wallet.address, self.reservation_id)
            .await
        {
            tracing::error!(
                %error,
                wallet = %self.entry.wallet.address,
                "failed to release wallet reservation"
            );
        }
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

    async fn redis_url() -> (String, ContainerAsync<Redis>) {
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
    async fn tracker_fails_timed_out_transaction_and_releases_wallet() {
        let (url, _redis) = redis_url().await;
        let tracker = RequestTracker::new(url.clone(), None).await;
        tracker
            .new_request_with_id(
                "request-1".to_string(),
                GatewayRequestKind::CreateAccount,
                Vec::new(),
            )
            .await
            .unwrap();
        let wallet = address!("1111111111111111111111111111111111111111");
        let submitter = TransactionSubmitter::connect(
            Address::ZERO,
            provider_wallet(wallet),
            &url,
            tracker.clone(),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        let reservation_id = Uuid::new_v4();
        submitter
            .inner
            .store
            .reserve(wallet, reservation_id)
            .await
            .unwrap();
        submitter
            .inner
            .store
            .mark_submitted(
                wallet,
                reservation_id,
                TxHash::repeat_byte(0x22),
                vec!["request-1".to_string()],
                "create",
                now_unix_secs() - 11,
            )
            .await
            .unwrap();

        submitter.track_transactions().await.unwrap();

        let request = tracker.snapshot("request-1").await.unwrap();
        assert!(matches!(request.status, GatewayRequestState::Failed { .. }));
        assert_eq!(
            submitter.inner.store.transactions(&[wallet]).await.unwrap(),
            [None]
        );
    }
}
