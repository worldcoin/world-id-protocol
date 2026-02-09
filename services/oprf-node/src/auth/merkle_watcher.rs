//! This module provides functionality for watching and validating Merkle roots.
//! The `MerkleWatcher` subscribes to events from the `WorldIDRegistry` contract, and maintains a cache of valid Merkle roots with expiration based on a validity window.
//! In addition to the cache, it keeps track of the latest Merkle root (since it is always valid).
//! If a new root is recorded, it is added to the cache and the latest root is updated.
//! If the validity window is updated, the cache is adjusted accordingly.
//!
//! The `is_root_valid` method checks if a given root is valid like this:
//! - First, it checks if the root is the latest root or is present in the cache.
//! - If not found, it queries the contract to check if the root is valid.
//!   If valid, it adds the root to the cache with its remaining validity duration.
//!
//! # Caveats
//! - If the `root_validity_window` is updated to a smaller value, some roots in the cache may still be valid in the contract for a some time until they expire.
//!   The `MerkleWatcher` just evicts all cached roots in this case to avoid false positives.
//! - If the `root_validity_window` is updated to a larger value, existing cached roots are still valid but their expiration time is not extended.

use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::{DynProvider, Provider as _, ProviderBuilder, WsConnect},
    rpc::types::Filter,
    sol_types::SolEvent as _,
};
use eyre::Context;
use futures::StreamExt as _;
use moka::{Expiry, future::Cache};
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use world_id_core::world_id_registry::WorldIdRegistry::{
    self, RootRecorded, RootValidityWindowUpdated,
};
use world_id_primitives::FieldElement;

use crate::metrics::{
    METRICS_ID_NODE_MERKLE_WATCHER_CACHE_HITS, METRICS_ID_NODE_MERKLE_WATCHER_CACHE_MISSES,
    METRICS_ID_NODE_MERKLE_WATCHER_CACHE_SIZE,
};

/// Error returned by the [`MerkleWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
#[error("alloy error: {0}")]
pub(crate) struct MerkleWatcherError(alloy::contract::Error);

/// An expiry that implements `moka::Expiry` trait. `Expiry` trait provides the
/// default implementations of three callback methods `expire_after_create`,
/// `expire_after_read`, and `expire_after_update`.
///
/// In this example, we only override the `expire_after_create` method to set
/// the expiration duration based on `root_validity_window` (the value of the entry).
pub struct RootExpiry;

impl Expiry<FieldElement, Duration> for RootExpiry {
    /// Returns the duration of the expiration of the value that was just created.
    fn expire_after_create(
        &self,
        _key: &FieldElement,
        value: &Duration,
        _current_time: Instant,
    ) -> Option<Duration> {
        Some(*value)
    }
}

/// Monitors merkle roots from an on-chain `WorldIDRegistry` contract.
///
/// Subscribes to blockchain events and maintains a cache of valid merkle roots.
/// Uses LRU eviction when the cache exceeds the configured maximum capacity.
#[derive(Clone)]
pub(crate) struct MerkleWatcher {
    latest_root: Arc<RwLock<FieldElement>>,
    merkle_root_cache: Cache<FieldElement, Duration>,
    root_validity_window: Arc<AtomicU64>,
    provider: DynProvider, // do not drop provider while we want to stay subscribed
    contract_address: Address,
}

impl MerkleWatcher {
    /// Initializes the merkle watcher and starts listening for events.
    ///
    /// Connects to the blockchain via WebSocket, fetches the current merkle root,
    /// and spawns a background task to monitor for new `RootRecorded` events.
    ///
    /// # Arguments
    /// * `contract_address` - Address of the `WorldIDRegistry` contract
    /// * `ws_rpc_url` - WebSocket RPC URL for blockchain connection
    /// * `max_merkle_cache_size` - Maximum number of merkle roots to cache
    /// * `cache_maintenance_interval` - Interval for running cache maintenance tasks
    /// * `started` - AtomicBool to indicate when the service has started
    /// * `cancellation_token` - CancellationToken to cancel the service in case of an error
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        contract_address: Address,
        ws_rpc_url: &str,
        max_merkle_cache_size: u64,
        cache_maintenance_interval: Duration,
        started: Arc<AtomicBool>,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<(Self, tokio::task::JoinHandle<eyre::Result<()>>)> {
        ::metrics::gauge!(METRICS_ID_NODE_MERKLE_WATCHER_CACHE_SIZE).set(0.0);

        eyre::ensure!(
            max_merkle_cache_size > 0,
            "max merkle cache size must be > 0"
        );

        tracing::info!("creating provider...");
        let ws = WsConnect::new(ws_rpc_url);
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        let contract = WorldIdRegistry::new(contract_address, provider.clone());

        let merkle_root_cache = Cache::builder()
            .max_capacity(max_merkle_cache_size)
            .expire_after(RootExpiry)
            .build();

        // we subscribe here to not miss any events between fetching the latest root and starting the subscription
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Latest)
            .event_signature(vec![
                RootRecorded::SIGNATURE_HASH,
                RootValidityWindowUpdated::SIGNATURE_HASH,
            ]);
        let sub = provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();

        let get_latest_root = contract.getLatestRoot();
        let get_root_validity_window = contract.getRootValidityWindow();
        let (latest_root, root_validity_window) =
            tokio::join!(get_latest_root.call(), get_root_validity_window.call());

        let latest_root =
            FieldElement::try_from(latest_root.context("while fetching latest root")?)
                .expect("root is in field");
        let root_validity_window =
            u64::try_from(root_validity_window.context("while fetching root validity window")?)
                .expect("fits in u64");

        tracing::info!("latest root = {latest_root}");
        tracing::info!("root validity window = {root_validity_window} seconds");

        // insert the latest root into the cache
        // it might be older than the validity window, so we use the actual timestamp from the contract
        // to calculate the remaining validity duration
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs();
        let latest_root_timestamp =
            u64::try_from(contract.getRootTimestamp(latest_root.into()).call().await?)
                .expect("fits in u64");
        let elapsed = current_timestamp.saturating_sub(latest_root_timestamp);

        if elapsed >= root_validity_window {
            tracing::debug!("latest root is expired, not caching");
        } else {
            let remaining_validity =
                Duration::from_secs(root_validity_window.saturating_sub(elapsed));
            tracing::debug!("insert latest root with remaining validity {remaining_validity:?}");
            merkle_root_cache
                .insert(latest_root, remaining_validity)
                .await;
        }

        let latest_root = Arc::new(RwLock::new(latest_root));
        let root_validity_window = Arc::new(AtomicU64::new(root_validity_window));

        // indicate that the merkle watcher has started
        started.store(true, Ordering::Relaxed);

        tracing::info!("listening for events...");
        let subscribe_task = tokio::spawn({
            let latest_root = Arc::clone(&latest_root);
            let merkle_root_cache = merkle_root_cache.clone();
            let root_validity_window = Arc::clone(&root_validity_window);
            async move {
                // shutdown service if merkle watcher encounters an error and drops this guard
                let _drop_guard = cancellation_token.clone().drop_guard();
                loop {
                    let log = tokio::select! {
                        log = stream.next() => {
                            log.ok_or_else(||eyre::eyre!("MerkleWatcher subscribe stream was closed"))?
                        }
                        _ = cancellation_token.cancelled() => {
                            break;
                        }
                    };

                    match log.topic0() {
                        Some(&RootRecorded::SIGNATURE_HASH) => {
                            match RootRecorded::decode_log(log.as_ref()) {
                                Ok(event) => {
                                    tracing::info!("got root {}", event.root,);
                                    let root = FieldElement::try_from(event.root)
                                        .expect("root is in field");

                                    // update latest root
                                    *latest_root.write().expect("not poisoned") = root;

                                    let root_validity_window = Duration::from_secs(
                                        root_validity_window.load(Ordering::Relaxed),
                                    );
                                    tracing::debug!(
                                        "insert root with current validity window {root_validity_window:?}"
                                    );
                                    merkle_root_cache.insert(root, root_validity_window).await;
                                }
                                Err(err) => {
                                    tracing::warn!("failed to decode contract event: {err:?}");
                                }
                            }
                        }
                        Some(&RootValidityWindowUpdated::SIGNATURE_HASH) => {
                            match RootValidityWindowUpdated::decode_log(log.as_ref()) {
                                Ok(event) => {
                                    tracing::info!("got root validity window update");
                                    let old_window =
                                        u64::try_from(event.oldWindow).expect("fits in u64");
                                    let new_window =
                                        u64::try_from(event.newWindow).expect("fits in u64");

                                    tracing::info!(
                                        "root validity window updated from {old_window}s to {new_window}s"
                                    );
                                    root_validity_window.store(new_window, Ordering::Relaxed);

                                    // invalidate all cached roots if the validity window decreased
                                    if new_window < old_window {
                                        merkle_root_cache.invalidate_all();
                                    }

                                    // could theoretically be optimized to only invalidate roots that are expired after the update.
                                    // in case the validity window increased, all existing roots are still valid but should be valid for longer.
                                    // could re-insert them with the remaining validity time, but not strictly necessary.
                                }
                                Err(err) => {
                                    tracing::warn!("failed to decode contract event: {err:?}");
                                }
                            }
                        }
                        x => {
                            tracing::warn!("received unknown event {x:?}");
                        }
                    }
                }
                tracing::info!("Successfully shutdown MerkleWatcher");
                eyre::Ok(())
            }
        });

        // periodically run maintenance tasks on the cache and update metrics
        tokio::spawn({
            let merkle_root_cache = merkle_root_cache.clone();
            let mut interval = tokio::time::interval(cache_maintenance_interval);
            async move {
                loop {
                    interval.tick().await;
                    merkle_root_cache.run_pending_tasks().await;
                    let size = merkle_root_cache.entry_count() as f64;
                    ::metrics::gauge!(METRICS_ID_NODE_MERKLE_WATCHER_CACHE_SIZE).set(size);
                }
            }
        });

        let merkle_watcher = Self {
            latest_root,
            merkle_root_cache,
            root_validity_window,
            provider: provider.erased(),
            contract_address,
        };

        Ok((merkle_watcher, subscribe_task))
    }

    #[instrument(level = "debug", skip(self))]
    pub(crate) async fn is_root_valid(
        &self,
        root: FieldElement,
    ) -> Result<bool, MerkleWatcherError> {
        // first check if the merkle root is already in cache or is the latest root
        if *self.latest_root.read().expect("not poisoned") == root
            || self.merkle_root_cache.contains_key(&root)
        {
            tracing::trace!("root was in cache");
            tracing::trace!("root valid: true");
            ::metrics::counter!(METRICS_ID_NODE_MERKLE_WATCHER_CACHE_HITS).increment(1);
            return Ok(true);
        }

        tracing::debug!("check in contract");
        let contract = WorldIdRegistry::new(self.contract_address, self.provider.clone());
        let valid = contract
            .isValidRoot(root.into())
            .call()
            .await
            .map_err(MerkleWatcherError)?;

        tracing::debug!("root valid: {valid}");

        if valid {
            ::metrics::counter!(METRICS_ID_NODE_MERKLE_WATCHER_CACHE_MISSES).increment(1);

            let root_validity_window = self.root_validity_window.load(Ordering::Relaxed);
            let current_timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after epoch")
                .as_secs();
            let root_timestamp = u64::try_from(
                contract
                    .getRootTimestamp(root.into())
                    .call()
                    .await
                    .map_err(MerkleWatcherError)?,
            )
            .expect("fits in u64");
            let elapsed = current_timestamp.saturating_sub(root_timestamp);

            if elapsed >= root_validity_window {
                tracing::debug!("root is expired, not caching");
            } else {
                let remaining_validity =
                    Duration::from_secs(root_validity_window.saturating_sub(elapsed));
                tracing::debug!("insert root with remaining validity {remaining_validity:?}");
                self.merkle_root_cache
                    .insert(root, remaining_validity)
                    .await;
            }
        }

        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{U256, address};
    use taceo_oprf::service::StartedServices;
    use test_utils::anvil::TestAnvil;
    use tokio_util::sync::CancellationToken;

    const CACHED: u8 = 0b0001;
    const LATEST: u8 = 0b0010;

    macro_rules! assert_root {
        ($merkle_watcher: expr, $root: expr, $flags: expr) => {
            if ($flags & CACHED) != 0 {
                assert!(
                    $merkle_watcher.merkle_root_cache.contains_key(&$root),
                    concat!(stringify!($root), " should be cached")
                );
            } else {
                assert!(
                    !$merkle_watcher.merkle_root_cache.contains_key(&$root),
                    concat!(stringify!($root), " should NOT be cached")
                );
            }

            if ($flags & LATEST) != 0 {
                assert!(
                    *$merkle_watcher.latest_root.read().expect("not poisoned") == $root,
                    concat!(stringify!($root), " should be latest")
                );
            } else {
                assert!(
                    *$merkle_watcher.latest_root.read().expect("not poisoned") != $root,
                    concat!(stringify!($root), " should NOT be latest")
                );
            }
        };
    }

    /// Regression test for HackerOne report #3494201.
    #[tokio::test]
    async fn test_invalid_root_not_cached() {
        let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
        let signer = anvil.signer(0).expect("failed to get signer");
        let registry_address = anvil
            .deploy_world_id_registry(signer)
            .await
            .expect("failed to deploy WorldIDRegistry");
        let contract = WorldIdRegistry::new(registry_address, anvil.provider().unwrap());

        let started_services = StartedServices::default();

        let cancellation_token = CancellationToken::new();

        let (merkle_watcher, _) = MerkleWatcher::init(
            registry_address,
            anvil.ws_endpoint(),
            100,
            Duration::from_secs(3600),
            started_services.new_service(),
            cancellation_token,
        )
        .await
        .expect("failed to init MerkleWatcher");

        let invalid_root = FieldElement::from(12345u64);

        assert_root!(merkle_watcher, invalid_root, !(CACHED | LATEST));

        let valid_root = FieldElement::try_from(
            contract
                .getLatestRoot()
                .call()
                .await
                .expect("failed to fetch root"),
        )
        .expect("root in field");

        assert_root!(merkle_watcher, valid_root, CACHED | LATEST);
    }

    #[tokio::test]
    async fn test_root_validity_window() {
        let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
        let signer = anvil.signer(0).expect("failed to get signer");
        let registry_address = anvil
            .deploy_world_id_registry(signer.clone())
            .await
            .expect("failed to deploy WorldIDRegistry");
        let contract = WorldIdRegistry::new(registry_address, anvil.provider().unwrap());
        anvil
            .set_root_validity_window(registry_address, signer.clone(), 5)
            .await;

        let started_services = StartedServices::default();

        let cancellation_token = CancellationToken::new();

        let (merkle_watcher, _) = MerkleWatcher::init(
            registry_address,
            anvil.ws_endpoint(),
            100,
            Duration::from_secs(1),
            started_services.new_service(),
            cancellation_token,
        )
        .await
        .expect("failed to init MerkleWatcher");

        let root_0 = FieldElement::try_from(
            contract
                .getLatestRoot()
                .call()
                .await
                .expect("failed to fetch root"),
        )
        .expect("root in field");

        // root_0 should be cached and latest, unless it took longer than validity window to get here
        assert_root!(merkle_watcher, root_0, CACHED | LATEST);

        let root_1 = anvil
            .create_account(
                registry_address,
                signer.clone(),
                address!("0x0000000000000000000000000000000000000011"),
                U256::from(11),
                U256::from(1),
            )
            .await;

        // root_0 should still be cached, unless createAccount took longer than validity window
        assert_root!(merkle_watcher, root_0, CACHED);

        assert_root!(merkle_watcher, root_1, CACHED | LATEST);

        // wait for validity window to pass
        tokio::time::sleep(Duration::from_secs(6)).await;

        assert_root!(merkle_watcher, root_0, !(CACHED | LATEST));

        assert_root!(merkle_watcher, root_1, LATEST);
    }

    #[tokio::test]
    async fn test_root_validity_window_update() {
        let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
        let signer = anvil.signer(0).expect("failed to get signer");
        let registry_address = anvil
            .deploy_world_id_registry(signer.clone())
            .await
            .expect("failed to deploy WorldIDRegistry");
        let contract = WorldIdRegistry::new(registry_address, anvil.provider().unwrap());
        anvil
            .set_root_validity_window(registry_address, signer.clone(), 5)
            .await;

        let started_services = StartedServices::default();

        let cancellation_token = CancellationToken::new();

        let (merkle_watcher, _) = MerkleWatcher::init(
            registry_address,
            anvil.ws_endpoint(),
            100,
            Duration::from_secs(1),
            started_services.new_service(),
            cancellation_token,
        )
        .await
        .expect("failed to init MerkleWatcher");
        let root_0 = FieldElement::try_from(
            contract
                .getLatestRoot()
                .call()
                .await
                .expect("failed to fetch root"),
        )
        .expect("root in field");

        // root_0 should be cached and latest, unless it took longer than validity window to get here
        assert_root!(merkle_watcher, root_0, CACHED | LATEST);

        // set longer validity window
        anvil
            .set_root_validity_window(registry_address, signer.clone(), 3600)
            .await;

        let root_1 = anvil
            .create_account(
                registry_address,
                signer.clone(),
                address!("0x0000000000000000000000000000000000000011"),
                U256::from(11),
                U256::from(1),
            )
            .await;

        // wait for old validity window to pass
        tokio::time::sleep(Duration::from_secs(6)).await;

        // atm we dont reinsert old roots on validity window update, so root_0 is not cached anymore
        assert_root!(merkle_watcher, root_0, !(CACHED | LATEST));

        // root_1 should be cached and latest because validity window is 1h
        assert_root!(merkle_watcher, root_1, CACHED | LATEST);
    }
}
