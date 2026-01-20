//! This module provides functionality for watching and validating Merkle roots. It includes:
//!
//! - A `MerkleWatcher` trait for services that validate Merkle roots.
//!
//! Current `MerkleWatcher` implementations:
//! - alloy (uses the alloy crate to interact with smart contracts)
//! - test (contains initially provided merkle roots)

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::{DynProvider, Provider as _, ProviderBuilder, WsConnect},
    rpc::types::Filter,
    sol_types::SolEvent as _,
};
use futures::StreamExt as _;
use moka::future::Cache;
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use world_id_core::world_id_registry::WorldIdRegistry::{self, RootRecorded};
use world_id_primitives::FieldElement;

/// Error returned by the [`MerkleWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
#[error("alloy error: {0}")]
pub(crate) struct MerkleWatcherError(alloy::contract::Error);

/// Monitors merkle roots from an on-chain `WorldIDRegistry` contract.
///
/// Subscribes to blockchain events and maintains a cache of valid merkle roots.
/// Uses LRU eviction when the cache exceeds the configured maximum capacity.
#[derive(Clone)]
pub(crate) struct MerkleWatcher {
    merkle_root_cache: Cache<FieldElement, ()>,
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
    /// * `cancellation_token` - CancellationToken to cancel the service in case of an error
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        contract_address: Address,
        ws_rpc_url: &str,
        max_merkle_cache_size: u64,
        started: Arc<AtomicBool>,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<Self> {
        eyre::ensure!(max_merkle_cache_size > 0, "max merkle cache size must be > 0");

        tracing::info!("creating provider...");
        let ws = WsConnect::new(ws_rpc_url);
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        let contract = WorldIdRegistry::new(contract_address, provider.clone());

        tracing::info!("get current root...");
        let current_root = contract.currentRoot().call().await?;
        tracing::info!("root = {current_root}");

        let merkle_root_cache: Cache<FieldElement, ()> = Cache::builder()
            .max_capacity(max_merkle_cache_size)
            .build();

        // Insert current root
        merkle_root_cache
            .insert(current_root.try_into()?, ())
            .await;
        tracing::info!("starting with cache size: 1");

        tracing::info!("listening for events...");
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Latest)
            .event_signature(RootRecorded::SIGNATURE_HASH);
        let sub = provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();

        // indicate that the merkle watcher has started
        started.store(true, Ordering::Relaxed);

        tokio::spawn({
            let merkle_root_cache = merkle_root_cache.clone();
            async move {
                // shutdown service if merkle watcher encounters an error and drops this guard
                let _drop_guard = cancellation_token.drop_guard();
                while let Some(log) = stream.next().await {
                    match RootRecorded::decode_log(log.as_ref()) {
                        Ok(event) => {
                            tracing::info!("got root {} timestamp {}", event.root, event.timestamp);
                            merkle_root_cache
                                .insert(
                                    event.root.try_into().expect("root is in field"),
                                    (),
                                )
                                .await;
                            tracing::trace!("registered new root: {}", event.root);
                        }
                        Err(err) => {
                            tracing::warn!("failed to decode contract event: {err:?}");
                        }
                    }
                }
            }
        });

        Ok(Self {
            merkle_root_cache,
            provider: provider.erased(),
            contract_address,
        })
    }

    #[instrument(level = "debug", skip(self))]
    pub(crate) async fn is_root_valid(
        &self,
        root: FieldElement,
    ) -> Result<bool, MerkleWatcherError> {
        // first check if the merkle root is already in cache
        if self.merkle_root_cache.contains_key(&root) {
            tracing::trace!("root was in cache");
            tracing::trace!("root valid: true");
            return Ok(true);
        }

        tracing::debug!("check in contract");
        let contract = WorldIdRegistry::new(self.contract_address, self.provider.clone());
        let valid = contract
            .isValidRoot(root.into())
            .call()
            .await
            .map_err(MerkleWatcherError)?;

        if valid {
            tracing::debug!("add root to cache");
            self.merkle_root_cache.insert(root, ()).await;
        }
        tracing::debug!("root valid: {valid}");

        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use taceo_oprf_service::StartedServices;
    use test_utils::anvil::TestAnvil;
    use tokio_util::sync::CancellationToken;

    /// Regression test for HackerOne report #3494201.
    #[tokio::test]
    async fn test_invalid_root_not_cached() {
        let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
        let signer = anvil.signer(0).expect("failed to get signer");
        let registry_address = anvil
            .deploy_world_id_registry(signer)
            .await
            .expect("failed to deploy WorldIDRegistry");

        let mut started_services = StartedServices::default();

        let cancellation_token = CancellationToken::new();

        let merkle_watcher = MerkleWatcher::init(
            registry_address,
            anvil.ws_endpoint(),
            100,
            started_services.new_service(),
            cancellation_token,
        )
        .await
        .expect("failed to init MerkleWatcher");

        let invalid_root = FieldElement::from(12345u64);

        let valid = merkle_watcher
            .is_root_valid(invalid_root)
            .await
            .expect("first is_root_valid call should not error");

        assert!(!valid, "First call should return false for invalid root");

        assert!(
            !merkle_watcher.merkle_root_cache.contains_key(&invalid_root),
            "Invalid root should NOT be cached after first rejection"
        );

        let valid_root = WorldIdRegistry::new(registry_address, anvil.provider().unwrap())
            .latestRoot()
            .call()
            .await
            .expect("failed to fetch root");

        let valid = merkle_watcher
            .is_root_valid(valid_root.try_into().expect("root in field"))
            .await
            .expect("second is_root_valid call should not error");

        assert!(valid, "Second call should return true for valid root");
    }
}
