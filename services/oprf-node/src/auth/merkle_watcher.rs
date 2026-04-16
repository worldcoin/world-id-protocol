//! This module provides functionality for validating Merkle roots on-demand.
//!
//! The `MerkleWatcher` maintains an in-memory cache of recently validated Merkle roots with a
//! fixed time-to-live. On a cache miss, it queries the `WorldIDRegistry` contract's `isValidRoot`
//! method. Valid roots are inserted into the cache; invalid roots are never cached.
//!
//! Concurrent requests for the same root are deduplicated by moka: only one contract call is made
//! and the result is shared among all waiters.

use std::{sync::Arc, time::Duration};

use alloy::{primitives::Address, providers::DynProvider};
use eyre::Context;
use moka::future::Cache;
use taceo_nodes_common::web3;
use tracing::instrument;
use world_id_core::world_id_registry::WorldIdRegistry::{self, WorldIdRegistryInstance};
use world_id_primitives::FieldElement;

use crate::metrics::{
    METRICS_ID_NODE_MERKLE_WATCHER_CACHE_HITS, METRICS_ID_NODE_MERKLE_WATCHER_CACHE_MISSES,
    METRICS_ID_NODE_MERKLE_WATCHER_CACHE_SIZE,
};

/// Error returned by the [`MerkleWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MerkleWatcherError {
    #[error("invalid Merkle root")]
    InvalidMerkleRoot,
    #[error(transparent)]
    Internal(#[from] eyre::Report),
}

impl From<Arc<MerkleWatcherError>> for MerkleWatcherError {
    fn from(value: Arc<MerkleWatcherError>) -> Self {
        match value.as_ref() {
            MerkleWatcherError::InvalidMerkleRoot => MerkleWatcherError::InvalidMerkleRoot,
            MerkleWatcherError::Internal(report) => {
                MerkleWatcherError::Internal(eyre::eyre!("{report:?}"))
            }
        }
    }
}
/// Validates merkle roots on-demand against the `WorldIDRegistry` contract.
///
/// Maintains an in-memory cache of recently validated roots with a fixed time-to-live.
/// Uses LRU eviction when the cache exceeds the configured maximum capacity.
#[derive(Clone)]
pub(crate) struct MerkleWatcher {
    merkle_root_cache: Cache<FieldElement, ()>,
    contract: WorldIdRegistryInstance<DynProvider>,
}

impl MerkleWatcher {
    /// Initializes the merkle watcher.
    ///
    /// Connects to the blockchain via the provided `rpc_provider` and sets up an in-memory cache
    /// for validated merkle roots.
    ///
    /// # Arguments
    /// * `contract_address` - Address of the `WorldIDRegistry` contract
    /// * `rpc_provider` - A configured `RpcProvider` from the `nodes-common` crate
    /// * `max_merkle_cache_size` - Maximum number of merkle roots to cache
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        contract_address: Address,
        rpc_provider: &web3::RpcProvider,
        max_merkle_cache_size: u64,
    ) -> eyre::Result<Self> {
        ::metrics::gauge!(METRICS_ID_NODE_MERKLE_WATCHER_CACHE_SIZE).set(0.0);

        eyre::ensure!(
            max_merkle_cache_size > 0,
            "max merkle cache size must be > 0"
        );

        let contract = WorldIdRegistry::new(contract_address, rpc_provider.http());

        let merkle_root_cache = Cache::builder()
            .max_capacity(max_merkle_cache_size)
            .time_to_live(Duration::from_secs(10 * 60))
            .eviction_listener(move |k, (), cause| {
                tracing::trace!("removing root {k} because: {cause:?}");
                metrics::gauge!(METRICS_ID_NODE_MERKLE_WATCHER_CACHE_SIZE,).decrement(1);
            })
            .build();

        let merkle_watcher = Self {
            merkle_root_cache,
            contract,
        };

        Ok(merkle_watcher)
    }

    #[instrument(level = "debug", skip_all, fields(root=%root))]
    pub(crate) async fn ensure_root_valid(
        &self,
        root: FieldElement,
    ) -> Result<(), MerkleWatcherError> {
        // moka promises that requests on the same key will only evaluate once and only the inserted entry will get entry.is_fresh() == true
        let entry = self
            .merkle_root_cache
            .entry(root)
            .or_try_insert_with(self.is_root_valid(root))
            .await?;
        if entry.is_fresh() {
            ::metrics::counter!(METRICS_ID_NODE_MERKLE_WATCHER_CACHE_MISSES).increment(1);
            metrics::gauge!(METRICS_ID_NODE_MERKLE_WATCHER_CACHE_SIZE).increment(1);
        } else {
            ::metrics::counter!(METRICS_ID_NODE_MERKLE_WATCHER_CACHE_HITS).increment(1);
        }
        Ok(())
    }

    async fn is_root_valid(&self, root: FieldElement) -> Result<(), MerkleWatcherError> {
        let valid = self
            .contract
            .isValidRoot(root.into())
            .call()
            .await
            .context("while calling isValidRoot")?;
        if valid {
            Ok(())
        } else {
            Err(MerkleWatcherError::InvalidMerkleRoot)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::tests::build_rpc_provider;

    use super::*;
    use world_id_test_utils::anvil::TestAnvil;

    /// Regression test for `HackerOne` report #3494201.
    ///
    /// Ensures that an invalid root queried from the contract is not inserted into the cache
    /// (so a subsequent call still hits the contract, not a stale cached "invalid" entry).
    #[tokio::test]
    async fn test_invalid_root_not_cached() {
        let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
        let signer = anvil.signer(0).expect("failed to get signer");
        let registry_address = anvil
            .deploy_world_id_registry(signer)
            .await
            .expect("failed to deploy WorldIDRegistry");

        let rpc_provider = build_rpc_provider(&anvil.instance).await;

        let merkle_watcher = MerkleWatcher::init(registry_address, &rpc_provider, 100)
            .await
            .expect("failed to init MerkleWatcher");

        let invalid_root = FieldElement::from(12345u64);

        let result = merkle_watcher.ensure_root_valid(invalid_root).await;
        assert!(
            matches!(result, Err(MerkleWatcherError::InvalidMerkleRoot)),
            "expected InvalidMerkleRoot, got {result:?}"
        );
        assert!(
            !merkle_watcher.merkle_root_cache.contains_key(&invalid_root),
            "invalid root must not be inserted into the cache"
        );
    }

    /// Verifies that a valid root is cached after the first call and that a second call is served
    /// from the cache (i.e., both calls succeed).
    #[tokio::test]
    async fn test_valid_root_is_cached_on_hit() {
        let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
        let signer = anvil.signer(0).expect("failed to get signer");
        let registry_address = anvil
            .deploy_world_id_registry(signer)
            .await
            .expect("failed to deploy WorldIDRegistry");

        let contract = WorldIdRegistry::new(
            registry_address,
            anvil.provider().expect("Can get anvil provider"),
        );

        let rpc_provider = build_rpc_provider(&anvil.instance).await;

        let merkle_watcher = MerkleWatcher::init(registry_address, &rpc_provider, 100)
            .await
            .expect("failed to init MerkleWatcher");

        let valid_root = FieldElement::try_from(
            contract
                .getLatestRoot()
                .call()
                .await
                .expect("failed to fetch root"),
        )
        .expect("root in field");

        // First call: cache miss — contract is queried, root inserted into cache.
        merkle_watcher
            .ensure_root_valid(valid_root)
            .await
            .expect("first call should succeed");

        assert!(
            merkle_watcher.merkle_root_cache.contains_key(&valid_root),
            "valid root should be in cache after first call"
        );

        // Second call: cache hit — must still succeed.
        merkle_watcher
            .ensure_root_valid(valid_root)
            .await
            .expect("second call (cache hit) should succeed");
    }
}
