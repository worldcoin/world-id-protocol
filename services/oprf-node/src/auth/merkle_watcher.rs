//! On-demand validation and caching of Merkle roots from the `WorldIDRegistry`.
//!
//! The [`MerkleWatcher`] validates roots against the on-chain contract on cache
//! miss, then caches valid roots for a configurable TTL. Subsequent requests for
//! the same root are served from cache until the entry expires.
//!
//! On-chain root changes (new `RootRecorded` events or validity window updates)
//! may take up to the configured TTL to propagate. Operators should use a
//! reasonably small TTL to balance freshness against RPC load.

use std::sync::Arc;

use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider},
};
use backon::Retryable as _;
use eyre::Context;
use moka::future::Cache;
use taceo_nodes_common::web3;
use tracing::instrument;
use world_id_primitives::FieldElement;
use world_id_registries::world_id::WorldIdRegistry::{self, WorldIdRegistryInstance};

use crate::{config::WatcherCacheConfig, metrics};

/// Error returned by the [`MerkleWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MerkleWatcherError {
    #[error("invalid Merkle root")]
    InvalidMerkleRoot,
    #[error("merkle root unknown")]
    UnknownMerkleRoot,
    #[error("Internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

/// Validates and caches merkle roots from the `WorldIDRegistry` contract.
///
/// Roots are validated on-demand via `eth_call` and cached with a configurable
/// TTL. Uses LRU eviction when the cache exceeds the configured maximum capacity.
#[derive(Clone)]
pub(crate) struct MerkleWatcher {
    merkle_root_cache: Cache<FieldElement, ()>,
    contract: WorldIdRegistryInstance<DynProvider>,
    cache_config: WatcherCacheConfig,
}

impl MerkleWatcher {
    /// Initializes the merkle watcher with an empty cache.
    ///
    /// # Arguments
    /// * `contract_address` - Address of the `WorldIDRegistry` contract
    /// * `http_rpc_provider` - HTTP RPC provider for on-chain calls
    /// * `cache_config` - Cache size and TTL configuration
    #[instrument(level = "info", skip_all)]
    pub(crate) fn init(
        contract_address: Address,
        http_rpc_provider: &web3::HttpRpcProvider,
        cache_config: WatcherCacheConfig,
    ) -> Self {
        metrics::merkle_cache::reset();

        let contract = WorldIdRegistry::new(contract_address, http_rpc_provider.inner());

        let merkle_root_cache_builder = Cache::builder()
            .max_capacity(cache_config.max_cache_size.get())
            .time_to_live(cache_config.time_to_live)
            .eviction_listener(move |root, (), cause| {
                tracing::debug!("removing merkle-root {root} because: {cause:?}");
                metrics::merkle_cache::dec();
            });

        let merkle_root_cache = if let Some(time_to_idle) = cache_config.time_to_idle {
            merkle_root_cache_builder.time_to_idle(time_to_idle).build()
        } else {
            merkle_root_cache_builder.build()
        };

        Self {
            merkle_root_cache,
            contract,
            cache_config,
        }
    }

    #[instrument(level = "debug", skip_all, fields(root=%root))]
    pub(crate) async fn ensure_root_valid(
        &self,
        root: FieldElement,
    ) -> Result<(), Arc<MerkleWatcherError>> {
        let is_valid_root = (|| async {
            let (valid, root_time_stamp) = self
                .contract
                .provider()
                .multicall()
                .add(self.contract.isValidRoot(root.into()))
                .add(self.contract.getRootTimestamp(root.into()))
                .aggregate()
                .await
                .context("while doing isValidRoot multi-call")?;
            if valid {
                Ok(())
            } else if root_time_stamp == 0 {
                Err(MerkleWatcherError::UnknownMerkleRoot)
            } else {
                Err(MerkleWatcherError::InvalidMerkleRoot)
            }
        })
        .retry(self.cache_config.backoff_strategy())
        .sleep(tokio::time::sleep)
        .when(|e| matches!(e, MerkleWatcherError::UnknownMerkleRoot))
        .notify(|err, duration| {
            tracing::warn!(%err, "Ensure root valid will retry after {duration:?}");
        });

        let entry = self
            .merkle_root_cache
            .entry(root)
            .or_try_insert_with(is_valid_root)
            .await?;
        if entry.is_fresh() {
            metrics::merkle_cache::inc();
            metrics::merkle_cache::miss();
        } else {
            metrics::merkle_cache::hit();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use alloy::primitives::{Address, U256};
    use world_id_test_utils::anvil::TestAnvil;

    use crate::{auth::tests::build_http_provider, config::WatcherCacheConfig};

    #[tokio::test]
    async fn test_valid_root_accepted() -> eyre::Result<()> {
        let anvil = TestAnvil::spawn_with_multicall3().await?;
        let signer = anvil.signer(0)?;
        let registry_address = anvil.deploy_world_id_registry(signer.clone()).await?;
        let root = anvil
            .create_account(
                registry_address,
                signer.clone(),
                Address::with_last_byte(1),
                U256::from(42),
                U256::from(1),
            )
            .await;

        let http_rpc_provider = build_http_provider(&anvil.instance);
        let watcher = MerkleWatcher::init(
            registry_address,
            &http_rpc_provider,
            WatcherCacheConfig::default(),
        );

        watcher
            .ensure_root_valid(root)
            .await
            .expect("valid root should be accepted");
        Ok(())
    }

    #[tokio::test]
    async fn test_unknown_root_rejected() -> eyre::Result<()> {
        let anvil = TestAnvil::spawn_with_multicall3().await?;
        let signer = anvil.signer(0)?;
        let registry_address = anvil.deploy_world_id_registry(signer.clone()).await?;

        let http_rpc_provider = build_http_provider(&anvil.instance);
        let watcher = MerkleWatcher::init(
            registry_address,
            &http_rpc_provider,
            WatcherCacheConfig::default(),
        );

        let unknown_root = FieldElement::from(99999u64);
        let err = watcher
            .ensure_root_valid(unknown_root)
            .await
            .expect_err("unknown root should be rejected");
        assert!(
            matches!(err.as_ref(), MerkleWatcherError::UnknownMerkleRoot),
            "expected UnknownMerkleRoot, got: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_outdated_root_rejected() -> eyre::Result<()> {
        let anvil = TestAnvil::spawn_with_multicall3().await?;
        let signer = anvil.signer(0)?;
        let registry_address = anvil.deploy_world_id_registry(signer.clone()).await?;

        // Record root1 (becomes latest).
        let root1 = anvil
            .create_account(
                registry_address,
                signer.clone(),
                Address::with_last_byte(1),
                U256::from(42),
                U256::from(1),
            )
            .await;

        // Collapse the validity window so any non-latest root is immediately expired.
        anvil
            .set_root_validity_window(registry_address, signer.clone(), 0)
            .await;

        // Record root2 — this supersedes root1, which is now expired (ts1 + 0 < block.timestamp).
        let root2 = anvil
            .create_account(
                registry_address,
                signer.clone(),
                Address::with_last_byte(2),
                U256::from(43),
                U256::from(2),
            )
            .await;

        let http_rpc_provider = build_http_provider(&anvil.instance);
        let watcher = MerkleWatcher::init(
            registry_address,
            &http_rpc_provider,
            WatcherCacheConfig::default(),
        );

        // root1 was recorded (ts != 0) but is now expired — InvalidMerkleRoot, not retried.
        let err = watcher
            .ensure_root_valid(root1)
            .await
            .expect_err("outdated root should be rejected");
        assert!(
            matches!(err.as_ref(), MerkleWatcherError::InvalidMerkleRoot),
            "expected InvalidMerkleRoot for outdated root, got: {err:?}"
        );
        assert!(
            !watcher.merkle_root_cache.contains_key(&root1),
            "outdated root must not be cached"
        );

        // root2 is the current latest root and must be accepted.
        watcher
            .ensure_root_valid(root2)
            .await
            .expect("latest root should be accepted");
        Ok(())
    }

    /// Regression test for `HackerOne` report #3494201: invalid roots must not be cached.
    #[tokio::test]
    async fn test_invalid_root_not_cached() -> eyre::Result<()> {
        let anvil = TestAnvil::spawn_with_multicall3().await?;
        let signer = anvil.signer(0)?;
        let registry_address = anvil.deploy_world_id_registry(signer.clone()).await?;

        let http_rpc_provider = build_http_provider(&anvil.instance);
        let watcher = MerkleWatcher::init(
            registry_address,
            &http_rpc_provider,
            WatcherCacheConfig::default(),
        );

        let unknown_root = FieldElement::from(99999u64);

        let err1 = watcher
            .ensure_root_valid(unknown_root)
            .await
            .expect_err("first call should fail");
        assert!(matches!(
            err1.as_ref(),
            MerkleWatcherError::UnknownMerkleRoot
        ));

        assert!(
            !watcher.merkle_root_cache.contains_key(&unknown_root),
            "Cache should not have unknown root cached"
        );

        // second call should fail again
        let err2 = watcher
            .ensure_root_valid(unknown_root)
            .await
            .expect_err("second call should also fail (error must not be cached)");
        assert!(matches!(
            err2.as_ref(),
            MerkleWatcherError::UnknownMerkleRoot
        ));
        Ok(())
    }

    #[tokio::test]
    async fn test_valid_root_cache_hit() -> eyre::Result<()> {
        let anvil = TestAnvil::spawn_with_multicall3().await?;
        let signer = anvil.signer(0)?;
        let registry_address = anvil.deploy_world_id_registry(signer.clone()).await?;
        let root = anvil
            .create_account(
                registry_address,
                signer.clone(),
                Address::with_last_byte(1),
                U256::from(42),
                U256::from(1),
            )
            .await;

        let http_rpc_provider = build_http_provider(&anvil.instance);
        let watcher = MerkleWatcher::init(
            registry_address,
            &http_rpc_provider,
            WatcherCacheConfig::default(),
        );

        assert!(
            !watcher.merkle_root_cache.contains_key(&root),
            "Should not have root at this moment"
        );
        watcher
            .ensure_root_valid(root)
            .await
            .expect("first call should succeed");
        assert!(
            watcher.merkle_root_cache.contains_key(&root),
            "Root should be cached now"
        );
        watcher
            .ensure_root_valid(root)
            .await
            .expect("second call should succeed (cache hit)");
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_ttl_expiry() -> eyre::Result<()> {
        let anvil = TestAnvil::spawn_with_multicall3().await?;
        let signer = anvil.signer(0)?;
        let registry_address = anvil.deploy_world_id_registry(signer.clone()).await?;
        let root = anvil
            .create_account(
                registry_address,
                signer.clone(),
                Address::with_last_byte(1),
                U256::from(42),
                U256::from(1),
            )
            .await;

        let http_rpc_provider = build_http_provider(&anvil.instance);
        let cache_config = WatcherCacheConfig {
            time_to_live: Duration::from_secs(1),
            ..Default::default()
        };
        let watcher = MerkleWatcher::init(registry_address, &http_rpc_provider, cache_config);

        watcher
            .ensure_root_valid(root)
            .await
            .expect("should succeed");
        assert!(
            watcher.merkle_root_cache.contains_key(&root),
            "Should be in cache"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            !watcher.merkle_root_cache.contains_key(&root),
            "Should not be in cache after TTL"
        );
        watcher
            .ensure_root_valid(root)
            .await
            .expect("should succeed after TTL expiry (re-fetched from chain)");
        assert!(
            watcher.merkle_root_cache.contains_key(&root),
            "Should be in cache again"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_contract_call_failure_returns_internal() -> eyre::Result<()> {
        let anvil = TestAnvil::spawn_with_multicall3().await?;
        let http_rpc_provider = build_http_provider(&anvil.instance);
        // Address with no contract bytecode — isValidRoot() response cannot be ABI-decoded
        let watcher = MerkleWatcher::init(
            Address::with_last_byte(42),
            &http_rpc_provider,
            WatcherCacheConfig::default(),
        );

        let err = watcher
            .ensure_root_valid(FieldElement::from(1u64))
            .await
            .expect_err("call to non-existent contract should fail");
        assert!(
            matches!(err.as_ref(), MerkleWatcherError::Internal(_)),
            "expected Internal, got: {err:?}"
        );
        Ok(())
    }
}
