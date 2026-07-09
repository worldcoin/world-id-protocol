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
    primitives::{Address, U256},
    providers::{DynProvider, Provider},
};
use eyre::Context;
use moka::future::Cache;
use taceo_nodes_common::web3;
use tracing::instrument;
use world_id_primitives::{FieldElement, oprf::WorldIdRequestAuthError};
use world_id_registries::world_id::WorldIdRegistry::{self, WorldIdRegistryInstance};

use crate::{config::WatcherCacheConfig, metrics};

/// Error returned by the [`MerkleWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MerkleWatcherError {
    #[error(
        "invalid Merkle root {root} at block #{block}. Timestamp on block {timestamp_block} - root time stamp from contract: {root_time_stamp}"
    )]
    InvalidMerkleRoot {
        root: FieldElement,
        block: U256,
        timestamp_block: U256,
        root_time_stamp: U256,
    },
    #[error("unknown Merkle root {root} at #{block}")]
    UnknownMerkleRoot { root: FieldElement, block: U256 },
    #[error("Internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

impl From<&MerkleWatcherError> for WorldIdRequestAuthError {
    fn from(value: &MerkleWatcherError) -> Self {
        match value {
            MerkleWatcherError::InvalidMerkleRoot { .. }
            | MerkleWatcherError::UnknownMerkleRoot { .. } => Self::InvalidMerkleRoot,
            MerkleWatcherError::Internal(_) => Self::Internal,
        }
    }
}

/// Validates and caches merkle roots from the `WorldIDRegistry` contract.
///
/// Roots are validated on-demand via `eth_call` and cached with a configurable
/// TTL. Uses LRU eviction when the cache exceeds the configured maximum capacity.
#[derive(Clone)]
pub(crate) struct MerkleWatcher {
    merkle_root_cache: Cache<FieldElement, ()>,
    contract: WorldIdRegistryInstance<DynProvider>,
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
        let contract = WorldIdRegistry::new(contract_address, http_rpc_provider.inner());

        let merkle_root_cache_builder = Cache::builder()
            .max_capacity(cache_config.max_cache_size.get())
            .time_to_live(cache_config.time_to_live);

        let merkle_root_cache = if let Some(time_to_idle) = cache_config.time_to_idle {
            merkle_root_cache_builder.time_to_idle(time_to_idle).build()
        } else {
            merkle_root_cache_builder.build()
        };

        Self {
            merkle_root_cache,
            contract,
        }
    }

    #[instrument(level = "debug", skip_all, fields(root=%root))]
    pub(crate) async fn ensure_root_valid(
        &self,
        root: FieldElement,
    ) -> Result<(), Arc<MerkleWatcherError>> {
        let is_valid_root = async {
            let (valid, root_time_stamp, current_block, timestamp_block) = self
                .contract
                .provider()
                .multicall()
                .add(self.contract.isValidRoot(root.into()))
                .add(self.contract.getRootTimestamp(root.into()))
                .get_block_number()
                .get_current_block_timestamp()
                .aggregate()
                .await
                .context("while doing isValidRoot multi-call")?;
            if valid {
                Ok(())
            } else if root_time_stamp == 0 {
                Err(MerkleWatcherError::UnknownMerkleRoot {
                    root,
                    block: current_block,
                })
            } else {
                Err(MerkleWatcherError::InvalidMerkleRoot {
                    root,
                    block: current_block,
                    timestamp_block,
                    root_time_stamp,
                })
            }
        };

        let entry = self
            .merkle_root_cache
            .entry(root)
            .or_try_insert_with(is_valid_root)
            .await?;
        if entry.is_fresh() {
            metrics::merkle_cache::set(self.merkle_root_cache.entry_count());
            metrics::merkle_cache::miss();
            tracing::trace!("merkle root {root} loaded from chain");
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

    struct Setup {
        anvil: TestAnvil,
        registry: Address,
        watcher: MerkleWatcher,
    }

    /// Spawns anvil, deploys the World ID registry and initializes a watcher on it.
    async fn setup(cache_config: WatcherCacheConfig) -> eyre::Result<Setup> {
        let anvil = TestAnvil::spawn_auto_mine_with_multicall3().await?;
        let registry = anvil.deploy_world_id_registry(anvil.signer(0)?).await?;
        let watcher = MerkleWatcher::init(
            registry,
            &build_http_provider(&anvil.instance),
            cache_config,
        );
        Ok(Setup {
            anvil,
            registry,
            watcher,
        })
    }

    impl Setup {
        /// Records a new merkle root by creating an account; `n` disambiguates accounts.
        async fn record_root(&self, n: u8) -> eyre::Result<FieldElement> {
            Ok(self
                .anvil
                .create_account(
                    self.registry,
                    self.anvil.signer(0)?,
                    Address::with_last_byte(n),
                    U256::from(n),
                    U256::from(n),
                )
                .await)
        }
    }

    #[tokio::test]
    async fn test_valid_root_accepted() -> eyre::Result<()> {
        let setup = setup(WatcherCacheConfig::default()).await?;
        let root = setup.record_root(1).await?;

        setup
            .watcher
            .ensure_root_valid(root)
            .await
            .expect("valid root should be accepted");
        Ok(())
    }

    #[tokio::test]
    async fn test_unknown_root_rejected() -> eyre::Result<()> {
        let setup = setup(WatcherCacheConfig::default()).await?;

        let unknown_root = FieldElement::from(99999u64);
        let err = setup
            .watcher
            .ensure_root_valid(unknown_root)
            .await
            .expect_err("unknown root should be rejected");
        let MerkleWatcherError::UnknownMerkleRoot { root, block } = err.as_ref() else {
            panic!("expected UnknownMerkleRoot, got: {err:?}");
        };
        assert!(*block > U256::ZERO, "block number should be non-zero");
        assert_eq!(*root, unknown_root);
        Ok(())
    }

    #[tokio::test]
    async fn test_outdated_root_rejected() -> eyre::Result<()> {
        let setup = setup(WatcherCacheConfig::default()).await?;

        // Record root1 (becomes latest).
        let root1 = setup.record_root(1).await?;

        // Collapse the validity window so any non-latest root is immediately expired.
        setup
            .anvil
            .set_root_validity_window(setup.registry, setup.anvil.signer(0)?, 0)
            .await;

        // Advance chain time: with auto-mine both roots' blocks can share a
        // timestamp, in which case root1 (ts1 + 0 >= block.timestamp) stays valid.
        let _: serde_json::Value = setup
            .anvil
            .provider()?
            .client()
            .request("evm_increaseTime", (2u64,))
            .await?;

        // Record root2 — this supersedes root1, which is now expired (ts1 + 0 < block.timestamp).
        let root2 = setup.record_root(2).await?;

        // root1 was recorded (ts != 0) but is now expired — InvalidMerkleRoot, not retried.
        let err = setup
            .watcher
            .ensure_root_valid(root1)
            .await
            .expect_err("outdated root should be rejected");
        let MerkleWatcherError::InvalidMerkleRoot {
            root,
            block,
            timestamp_block,
            root_time_stamp,
        } = err.as_ref()
        else {
            panic!("expected InvalidMerkleRoot for outdated root, got: {err:?}");
        };
        assert_eq!(*root, root1);
        assert!(*block > U256::ZERO, "block number should be non-zero");
        assert!(
            *root_time_stamp > U256::ZERO,
            "root was recorded, so timestamp should be non-zero"
        );
        assert!(
            *timestamp_block >= *root_time_stamp,
            "with window=0 the block timestamp should be at or past the root timestamp"
        );
        assert!(
            !setup.watcher.merkle_root_cache.contains_key(&root1),
            "outdated root must not be cached"
        );

        // root2 is the current latest root and must be accepted.
        setup
            .watcher
            .ensure_root_valid(root2)
            .await
            .expect("latest root should be accepted");
        Ok(())
    }

    /// Regression test for `HackerOne` report #3494201: invalid roots must not be cached.
    #[tokio::test]
    async fn test_invalid_root_not_cached() -> eyre::Result<()> {
        let setup = setup(WatcherCacheConfig::default()).await?;

        let unknown_root = FieldElement::from(99999u64);

        let err1 = setup
            .watcher
            .ensure_root_valid(unknown_root)
            .await
            .expect_err("first call should fail");
        let MerkleWatcherError::UnknownMerkleRoot {
            root: root1,
            block: block1,
        } = err1.as_ref()
        else {
            panic!("expected UnknownMerkleRoot on first call, got: {err1:?}");
        };
        assert_eq!(*root1, unknown_root);
        assert!(*block1 > U256::ZERO, "block number should be non-zero");

        assert!(
            !setup.watcher.merkle_root_cache.contains_key(&unknown_root),
            "Cache should not have unknown root cached"
        );

        // second call should fail again
        let err2 = setup
            .watcher
            .ensure_root_valid(unknown_root)
            .await
            .expect_err("second call should also fail (error must not be cached)");
        let MerkleWatcherError::UnknownMerkleRoot {
            root: root2,
            block: block2,
        } = err2.as_ref()
        else {
            panic!("expected UnknownMerkleRoot on second call, got: {err2:?}");
        };
        assert_eq!(*root2, unknown_root);
        assert!(*block2 > U256::ZERO, "block number should be non-zero");
        Ok(())
    }

    #[tokio::test]
    async fn test_valid_root_cache_hit() -> eyre::Result<()> {
        let setup = setup(WatcherCacheConfig::default()).await?;
        let root = setup.record_root(1).await?;

        assert!(
            !setup.watcher.merkle_root_cache.contains_key(&root),
            "Should not have root at this moment"
        );
        setup
            .watcher
            .ensure_root_valid(root)
            .await
            .expect("first call should succeed");
        assert!(
            setup.watcher.merkle_root_cache.contains_key(&root),
            "Root should be cached now"
        );
        setup
            .watcher
            .ensure_root_valid(root)
            .await
            .expect("second call should succeed (cache hit)");
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_ttl_expiry() -> eyre::Result<()> {
        let setup = setup(WatcherCacheConfig {
            time_to_live: Duration::from_millis(100),
            ..Default::default()
        })
        .await?;
        let root = setup.record_root(1).await?;

        setup
            .watcher
            .ensure_root_valid(root)
            .await
            .expect("should succeed");
        assert!(
            setup.watcher.merkle_root_cache.contains_key(&root),
            "Should be in cache"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !setup.watcher.merkle_root_cache.contains_key(&root),
            "Should not be in cache after TTL"
        );
        setup
            .watcher
            .ensure_root_valid(root)
            .await
            .expect("should succeed after TTL expiry (re-fetched from chain)");
        assert!(
            setup.watcher.merkle_root_cache.contains_key(&root),
            "Should be in cache again"
        );
        Ok(())
    }
}
