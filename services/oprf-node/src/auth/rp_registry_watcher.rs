use std::{sync::Arc, time::Duration};

use crate::{
    auth::{
        rp_module::{RelyingParty, wip101},
        rp_registry_watcher::{
            BillingContract::BillingContractInstance, RpRegistry::RpRegistryInstance,
        },
    },
    config::WatcherCacheConfig,
    metrics,
};
use alloy::{
    primitives::{Address, U256},
    providers::{CallItemBuilder, DynProvider, Failure, Provider},
    sol_types::SolError,
};
use eyre::Context;
use moka::future::Cache;
use taceo_nodes_common::web3;
use taceo_oprf::types::OprfKeyId;
use tracing::instrument;
use world_id_primitives::{oprf::WorldIdRequestAuthError, rp::RpId};

// Copied from IRpRegistry.sol/IBillingContract.sol.
//
// For brevity we only copy the methods that are relevant for the watcher
alloy::sol! {
    #[sol(rpc)]
    interface RpRegistry {
        struct RelyingParty {
            bool initialized;
            bool active;
            address manager;
            address signer;
            uint160 oprfKeyId;
            string unverifiedWellKnownDomain;
        }

        error RpIdDoesNotExist();
        error RpIdInactive();

        function getRp(uint64 rpId) external view returns (RelyingParty memory);
    }

    #[sol(rpc)]
    interface BillingContract {
        function isBlocked(uint64 rpId) external view returns (bool);
    }
}

/// Error returned by the [`RpRegistryWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RpRegistryWatcherError {
    /// Unknown RP.
    #[error("unknown rp: {rp} at block #{block} with timestamp: {timestamp}")]
    UnknownRp {
        rp: RpId,
        block: U256,
        timestamp: U256,
    },
    /// Timeout while doing wip101 check
    #[error("timeout during wip101 account check for: {0}")]
    Timeout(RpId),
    /// Inactive RP.
    #[error("inactive rp: {rp} at block #{block} with timestamp: {timestamp}")]
    InactiveRp {
        rp: RpId,
        block: U256,
        timestamp: U256,
    },
    /// Internal Error
    #[error("Internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

impl From<&RpRegistryWatcherError> for WorldIdRequestAuthError {
    fn from(value: &RpRegistryWatcherError) -> Self {
        match value {
            RpRegistryWatcherError::UnknownRp { .. } => Self::UnknownRp,
            RpRegistryWatcherError::InactiveRp { .. } => Self::InactiveRp,
            RpRegistryWatcherError::Timeout(_) => Self::Wip101AccountCheckTimeout,
            RpRegistryWatcherError::Internal(_) => Self::Internal,
        }
    }
}

/// Validates and caches RPs from the `RpRegistry` contract.
///
/// RPs are lazily loaded: the cache starts empty and entries are fetched from
/// chain on first request, then cached for the configured TTL.
///
/// Per WIP-101 §8, on-chain RP signer updates may take up to the configured
/// cache TTL to propagate. Operators should use a reasonably small TTL.
#[derive(Clone)]
pub(crate) struct RpRegistryWatcher {
    rp_store: Cache<RpId, RelyingParty>,
    rp_registry_contract: RpRegistryInstance<DynProvider>,
    billing_contract: BillingContractInstance<DynProvider>,
    timeout_external_eth_call: Duration,
    http_rpc_provider: web3::HttpRpcProvider,
}

impl RpRegistryWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) fn init(
        rp_registry_address: Address,
        billing_contract_address: Address,
        http_rpc_provider: web3::HttpRpcProvider,
        timeout_external_eth_call: Duration,
        cache_config: WatcherCacheConfig,
    ) -> Self {
        let rp_store_builder = Cache::builder()
            .max_capacity(cache_config.max_cache_size.get())
            .time_to_live(cache_config.time_to_live);

        let rp_store = if let Some(time_to_idle) = cache_config.time_to_idle {
            rp_store_builder.time_to_idle(time_to_idle).build()
        } else {
            rp_store_builder.build()
        };

        Self {
            rp_store,
            rp_registry_contract: RpRegistry::new(rp_registry_address, http_rpc_provider.inner()),
            billing_contract: BillingContract::new(
                billing_contract_address,
                http_rpc_provider.inner(),
            ),
            timeout_external_eth_call,
            http_rpc_provider,
        }
    }

    #[instrument(level = "debug", skip_all, fields(rp_id=%rp_id))]
    pub(crate) async fn get_rp(
        &self,
        rp_id: RpId,
    ) -> Result<RelyingParty, Arc<RpRegistryWatcherError>> {
        let entry = self
            .rp_store
            .entry(rp_id)
            .or_try_insert_with(self.fetch_rp_from_chain(rp_id))
            .await?;
        let rp = if entry.is_fresh() {
            let rp = entry.into_value();
            metrics::rp_registry_cache::set(self.rp_store.entry_count());
            metrics::rp_registry_cache::miss();
            tracing::trace!("rp {rp_id}/{} loaded from chain", rp.account_type);
            rp
        } else {
            metrics::rp_registry_cache::hit();
            entry.into_value()
        };

        tracing::trace!("returning {rp_id}/{}", rp.account_type);
        Ok(rp)
    }

    #[instrument(level = "debug", skip_all, fields(rp_id=%rp_id))]
    async fn fetch_rp_from_chain(
        &self,
        rp_id: RpId,
    ) -> Result<RelyingParty, RpRegistryWatcherError> {
        tracing::trace!("rp {rp_id} not found in store, querying RpRegistry...");
        let rp_id_u64 = rp_id.into_inner();
        let get_rp_call =
            CallItemBuilder::new(self.rp_registry_contract.getRp(rp_id_u64)).allow_failure(true);
        let (get_rp_result, is_blocked, current_block, timestamp) = self
            .rp_registry_contract
            .provider()
            .multicall()
            .add_call(get_rp_call)
            // we expect that isBlocked cannot revert
            .add(self.billing_contract.isBlocked(rp_id_u64))
            .get_block_number()
            .get_current_block_timestamp()
            .aggregate3()
            .await
            .context("while doing fetch-rp multi-call")?;

        let is_blocked = is_blocked.context("is_blocked failed but allow-failure=false")?;
        let current_block = current_block.context("block_number failed but allow-failure=false")?;
        let timestamp = timestamp.context("timestamp_block failed but allow-failure=false")?;

        let rp = match get_rp_result {
            Ok(rp) => rp,
            Err(Failure { return_data, .. }) => {
                if RpRegistry::RpIdDoesNotExist::abi_decode(&return_data).is_ok() {
                    return Err(RpRegistryWatcherError::UnknownRp {
                        rp: rp_id,
                        block: current_block,
                        timestamp,
                    });
                }
                if RpRegistry::RpIdInactive::abi_decode(&return_data).is_ok() {
                    return Err(RpRegistryWatcherError::InactiveRp {
                        rp: rp_id,
                        block: current_block,
                        timestamp,
                    });
                }
                return Err(RpRegistryWatcherError::Internal(eyre::eyre!(
                    "unknown error selector from get_rp: {return_data:#?}"
                )));
            }
        };

        tracing::trace!("checking if RP is EOA or smart contract..");

        let account_type = tokio::time::timeout(
            self.timeout_external_eth_call,
            wip101::account_check(rp.signer, &self.http_rpc_provider),
        )
        .await
        .map_err(|_| RpRegistryWatcherError::Timeout(rp_id))?
        .context("while performing WIP101 check")?;

        let relying_party = RelyingParty {
            signer: rp.signer,
            oprf_key_id: OprfKeyId::new(rp.oprfKeyId),
            account_type,
            is_blocked,
            fetched_at_block: current_block,
            fetched_at_timestamp: timestamp,
        };

        Ok(relying_party)
    }

    #[allow(dead_code, reason = "is only used in tests")]
    #[cfg(test)]
    pub(crate) fn set_timeout_external_eth_call(&mut self, duration: Duration) {
        self.timeout_external_eth_call = duration;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::LocalSigner;
    use rand::Rng;
    use world_id_primitives::rp::RpId;
    use world_id_test_utils::{anvil::TestAnvil, fixtures};

    use crate::{auth::tests::build_http_provider, config::WatcherCacheConfig};

    /// Deploys only what the watcher needs (RP registry + billing mock) and registers one RP.
    async fn setup(
        ttl: Duration,
    ) -> eyre::Result<(RpRegistryWatcher, TestAnvil, fixtures::RpFixture, Address)> {
        let anvil = TestAnvil::spawn_auto_mine_with_multicall3().await?;
        let deployer = anvil.signer(0)?;
        let oprf_key_registry = anvil
            .deploy_mock_oprf_key_registry(deployer.clone())
            .await?;
        let rp_registry = anvil
            .deploy_rp_registry(deployer.clone(), oprf_key_registry)
            .await?;
        let billing_contract = anvil.deploy_billing_contract(deployer.clone()).await?;

        let rp_fixture = fixtures::generate_rp_fixture();
        let rp_signer = LocalSigner::from_signing_key(rp_fixture.signing_key.clone());

        anvil
            .register_rp(
                rp_registry,
                deployer.clone(),
                rp_fixture.world_rp_id,
                rp_signer.address(),
                rp_signer.address(),
                "test.domain".to_string(),
            )
            .await?;

        anvil
            .register_rp(
                rp_registry,
                deployer,
                RpId::new(42),
                rp_signer.address(),
                rp_signer.address(),
                "test.domain".to_string(),
            )
            .await?;
        let http_rpc_provider = build_http_provider(&anvil.instance);

        let watcher = RpRegistryWatcher::init(
            rp_registry,
            billing_contract,
            http_rpc_provider,
            Duration::from_secs(10),
            WatcherCacheConfig {
                time_to_live: ttl,
                ..Default::default()
            },
        );

        Ok((watcher, anvil, rp_fixture, rp_registry))
    }

    #[tokio::test]
    async fn test_known_rp_returned() -> eyre::Result<()> {
        let (watcher, _anvil, rp_fixture, _) = setup(Duration::from_secs(10)).await?;

        let rp = watcher
            .get_rp(rp_fixture.world_rp_id)
            .await
            .expect("known RP should be returned");

        let expected_signer =
            LocalSigner::from_signing_key(rp_fixture.signing_key.clone()).address();
        assert_eq!(rp.signer, expected_signer);

        assert!(!rp.is_blocked, "RP should not be blocked");
        assert!(
            watcher.rp_store.contains_key(&rp_fixture.world_rp_id),
            "Cache should have stored RP"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_blocked_rp_cached() -> eyre::Result<()> {
        let (watcher, _anvil, _, _) = setup(Duration::from_secs(10)).await?;
        let blocked_rp = RpId::new(42);

        // 42 is blocked on the mock contract
        let rp = watcher
            .get_rp(blocked_rp)
            .await
            .expect("getRp should succeed and cache the RP");

        assert!(rp.is_blocked, "RP should be blocked");

        assert!(
            watcher.rp_store.contains_key(&blocked_rp),
            "Cache should have stored RP"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_unknown_rp_rejected() -> eyre::Result<()> {
        let (watcher, _anvil, _, _) = setup(Duration::from_secs(10)).await?;

        let unknown_id = RpId::new(rand::thread_rng().r#gen::<u64>());
        let err = watcher
            .get_rp(unknown_id)
            .await
            .expect_err("unknown RP should be rejected");
        assert!(
            matches!(err.as_ref(), RpRegistryWatcherError::UnknownRp{ rp:is_id,..} if *is_id == unknown_id),
            "expected UnknownRp, got: {err:?}"
        );
        assert!(
            !watcher.rp_store.contains_key(&unknown_id),
            "Cache should have not stored RP"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_inactive_rp_rejected() -> eyre::Result<()> {
        let (watcher, anvil, rp_fixture, rp_registry) = setup(Duration::from_secs(10)).await?;

        let deployer = anvil.signer(0)?;
        let rp_signer = LocalSigner::from_signing_key(rp_fixture.signing_key.clone());

        // Deactivate the RP before the first get_rp call so the cache is empty.
        anvil
            .update_rp(
                rp_registry,
                deployer,
                rp_signer.clone(),
                rp_fixture.world_rp_id,
                true, // toggle_active deactivates the RP
                rp_signer.address(),
                rp_signer.address(),
                "test.domain".to_string(),
            )
            .await?;

        let err = watcher
            .get_rp(rp_fixture.world_rp_id)
            .await
            .expect_err("inactive RP should be rejected");
        assert!(
            matches!(err.as_ref(), RpRegistryWatcherError::InactiveRp{rp:inactive,..} if *inactive == rp_fixture.world_rp_id),
            "expected InactiveRp, got: {err:?}"
        );

        assert!(
            !watcher.rp_store.contains_key(&rp_fixture.world_rp_id),
            "Inactive RP should not be in cache"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_cache_ttl_expiry() -> eyre::Result<()> {
        let (watcher, _anvil, rp_fixture, _) = setup(Duration::from_millis(100)).await?;

        let rp1 = watcher.get_rp(rp_fixture.world_rp_id).await?;
        assert!(
            watcher.rp_store.contains_key(&rp_fixture.world_rp_id),
            "RP should be in cache"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !watcher.rp_store.contains_key(&rp_fixture.world_rp_id),
            "RP should NOT be in cache anymore"
        );
        let rp2 = watcher.get_rp(rp_fixture.world_rp_id).await?;
        assert_eq!(rp1.signer, rp2.signer);
        assert_eq!(rp1.oprf_key_id, rp2.oprf_key_id);
        Ok(())
    }
}
