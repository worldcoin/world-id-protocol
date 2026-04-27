use std::{sync::Arc, time::Duration};

use crate::{
    auth::{
        rp_module::{RelyingParty, wip101},
        rp_registry_watcher::RpRegistry::RpRegistryInstance,
    },
    config::WatcherCacheConfig,
    metrics::{
        METRICS_ATTRID_RP_TYPE, METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_HITS,
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES,
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE,
    },
};
use alloy::{primitives::Address, providers::DynProvider};
use eyre::Context;
use moka::future::Cache;
use taceo_nodes_common::web3;
use taceo_oprf::types::OprfKeyId;
use tracing::instrument;
use world_id_primitives::rp::RpId;

alloy::sol! {
    #[allow(missing_docs, clippy::too_many_arguments, reason="Get this errors from sol macro")]
    #[sol(rpc)]
    RpRegistry,
    "abi/RpRegistryAbi.json"
}

/// Error returned by the [`RpRegistryWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RpRegistryWatcherError {
    /// Unknown RP.
    #[error("unknown rp: {0}")]
    UnknownRp(RpId),
    /// Timeout while doing wip101 check
    #[error("timeout during wip101 account check for: {0}")]
    Timeout(RpId),
    /// Inactive RP.
    #[error("inactive rp: {0}")]
    InactiveRp(RpId),
    /// Internal Error
    #[error(transparent)]
    Internal(#[from] eyre::Report),
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
    contract: RpRegistryInstance<DynProvider>,
    timeout_external_eth_call: Duration,
    http_rpc_provider: web3::HttpRpcProvider,
}

impl RpRegistryWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) fn init(
        contract_address: Address,
        http_rpc_provider: web3::HttpRpcProvider,
        timeout_external_eth_call: Duration,
        cache_config: WatcherCacheConfig,
    ) -> Self {
        ::metrics::gauge!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE).set(0.0);

        let WatcherCacheConfig {
            max_cache_size,
            time_to_live,
        } = cache_config;

        let rp_store = Cache::builder()
            .max_capacity(max_cache_size.get())
            .time_to_live(time_to_live)
            .eviction_listener(move |k, v: RelyingParty, cause| {
                tracing::debug!("removing rp {k}/{} because: {cause:?}", v.account_type);

                metrics::gauge!(
                    METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE,
                    METRICS_ATTRID_RP_TYPE => v.account_type.metrics_label(),
                )
                .decrement(1);
            })
            .build();

        Self {
            rp_store,
            contract: RpRegistry::new(contract_address, http_rpc_provider.inner()),
            timeout_external_eth_call,
            http_rpc_provider,
        }
    }

    #[instrument(level = "debug", skip_all, fields(rp_id=%rp_id))]
    pub(crate) async fn get_rp(
        &self,
        rp_id: &RpId,
    ) -> Result<RelyingParty, Arc<RpRegistryWatcherError>> {
        let entry = self
            .rp_store
            .entry(*rp_id)
            .or_try_insert_with(self.fetch_rp_from_chain(*rp_id))
            .await?;
        let rp = if entry.is_fresh() {
            let rp = entry.value().to_owned();
            metrics::gauge!(
                METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE,
                METRICS_ATTRID_RP_TYPE => rp.account_type.metrics_label(),
            )
            .increment(1);
            ::metrics::counter!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES).increment(1);
            tracing::debug!("rp {rp_id}/{} loaded from chain", rp.account_type);
            rp
        } else {
            ::metrics::counter!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_HITS).increment(1);
            entry.value().to_owned()
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
        let rp = match self.contract.getRp(rp_id.into_inner()).call().await {
            Ok(rp) => rp,
            Err(err) => {
                if let Some(RpRegistry::RpIdDoesNotExist) =
                    err.as_decoded_error::<RpRegistry::RpIdDoesNotExist>()
                {
                    return Err(RpRegistryWatcherError::UnknownRp(rp_id));
                } else if let Some(RpRegistry::RpIdInactive) =
                    err.as_decoded_error::<RpRegistry::RpIdInactive>()
                {
                    return Err(RpRegistryWatcherError::InactiveRp(rp_id));
                }
                return Err(RpRegistryWatcherError::Internal(eyre::Report::from(err)));
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
    use world_id_test_utils::{
        anvil::TestAnvil,
        fixtures::{self, RegistryTestContext},
    };

    use crate::{auth::tests::build_http_provider, config::WatcherCacheConfig};

    async fn setup_with_rp()
    -> eyre::Result<(RpRegistryWatcher, TestAnvil, fixtures::RpFixture, Address)> {
        setup_with_rp_with_ttl(Duration::from_secs(10)).await
    }

    async fn setup_with_rp_with_ttl(
        ttl: Duration,
    ) -> eyre::Result<(RpRegistryWatcher, TestAnvil, fixtures::RpFixture, Address)> {
        let RegistryTestContext {
            anvil, rp_registry, ..
        } = RegistryTestContext::new_with_mock_oprf_key_registry().await?;

        let deployer = anvil.signer(0)?;
        let rp_fixture = fixtures::generate_rp_fixture();
        let rp_signer = LocalSigner::from_signing_key(rp_fixture.signing_key.clone());

        anvil
            .register_rp(
                rp_registry,
                deployer,
                rp_fixture.world_rp_id,
                rp_signer.address(),
                rp_signer.address(),
                "test.domain".to_string(),
            )
            .await?;

        let http_rpc_provider = build_http_provider(&anvil.instance);
        let watcher = RpRegistryWatcher::init(
            rp_registry,
            http_rpc_provider,
            ttl,
            WatcherCacheConfig::default(),
        );

        Ok((watcher, anvil, rp_fixture, rp_registry))
    }

    #[tokio::test]
    async fn test_known_rp_returned() -> eyre::Result<()> {
        let (watcher, _anvil, rp_fixture, _) = setup_with_rp().await?;

        let rp = watcher
            .get_rp(&rp_fixture.world_rp_id)
            .await
            .expect("known RP should be returned");

        let expected_signer =
            LocalSigner::from_signing_key(rp_fixture.signing_key.clone()).address();
        assert_eq!(rp.signer, expected_signer);

        assert!(
            watcher.rp_store.contains_key(&rp_fixture.world_rp_id),
            "Cache should have stored RP"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_unknown_rp_rejected() -> eyre::Result<()> {
        let (watcher, _anvil, _, _) = setup_with_rp().await?;

        let unknown_id = RpId::new(rand::thread_rng().r#gen::<u64>());
        let err = watcher
            .get_rp(&unknown_id)
            .await
            .expect_err("unknown RP should be rejected");
        assert!(
            matches!(err.as_ref(), RpRegistryWatcherError::UnknownRp(is_id) if *is_id == unknown_id),
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
        let (watcher, anvil, rp_fixture, rp_registry) = setup_with_rp().await?;

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
            .get_rp(&rp_fixture.world_rp_id)
            .await
            .expect_err("inactive RP should be rejected");
        assert!(
            matches!(err.as_ref(), RpRegistryWatcherError::InactiveRp(inactive) if *inactive == rp_fixture.world_rp_id),
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
        let (watcher, _anvil, rp_fixture, _) =
            setup_with_rp_with_ttl(Duration::from_secs(1)).await?;

        let rp1 = watcher.get_rp(&rp_fixture.world_rp_id).await?;
        assert!(
            watcher.rp_store.contains_key(&rp_fixture.world_rp_id),
            "RP should be in cache"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            watcher.rp_store.contains_key(&rp_fixture.world_rp_id),
            "RP should NOT be in cache anymore"
        );
        let rp2 = watcher.get_rp(&rp_fixture.world_rp_id).await?;
        assert_eq!(rp1.signer, rp2.signer);
        assert_eq!(rp1.oprf_key_id, rp2.oprf_key_id);
        Ok(())
    }

    #[tokio::test]
    async fn test_contract_call_failure_returns_internal() -> eyre::Result<()> {
        let RegistryTestContext { anvil, .. } =
            RegistryTestContext::new_with_mock_oprf_key_registry().await?;
        let http_rpc_provider = build_http_provider(&anvil.instance);
        // Address with no contract bytecode — getRp() response cannot be ABI-decoded
        let watcher = RpRegistryWatcher::init(
            Address::with_last_byte(42),
            http_rpc_provider,
            Duration::from_secs(10),
            WatcherCacheConfig::default(),
        );

        let rp_id = RpId::new(rand::thread_rng().r#gen::<u64>());
        let err = watcher
            .get_rp(&rp_id)
            .await
            .expect_err("call to non-existent contract should fail");
        assert!(
            matches!(err.as_ref(), RpRegistryWatcherError::Internal(_)),
            "expected Internal, got: {err:?}"
        );
        Ok(())
    }
}
