use std::{sync::Arc, time::Duration};

use crate::{
    auth::{
        rp_module::{RelyingParty, wip101},
        rp_registry_watcher::RpRegistry::RpRegistryInstance,
    },
    config::WatcherCacheConfig,
    metrics,
};
use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use backon::Retryable as _;
use eyre::Context;
use moka::future::Cache;
use taceo_nodes_common::web3;
use taceo_oprf::types::OprfKeyId;
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use world_id_primitives::{oprf::WorldIdRequestAuthError, rp::RpId};

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
    #[error("Internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

impl From<&RpRegistryWatcherError> for WorldIdRequestAuthError {
    fn from(value: &RpRegistryWatcherError) -> Self {
        match value {
            RpRegistryWatcherError::UnknownRp(_) => Self::UnknownRp,
            RpRegistryWatcherError::InactiveRp(_) => Self::InactiveRp,
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
    contract: RpRegistryInstance<DynProvider>,
    timeout_external_eth_call: Duration,
    http_rpc_provider: web3::HttpRpcProvider,
    cache_config: WatcherCacheConfig,
}

impl RpRegistryWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) fn init(
        contract_address: Address,
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
            contract: RpRegistry::new(contract_address, http_rpc_provider.inner()),
            timeout_external_eth_call,
            http_rpc_provider,
            cache_config,
        }
    }

    #[instrument(level = "debug", skip_all, fields(rp_id=%rp_id))]
    pub(crate) async fn get_rp(
        &self,
        rp_id: &RpId,
    ) -> Result<RelyingParty, Arc<RpRegistryWatcherError>> {
        let backon_fetch_rp = (|| async { self.fetch_rp_from_chain(*rp_id).await })
            .retry(self.cache_config.backoff_strategy())
            .sleep(tokio::time::sleep)
            .when(|e| matches!(e, RpRegistryWatcherError::UnknownRp(_)))
            .notify(|err, duration| {
                tracing::warn!(%err, "fetch rp from chain will retry after {duration:?}");
            });

        let entry = self
            .rp_store
            .entry(*rp_id)
            .or_try_insert_with(backon_fetch_rp)
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

    /// Polls the `RpRegistry` for `RpUpdated` events and invalidates the cached
    /// entry of every RP whose record changed.
    ///
    /// This collapses the propagation time of an on-chain signer rotation or
    /// deactivation from the full cache TTL down to roughly one poll interval,
    /// which is what makes prompt revocation of a compromised signer possible.
    ///
    /// Design notes:
    /// - Over-invalidation is safe: the worst case of dropping an entry we did
    ///   not strictly need to is a single `getRp` refetch on the next request.
    ///   We therefore ignore reorgs and simply re-fetch logs for any range that
    ///   failed, rather than tracking chain state precisely.
    /// - Fail-safe: any RPC error is logged and the same block range is retried
    ///   on the next tick. The loop only terminates on cancellation. The cache
    ///   TTL remains the backstop if this loop stalls — see [`Self`] docs.
    /// - We start watching from the current head: on startup the cache is empty,
    ///   so there is nothing stale to invalidate for past updates, and entries
    ///   loaded afterwards are at most one TTL old regardless.
    pub(crate) async fn run_invalidation_loop(
        self,
        poll_interval: Duration,
        cancellation_token: CancellationToken,
    ) {
        let provider = self.contract.provider().clone();
        let address = *self.contract.address();

        // Establish the starting block (current head + 1), retrying on failure.
        let mut from_block = loop {
            tokio::select! {
                () = cancellation_token.cancelled() => return,
                res = provider.get_block_number() => match res {
                    Ok(n) => break n.saturating_add(1),
                    Err(e) => {
                        tracing::warn!(error = %e, "rp invalidation: failed to fetch initial block number, retrying");
                        tokio::select! {
                            () = cancellation_token.cancelled() => return,
                            () = tokio::time::sleep(poll_interval) => {}
                        }
                    }
                }
            }
        };

        tracing::info!(
            from_block,
            ?poll_interval,
            "rp registry invalidation loop started"
        );

        loop {
            tokio::select! {
                () = cancellation_token.cancelled() => {
                    tracing::info!("rp registry invalidation loop shutting down");
                    return;
                }
                () = tokio::time::sleep(poll_interval) => {}
            }

            let latest = match provider.get_block_number().await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(error = %e, "rp invalidation: failed to fetch block number, retrying");
                    continue;
                }
            };
            if latest < from_block {
                continue;
            }

            let filter = Filter::new()
                .address(address)
                .event_signature(RpRegistry::RpUpdated::SIGNATURE_HASH)
                .from_block(from_block)
                .to_block(latest);

            match provider.get_logs(&filter).await {
                Ok(logs) => {
                    for log in logs {
                        match log.log_decode::<RpRegistry::RpUpdated>() {
                            Ok(decoded) => {
                                let rp_id = RpId::new(decoded.inner.data.rpId);
                                self.rp_store.invalidate(&rp_id).await;
                                metrics::rp_registry_cache::invalidation();
                                tracing::info!(%rp_id, "invalidated cached RP after on-chain RpUpdated");
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "rp invalidation: failed to decode RpUpdated log");
                            }
                        }
                    }
                    from_block = latest.saturating_add(1);
                    // Heartbeat: alert if this stops advancing (stalled poller).
                    metrics::rp_registry_cache::set_last_polled_block(latest);
                }
                Err(e) => {
                    // Keep `from_block` to retry this range; over-invalidation is safe.
                    tracing::warn!(error = %e, from_block, to_block = latest, "rp invalidation: get_logs failed, will retry range");
                }
            }
        }
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
            !watcher.rp_store.contains_key(&rp_fixture.world_rp_id),
            "RP should NOT be in cache anymore"
        );
        let rp2 = watcher.get_rp(&rp_fixture.world_rp_id).await?;
        assert_eq!(rp1.signer, rp2.signer);
        assert_eq!(rp1.oprf_key_id, rp2.oprf_key_id);
        Ok(())
    }

    #[tokio::test]
    async fn test_event_driven_invalidation() -> eyre::Result<()> {
        // Long TTL so that any eviction we observe is caused by the event-driven
        // invalidation loop, not by TTL expiry.
        let (watcher, anvil, rp_fixture, rp_registry) =
            setup_with_rp_with_ttl(Duration::from_secs(600)).await?;

        // Prime the cache.
        watcher.get_rp(&rp_fixture.world_rp_id).await?;
        assert!(
            watcher.rp_store.contains_key(&rp_fixture.world_rp_id),
            "RP should be cached after first fetch"
        );

        // Start the invalidation loop. The clone shares the same moka store, so
        // evictions it performs are visible on `watcher`.
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(
            watcher
                .clone()
                .run_invalidation_loop(Duration::from_millis(200), cancel.clone()),
        );

        // Trigger an on-chain RpUpdated by rotating the signer to a fresh key.
        let deployer = anvil.signer(0)?;
        let manager = LocalSigner::from_signing_key(rp_fixture.signing_key.clone());
        let new_signer = LocalSigner::random().address();
        anvil
            .update_rp(
                rp_registry,
                deployer,
                manager.clone(),
                rp_fixture.world_rp_id,
                false, // keep active
                manager.address(),
                new_signer,
                "test.domain".to_string(),
            )
            .await?;

        // The loop should evict the stale entry within a few poll intervals.
        let mut invalidated = false;
        for _ in 0..50 {
            if !watcher.rp_store.contains_key(&rp_fixture.world_rp_id) {
                invalidated = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        cancel.cancel();
        handle
            .await
            .expect("invalidation loop task should not panic");

        assert!(
            invalidated,
            "cache entry should be invalidated after the RpUpdated event"
        );

        // A subsequent fetch reflects the rotated signer.
        let rp = watcher.get_rp(&rp_fixture.world_rp_id).await?;
        assert_eq!(
            rp.signer, new_signer,
            "refetched RP should carry the rotated signer"
        );
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
