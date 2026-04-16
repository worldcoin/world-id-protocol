use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::{
    auth::{
        rp_module::{RelyingParty, wip101},
        rp_registry_watcher::RpRegistry::RpRegistryInstance,
    },
    config::WatcherCacheConfig,
    metrics::{
        METRICS_ATTRID_RP_TYPE, METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES,
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE,
    },
};
use alloy::{primitives::Address, providers::DynProvider};
use eyre::Context;
use futures::StreamExt;
use moka::future::Cache;
use taceo_nodes_common::web3;
use taceo_oprf::types::OprfKeyId;
use tokio_util::sync::CancellationToken;
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

impl From<Arc<RpRegistryWatcherError>> for RpRegistryWatcherError {
    fn from(value: Arc<RpRegistryWatcherError>) -> Self {
        match value.as_ref() {
            RpRegistryWatcherError::UnknownRp(rp_id) => Self::UnknownRp(*rp_id),
            RpRegistryWatcherError::Timeout(rp_id) => Self::Timeout(*rp_id),
            RpRegistryWatcherError::InactiveRp(rp_id) => Self::InactiveRp(*rp_id),
            RpRegistryWatcherError::Internal(report) => Self::Internal(eyre::eyre!("{report:?}")),
        }
    }
}

/// Monitors the RPs from the `RpRegistry` contract.
///
/// RPs are lazily loaded, meaning in the beginning the store will be empty.
///
/// When valid requests are coming in from users, this service will go to chain
/// and try fetching the ecdsa keys and store them up to a configurable maximum.
///
/// Additionally, will subscribe to chain events to handle `RpUpdate` events.
#[derive(Clone)]
pub(crate) struct RpRegistryWatcher {
    rp_store: Cache<RpId, RelyingParty>,
    contract: RpRegistryInstance<DynProvider>,
    timeout_external_eth_call: Duration,
    rpc_provider: web3::RpcProvider,
}

impl RpRegistryWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        contract_address: Address,
        rpc_provider: web3::RpcProvider,
        cache_config: WatcherCacheConfig,
        timeout_external_eth_call: Duration,
        started: Arc<AtomicBool>,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<(Self, tokio::task::JoinHandle<eyre::Result<()>>)> {
        ::metrics::gauge!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE).set(0.0);

        let WatcherCacheConfig {
            max_cache_size,
            time_to_live,
            time_to_idle,
        } = cache_config;

        let rp_store: Cache<RpId, RelyingParty> = Cache::builder()
            .max_capacity(max_cache_size)
            .time_to_live(time_to_live)
            .time_to_idle(time_to_idle)
            .eviction_listener(move |k, v: RelyingParty, cause| {
                tracing::debug!("removing {k}/{} because: {cause:?}", v.account_type);

                metrics::gauge!(
                    METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE,
                    METRICS_ATTRID_RP_TYPE => v.account_type.metrics_label(),
                )
                .decrement(1);
            })
            .build();

        let contract = RpRegistry::new(contract_address, rpc_provider.http());

        let subscribe_task = tokio::task::spawn(subscribe_task(
            rp_store.clone(),
            contract.clone(),
            started,
            cancellation_token,
        ));

        let rp_registry = Self {
            rp_store,
            contract,
            timeout_external_eth_call,
            rpc_provider,
        };

        Ok((rp_registry, subscribe_task))
    }

    #[instrument(level = "debug", skip_all, fields(rp_id=%rp_id))]
    pub(crate) async fn get_rp(&self, rp_id: RpId) -> Result<RelyingParty, RpRegistryWatcherError> {
        let entry = self
            .rp_store
            .entry(rp_id)
            .or_try_insert_with(self.fetch_rp_and_check_type(rp_id))
            .await?;
        if entry.is_fresh() {
            // check the value is still valid - maybe we just missed the invalidate event and now we would insert the RP with a long TTL
            match self.fetch_rp_from_chain(rp_id).await {
                Ok(_) => {
                    ::metrics::counter!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES)
                        .increment(1);
                    metrics::gauge!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE).increment(1);
                }
                Err(err) => {
                    // the RP was set invalid in the meantime
                    tracing::debug!("missed invalidate event during insert - removing now");
                    self.rp_store.invalidate(&rp_id).await;
                    return Err(err);
                }
            }
        }
        let rp = entry.into_value();
        tracing::trace!("returning {rp_id}/{}", rp.account_type);
        Ok(rp)
    }

    async fn fetch_rp_from_chain(
        &self,
        rp_id: RpId,
    ) -> Result<IRpRegistry::RelyingParty, RpRegistryWatcherError> {
        self.contract
            .getRp(rp_id.into_inner())
            .call()
            .await
            .map_err(|err| {
                if err
                    .as_decoded_error::<RpRegistry::RpIdDoesNotExist>()
                    .is_some()
                {
                    RpRegistryWatcherError::UnknownRp(rp_id)
                } else if err.as_decoded_error::<RpRegistry::RpIdInactive>().is_some() {
                    RpRegistryWatcherError::InactiveRp(rp_id)
                } else {
                    RpRegistryWatcherError::Internal(eyre::Report::from(err))
                }
            })
    }

    async fn fetch_rp_and_check_type(
        &self,
        rp_id: RpId,
    ) -> Result<RelyingParty, RpRegistryWatcherError> {
        tracing::trace!("rp {rp_id} not found in store, querying RpRegistry...");
        let rp = self.fetch_rp_from_chain(rp_id).await?;

        tracing::trace!("checking if RP is EOA or smart contract..");
        metrics::counter!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES).increment(1);

        let account_type = tokio::time::timeout(
            self.timeout_external_eth_call,
            wip101::account_check(rp.signer, &self.rpc_provider),
        )
        .await
        .map_err(|_| RpRegistryWatcherError::Timeout(rp_id))?
        .context("while performing WIP101 check")?;

        metrics::gauge!(
            METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE,
            METRICS_ATTRID_RP_TYPE => account_type.metrics_label(),
        )
        .increment(1);

        let relying_party = RelyingParty {
            signer: rp.signer,
            oprf_key_id: OprfKeyId::new(rp.oprfKeyId),
            account_type,
        };

        tracing::debug!("rp {rp_id}/{account_type} loaded from chain");
        Ok(relying_party)
    }
}

async fn subscribe_task(
    rp_store: Cache<RpId, RelyingParty>,
    contract: RpRegistryInstance<DynProvider>,
    started: Arc<AtomicBool>,
    cancellation_token: CancellationToken,
) -> eyre::Result<()> {
    let mut sub = contract.RpUpdated_filter().watch().await?.into_stream();
    started.store(true, Ordering::Relaxed);
    loop {
        let rp_update = tokio::select! {
            event = sub.next() => {
                let (rp_update,_) = event.ok_or_else(||{
                    tracing::warn!("RpRegistry subscribe stream was closed");
                    eyre::eyre!("RpRegistry subscribe stream was closed")
                })??;
                rp_update
            }
            () = cancellation_token.cancelled() => {
                break;
            }
        };
        let rp_id = RpId::new(rp_update.rpId);
        if let Some(rp) = rp_store.remove(&rp_id).await {
            tracing::debug!("invalidated {rp_id}/{} due to chain event", rp.account_type);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use alloy::signers::local::LocalSigner;
    use tokio_util::sync::CancellationToken;
    use world_id_test_utils::fixtures::{self, RegistryTestContext};

    use crate::{
        auth::{
            rp_registry_watcher::{RpRegistryWatcher, RpRegistryWatcherError},
            tests::build_rpc_provider,
        },
        config::WatcherCacheConfig,
    };

    impl RpRegistryWatcher {
        #[allow(dead_code, reason = "is only used in tests")]
        pub(crate) fn set_timeout_external_eth_call(&mut self, duration: Duration) {
            self.timeout_external_eth_call = duration;
        }
    }

    #[tokio::test]
    async fn test_timeout_wip101_account_check() -> eyre::Result<()> {
        let RegistryTestContext {
            anvil, rp_registry, ..
        } = RegistryTestContext::new_with_mock_oprf_key_registry()
            .await
            .expect("Should be able to create test-fixture");
        let rpc_provider = build_rpc_provider(&anvil.instance).await;

        let (watcher, _) = RpRegistryWatcher::init(
            rp_registry,
            rpc_provider,
            WatcherCacheConfig::default(),
            Duration::from_secs(0), // timeout set to zero
            Arc::new(AtomicBool::default()),
            CancellationToken::new(),
        )
        .await
        .expect("Should be able to start registry watcher");

        let rp_fixture = fixtures::generate_rp_fixture();

        // Register the RP which also triggers a OPRF key-gen.
        let rp_signer = LocalSigner::from_signing_key(rp_fixture.signing_key.clone());
        anvil
            .register_rp(
                rp_registry,
                anvil.signer(0)?,
                rp_fixture.world_rp_id,
                rp_signer.address(),
                rp_signer.address(),
                "taceo.oprf".to_string(),
            )
            .await?;

        let should_err = watcher
            .get_rp(rp_fixture.world_rp_id)
            .await
            .expect_err("Should be an error");
        assert!(
            matches!(should_err, RpRegistryWatcherError::Timeout(id) if id == rp_fixture.world_rp_id)
        );
        Ok(())
    }
}
