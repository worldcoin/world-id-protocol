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
        rp_registry_watcher::RpRegistry::{RpRegistryInstance, RpUpdated},
    },
    config::WatcherCacheConfig,
    metrics::{
        METRICS_ATTRID_RP_TYPE, METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES,
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE,
    },
};
use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::{DynProvider, Provider as _},
    pubsub::SubscriptionStream,
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use eyre::Context;
use futures::StreamExt as _;
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
    http_rpc_provider: web3::HttpRpcProvider,
}

pub(crate) struct RpRegistryWatcherArgs<'a> {
    pub(crate) contract_address: Address,
    pub(crate) http_rpc_provider: web3::HttpRpcProvider,
    pub(crate) ws_rpc_provider: &'a DynProvider,
    pub(crate) cache_config: WatcherCacheConfig,
    pub(crate) maintenance_interval: Duration,
    pub(crate) timeout_external_eth_call: Duration,
    pub(crate) started: Arc<AtomicBool>,
    pub(crate) cancellation_token: CancellationToken,
}

impl RpRegistryWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        args: RpRegistryWatcherArgs<'_>,
    ) -> eyre::Result<(Self, tokio::task::JoinHandle<eyre::Result<()>>)> {
        let RpRegistryWatcherArgs {
            contract_address,
            http_rpc_provider,
            ws_rpc_provider,
            cache_config,
            maintenance_interval,
            timeout_external_eth_call,
            started,
            cancellation_token,
        } = args;
        ::metrics::gauge!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE).set(0.0);

        tracing::info!("listening for events...");
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Latest)
            .event_signature(RpUpdated::SIGNATURE_HASH);
        let sub = ws_rpc_provider.subscribe_logs(&filter).await?;
        let stream = sub.into_stream();

        // indicate that the RpRegistry watcher has started
        started.store(true, Ordering::Relaxed);

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
        tracing::info!("starting subscribe task");
        let subscribe_task =
            tokio::task::spawn(subscribe_task(stream, rp_store.clone(), cancellation_token));

        // periodically run maintenance tasks on the cache and update metrics
        tokio::spawn({
            let rp_store = rp_store.clone();
            let mut interval = tokio::time::interval(maintenance_interval);
            async move {
                loop {
                    interval.tick().await;
                    rp_store.run_pending_tasks().await;
                }
            }
        });

        let rp_registry = Self {
            rp_store,
            contract: RpRegistry::new(contract_address, http_rpc_provider.inner()),
            timeout_external_eth_call,
            http_rpc_provider,
        };

        Ok((rp_registry, subscribe_task))
    }

    #[instrument(level = "debug", skip_all, fields(rp_id=%rp_id))]
    pub(crate) async fn get_rp(
        &self,
        rp_id: &RpId,
    ) -> Result<RelyingParty, RpRegistryWatcherError> {
        let rp = self
            .rp_store
            .try_get_with(*rp_id, {
                let contract = self.contract.clone();
                let rpc_provider = self.http_rpc_provider.clone();
                async {
                    try_load_rp_from_chain(
                        *rp_id,
                        contract,
                        self.timeout_external_eth_call,
                        rpc_provider,
                    )
                    .await
                }
            })
            .await?;
        tracing::trace!("returning {rp_id}/{}", rp.account_type);
        Ok(rp)
    }

    #[allow(dead_code, reason = "is only used in tests")]
    #[cfg(test)]
    pub(crate) fn set_timeout_external_eth_call(&mut self, duration: Duration) {
        self.timeout_external_eth_call = duration;
    }
}

async fn try_load_rp_from_chain(
    rp_id: RpId,
    contract: RpRegistryInstance<DynProvider>,
    timeout_external_eth_call: Duration,
    rpc_provider: web3::HttpRpcProvider,
) -> Result<RelyingParty, RpRegistryWatcherError> {
    tracing::trace!("rp {rp_id} not found in store, querying RpRegistry...");
    let rp = match contract.getRp(rp_id.into_inner()).call().await {
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
    metrics::counter!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES).increment(1);

    let account_type = tokio::time::timeout(
        timeout_external_eth_call,
        wip101::account_check(rp.signer, &rpc_provider),
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

async fn subscribe_task(
    mut subscription: SubscriptionStream<Log>,
    rp_store: Cache<RpId, RelyingParty>,
    cancellation_token: CancellationToken,
) -> eyre::Result<()> {
    // shutdown service if RP registry watcher encounters an error and drops this guard
    let _drop_guard = cancellation_token.clone().drop_guard();
    loop {
        let log = tokio::select! {
            log = subscription.next() => {
                log.ok_or_else(||{
                    tracing::warn!("RpRegistry subscribe stream was closed");
                    eyre::eyre!("RpRegistry subscribe stream was closed")
                })?
            }
            () = cancellation_token.cancelled() => {
                break;
            }
        };

        match RpUpdated::decode_log(log.as_ref()) {
            Ok(event) => {
                let rp_id = RpId::new(event.rpId);
                tracing::debug!("update event for {rp_id} - invalidate cache-entry");
                // according to WIP101/8 OPRF nodes MUST invalidate the RP cache in case they receive an RpUpdate event
                rp_store.invalidate(&rp_id).await;
            }
            Err(err) => {
                tracing::warn!("failed to decode RpUpdated contract event: {err:?}");
            }
        }
    }
    tracing::info!("Successfully shutdown RpRegistry");
    eyre::Ok(())
}
