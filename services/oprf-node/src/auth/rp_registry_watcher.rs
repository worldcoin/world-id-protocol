use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::{
    auth::rp_registry_watcher::RpRegistry::{RpRegistryInstance, RpUpdated},
    config::WatcherCacheConfig,
    metrics::{
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_HITS,
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES,
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE,
    },
};
use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::{DynProvider, Provider as _},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use futures::StreamExt as _;
use moka::{future::Cache, ops::compute::Op};
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

#[derive(Clone, Debug)]
pub(crate) struct RelyingParty {
    pub(crate) signer: Address,
    pub(crate) oprf_key_id: OprfKeyId,
}

/// Error returned by the [`RpRegistryWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RpRegistryWatcherError {
    /// Unknown RP.
    #[error("unknown rp: {0}")]
    UnknownRp(RpId),
    /// Inactive RP.
    #[error("inactive rp: {0}")]
    InactiveRp(RpId),
    /// Internal Error
    #[error(transparent)]
    Internal(#[from] eyre::Report),
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
}

impl RpRegistryWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        contract_address: Address,
        rpc_provider: &web3::RpcProvider,
        cache_config: WatcherCacheConfig,
        maintenance_interval: Duration,
        started: Arc<AtomicBool>,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<(Self, tokio::task::JoinHandle<eyre::Result<()>>)> {
        ::metrics::gauge!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE).set(0.0);

        tracing::info!("listening for events...");
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Latest)
            .event_signature(RpUpdated::SIGNATURE_HASH);
        let sub = rpc_provider.subscriptions().subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();

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
            .build();
        let subscribe_task = tokio::task::spawn({
            let rp_store = rp_store.clone();
            async move {
                // shutdown service if RP registry watcher encounters an error and drops this guard
                let _drop_guard = cancellation_token.clone().drop_guard();
                loop {
                    let log = tokio::select! {
                        log = stream.next() => {
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
                            tracing::trace!("got rp-update event for rp: {rp_id}");
                            if event.active {
                                rp_store
                                    .entry(rp_id)
                                    .and_compute_with(|entry| async {
                                        if let Some(entry) = entry {
                                            tracing::debug!("updating rp {rp_id} in store");
                                            let mut rp = entry.into_value();
                                            // Note: we don't update oprf key id because it cannot mutate
                                            rp.signer = event.signer;
                                            Op::Put(rp)
                                        } else {
                                            tracing::trace!(
                                                "rp {rp_id} not found in store, ignoring update"
                                            );
                                            Op::Nop
                                        }
                                    })
                                    .await;
                            } else {
                                tracing::debug!(
                                    "removing rp {rp_id} from store because it is not active"
                                );
                                rp_store.invalidate(&rp_id).await;
                            }
                        }
                        Err(err) => {
                            tracing::warn!("failed to decode RpUpdated contract event: {err:?}");
                        }
                    }
                }
                tracing::info!("Successfully shutdown RpRegistry");
                eyre::Ok(())
            }
        });

        // periodically run maintenance tasks on the cache and update metrics
        tokio::spawn({
            let rp_store = rp_store.clone();
            let mut interval = tokio::time::interval(maintenance_interval);
            async move {
                loop {
                    interval.tick().await;
                    rp_store.run_pending_tasks().await;
                    let size = rp_store.entry_count() as f64;
                    ::metrics::gauge!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE).set(size);
                }
            }
        });

        let rp_registry = Self {
            rp_store,
            contract: RpRegistry::new(contract_address, rpc_provider.http()),
        };

        Ok((rp_registry, subscribe_task))
    }

    #[instrument(level = "debug", skip_all, fields(rp_id=%rp_id))]
    pub(crate) async fn get_rp(
        &self,
        rp_id: &RpId,
    ) -> Result<RelyingParty, RpRegistryWatcherError> {
        if let Some(rp) = self.rp_store.get(rp_id).await {
            tracing::trace!("rp {rp_id} found in store");
            ::metrics::counter!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_HITS).increment(1);
            return Ok(rp);
        }

        tracing::trace!("rp {rp_id} not found in store, querying RpRegistry...");
        let rp = match self.contract.getRp(rp_id.into_inner()).call().await {
            Ok(rp) => rp,
            Err(err) => {
                if let Some(RpRegistry::RpIdDoesNotExist) =
                    err.as_decoded_error::<RpRegistry::RpIdDoesNotExist>()
                {
                    return Err(RpRegistryWatcherError::UnknownRp(*rp_id));
                } else if let Some(RpRegistry::RpIdInactive) =
                    err.as_decoded_error::<RpRegistry::RpIdInactive>()
                {
                    return Err(RpRegistryWatcherError::InactiveRp(*rp_id));
                }
                return Err(RpRegistryWatcherError::Internal(eyre::eyre!(
                    "failed to fetch RP info from chain: {err:?}"
                )));
            }
        };

        ::metrics::counter!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES).increment(1);

        let relying_party = RelyingParty {
            signer: rp.signer,
            oprf_key_id: OprfKeyId::new(rp.oprfKeyId),
        };
        self.rp_store.insert(*rp_id, relying_party.clone()).await;

        tracing::debug!("rp {rp_id} loaded from chain and stored");

        Ok(relying_party)
    }
}
