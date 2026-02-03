use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::{
    auth::rp_registry_watcher::RpRegistry::RpUpdated,
    metrics::{
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_HITS,
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES,
        METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE,
    },
};
use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::{DynProvider, Provider as _, ProviderBuilder, WsConnect},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use futures::StreamExt as _;
use moka::{future::Cache, ops::compute::Op};
use taceo_oprf::types::OprfKeyId;
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use world_id_primitives::rp::RpId;

alloy::sol! {
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    RpRegistry,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/RpRegistry.sol/RpRegistry.json"
    )
}

#[derive(Clone, Debug)]
pub(crate) struct RelyingParty {
    pub(crate) signer: Address,
    pub(crate) oprf_key_id: OprfKeyId,
}

/// Error returned by the [`RpRegistryWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RpRegistryWatcherError {
    /// Error communicating with the chain.
    #[error("alloy error: {0}")]
    AlloyError(alloy::contract::Error),

    /// Unknown RP.
    #[error("unknown rp: {0}")]
    UnknownRp(RpId),
}

/// Monitors the RPs from the RpRegistry contract.
///
/// RPs are lazily loaded, meaning in the beginning the store will be empty. When valid requests are coming in from users, this service will go to chain and try fetching the ecdsa keys and store them up to a configurable maximum.
///
/// Additionally, will subscribe to chain events to handle RpUpdate events.
#[derive(Clone)]
pub(crate) struct RpRegistryWatcher {
    rp_store: Cache<RpId, RelyingParty>,
    provider: DynProvider, // do not drop provider while we want to stay subscribed
    contract_address: Address,
}

impl RpRegistryWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        contract_address: Address,
        ws_rpc_url: &str,
        max_rp_registry_store_size: u64,
        cache_maintenance_interval: Duration,
        started: Arc<AtomicBool>,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<Self> {
        ::metrics::gauge!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE).set(0.0);

        tracing::info!("creating provider for rp-registry-watcher...");
        let ws = WsConnect::new(ws_rpc_url);
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        tracing::info!("listening for events...");
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Latest)
            .event_signature(RpUpdated::SIGNATURE_HASH);
        let sub = provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();

        // indicate that the RpRegistry watcher has started
        started.store(true, Ordering::Relaxed);

        let rp_store: Cache<RpId, RelyingParty> = Cache::builder()
            .max_capacity(max_rp_registry_store_size)
            .build();
        tokio::task::spawn({
            let rp_store = rp_store.clone();
            async move {
                // shutdown service if RP registry watcher encounters an error and drops this guard
                let _drop_guard = cancellation_token.drop_guard();
                while let Some(log) = stream.next().await {
                    match RpUpdated::decode_log(log.as_ref()) {
                        Ok(event) => {
                            let rp_id = RpId::new(event.rpId);
                            tracing::info!("got rp-update event for rp: {rp_id}");
                            if event.active {
                                rp_store
                                    .entry(rp_id)
                                    .and_compute_with(|entry| async {
                                        if let Some(entry) = entry {
                                            tracing::debug!("updating rp {rp_id} in store");
                                            let mut rp = entry.into_value();
                                            rp.signer = event.signer;
                                            rp.oprf_key_id = OprfKeyId::new(event.oprfKeyId);
                                            Op::Put(rp)
                                        } else {
                                            tracing::debug!(
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
            }
        });

        // periodically run maintenance tasks on the cache and update metrics
        tokio::spawn({
            let rp_store = rp_store.clone();
            let mut interval = tokio::time::interval(cache_maintenance_interval);
            async move {
                loop {
                    interval.tick().await;
                    rp_store.run_pending_tasks().await;
                    let size = rp_store.entry_count() as f64;
                    ::metrics::gauge!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_SIZE).set(size);
                }
            }
        });

        Ok(Self {
            rp_store,
            provider: provider.erased(),
            contract_address,
        })
    }

    pub(crate) async fn get_rp(
        &self,
        rp_id: &RpId,
    ) -> Result<RelyingParty, RpRegistryWatcherError> {
        {
            if let Some(rp) = self.rp_store.get(rp_id).await {
                tracing::debug!("rp {rp_id} found in store");
                ::metrics::counter!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_HITS).increment(1);
                return Ok(rp);
            }
        }

        tracing::debug!("rp {rp_id} not found in store, querying RpRegistry...");
        let contract = RpRegistry::new(self.contract_address, &self.provider);
        let rp = contract
            .getRp(rp_id.into_inner())
            .call()
            .await
            .map_err(RpRegistryWatcherError::AlloyError)?;

        if rp.initialized {
            ::metrics::counter!(METRICS_ID_NODE_RP_REGISTRY_WATCHER_CACHE_MISSES).increment(1);

            let relying_party = RelyingParty {
                signer: rp.signer,
                oprf_key_id: OprfKeyId::new(rp.oprfKeyId),
            };
            self.rp_store.insert(*rp_id, relying_party.clone()).await;

            tracing::debug!("rp {rp_id} loaded from chain and stored");

            Ok(relying_party)
        } else {
            Err(RpRegistryWatcherError::UnknownRp(*rp_id))
        }
    }
}
