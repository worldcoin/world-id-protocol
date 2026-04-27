use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::{
    auth::{
        WatcherBackgroundTasks,
        schema_issuer_registry_watcher::CredentialSchemaIssuerRegistry::{
            CredentialSchemaIssuerRegistryInstance, IssuerSchemaRemoved,
        },
    },
    config::WatcherCacheConfig,
    metrics::{
        METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_MISSES,
        METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE,
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
use tokio_util::sync::CancellationToken;
use tracing::instrument;

alloy::sol! {
    #[allow(missing_docs, clippy::too_many_arguments, reason="Get this errors from sol macro")]
    #[sol(rpc)]
    CredentialSchemaIssuerRegistry,
    "abi/CredentialSchemaIssuerRegistryAbi.json"
}

/// Error returned by the [`IssuerSchemaRegistryWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SchemaIssuerRegistryWatcherError {
    /// Unknown schema issuer.
    #[error("unknown schema issuer: {0}")]
    UnknownSchemaIssuerId(u64),
    /// Internal Error
    #[error(transparent)]
    Internal(#[from] eyre::Report),
}

/// Monitors the issuer from the `CredentialSchemaIssuerRegistry` contract.
///
/// Issuers are lazily loaded, meaning in the beginning the store will be empty. When valid requests are coming in from users,
/// this service will go to chain and check if the issuer schema id is valid and cache them for future requests.
/// Additionally, will subscribe to chain events to handle `IssuerSchemaRemoved` events and remove entries from the cache.
#[derive(Clone)]
pub(crate) struct SchemaIssuerRegistryWatcher {
    issuer_schema_store: Cache<u64, ()>,
    contract: CredentialSchemaIssuerRegistryInstance<DynProvider>,
}

impl SchemaIssuerRegistryWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        contract_address: Address,
        http_rpc_provider: &web3::HttpRpcProvider,
        ws_rpc_provider: &DynProvider,
        cache_config: WatcherCacheConfig,
        maintenance_interval: Duration,
        started: Arc<AtomicBool>,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<(Self, WatcherBackgroundTasks)> {
        tracing::info!("listening for events...");
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Latest)
            .event_signature(IssuerSchemaRemoved::SIGNATURE_HASH);
        let sub = ws_rpc_provider.subscribe_logs(&filter).await?;
        let stream = sub.into_stream();

        ::metrics::gauge!(METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE).set(0.0);

        // indicate that the IssuerRegistry watcher has started
        started.store(true, Ordering::Relaxed);

        let WatcherCacheConfig {
            max_cache_size,
            time_to_live,
            time_to_idle,
        } = cache_config;

        let issuer_schema_store: Cache<u64, ()> = Cache::builder()
            .max_capacity(max_cache_size)
            .time_to_live(time_to_live)
            .time_to_idle(time_to_idle)
            .build();
        let subscribe = tokio::task::spawn(subscribe_task(
            stream,
            issuer_schema_store.clone(),
            cancellation_token.clone(),
        ));

        let maintenance = tokio::spawn(maintenance_task(
            issuer_schema_store.clone(),
            maintenance_interval,
            cancellation_token,
        ));

        let schema_issuer_registry = Self {
            issuer_schema_store,
            contract: CredentialSchemaIssuerRegistryInstance::new(
                contract_address,
                http_rpc_provider.inner(),
            ),
        };
        Ok((
            schema_issuer_registry,
            WatcherBackgroundTasks {
                subscribe,
                maintenance,
            },
        ))
    }

    #[instrument(level = "debug", skip_all, fields(issuer_schema_id=issuer_schema_id))]
    pub(crate) async fn is_valid_issuer(
        &self,
        issuer_schema_id: u64,
    ) -> Result<(), SchemaIssuerRegistryWatcherError> {
        self.issuer_schema_store.try_get_with(issuer_schema_id, async {
            tracing::trace!(
                "issuer {issuer_schema_id} not found in store, querying CredentialSchemaIssuerRegistry..."
            );
            let signer = self
                .contract
                .getSignerForIssuerSchemaId(issuer_schema_id)
                .call()
                .await
                .context("while getting signer for issuer-schema")?;

            if signer == Address::ZERO {
                Err(SchemaIssuerRegistryWatcherError::UnknownSchemaIssuerId(
                    issuer_schema_id,
                ))
            } else {
                ::metrics::counter!(METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_MISSES)
                    .increment(1);

                tracing::debug!("issuer {issuer_schema_id} loaded from chain");

                Ok(())
            }
        }).await.map_err(|arc| match arc.as_ref() {
            SchemaIssuerRegistryWatcherError::UnknownSchemaIssuerId(id) => SchemaIssuerRegistryWatcherError::UnknownSchemaIssuerId(*id),
            SchemaIssuerRegistryWatcherError::Internal(report) => SchemaIssuerRegistryWatcherError::Internal(eyre::eyre!("{report:?}")),
        })
    }
}

async fn subscribe_task(
    mut stream: SubscriptionStream<Log>,
    issuer_schema_store: Cache<u64, ()>,
    cancellation_token: CancellationToken,
) -> eyre::Result<()> {
    // shutdown service if issuer registry watcher encounters an error and drops this guard
    let _drop_guard = cancellation_token.clone().drop_guard();

    loop {
        let log = tokio::select! {
            log = stream.next() => {
                log.ok_or_else(||{
                    tracing::warn!("SchemaIssuerRegistryWatcher subscribe stream was closed");
                    eyre::eyre!("SchemaIssuerRegistryWatcher subscribe stream was closed")
                })?
            }
            () = cancellation_token.cancelled() => {
                break;
            }
        };

        match IssuerSchemaRemoved::decode_log(log.as_ref()) {
            Ok(event) => {
                let issuer_schema_id = event.issuerSchemaId;
                tracing::info!(
                    "got issuer-schema-removed event for issuer_schema_id: {issuer_schema_id}"
                );
                issuer_schema_store.invalidate(&issuer_schema_id).await;
            }
            Err(err) => {
                tracing::warn!("failed to decode IssuerSchemaRemoved contract event: {err:?}");
            }
        }
    }
    tracing::info!("Successfully shutdown SchemaIssuerRegistryWatcher");
    eyre::Ok(())
}

/// Periodically runs cache maintenance tasks and updates the cache size metric
/// until cancellation is requested.
async fn maintenance_task(
    issuer_schema_store: Cache<u64, ()>,
    maintenance_interval: Duration,
    cancellation_token: CancellationToken,
) -> eyre::Result<()> {
    // shutdown service if the maintenance task panics or exits unexpectedly
    let _drop_guard = cancellation_token.clone().drop_guard();
    let mut interval = tokio::time::interval(maintenance_interval);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                issuer_schema_store.run_pending_tasks().await;
                let size = issuer_schema_store.entry_count() as f64;
                ::metrics::gauge!(METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE)
                    .set(size);
            }
            () = cancellation_token.cancelled() => {
                break;
            }
        }
    }
    tracing::info!("Successfully shutdown SchemaIssuerRegistryWatcher cache maintenance task");
    eyre::Ok(())
}
