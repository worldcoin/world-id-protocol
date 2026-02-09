use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crate::{
    auth::schema_issuer_registry_watcher::CredentialSchemaIssuerRegistry::IssuerSchemaRemoved,
    metrics::{
        METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_HITS,
        METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_MISSES,
        METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE,
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
use moka::future::Cache;
use tokio_util::sync::CancellationToken;
use tracing::instrument;

alloy::sol! {
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    CredentialSchemaIssuerRegistry,
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/CredentialSchemaIssuerRegistry.sol/CredentialSchemaIssuerRegistry.json"
    )
}

/// Error returned by the [`IssuerSchemaRegistryWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SchemaIssuerRegistryWatcherError {
    /// Error communicating with the chain.
    #[error("alloy error: {0}")]
    AlloyError(alloy::contract::Error),

    /// Unknown schema issuer.
    #[error("unknown schema issuer: {0}")]
    UnknownSchemaIssuer(u64),
}

/// Monitors the issuer from the CredentialSchemaIssuerRegistry contract.
///
/// Issuers are lazily loaded, meaning in the beginning the store will be empty. When valid requests are coming in from users,
/// this service will go to chain and check if the issuer schema id is valid and cache them for future requests.
/// Additionally, will subscribe to chain events to handle IssuerSchemaRemoved events and remove entries from the cache.
#[derive(Clone)]
pub(crate) struct SchemaIssuerRegistryWatcher {
    issuer_schema_store: Cache<u64, ()>,
    provider: DynProvider, // do not drop provider while we want to stay subscribed
    contract_address: Address,
}

impl SchemaIssuerRegistryWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        contract_address: Address,
        ws_rpc_url: &str,
        max_issuer_registry_store_size: u64,
        cache_maintenance_interval: Duration,
        started: Arc<AtomicBool>,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<(Self, tokio::task::JoinHandle<eyre::Result<()>>)> {
        tracing::info!("creating provider for issuer-schema-registry-watcher...");
        let ws = WsConnect::new(ws_rpc_url);
        let provider = ProviderBuilder::new().connect_ws(ws).await?;
        tracing::info!("listening for events...");
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Latest)
            .event_signature(IssuerSchemaRemoved::SIGNATURE_HASH);
        let sub = provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();

        ::metrics::gauge!(METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE).set(0.0);

        // indicate that the IssuerRegistry watcher has started
        started.store(true, Ordering::Relaxed);

        let issuer_schema_store: Cache<u64, ()> = Cache::builder()
            .max_capacity(max_issuer_registry_store_size)
            .build();
        let subscribe_task = tokio::task::spawn({
            let issuer_schema_store = issuer_schema_store.clone();
            async move {
                // shutdown service if issuer registry watcher encounters an error and drops this guard
                let _drop_guard = cancellation_token.clone().drop_guard();

                loop {
                    let log = tokio::select! {
                        log = stream.next() => {
                            log.ok_or_else(||eyre::eyre!("SchemaIssuerRegistryWatcher subscribe stream was closed"))?
                        }
                        _ = cancellation_token.cancelled() => {
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
                            tracing::warn!(
                                "failed to decode IssuerSchemaRemoved contract event: {err:?}"
                            );
                        }
                    }
                }
                tracing::info!("Successfully shutdown SchemaIssuerRegistryWatcher");
                eyre::Ok(())
            }
        });

        // periodically run maintenance tasks on the cache and update metrics
        tokio::spawn({
            let issuer_schema_store = issuer_schema_store.clone();
            let mut interval = tokio::time::interval(cache_maintenance_interval);
            async move {
                loop {
                    interval.tick().await;
                    issuer_schema_store.run_pending_tasks().await;
                    let size = issuer_schema_store.entry_count() as f64;
                    ::metrics::gauge!(METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE)
                        .set(size);
                }
            }
        });
        let schema_issuer_registry = Self {
            issuer_schema_store,
            provider: provider.erased(),
            contract_address,
        };
        Ok((schema_issuer_registry, subscribe_task))
    }

    pub(crate) async fn is_valid_issuer(
        &self,
        issuer_schema_id: u64,
    ) -> Result<(), SchemaIssuerRegistryWatcherError> {
        {
            if self
                .issuer_schema_store
                .get(&issuer_schema_id)
                .await
                .is_some()
            {
                tracing::debug!("issuer {issuer_schema_id} found in store");
                ::metrics::counter!(METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_HITS)
                    .increment(1);
                return Ok(());
            }
        }

        tracing::debug!(
            "issuer {issuer_schema_id} not found in store, querying CredentialSchemaIssuerRegistry..."
        );
        let contract = CredentialSchemaIssuerRegistry::new(self.contract_address, &self.provider);
        let signer = contract
            .getSignerForIssuerSchemaId(issuer_schema_id)
            .call()
            .await
            .map_err(SchemaIssuerRegistryWatcherError::AlloyError)?;

        if signer != Address::ZERO {
            ::metrics::counter!(METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_MISSES)
                .increment(1);

            self.issuer_schema_store.insert(issuer_schema_id, ()).await;

            tracing::debug!("issuer {issuer_schema_id} loaded from chain and stored");

            Ok(())
        } else {
            Err(SchemaIssuerRegistryWatcherError::UnknownSchemaIssuer(
                issuer_schema_id,
            ))
        }
    }
}
