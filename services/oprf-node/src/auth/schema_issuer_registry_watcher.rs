use std::sync::Arc;

use crate::{
    auth::schema_issuer_registry_watcher::CredentialSchemaIssuerRegistry::CredentialSchemaIssuerRegistryInstance,
    config::WatcherCacheConfig,
    metrics::{
        METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_MISSES,
        METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE,
    },
};
use alloy::{primitives::Address, providers::DynProvider};
use eyre::Context;
use moka::future::Cache;
use taceo_nodes_common::web3;
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

impl From<Arc<SchemaIssuerRegistryWatcherError>> for SchemaIssuerRegistryWatcherError {
    fn from(value: Arc<SchemaIssuerRegistryWatcherError>) -> Self {
        match value.as_ref() {
            SchemaIssuerRegistryWatcherError::UnknownSchemaIssuerId(issuer_id) => {
                Self::UnknownSchemaIssuerId(*issuer_id)
            }
            SchemaIssuerRegistryWatcherError::Internal(report) => {
                Self::Internal(eyre::eyre!("{report:?}"))
            }
        }
    }
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
        rpc_provider: &web3::RpcProvider,
        cache_config: WatcherCacheConfig,
    ) -> eyre::Result<Self> {
        ::metrics::gauge!(METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE).set(0.0);

        let WatcherCacheConfig {
            max_cache_size,
            time_to_live,
            time_to_idle: _,
        } = cache_config;

        let issuer_schema_store: Cache<u64, ()> = Cache::builder()
            .max_capacity(max_cache_size)
            .time_to_live(time_to_live)
            .eviction_listener(move |k, (), cause| {
                tracing::debug!("removing {k} because: {cause:?}");
                metrics::gauge!(METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE,)
                    .decrement(1);
            })
            .build();

        let schema_issuer_registry = Self {
            issuer_schema_store,
            contract: CredentialSchemaIssuerRegistryInstance::new(
                contract_address,
                rpc_provider.http(),
            ),
        };
        Ok(schema_issuer_registry)
    }

    #[instrument(level = "debug", skip_all, fields(issuer_schema_id=issuer_schema_id))]
    pub(crate) async fn is_valid_issuer(
        &self,
        issuer_schema_id: u64,
    ) -> Result<(), SchemaIssuerRegistryWatcherError> {
        let entry = self
            .issuer_schema_store
            .entry(issuer_schema_id)
            .or_try_insert_with(self.fetch_signer_for_issuer(issuer_schema_id))
            .await?;
        if entry.is_fresh() {
            ::metrics::counter!(METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_MISSES)
                .increment(1);
            metrics::gauge!(METRICS_ID_NODE_SCHEMA_ISSUER_REGISTRY_WATCHER_CACHE_SIZE,)
                .increment(1);
        }
        Ok(())
    }

    async fn fetch_signer_for_issuer(
        &self,
        issuer_schema_id: u64,
    ) -> Result<(), SchemaIssuerRegistryWatcherError> {
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
            tracing::debug!("issuer {issuer_schema_id} loaded from chain");

            Ok(())
        }
    }
}
