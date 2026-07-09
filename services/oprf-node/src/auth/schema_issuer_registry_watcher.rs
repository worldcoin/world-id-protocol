use std::sync::Arc;

use crate::{
    auth::schema_issuer_registry_watcher::CredentialSchemaIssuerRegistry::CredentialSchemaIssuerRegistryInstance,
    config::WatcherCacheConfig, metrics,
};
use alloy::{primitives::Address, providers::DynProvider};
use backon::Retryable as _;
use eyre::Context;
use moka::future::Cache;
use taceo_nodes_common::web3;
use tracing::instrument;
use world_id_primitives::oprf::WorldIdRequestAuthError;

// Copied from I.ICredentialSchemaIssuerRegistry.sol.
//
// For brevity we only copy the methods that are relevant for the watcher
alloy::sol! {
    #[sol(rpc)]
    interface CredentialSchemaIssuerRegistry {
        function getSignerForIssuerSchemaId(uint64 issuerSchemaId) returns (address);
    }
}

/// Error returned by the [`SchemaIssuerRegistryWatcher`] implementation.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SchemaIssuerRegistryWatcherError {
    /// Unknown schema issuer.
    #[error("unknown schema issuer: {0}")]
    UnknownSchemaIssuerId(u64),
    /// Internal Error
    #[error("Internal error: {0:?}")]
    Internal(#[from] eyre::Report),
}

impl From<&SchemaIssuerRegistryWatcherError> for WorldIdRequestAuthError {
    fn from(value: &SchemaIssuerRegistryWatcherError) -> Self {
        match value {
            SchemaIssuerRegistryWatcherError::UnknownSchemaIssuerId(_) => {
                Self::UnknownSchemaIssuerId
            }
            SchemaIssuerRegistryWatcherError::Internal(_) => Self::Internal,
        }
    }
}

/// Validates and caches issuers from the `CredentialSchemaIssuerRegistry` contract.
///
/// Issuers are lazily loaded: the cache starts empty and entries are validated
/// on-chain on first request, then cached for the configured TTL.
///
/// On-chain issuer removals may take up to the configured cache TTL to
/// propagate. Operators should use a reasonably small TTL.
#[derive(Clone)]
pub(crate) struct SchemaIssuerRegistryWatcher {
    issuer_schema_store: Cache<u64, ()>,
    contract: CredentialSchemaIssuerRegistryInstance<DynProvider>,
    cache_config: WatcherCacheConfig,
}

impl SchemaIssuerRegistryWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) fn init(
        contract_address: Address,
        http_rpc_provider: &web3::HttpRpcProvider,
        cache_config: WatcherCacheConfig,
    ) -> Self {
        let store_builder = Cache::builder()
            .max_capacity(cache_config.max_cache_size.get())
            .time_to_live(cache_config.time_to_live);
        let issuer_schema_store = if let Some(time_to_idle) = cache_config.time_to_idle {
            store_builder.time_to_idle(time_to_idle).build()
        } else {
            store_builder.build()
        };

        Self {
            issuer_schema_store,
            contract: CredentialSchemaIssuerRegistryInstance::new(
                contract_address,
                http_rpc_provider.inner(),
            ),
            cache_config,
        }
    }

    #[instrument(level = "debug", skip_all, fields(issuer_schema_id=issuer_schema_id))]
    pub(crate) async fn is_valid_issuer(
        &self,
        issuer_schema_id: u64,
    ) -> Result<(), Arc<SchemaIssuerRegistryWatcherError>> {
        let backon_fetch_issuer = (|| async { self.fetch_issuer(issuer_schema_id).await })
            .retry(self.cache_config.backoff_strategy())
            .sleep(tokio::time::sleep)
            .when(|e| {
                matches!(
                    e,
                    SchemaIssuerRegistryWatcherError::UnknownSchemaIssuerId(_)
                )
            })
            .notify(|err, duration| {
                tracing::warn!(%err, "fetch issuer will retry after {duration:?}");
            });

        let entry = self
            .issuer_schema_store
            .entry(issuer_schema_id)
            .or_try_insert_with(backon_fetch_issuer)
            .await?;

        if entry.is_fresh() {
            metrics::schema_issuer_cache::set(self.issuer_schema_store.entry_count());
            metrics::schema_issuer_cache::miss();
            tracing::trace!("issuer {issuer_schema_id} loaded from chain");
        } else {
            metrics::schema_issuer_cache::hit();
        }
        Ok(())
    }

    #[instrument(level = "debug", skip_all, fields(issuer_schema_id))]
    async fn fetch_issuer(
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
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use eddsa_babyjubjub::EdDSAPrivateKey;
    use rand::Rng;
    use world_id_test_utils::anvil::TestAnvil;

    use crate::{auth::tests::build_http_provider, config::WatcherCacheConfig};

    /// Deploys only what the watcher needs (credential registry) and registers one issuer.
    async fn setup_with_issuer(
        cache_config: WatcherCacheConfig,
    ) -> eyre::Result<(SchemaIssuerRegistryWatcher, TestAnvil, u64, Address)> {
        let mut rng = rand::thread_rng();
        let anvil = TestAnvil::spawn_auto_mine_with_multicall3().await?;
        let deployer = anvil.signer(0)?;
        let oprf_key_registry = anvil
            .deploy_mock_oprf_key_registry(deployer.clone())
            .await?;
        let credential_registry = anvil
            .deploy_credential_schema_issuer_registry(deployer.clone(), oprf_key_registry)
            .await?;

        let issuer_schema_id: u64 = rng.r#gen();
        let issuer_sk = EdDSAPrivateKey::random(&mut rng);

        anvil
            .register_issuer(
                credential_registry,
                deployer,
                issuer_schema_id,
                issuer_sk.public(),
            )
            .await?;

        let watcher = SchemaIssuerRegistryWatcher::init(
            credential_registry,
            &build_http_provider(&anvil.instance),
            cache_config,
        );

        Ok((watcher, anvil, issuer_schema_id, credential_registry))
    }

    #[tokio::test]
    async fn test_valid_issuer_accepted() -> eyre::Result<()> {
        let (watcher, _anvil, issuer_schema_id, _) =
            setup_with_issuer(WatcherCacheConfig::default()).await?;

        watcher
            .is_valid_issuer(issuer_schema_id)
            .await
            .expect("registered issuer should be accepted");
        assert!(
            watcher.issuer_schema_store.contains_key(&issuer_schema_id),
            "Cache should have issuer cached"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_unknown_issuer_rejected() -> eyre::Result<()> {
        let (watcher, _anvil, _, _) = setup_with_issuer(WatcherCacheConfig::default()).await?;

        let unknown_id = 99999u64;
        let err = watcher
            .is_valid_issuer(unknown_id)
            .await
            .expect_err("unknown issuer should be rejected");
        assert!(
            matches!(
                err.as_ref(),
                SchemaIssuerRegistryWatcherError::UnknownSchemaIssuerId(id) if *id == unknown_id
            ),
            "expected UnknownSchemaIssuerId({unknown_id}), got: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_removed_issuer_rejected_after_ttl() -> eyre::Result<()> {
        let (watcher, anvil, issuer_schema_id, credential_registry) =
            setup_with_issuer(WatcherCacheConfig {
                time_to_live: Duration::from_millis(100),
                ..Default::default()
            })
            .await?;

        watcher
            .is_valid_issuer(issuer_schema_id)
            .await
            .expect("should be valid before removal");

        let deployer = anvil.signer(0)?;
        anvil
            .remove_issuer(
                credential_registry,
                deployer.clone(),
                deployer,
                issuer_schema_id,
            )
            .await?;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let err = watcher
            .is_valid_issuer(issuer_schema_id)
            .await
            .expect_err("should fail after TTL expiry");
        assert!(
            !watcher.issuer_schema_store.contains_key(&issuer_schema_id),
            "Cache should not have removed issuer cached"
        );
        assert!(
            matches!(
                err.as_ref(),
                SchemaIssuerRegistryWatcherError::UnknownSchemaIssuerId(_)
            ),
            "expected UnknownSchemaIssuerId, got: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_error_not_cached() -> eyre::Result<()> {
        let (watcher, _anvil, _, _) = setup_with_issuer(WatcherCacheConfig::default()).await?;

        let unknown_id = 99999;
        watcher
            .is_valid_issuer(unknown_id)
            .await
            .expect_err("first call should fail");
        assert!(
            !watcher.issuer_schema_store.contains_key(&unknown_id),
            "Cache should not have unknown issuer cached"
        );
        watcher
            .is_valid_issuer(unknown_id)
            .await
            .expect_err("second call should also fail (error must not be cached)");
        assert!(
            !watcher.issuer_schema_store.contains_key(&unknown_id),
            "Cache should not have unknown issuer cached"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_contract_call_failure_returns_internal() -> eyre::Result<()> {
        let anvil = TestAnvil::spawn_auto_mine_with_multicall3().await?;
        let http_rpc_provider = build_http_provider(&anvil.instance);
        // Address with no contract bytecode — getSignerForIssuerSchemaId() call will fail
        let watcher = SchemaIssuerRegistryWatcher::init(
            Address::with_last_byte(42),
            &http_rpc_provider,
            WatcherCacheConfig::default(),
        );

        let err = watcher
            .is_valid_issuer(rand::thread_rng().r#gen::<u64>())
            .await
            .expect_err("call to non-existent contract should fail");
        assert!(
            matches!(err.as_ref(), SchemaIssuerRegistryWatcherError::Internal(_)),
            "expected Internal, got: {err:?}"
        );
        Ok(())
    }
}
