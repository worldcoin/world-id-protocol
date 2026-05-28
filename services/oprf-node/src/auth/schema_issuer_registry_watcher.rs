use std::{sync::Arc, time::Duration};

use crate::{
    auth::schema_issuer_registry_watcher::CredentialSchemaIssuerRegistry::CredentialSchemaIssuerRegistryInstance,
    config::WatcherCacheConfig, metrics,
};
use alloy::{primitives::Address, providers::DynProvider};
use backon::{BackoffBuilder as _, ConstantBackoff, ConstantBuilder, Retryable as _};
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
    retry_interval: Duration,
    retry_max_times: usize,
}

impl SchemaIssuerRegistryWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) fn init(
        contract_address: Address,
        http_rpc_provider: &web3::HttpRpcProvider,
        cache_config: WatcherCacheConfig,
        retry_interval: Duration,
        retry_max_times: usize,
    ) -> Self {
        metrics::schema_issuer_cache::reset();

        let WatcherCacheConfig {
            max_cache_size,
            time_to_live,
            time_to_idle,
        } = cache_config;

        let store_builder = Cache::builder()
            .max_capacity(max_cache_size.get())
            .time_to_live(time_to_live)
            .eviction_listener(move |k, (), cause| {
                tracing::debug!("removing issuer {k} because: {cause:?}");
                metrics::schema_issuer_cache::dec();
            });
        let issuer_schema_store = if let Some(time_to_idle) = time_to_idle {
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
            retry_interval,
            retry_max_times,
        }
    }

    #[instrument(level = "debug", skip_all, fields(issuer_schema_id=issuer_schema_id))]
    pub(crate) async fn is_valid_issuer(
        &self,
        issuer_schema_id: u64,
    ) -> Result<(), Arc<SchemaIssuerRegistryWatcherError>> {
        let backon_fetch_issuer = (|| async { self.fetch_issuer(issuer_schema_id).await })
            .retry(self.backoff_strategy())
            .sleep(tokio::time::sleep)
            .notify(|err, duration| {
                tracing::warn!(%err, "fetch issuer will retry after {duration:?}");
            });

        let entry = self
            .issuer_schema_store
            .entry(issuer_schema_id)
            .or_try_insert_with(backon_fetch_issuer)
            .await?;

        if entry.is_fresh() {
            metrics::schema_issuer_cache::inc();
            metrics::schema_issuer_cache::miss();
            tracing::debug!("issuer {issuer_schema_id} loaded from chain");
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

    #[inline]
    fn backoff_strategy(&self) -> ConstantBackoff {
        ConstantBuilder::new()
            .with_delay(self.retry_interval)
            .with_max_times(self.retry_max_times)
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use eddsa_babyjubjub::EdDSAPrivateKey;
    use rand::Rng;
    use world_id_test_utils::{anvil::TestAnvil, fixtures::RegistryTestContext};

    use crate::{auth::tests::build_http_provider, config::WatcherCacheConfig};

    async fn setup_with_issuer()
    -> eyre::Result<(SchemaIssuerRegistryWatcher, TestAnvil, u64, Address)> {
        let mut rng = rand::thread_rng();
        let RegistryTestContext {
            anvil,
            credential_registry,
            ..
        } = RegistryTestContext::new_with_mock_oprf_key_registry().await?;

        let deployer = anvil.signer(0)?;
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

        let http_rpc_provider = build_http_provider(&anvil.instance);
        let watcher = SchemaIssuerRegistryWatcher::init(
            credential_registry,
            &http_rpc_provider,
            WatcherCacheConfig::default(),
            Duration::from_secs(0),
            0,
        );

        Ok((watcher, anvil, issuer_schema_id, credential_registry))
    }

    #[tokio::test]
    async fn test_valid_issuer_accepted() -> eyre::Result<()> {
        let (watcher, _anvil, issuer_schema_id, _) = setup_with_issuer().await?;

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
        let (watcher, _anvil, _, _) = setup_with_issuer().await?;

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
        let mut rng = rand::thread_rng();
        let RegistryTestContext {
            anvil,
            credential_registry,
            ..
        } = RegistryTestContext::new_with_mock_oprf_key_registry().await?;

        let deployer = anvil.signer(0)?;
        let issuer_schema_id = 42;
        let issuer_sk = EdDSAPrivateKey::random(&mut rng);

        anvil
            .register_issuer(
                credential_registry,
                deployer.clone(),
                issuer_schema_id,
                issuer_sk.public(),
            )
            .await?;

        let http_rpc_provider = build_http_provider(&anvil.instance);
        let cache_config = WatcherCacheConfig {
            time_to_live: Duration::from_secs(1),
            ..Default::default()
        };
        let watcher = SchemaIssuerRegistryWatcher::init(
            credential_registry,
            &http_rpc_provider,
            cache_config,
            Duration::from_secs(2),
            5,
        );

        watcher
            .is_valid_issuer(issuer_schema_id)
            .await
            .expect("should be valid before removal");

        anvil
            .remove_issuer(
                credential_registry,
                deployer.clone(),
                deployer,
                issuer_schema_id,
            )
            .await?;

        tokio::time::sleep(Duration::from_secs(2)).await;

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
        let (watcher, _anvil, _, _) = setup_with_issuer().await?;

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
        let RegistryTestContext { anvil, .. } =
            RegistryTestContext::new_with_mock_oprf_key_registry().await?;
        let http_rpc_provider = build_http_provider(&anvil.instance);
        // Address with no contract bytecode — getSignerForIssuerSchemaId() call will fail
        let watcher = SchemaIssuerRegistryWatcher::init(
            Address::with_last_byte(42),
            &http_rpc_provider,
            WatcherCacheConfig::default(),
            Duration::from_secs(0),
            0,
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
