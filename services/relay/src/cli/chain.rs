use std::{sync::Arc, time::Duration};

use alloy::providers::DynProvider;

use crate::{
    bindings::{
        ICredentialSchemaIssuerRegistry::ICredentialSchemaIssuerRegistryInstance,
        IOprfKeyRegistry::IOprfKeyRegistryInstance, IWorldIDRegistry::IWorldIDRegistryInstance,
        IWorldIDSource::IWorldIDSourceInstance,
    },
    cli::WorldChainConfig,
};

/// World Chain source chain state, holding contract instances and the provider.
///
/// All contract instances share the same `Arc<DynProvider>`, avoiding redundant
/// generic parameters throughout the codebase.
pub struct WorldChain {
    /// The provider for the World Chain.
    provider: Arc<DynProvider>,

    /// The World ID registry contract on World Chain.
    world_id_registry: IWorldIDRegistryInstance<Arc<DynProvider>>,

    /// The credential issuer schema registry contract on World Chain.
    credential_issuer_schema_registry: ICredentialSchemaIssuerRegistryInstance<Arc<DynProvider>>,

    /// The OPRF key registry contract on World Chain.
    oprf_key_registry: IOprfKeyRegistryInstance<Arc<DynProvider>>,

    /// The WorldIDSource proxy contract on World Chain.
    world_id_source: IWorldIDSourceInstance<Arc<DynProvider>>,

    /// The bridging interval for periodic `propagateState` calls.
    bridge_interval: Duration,

    /// Block number at which the WorldIDSource contract was deployed.
    deployment_block: u64,
}

impl WorldChain {
    /// Constructs a new `WorldChain` from a pre-built provider and CLI config.
    ///
    /// This is intentionally synchronous -- provider construction is the caller's
    /// responsibility, keeping I/O at the edges.
    pub fn new(config: &WorldChainConfig, provider: Arc<DynProvider>) -> Self {
        Self {
            world_id_registry: IWorldIDRegistryInstance::new(
                config.world_id_registry,
                provider.clone(),
            ),
            credential_issuer_schema_registry: ICredentialSchemaIssuerRegistryInstance::new(
                config.credential_issuer_schema_registry,
                provider.clone(),
            ),
            oprf_key_registry: IOprfKeyRegistryInstance::new(
                config.oprf_key_registry,
                provider.clone(),
            ),
            world_id_source: IWorldIDSourceInstance::new(config.world_id_source, provider.clone()),
            bridge_interval: Duration::from_secs(config.bridge_interval),
            deployment_block: config.deployment_block,
            provider,
        }
    }

    pub fn provider(&self) -> &Arc<DynProvider> {
        &self.provider
    }

    pub fn world_id_registry(&self) -> &IWorldIDRegistryInstance<Arc<DynProvider>> {
        &self.world_id_registry
    }

    pub fn credential_issuer_schema_registry(
        &self,
    ) -> &ICredentialSchemaIssuerRegistryInstance<Arc<DynProvider>> {
        &self.credential_issuer_schema_registry
    }

    pub fn oprf_key_registry(&self) -> &IOprfKeyRegistryInstance<Arc<DynProvider>> {
        &self.oprf_key_registry
    }

    pub fn world_id_source(&self) -> &IWorldIDSourceInstance<Arc<DynProvider>> {
        &self.world_id_source
    }

    pub fn bridge_interval(&self) -> Duration {
        self.bridge_interval
    }

    pub fn deployment_block(&self) -> u64 {
        self.deployment_block
    }
}
