use std::{sync::Arc, time::Duration};

use alloy::providers::{DynProvider, Provider};

use crate::{
    bindings::{
        ICredentialSchemaIssuerRegistry::ICredentialSchemaIssuerRegistryInstance,
        IDisputeGameFactory::IDisputeGameFactoryInstance, IGateway::IGatewayInstance,
        IOprfKeyRegistry::IOprfKeyRegistryInstance, IWorldIDRegistry::IWorldIDRegistryInstance,
        IWorldIDSatellite::IWorldIDSatelliteInstance, IWorldIDSource::IWorldIDSourceInstance,
    },
    cli::{EthereumChainConfig, WorldChainConfig},
    satellite::{EthereumMptSatellite, Satellite},
};

pub struct WorldChain<P: Provider = Arc<DynProvider>> {
    /// The provider for the World Chain.
    provider: P,

    /// The World ID registry address on the World Chain.
    world_id_registry: IWorldIDRegistryInstance<P>,

    /// The credential issuer schema registry address on the World Chain.
    credential_issuer_schema_registry: ICredentialSchemaIssuerRegistryInstance<P>,

    /// The OPRF key registry address on the World Chain.
    oprf_key_registry: IOprfKeyRegistryInstance<P>,

    /// The WorldIDSource proxy address on the World Chain.
    world_id_source: IWorldIDSourceInstance<P>,

    /// The bridgeing interval.
    bridge_interval: std::time::Duration,
}

impl WorldChain {
    pub async fn new(world_chain: &WorldChainConfig) -> Self {
        let provider = Arc::new(
            world_chain
                .provider
                .clone()
                .http()
                .await
                .expect("failed to connect to World Chain provider"),
        );
        let world_id_registry = world_chain.world_id_registry;
        let credential_issuer_schema_registry = world_chain.credential_issuer_schema_registry;
        let oprf_key_registry = world_chain.oprf_key_registry;
        let world_id_source = world_chain.world_id_source;

        Self {
            provider: provider.clone(),
            world_id_registry: IWorldIDRegistryInstance::new(world_id_registry, provider.clone()),
            credential_issuer_schema_registry: ICredentialSchemaIssuerRegistryInstance::new(
                credential_issuer_schema_registry,
                provider.clone(),
            ),
            oprf_key_registry: IOprfKeyRegistryInstance::new(oprf_key_registry, provider.clone()),
            world_id_source: IWorldIDSourceInstance::new(world_id_source, provider.clone()),
            bridge_interval: Duration::from_secs(world_chain.bridge_interval),
        }
    }
}

impl<P: Provider> WorldChain<P> {
    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn world_id_registry(&self) -> &IWorldIDRegistryInstance<P> {
        &self.world_id_registry
    }

    pub fn credential_issuer_schema_registry(&self) -> &ICredentialSchemaIssuerRegistryInstance<P> {
        &self.credential_issuer_schema_registry
    }

    pub fn oprf_key_registry(&self) -> &IOprfKeyRegistryInstance<P> {
        &self.oprf_key_registry
    }

    pub fn world_id_source(&self) -> &IWorldIDSourceInstance<P> {
        &self.world_id_source
    }

    pub fn bridge_interval(&self) -> Duration {
        self.bridge_interval
    }
}

pub trait SatelliteChainConfig {
    fn satellite(&self) -> Box<dyn Satellite>;
}

pub struct Ethereum<P: Provider = Arc<DynProvider>> {
    /// The Chain ID of the destination chain.
    chain_id: u64,

    /// The World Chain (source) address.
    world_id_source: IWorldIDSourceInstance<P>,

    /// The Source Chain Provider (World Chain).
    source_provider: P,

    /// Source Chain ID
    anchor_chain_id: u64,

    /// The provider for this destination chain.
    provider: P,

    /// The gateway contract address on this destination chain.
    gateway: IGatewayInstance<P>,

    /// The satellite (bridge) contract address on this destination chain.
    satellite: IWorldIDSatelliteInstance<P>,

    /// The dispute game factory contract on this chain.
    dispute_game_factory: IDisputeGameFactoryInstance<P>,

    /// The dispute game type for this chain (default: 0 = CANNON).
    game_type: u32,

    /// Whether to require dispute games to be finalized (DEFENDER_WINS) before relaying.
    require_finalized: bool,
}

impl Ethereum {
    pub async fn new(world_chain: WorldChainConfig, ethereum: EthereumChainConfig) -> Self {
        let provider = Arc::new(
            ethereum
                .base
                .provider
                .clone()
                .http()
                .await
                .expect("failed to connect to Ethereum provider"),
        );
        let source_provider = Arc::new(
            world_chain
                .provider
                .clone()
                .http()
                .await
                .expect("failed to connect to World Chain provider"),
        );
        Self {
            chain_id: ethereum.base.chain_id,
            world_id_source: IWorldIDSourceInstance::new(
                world_chain.world_id_source,
                source_provider.clone(),
            ),
            source_provider,
            anchor_chain_id: world_chain.chain_id,
            provider: provider.clone(),
            gateway: IGatewayInstance::new(ethereum.base.gateway, provider.clone()),
            satellite: IWorldIDSatelliteInstance::new(ethereum.base.satellite, provider.clone()),
            dispute_game_factory: IDisputeGameFactoryInstance::new(
                ethereum.dispute_game_factory,
                provider.clone(),
            ),
            game_type: ethereum.game_type,
            require_finalized: ethereum.require_finalized,
        }
    }
}

impl SatelliteChainConfig for Ethereum {
    fn satellite(&self) -> Box<dyn Satellite> {
        Box::new(EthereumMptSatellite::new(
            format!("ethereum-satellite-{}", self.chain_id),
            self.chain_id,
            self.gateway.clone(),
            self.satellite.clone(),
            self.anchor_chain_id,
            self.provider.clone(),
            self.source_provider.clone(),
            self.world_id_source.clone(),
            self.dispute_game_factory.clone(),
            self.game_type,
            self.require_finalized,
        ))
    }
}
