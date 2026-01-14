use std::{collections::HashMap, sync::Arc};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::{DynProvider, Provider as _, ProviderBuilder, WsConnect},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use futures::StreamExt as _;
use parking_lot::Mutex;
use taceo_oprf_types::OprfKeyId;
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use world_id_primitives::rp::RpId;

use crate::auth::rp_registry_watcher::RpRegistry::RpUpdated;

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
    rp_store: Arc<Mutex<HashMap<RpId, RelyingParty>>>,
    provider: DynProvider, // do not drop provider while we want to stay subscribed
    contract_address: Address,
    max_rp_registry_store_size: usize,
}

impl RpRegistryWatcher {
    #[instrument(level = "info", skip_all)]
    pub(crate) async fn init(
        contract_address: Address,
        ws_rpc_url: &str,
        max_rp_registry_store_size: usize,
        cancellation_token: CancellationToken,
    ) -> eyre::Result<Self> {
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

        let rp_store = Arc::new(Mutex::new(HashMap::<RpId, RelyingParty>::new()));
        tokio::task::spawn({
            let rp_store = Arc::clone(&rp_store);
            async move {
                // shutdown service if RP registry watcher encounters an error and drops this guard
                let _drop_guard = cancellation_token.drop_guard();
                while let Some(log) = stream.next().await {
                    match RpUpdated::decode_log(log.as_ref()) {
                        Ok(event) => {
                            let rp_id = RpId::new(event.rpId);
                            tracing::info!("got rp-update event for rp: {rp_id}");
                            if event.active {
                                if let Some(rp) = rp_store.lock().get_mut(&rp_id) {
                                    tracing::debug!("updating rp {rp_id} in store");
                                    rp.signer = event.signer;
                                } else {
                                    tracing::debug!(
                                        "rp {rp_id} not found in store, ignoring update"
                                    );
                                }
                            } else {
                                tracing::debug!(
                                    "removing rp {rp_id} from store because it is not active"
                                );
                                rp_store.lock().remove(&rp_id);
                            }
                        }
                        Err(err) => {
                            tracing::warn!("failed to decode RpUpdated contract event: {err:?}");
                        }
                    }
                }
            }
        });

        Ok(Self {
            rp_store,
            provider: provider.erased(),
            contract_address,
            max_rp_registry_store_size,
        })
    }

    pub(crate) async fn get_rp(
        &self,
        rp_id: &RpId,
    ) -> Result<RelyingParty, RpRegistryWatcherError> {
        {
            if let Some(rp) = self.rp_store.lock().get(rp_id) {
                tracing::debug!("rp {rp_id} found in store");
                return Ok(rp.clone());
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
            let relying_party = RelyingParty {
                signer: rp.signer,
                oprf_key_id: OprfKeyId::new(rp.oprfKeyId),
            };
            let mut store = self.rp_store.lock();
            store.insert(*rp_id, relying_party.clone());
            tracing::debug!("rp {rp_id} loaded from chain and stored");

            if store.len() == self.max_rp_registry_store_size {
                tracing::debug!(
                    "rp store max size {} reached, evicting a entry",
                    self.max_rp_registry_store_size
                );
                // TODO maybe implement LRU cache
                let to_remove = store.keys().next().copied().expect("store is not empty");
                store.remove(&to_remove);
            }

            Ok(relying_party)
        } else {
            Err(RpRegistryWatcherError::UnknownRp(*rp_id))
        }
    }
}
