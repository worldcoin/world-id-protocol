use std::sync::Arc;

use alloy::{providers::Provider, rpc::types::{Filter, Log}, sol_types::SolEventInterface};
use alloy_primitives::U256;
use eyre::Result;
use futures::{Stream, stream::BoxStream};
use futures_util::StreamExt;

use crate::{
    bindings::{
        CHAIN_COMMITTED_EVENTS,
        IChainCommitment::{
            ChainCommitted, IChainCommitmentEvents, IssuerSchemaPubkeyUpdated,
            IssuerSchemaRegistered, IssuerSchemaRemoved,
        },
        ISSUER_REGISTRY_EVENTS,
        IWorldIDSource::Affine,
        OPRF_REGISTRY_EVENTS, WORLD_ID_REGISTRY_EVENTS,
    },
    cli::chain::WorldChain,
    primitives::{
        BlockTimestampAndLogIndex, ChainCommitment, PubKeyCommitment, PubKeyId, RootCommitment,
        StateCommitment,
    },
};

pub type StateStream<'a, T> = Box<dyn Stream<Item = Result<T>> + Send + Unpin + 'a>;

pub struct MappedStream<S, F> {
    pub stream: S,
    f: F,
}

impl<T, R, S, F> MappedStream<S, F>
where
    F: Fn(T) -> Result<R> + Send + Sync + 'static,
    S: Stream<Item = T> + Send + 'static,
    T: Send + 'static,
    R: Send + 'static,
{
    pub fn new(stream: S, f: F) -> Self {
        Self { stream, f }
    }

    pub fn map_stream<'a>(self) -> BoxStream<'a, Result<R>> {
        self.stream.map(self.f).boxed()
    }
}

pub struct MergedStream<S, F> {
    streams: Vec<MappedStream<S, F>>,
    hooks: RegistryEventHooks,
}

impl<S, F> MergedStream<S, F> {
    pub fn new(streams: Vec<MappedStream<S, F>>, hooks: RegistryEventHooks) -> Self {
        Self { streams, hooks }
    }
}

impl<T, S, F> MergedStream<S, F>
where
    F: Fn(T) -> Result<StateCommitment> + Send + Sync + 'static,
    S: Stream<Item = T> + Send + 'static,
    T: Send + 'static,
{
    pub fn into_stream<'a>(self) -> StateStream<'a, StateCommitment> {
        let hooks = Arc::new(self.hooks);
        let mapped = self
            .streams
            .into_iter()
            .map(|s| s.map_stream() as BoxStream<'a, Result<StateCommitment>>);

        Box::new(futures::stream::select_all(mapped).inspect(move |result| {
            if let Ok(item) = result {
                hooks.dispatch(item);
            }
        }))
    }
}

macro_rules! state_stream {
    ($provider:expr, $address:expr, $events:expr) => {{
        let filter = Filter::new()
            .address($address)
            .event_signature($events.to_vec());

        let poller = $provider.watch_logs(&filter).await?;

        let stream = poller
            .into_stream()
            .flat_map(|batch| futures::stream::iter(batch))
            .boxed();

        MappedStream::new(
            stream,
            decode_state_commitment as fn(alloy::rpc::types::Log) -> Result<StateCommitment>,
        )
    }};
}

pub async fn merged_registry_stream<P: Provider>(
    world_chain: &WorldChain<P>,
    hooks: RegistryEventHooks,
) -> Result<StateStream<'static, StateCommitment>> {
    let streams = vec![
        state_stream!(
            world_chain.provider(),
            *world_chain.world_id_registry().address(),
            WORLD_ID_REGISTRY_EVENTS
        ),
        state_stream!(
            world_chain.provider(),
            *world_chain.credential_issuer_schema_registry().address(),
            ISSUER_REGISTRY_EVENTS
        ),
        state_stream!(
            world_chain.provider(),
            *world_chain.oprf_key_registry().address(),
            OPRF_REGISTRY_EVENTS
        ),
        state_stream!(
            world_chain.provider(),
            *world_chain.world_id_source().address(),
            CHAIN_COMMITTED_EVENTS
        ),
    ];

    Ok(MergedStream::new(streams, hooks).into_stream())
}

pub async fn backfill_commitments<P: Provider>(
    world_chain: &WorldChain<P>,
    log: &crate::log::SourceStateLog,
    from_block: u64,
) -> Result<()> {
    let registry_filters = vec![
        Filter::new()
            .address(*world_chain.world_id_registry().address())
            .event_signature(WORLD_ID_REGISTRY_EVENTS.to_vec())
            .from_block(from_block),
        Filter::new()
            .address(*world_chain.credential_issuer_schema_registry().address())
            .event_signature(ISSUER_REGISTRY_EVENTS.to_vec())
            .from_block(from_block),
        Filter::new()
            .address(*world_chain.oprf_key_registry().address())
            .event_signature(OPRF_REGISTRY_EVENTS.to_vec())
            .from_block(from_block),
    ];

    let chain_committed_filter = Filter::new()
        .address(*world_chain.world_id_source().address())
        .event_signature(CHAIN_COMMITTED_EVENTS.to_vec())
        .from_block(from_block);

    let mut all_logs = Vec::new();
    for filter in registry_filters {
        all_logs.extend(world_chain.provider().get_logs(&filter).await?);
    }
    all_logs.extend(
        world_chain
            .provider()
            .get_logs(&chain_committed_filter)
            .await?,
    );

    all_logs.sort_by_key(|log| {
        (
            log.block_number.unwrap_or_default(),
            log.log_index.unwrap_or_default(),
        )
    });

    for raw_log in all_logs {
        match decode_state_commitment(raw_log) {
            Ok(StateCommitment::ChainCommitted(cc)) => {
                let _ = log.commit_chained(Arc::new(cc));
            }
            Ok(StateCommitment::OprfPubKey(_) | StateCommitment::CredentialIssuerPubKey(_)) => {
                // For simplicity, we only backfill the keccak chain from historical logs.
                // Backfilling pubkey commitments would require additional logic to handle
                // pending/finalized states and potential duplicates, so we rely on the
                // real-time stream to populate those.
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "backfill: failed to decode log"),
        }
    }

    tracing::info!(chain_head = %log.head(), entries = log.len(), "backfill complete");
    Ok(())
}

/// Converts a raw `Log` into a typed `Log<IChainCommitmentEvents>`.
fn decode_typed_log(
    log: alloy::rpc::types::Log,
) -> Result<alloy::rpc::types::Log<IChainCommitmentEvents>> {
    let event =
        IChainCommitmentEvents::decode_raw_log(log.inner.data.topics(), &log.inner.data.data)?;
    Ok(alloy::rpc::types::Log {
        inner: alloy_primitives::Log {
            address: log.inner.address,
            data: event,
        },
        block_hash: log.block_hash,
        block_number: log.block_number,
        block_timestamp: log.block_timestamp,
        transaction_hash: log.transaction_hash,
        transaction_index: log.transaction_index,
        log_index: log.log_index,
        removed: log.removed,
    })
}

/// Free function used as `fn(Log) -> Result<StateCommitment>` pointer in the macro.
fn decode_state_commitment(log: alloy::rpc::types::Log) -> Result<StateCommitment> {
    decode_typed_log(log).and_then(StateCommitment::try_from)
}


impl TryFrom<Log<IChainCommitmentEvents>> for StateCommitment {
    type Error = eyre::Report;

    fn try_from(log: alloy::rpc::types::Log<IChainCommitmentEvents>) -> Result<Self, Self::Error> {
        let event = log.data();

        let state_commitment = match event {
            IChainCommitmentEvents::RootRecorded(e) => Self::RootCommitment(RootCommitment {
                position: BlockTimestampAndLogIndex {
                    timestamp: log.block_timestamp.unwrap_or_default(),
                    log_index: log.log_index.unwrap_or_default() as usize,
                },
                root: e.root,
            }),
            IChainCommitmentEvents::IssuerSchemaPubkeyUpdated(IssuerSchemaPubkeyUpdated {
                newPubkey,
                issuerSchemaId,
                ..
            }) => {
                let affine = Affine {
                    x: newPubkey.x,
                    y: newPubkey.y,
                };
                Self::CredentialIssuerPubKey(PubKeyCommitment {
                    affine,
                    position: BlockTimestampAndLogIndex {
                        timestamp: log.block_timestamp.unwrap_or_default(),
                        log_index: log.log_index.unwrap_or_default() as usize,
                    },
                    id: PubKeyId::from(*issuerSchemaId),
                })
            }
            IChainCommitmentEvents::IssuerSchemaRegistered(IssuerSchemaRegistered {
                issuerSchemaId,
                pubkey,
                ..
            }) => {
                let affine = Affine {
                    x: pubkey.x,
                    y: pubkey.y,
                };
                Self::CredentialIssuerPubKey(PubKeyCommitment {
                    affine,
                    position: BlockTimestampAndLogIndex {
                        timestamp: log.block_timestamp.unwrap_or_default(),
                        log_index: log.log_index.unwrap_or_default() as usize,
                    },
                    id: PubKeyId::from(*issuerSchemaId),
                })
            }
            IChainCommitmentEvents::IssuerSchemaRemoved(IssuerSchemaRemoved {
                issuerSchemaId,
                pubkey: _,
                ..
            }) => Self::CredentialIssuerPubKey(PubKeyCommitment {
                affine: Affine {
                    x: U256::ZERO,
                    y: U256::ZERO,
                },
                position: BlockTimestampAndLogIndex {
                    timestamp: log.block_timestamp.unwrap_or_default(),
                    log_index: log.log_index.unwrap_or_default() as usize,
                },
                id: PubKeyId::from(*issuerSchemaId),
            }),
            IChainCommitmentEvents::SecretGenFinalize(e) => {
                Self::OprfPubKey(PubKeyCommitment {
                    affine: Affine {
                        x: U256::ZERO,
                        y: U256::ZERO,
                    }, // OPRF pubkey value is not included in event, relay must fetch from registry.
                    position: BlockTimestampAndLogIndex {
                        timestamp: log.block_timestamp.unwrap_or_default(),
                        log_index: log.log_index.unwrap_or_default() as usize,
                    },
                    id: PubKeyId::from(e.oprfKeyId),
                })
            }
            IChainCommitmentEvents::ChainCommitted(ChainCommitted {
                keccakChain,
                blockNumber,
                chainId,
                commitment,
            }) => Self::ChainCommitted(ChainCommitment {
                chain_head: *keccakChain,
                block_number: blockNumber.to::<u64>(),
                chain_id: chainId.to::<u64>(),
                commitment_payload: commitment.clone(),
                position: BlockTimestampAndLogIndex {
                    timestamp: log.block_timestamp.unwrap_or_default(),
                    log_index: log.log_index.unwrap_or_default() as usize,
                },
            }),
        };

        Ok(state_commitment)
    }
}

// ── StateHook trait + concrete implementations ──────────────────────────────

pub trait EventHook: Send + Sync + 'static {
    fn matches(&self, commitment: &StateCommitment) -> bool;
    fn on_event(&self, commitment: &StateCommitment);
}

// ── HookRegistry ────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct RegistryEventHooks {
    hooks: Vec<Box<dyn EventHook>>,
}

impl RegistryEventHooks {
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    pub fn register(mut self, hook: impl EventHook) -> Self {
        self.hooks.push(Box::new(hook));
        self
    }

    pub fn dispatch(&self, item: &StateCommitment) {
        for hook in &self.hooks {
            if hook.matches(item) {
                hook.on_event(item);
            }
        }
    }
}
