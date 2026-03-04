use std::sync::Arc;

use alloy::{
    providers::{DynProvider, Provider},
    rpc::types::{Filter, Log},
    sol_types::SolEventInterface,
};
use alloy_primitives::U256;
use eyre::Result;
use futures::stream::BoxStream;
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
    log::CommitmentLog,
    primitives::{
        ChainCommitment, IssuerKeyUpdate, IssuerSchemaId, OprfKeyId, OprfKeyUpdate, RootCommitment,
        StateCommitment,
    },
};

/// Creates a filtered event stream for a single contract address and event set.
async fn watch_events(
    provider: &Arc<DynProvider>,
    address: alloy_primitives::Address,
    events: &[alloy_primitives::B256],
) -> Result<BoxStream<'static, Result<StateCommitment>>> {
    let filter = Filter::new()
        .address(address)
        .event_signature(events.to_vec());

    let poller = provider.watch_logs(&filter).await?;

    Ok(poller
        .into_stream()
        .flat_map(futures::stream::iter)
        .map(decode_state_commitment)
        .boxed())
}

/// Creates a merged stream of all registry events from World Chain.
pub async fn registry_stream(
    world_chain: &WorldChain,
) -> Result<BoxStream<'static, Result<StateCommitment>>> {
    let streams = vec![
        watch_events(
            world_chain.provider(),
            *world_chain.world_id_registry().address(),
            &WORLD_ID_REGISTRY_EVENTS,
        )
        .await?,
        watch_events(
            world_chain.provider(),
            *world_chain.credential_issuer_schema_registry().address(),
            &ISSUER_REGISTRY_EVENTS,
        )
        .await?,
        watch_events(
            world_chain.provider(),
            *world_chain.oprf_key_registry().address(),
            &OPRF_REGISTRY_EVENTS,
        )
        .await?,
        watch_events(
            world_chain.provider(),
            *world_chain.world_id_source().address(),
            &CHAIN_COMMITTED_EVENTS,
        )
        .await?,
    ];

    Ok(futures::stream::select_all(streams).boxed())
}

/// Backfills the commitment log with historical events from World Chain.
pub async fn backfill_commitments(
    world_chain: &WorldChain,
    log: &CommitmentLog,
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
            Ok(StateCommitment::OprfPubKey(_) | StateCommitment::IssuerPubKey(_)) => {
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

/// Free function used as `fn(Log) -> Result<StateCommitment>` pointer.
fn decode_state_commitment(log: alloy::rpc::types::Log) -> Result<StateCommitment> {
    decode_typed_log(log).and_then(StateCommitment::try_from)
}

impl TryFrom<Log<IChainCommitmentEvents>> for StateCommitment {
    type Error = eyre::Report;

    fn try_from(log: alloy::rpc::types::Log<IChainCommitmentEvents>) -> Result<Self, Self::Error> {
        let event = log.data();
        let timestamp = log.block_timestamp.unwrap_or_default();

        let state_commitment = match event {
            IChainCommitmentEvents::RootRecorded(e) => Self::RootCommitment(RootCommitment {
                root: e.root,
                timestamp,
            }),
            IChainCommitmentEvents::IssuerSchemaPubkeyUpdated(IssuerSchemaPubkeyUpdated {
                newPubkey,
                issuerSchemaId,
                ..
            }) => Self::IssuerPubKey(IssuerKeyUpdate {
                affine: Affine {
                    x: newPubkey.x,
                    y: newPubkey.y,
                },
                timestamp,
                id: IssuerSchemaId(*issuerSchemaId),
            }),
            IChainCommitmentEvents::IssuerSchemaRegistered(IssuerSchemaRegistered {
                issuerSchemaId,
                pubkey,
                ..
            }) => Self::IssuerPubKey(IssuerKeyUpdate {
                affine: Affine {
                    x: pubkey.x,
                    y: pubkey.y,
                },
                timestamp,
                id: IssuerSchemaId(*issuerSchemaId),
            }),
            IChainCommitmentEvents::IssuerSchemaRemoved(IssuerSchemaRemoved {
                issuerSchemaId,
                ..
            }) => Self::IssuerPubKey(IssuerKeyUpdate {
                affine: Affine {
                    x: U256::ZERO,
                    y: U256::ZERO,
                },
                timestamp,
                id: IssuerSchemaId(*issuerSchemaId),
            }),
            IChainCommitmentEvents::SecretGenFinalize(e) => Self::OprfPubKey(OprfKeyUpdate {
                affine: Affine {
                    x: U256::ZERO,
                    y: U256::ZERO,
                },
                timestamp,
                id: OprfKeyId(e.oprfKeyId),
            }),
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
                timestamp,
            }),
        };

        Ok(state_commitment)
    }
}
