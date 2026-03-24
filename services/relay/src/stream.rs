use std::{sync::Arc, time::Duration};

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

/// Polling interval for `get_logs` based event streaming.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

struct EventFilter {
    address: alloy_primitives::Address,
    events: Vec<alloy_primitives::B256>,
    label: &'static str,
}

/// Creates a polling-based event stream using `eth_getLogs`.
///
/// Returns a stream that yields decoded `StateCommitment`s by polling
/// `get_logs` on a fixed interval. Uses a channel so the poller runs
/// as an async stream that the caller drives.
fn poll_events(
    provider: Arc<DynProvider>,
    filters: Vec<EventFilter>,
    initial_block: Option<u64>,
) -> BoxStream<'static, Result<StateCommitment>> {
    let stream = futures::stream::unfold(
        (provider, filters, initial_block, 0u64),
        |(provider, filters, from_block, poll_count)| async move {
            // On first poll, use the provided initial block number.
            let from_block = match from_block {
                Some(b) => b,
                None => {
                    tracing::info!("event poller: fetching initial block number...");
                    match provider.get_block_number().await {
                        Ok(n) => {
                            tracing::info!(from_block = n, poll_interval = ?POLL_INTERVAL, "event poller started");
                            n
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "failed to get initial block number");
                            // Retry after interval
                            tokio::time::sleep(POLL_INTERVAL).await;
                            return Some((vec![], (provider, filters, None, poll_count)));
                        }
                    }
                }
            };

            tokio::time::sleep(POLL_INTERVAL).await;

            let latest = match provider.get_block_number().await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to get block number, retrying");
                    return Some((vec![], (provider, filters, Some(from_block), poll_count)));
                }
            };

            if latest <= from_block {
                return Some((vec![], (provider, filters, Some(from_block), poll_count)));
            }

            let new_poll_count = poll_count + 1;
            // tracing::debug!(
            //     poll = new_poll_count,
            //     from = from_block + 1,
            //     to = latest,
            //     blocks = latest - from_block,
            //     "polling for events"
            // );

            let mut results = Vec::new();
            let mut all_succeeded = true;
            for f in &filters {
                let filter = Filter::new()
                    .address(f.address)
                    .event_signature(f.events.clone())
                    .from_block(from_block + 1)
                    .to_block(latest);

                match provider.get_logs(&filter).await {
                    Ok(logs) => {
                        if !logs.is_empty() {
                            tracing::info!(
                                count = logs.len(),
                                source = f.label,
                                "polled new events"
                            );
                        }
                        for log in logs {
                            results.push(decode_state_commitment(log));
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            source = f.label,
                            "get_logs failed, will retry this block range"
                        );
                        all_succeeded = false;
                    }
                }
            }

            let next_from_block = if all_succeeded { Some(latest) } else { Some(from_block) };
            Some((results, (provider, filters, next_from_block, new_poll_count)))
        },
    )
    .flat_map(futures::stream::iter);

    stream.boxed()
}

/// Creates a polling stream of all registry events from World Chain.
pub async fn registry_stream(
    world_chain: &WorldChain,
) -> Result<BoxStream<'static, Result<StateCommitment>>> {
    tracing::info!(
        registry = %world_chain.world_id_registry().address(),
        issuer_registry = %world_chain.credential_issuer_schema_registry().address(),
        oprf_registry = %world_chain.oprf_key_registry().address(),
        source = %world_chain.world_id_source().address(),
        deployment_block = %world_chain.deployment_block(),
        poll_interval = ?POLL_INTERVAL,
        "subscribing to World Chain events (HTTP polling)"
    );

    let filters = vec![
        EventFilter {
            address: *world_chain.world_id_registry().address(),
            events: WORLD_ID_REGISTRY_EVENTS.to_vec(),
            label: "WorldIDRegistry",
        },
        EventFilter {
            address: *world_chain.credential_issuer_schema_registry().address(),
            events: ISSUER_REGISTRY_EVENTS.to_vec(),
            label: "IssuerSchemaRegistry",
        },
        EventFilter {
            address: *world_chain.oprf_key_registry().address(),
            events: OPRF_REGISTRY_EVENTS.to_vec(),
            label: "OprfKeyRegistry",
        },
        EventFilter {
            address: *world_chain.world_id_source().address(),
            events: CHAIN_COMMITTED_EVENTS.to_vec(),
            label: "WorldIDSource",
        },
    ];

    let provider = world_chain.provider().clone();
    let initial_block = provider.get_block_number().await?;
    tracing::info!(
        from_block = initial_block,
        "event poller: captured initial block number"
    );

    Ok(poll_events(provider, filters, Some(initial_block)))
}

/// Maximum block range per `eth_getLogs` request during backfill.
///
/// Most RPC providers cap the range they'll scan in a single call (e.g.
/// Alchemy defaults to 2 000 blocks). We chunk aggressively to stay well
/// within limits and avoid timeouts.
const BACKFILL_CHUNK_SIZE: u64 = 1000;

/// Backfills the commitment log with historical `ChainCommitted` events.
///
/// Fetches logs from the source contract's deployment block to the current
/// head in chunks of [`BACKFILL_CHUNK_SIZE`] blocks. Only queries the
/// `WorldIDSource` contract — registry events (roots, issuer keys, OPRF
/// keys) are picked up by the live event stream.
pub async fn backfill_commitments(world_chain: &WorldChain, log: &CommitmentLog) -> Result<()> {
    let provider = world_chain.provider();
    let source_address = *world_chain.world_id_source().address();
    let event_sigs = CHAIN_COMMITTED_EVENTS.to_vec();
    let deployment_block = world_chain.deployment_block();

    let latest = provider.get_block_number().await?;
    tracing::info!(
        latest_block = latest,
        deployment_block,
        "starting chunked backfill"
    );

    let mut from = deployment_block;
    let mut total = 0usize;
    let total_blocks = latest.saturating_sub(deployment_block);
    let mut chunks_done = 0u64;
    let total_chunks = total_blocks.div_ceil(BACKFILL_CHUNK_SIZE);

    while from <= latest {
        let to = (from + BACKFILL_CHUNK_SIZE - 1).min(latest);

        let filter = Filter::new()
            .address(source_address)
            .event_signature(event_sigs.clone())
            .from_block(from)
            .to_block(to);

        let logs = provider.get_logs(&filter).await?;
        chunks_done += 1;

        let pct = if total_chunks > 0 {
            (chunks_done * 100) / total_chunks
        } else {
            100
        };

        tracing::debug!(
            from_block = from,
            to_block = to,
            events = logs.len(),
            progress = %format!("{chunks_done}/{total_chunks} ({pct}%)"),
            "backfill chunk"
        );

        for raw_log in logs {
            match decode_state_commitment(raw_log) {
                Ok(StateCommitment::ChainCommitted(cc)) => {
                    tracing::debug!(
                        block = cc.block_number,
                        chain_head = %cc.chain_head,
                        "backfill: replaying ChainCommitted"
                    );
                    if let Err(e) = log.commit_chained(Arc::new(cc)) {
                        tracing::error!(error = %e, "backfill: failed to commit ChainCommitted");
                    }
                    total += 1;
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "backfill: failed to decode log"),
            }
        }

        from = to + 1;
    }

    tracing::info!(
        chain_head = %log.head(),
        entries = total,
        blocks_scanned = latest,
        "backfill complete"
    );
    Ok(())
}

// ── Decoding ────────────────────────────────────────────────────────────────

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
