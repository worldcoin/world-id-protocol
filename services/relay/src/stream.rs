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
/// `anchor_block` is the chain-head block number captured at stream creation
/// time (before backfill begins). The poller starts from this block so that
/// events emitted between backfill completion and the first poll are never
/// skipped.
fn poll_events(
    provider: Arc<DynProvider>,
    filters: Vec<EventFilter>,
    anchor_block: u64,
) -> BoxStream<'static, Result<StateCommitment>> {
    tracing::info!(
        from_block = anchor_block,
        poll_interval = ?POLL_INTERVAL,
        "event poller anchored"
    );
    let stream = futures::stream::unfold(
        (provider, filters, anchor_block, 0u64),
        |(provider, filters, from_block, poll_count)| async move {

            tokio::time::sleep(POLL_INTERVAL).await;

            let latest = match provider.get_block_number().await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to get block number, retrying");
                    return Some((vec![], (provider, filters, from_block, poll_count)));
                }
            };

            if latest <= from_block {
                return Some((vec![], (provider, filters, from_block, poll_count)));
            }

            let new_poll_count = poll_count + 1;
            tracing::debug!(
                poll = new_poll_count,
                from = from_block + 1,
                to = latest,
                blocks = latest - from_block,
                "polling for events"
            );

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

            let next_from_block = if all_succeeded { latest } else { from_block };
            Some((results, (provider, filters, next_from_block, new_poll_count)))
        },
    )
    .flat_map(futures::stream::iter);

    stream.boxed()
}

/// Creates a polling stream of all registry events from World Chain.
///
/// The current chain-head block is captured here — before backfill runs —
/// and used as the `from_block` anchor for the live polling stream.  This
/// closes the gap where a `ChainCommitted` event could be emitted after
/// backfill's `get_logs` upper bound but before the first polling cycle
/// fires.
pub async fn registry_stream(
    world_chain: &WorldChain,
) -> Result<BoxStream<'static, Result<StateCommitment>>> {
    // Capture the chain head *now*, before backfill touches the network.
    // Any block ≥ this anchor will be covered by the live poll loop;
    // backfill covers [0, anchor] so together they are gapless.
    let anchor_block = world_chain.provider().get_block_number().await?;

    tracing::info!(
        registry = %world_chain.world_id_registry().address(),
        issuer_registry = %world_chain.credential_issuer_schema_registry().address(),
        oprf_registry = %world_chain.oprf_key_registry().address(),
        source = %world_chain.world_id_source().address(),
        poll_interval = ?POLL_INTERVAL,
        anchor_block,
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

    Ok(poll_events(world_chain.provider().clone(), filters, anchor_block))
}

/// Backfills the commitment log with historical `ChainCommitted` events.
///
/// Only fetches from the `WorldIDSource` contract — registry events (roots,
/// issuer keys, OPRF keys) are picked up by the live event stream.
pub async fn backfill_commitments(world_chain: &WorldChain, log: &CommitmentLog) -> Result<()> {
    let filter = Filter::new()
        .address(*world_chain.world_id_source().address())
        .event_signature(CHAIN_COMMITTED_EVENTS.to_vec())
        .from_block(0u64);

    tracing::info!("starting backfill of ChainCommitted events");

    let logs = world_chain.provider().get_logs(&filter).await?;
    tracing::debug!(count = logs.len(), "fetched ChainCommitted logs");

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
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "backfill: failed to decode log"),
        }
    }

    tracing::info!(chain_head = %log.head(), entries = log.len(), "backfill complete");
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

#[cfg(test)]
mod tests {
    use super::*;

    use alloy::providers::{DynProvider, ProviderBuilder};
    use alloy_primitives::{Address, B256, b256};
    use futures_util::StreamExt;
    use tokio::time;

    // keccak256("ChainCommitted(bytes32,uint256,uint256,bytes)")
    const CHAIN_COMMITTED_TOPIC: B256 =
        b256!("e6456e71ac59eedb01c8a33f8e1bcefa1a7a343f4dd490937cdb4c726c63894b");

    fn make_mock_provider(asserter: alloy::providers::mock::Asserter) -> Arc<DynProvider> {
        let p = ProviderBuilder::new().connect_mocked_client(asserter);
        Arc::new(DynProvider::new(p))
    }

    /// Returns a JSON array containing one `ChainCommitted` log at the given
    /// `block_number` on `chain_id`.
    fn chain_committed_logs_json(block_number: u64, chain_id: u64) -> serde_json::Value {
        // Indexed params go in topics[1..3]; non-indexed `bytes commitment` is
        // ABI-encoded in `data` as (offset=32, length=0).
        serde_json::json!([{
            "address": "0x0000000000000000000000000000000000000001",
            "topics": [
                format!("0x{}", alloy_primitives::hex::encode(CHAIN_COMMITTED_TOPIC)),
                // keccakChain (bytes32) = zero
                format!("0x{:064x}", 0u64),
                // blockNumber (uint256)
                format!("0x{:064x}", block_number),
                // chainId (uint256)
                format!("0x{:064x}", chain_id),
            ],
            // ABI-encoded `bytes commitment`: offset + empty length
            "data": "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000",
            "blockHash": format!("0x{:064x}", block_number),
            "blockNumber": format!("0x{:x}", block_number),
            "transactionHash": format!("0x{:064x}", 1u64),
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "removed": false
        }])
    }

    /// Regression test for the startup polling gap.
    ///
    /// Timeline being simulated:
    ///   t0: `registry_stream()` anchors at block 5 (stream creation)
    ///   t1: backfill runs and completes (covers blocks 0-5)
    ///       During backfill, block 6 is mined — a `ChainCommitted` is emitted
    ///   t2: first poll cycle fires
    ///       → `eth_blockNumber` returns 6 (latest)
    ///       → `eth_getLogs(from=6, to=6)` — **must** include block 6
    ///       → stream yields the `ChainCommitted` event
    ///
    /// Before the fix, `from_block` was lazily initialised on the first poll,
    /// causing `eth_blockNumber` to return 6 and set `from_block = 6`.  Then
    /// `latest (6) <= from_block (6)` was true and `eth_getLogs` was never
    /// called — the gap event was silently dropped.
    ///
    /// After the fix, `from_block` is anchored at 5 at creation time.  The
    /// first poll sees `latest (6) > from_block (5)` and correctly queries
    /// `[6, 6]`, capturing the event.
    #[tokio::test(start_paused = true)]
    async fn poll_stream_captures_event_emitted_during_backfill_window() {
        let asserter = alloy::providers::mock::Asserter::new();
        let provider = make_mock_provider(asserter.clone());

        // First poll cycle: latest = 6 (one block appeared during backfill)
        asserter.push_success(&6u64);
        // `eth_getLogs` for our single test filter → one `ChainCommitted` at block 6
        asserter.push_success(&chain_committed_logs_json(6, 480));

        let filter = EventFilter {
            address: Address::from([0x01; 20]),
            events: vec![CHAIN_COMMITTED_TOPIC],
            label: "test",
        };

        // Anchor at block 5 — this is what `registry_stream()` captures before
        // handing off to `backfill_commitments`.
        let mut stream = poll_events(provider, vec![filter], 5);

        // Spawn a task to drive the stream; `stream.next()` will block on the
        // POLL_INTERVAL sleep, which we release with `time::advance` below.
        let handle = tokio::spawn(async move { stream.next().await });

        // Advance mock time past POLL_INTERVAL to trigger the first poll.
        time::advance(POLL_INTERVAL + Duration::from_millis(1)).await;

        let item = handle
            .await
            .expect("stream task should not panic")
            .expect("stream should yield an item");

        assert!(
            matches!(item, Ok(StateCommitment::ChainCommitted(ref cc)) if cc.block_number == 6),
            "expected ChainCommitted at block 6 from the gap window, got: {:?}",
            item
        );
    }
}

