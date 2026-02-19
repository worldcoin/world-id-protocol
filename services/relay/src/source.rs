use std::time::Duration;

use alloy::{
    primitives::{Address, LogData, U160},
    providers::{DynProvider, Provider},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use tracing::{debug, error, info, warn};

use crate::{contracts::IWorldIDSource, error::RelayError, proof::ChainCommitment};

/// Runs the source-side loop: periodic propagation + event watching.
///
/// Two concurrent tasks:
/// - A ticker that calls `propagateState()` on cadence
/// - A poller that watches for `ChainCommitted` events and sends them to the relay
pub async fn run_source(
    wc_provider: DynProvider,
    source_address: Address,
    issuer_schema_ids: Vec<u64>,
    oprf_key_ids: Vec<u64>,
    propagation_interval: Duration,
    event_poll_interval: Duration,
    tx: tokio::sync::mpsc::Sender<ChainCommitment>,
) -> eyre::Result<()> {
    let source = IWorldIDSource::new(source_address, &wc_provider);

    let issuer_ids: Vec<u64> = issuer_schema_ids;
    let oprf_ids: Vec<U160> = oprf_key_ids.iter().map(|&id| U160::from(id)).collect();

    let mut propagation_ticker = tokio::time::interval(propagation_interval);
    let mut event_ticker = tokio::time::interval(event_poll_interval);

    let mut last_scanned_block = wc_provider.get_block_number().await?;

    info!(
        source = %source_address,
        issuer_ids = ?issuer_ids,
        oprf_ids = ?oprf_key_ids,
        interval = ?propagation_interval,
        start_block = last_scanned_block,
        "source loop started"
    );

    loop {
        tokio::select! {
            _ = propagation_ticker.tick() => {
                match propagate_state(&source, &issuer_ids, &oprf_ids).await {
                    Ok(()) => info!("propagateState() succeeded"),
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("NothingChanged") || err_str.contains("0x06923abf") {
                            debug!("propagateState(): nothing changed");
                        } else {
                            error!(error = %e, "propagateState() failed");
                        }
                    }
                }
            }
            _ = event_ticker.tick() => {
                match poll_chain_committed_events(
                    &wc_provider,
                    source_address,
                    last_scanned_block,
                    &tx,
                ).await {
                    Ok(new_block) => {
                        if new_block > last_scanned_block {
                            debug!(
                                from = last_scanned_block,
                                to = new_block,
                                "scanned blocks for events"
                            );
                            last_scanned_block = new_block;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "event polling failed, will retry");
                    }
                }
            }
        }
    }
}

/// Calls `WorldIDSource.propagateState()`.
///
/// Simulates via `eth_call` first to avoid poisoning the nonce cache on reverts
/// (e.g. `NothingChanged`). Without this, `CachedNonceManager` increments the
/// nonce on every `send()` attempt, even when gas estimation reverts, causing
/// subsequent transactions to hang with a too-high nonce.
async fn propagate_state(
    source: &IWorldIDSource::IWorldIDSourceInstance<&DynProvider>,
    issuer_ids: &[u64],
    oprf_ids: &[U160],
) -> Result<(), RelayError> {
    info!("calling propagateState()");

    let call = source.propagateState(issuer_ids.to_vec(), oprf_ids.to_vec());

    // Dry-run first — reverts here don't consume a nonce.
    call.call()
        .await
        .map_err(|e| RelayError::ContractRevert(format!("{e}")))?;

    // Simulation succeeded — safe to broadcast.
    let pending = call
        .send()
        .await
        .map_err(|e| RelayError::ContractRevert(format!("{e}")))?;

    let receipt = pending
        .get_receipt()
        .await
        .map_err(|e| RelayError::ContractRevert(format!("{e}")))?;

    info!(
        tx_hash = %receipt.transaction_hash,
        block = receipt.block_number.unwrap_or_default(),
        gas_used = receipt.gas_used,
        "propagateState() confirmed"
    );

    Ok(())
}

/// Polls for new `ChainCommitted` events from the source contract.
/// Returns the latest block number scanned.
async fn poll_chain_committed_events(
    provider: &DynProvider,
    source_address: Address,
    from_block: u64,
    tx: &tokio::sync::mpsc::Sender<ChainCommitment>,
) -> Result<u64, RelayError> {
    let latest_block = provider.get_block_number().await.map_err(RelayError::Rpc)?;

    if latest_block <= from_block {
        return Ok(from_block);
    }

    let filter = Filter::new()
        .address(source_address)
        .event_signature(IWorldIDSource::ChainCommitted::SIGNATURE_HASH)
        .from_block(from_block + 1)
        .to_block(latest_block);

    let logs = provider.get_logs(&filter).await.map_err(RelayError::Rpc)?;

    for log in logs {
        match decode_chain_committed_event(&log.inner.data) {
            Ok(commitment) => {
                info!(
                    chain_head = %commitment.chain_head,
                    block = commitment.block_number,
                    "received ChainCommitted event"
                );
                if tx.send(commitment).await.is_err() {
                    error!("relay channel closed, stopping source");
                    return Err(RelayError::Other(eyre::eyre!("relay channel closed")));
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to decode ChainCommitted event, skipping");
            }
        }
    }

    Ok(latest_block)
}

/// Decodes a `ChainCommitted` event from raw log data.
fn decode_chain_committed_event(log_data: &LogData) -> Result<ChainCommitment, RelayError> {
    let event = IWorldIDSource::ChainCommitted::decode_log_data(log_data)
        .map_err(|e| RelayError::EventDecode(format!("{e}")))?;

    Ok(ChainCommitment {
        chain_head: event.keccakChain,
        block_number: event.blockNumber.to::<u64>(),
        chain_id: event.chainId.to::<u64>(),
        commitment_payload: event.commitment,
    })
}
