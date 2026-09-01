mod ethereum_mpt;
pub mod permissioned;

pub use ethereum_mpt::EthereumMptSatellite;
pub use permissioned::{PermissionedSatellite, TempoSatellite};
use tracing::Instrument;

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use alloy::{
    primitives::{B256, Bytes},
    sol_types::SolValue,
};
use eyre::Result;

use crate::{
    bindings::IWorldIDSource,
    log::CommitmentLog,
    metrics as relay_metrics,
    primitives::{ChainCommitment, reduce},
};

/// Maximum time to wait for a single relay attempt (proof + transaction).
const RELAY_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum number of individual commitments to include in a single relay
/// transaction.
const DEFAULT_MAX_COMMITMENTS_PER_RELAY: usize = 64;

/// A destination chain that can receive bridged World ID state.
pub trait Satellite: Send + Sync {
    /// Human-readable name for logging (e.g. "ethereum-mainnet", "base-sepolia").
    fn name(&self) -> &str;

    /// The chain ID of this destination.
    fn chain_id(&self) -> u64;

    /// Maximum number of individual commitments to include in one relay
    /// transaction.
    ///
    /// Destinations with smaller limits can override this without reducing
    /// throughput for every other satellite.
    fn max_commitments_per_relay(&self) -> usize {
        DEFAULT_MAX_COMMITMENTS_PER_RELAY
    }

    /// Queries the destination chain's current keccak chain head.
    ///
    /// Used on startup to determine which commitments the destination has
    /// already received, so the relay can send any missing ones.
    fn remote_chain_head<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<B256>> + Send + 'a>>;

    /// Build the proof attributes for the given commitment.
    ///
    /// Returns `(attribute, payload)` ready for `gateway.sendMessage()`.
    #[allow(clippy::type_complexity)]
    fn build_proof<'a>(
        &'a self,
        commitment: &'a ChainCommitment,
    ) -> Pin<Box<dyn Future<Output = Result<(Bytes, Bytes)>> + Send + 'a>>;

    /// Send the relay transaction to the destination chain.
    fn relay<'a>(
        &'a self,
        commitment: &'a ChainCommitment,
    ) -> Pin<Box<dyn Future<Output = Result<B256>> + Send + 'a>>;
}

pub fn spawn_satellite(
    satellite: impl Satellite + 'static,
    log: Arc<CommitmentLog>,
) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
    Box::pin(async move {
        let span = tracing::info_span!(
            "satellite",
            name = satellite.name(),
            chain_id = satellite.chain_id(),
        );

        // Wait for backfill to complete so the log has all historical commits.
        log.wait_ready().await;
        tracing::info!("backfill complete, starting satellite relay loop");

        // Subscribe and immediately mark as changed so the first loop
        // iteration checks for a delta without waiting.
        let mut chain_head = log.subscribe();
        chain_head.mark_changed();

        // Initialize from the destination chain's current state.
        let mut local_head = match satellite.remote_chain_head().await {
            Ok(head) => {
                tracing::info!(remote_head = %head, "fetched destination chain head");
                head
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to fetch destination chain head, starting from zero");
                B256::ZERO
            }
        };

        let satellite_name = satellite.name().to_owned();

        async {
            loop {
                chain_head.changed().await?;

                let delta = match log.since(local_head) {
                    Some(d) if !d.is_empty() => d,
                    Some(_) => continue,
                    None if local_head == B256::ZERO => continue,
                    None => {
                        // local_head not in log — re-sync from destination.
                        local_head = resync_head(&satellite, &log, local_head).await;
                        continue;
                    }
                };

                // Relay the delta in bounded chunks so a large backlog (e.g. a
                // cold-start from a zero head) is never submitted as a single
                // oversized transaction. Each chunk ends on a real on-chain
                // chain head, so the satellite applies them incrementally; on
                // the first failure we stop and retry the remainder (from the
                // now-advanced `local_head`) on the next head change.
                let max_commitments = satellite.max_commitments_per_relay();
                let chunks = chunk_by_commitments(&delta, max_commitments);
                let chunk_total = chunks.len();

                for (chunk_idx, chunk) in chunks.into_iter().enumerate() {
                    let entries = chunk.len();

                    let merged = reduce(chunk)?;
                    let target_head = merged.chain_head;

                    tracing::info!(
                        entries,
                        max_commitments,
                        chunk = chunk_idx + 1,
                        chunks = chunk_total,
                        target_head = %target_head,
                        "submitting satellite relay"
                    );

                    let outcome =
                        tokio::time::timeout(RELAY_TIMEOUT, satellite.relay(&merged)).await;

                    match outcome {
                        Ok(Ok(tx_hash)) => {
                            local_head = target_head;
                            tracing::info!(
                                %tx_hash,
                                head = %local_head,
                                entries,
                                target_head = %target_head,
                                "relay succeeded"
                            );
                            relay_metrics::inc_satellite_relay_outcome(
                                &satellite_name,
                                relay_metrics::outcome::SUCCESS,
                            );
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "relay failed, will retry on next head");
                            relay_metrics::inc_satellite_relay_outcome(
                                &satellite_name,
                                relay_metrics::outcome::RELAY_FAILED,
                            );
                            break;
                        }
                        Err(_) => {
                            tracing::warn!(
                                "relay timed out after {RELAY_TIMEOUT:?}, will retry on next head"
                            );
                            relay_metrics::inc_satellite_relay_outcome(
                                &satellite_name,
                                relay_metrics::outcome::TIMEOUT,
                            );
                            break;
                        }
                    }
                }
            }
        }
        .instrument(span)
        .await
    })
}

/// Re-queries the destination chain when the local head is not found in the log.
async fn resync_head(satellite: &impl Satellite, log: &CommitmentLog, stale_head: B256) -> B256 {
    tracing::warn!(
        local_head = %stale_head,
        "local head not found in log, re-syncing from destination chain"
    );

    let remote = match satellite.remote_chain_head().await {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "failed to re-query destination head");
            return stale_head;
        }
    };

    if log.contains_head(&remote) {
        tracing::info!(new_head = %remote, "re-synced from destination chain");
        return remote;
    }

    if remote == log.head() {
        tracing::info!("destination is already at source head, nothing to relay");
        return remote;
    }

    tracing::warn!(
        remote = %remote,
        log_head = %log.head(),
        "destination head not found in log either, waiting"
    );
    stale_head
}

/// Number of individual commitments carried by a single `ChainCommitment`.
///
/// Falls back to `1` if the payload cannot be decoded (it always can in
/// practice — the log only accepts entries whose payload decoded and
/// hash-chained correctly), so a chunk is never sized at zero.
fn commitment_count(commitment: &ChainCommitment) -> usize {
    Vec::<IWorldIDSource::Commitment>::abi_decode_params(&commitment.commitment_payload)
        .map(|c| c.len())
        .unwrap_or(1)
        .max(1)
}

/// Splits `delta` into contiguous chunks, each holding at most
/// `max_commitments` individual commitments.
///
/// Entries are never split: a `ChainCommitment`'s proven chain head is only
/// valid once *all* of its commitments are applied, so each entry stays whole.
/// A single entry larger than the cap is emitted as its own chunk (we always
/// make progress).
fn chunk_by_commitments(
    delta: &[Arc<ChainCommitment>],
    max_commitments: usize,
) -> Vec<&[Arc<ChainCommitment>]> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut acc = 0usize;

    for (i, entry) in delta.iter().enumerate() {
        let n = commitment_count(entry);
        // Flush the in-progress chunk before adding an entry that would push it
        // over the cap — but only if the chunk already has at least one entry.
        if i > start && acc + n > max_commitments {
            chunks.push(&delta[start..i]);
            start = i;
            acc = 0;
        }
        acc += n;
    }
    if start < delta.len() {
        chunks.push(&delta[start..]);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::ICommitment;
    use alloy::{
        primitives::U256,
        sol_types::{SolCall, SolValue},
    };

    /// Builds a `ChainCommitment` carrying `n` individual commitments.
    fn commitment_with(n: usize) -> Arc<ChainCommitment> {
        let commits: Vec<IWorldIDSource::Commitment> = (0..n)
            .map(|i| IWorldIDSource::Commitment {
                blockHash: B256::with_last_byte(i as u8),
                data: ICommitment::updateRootCall {
                    _0: U256::from(i as u64),
                    _1: U256::from(1u64),
                    _2: B256::ZERO,
                }
                .abi_encode()
                .into(),
            })
            .collect();
        Arc::new(ChainCommitment {
            chain_head: B256::with_last_byte(n as u8),
            block_number: 1,
            chain_id: 480,
            commitment_payload: commits.abi_encode_params().into(),
            timestamp: 0,
        })
    }

    fn total_commitments(chunk: &[Arc<ChainCommitment>]) -> usize {
        chunk.iter().map(|c| commitment_count(c)).sum()
    }

    #[test]
    fn commitment_count_decodes_payload() {
        assert_eq!(commitment_count(&commitment_with(3)), 3);
        assert_eq!(commitment_count(&commitment_with(1)), 1);
    }

    #[test]
    fn chunks_cover_all_entries_in_order() {
        let delta: Vec<_> = (0..10).map(|_| commitment_with(2)).collect();
        let chunks = chunk_by_commitments(&delta, 6); // 3 entries (6 commits) per chunk
        assert_eq!(chunks.iter().map(|c| c.len()).sum::<usize>(), delta.len());
        // Reassembling the chunks reproduces the original sequence.
        let flat: Vec<_> = chunks.iter().flat_map(|c| c.iter()).collect();
        assert!(
            flat.iter()
                .zip(delta.iter())
                .all(|(a, b)| Arc::ptr_eq(a, b))
        );
    }

    #[test]
    fn no_chunk_exceeds_cap_when_entries_fit() {
        let delta: Vec<_> = (0..10).map(|_| commitment_with(2)).collect();
        for chunk in chunk_by_commitments(&delta, 6) {
            assert!(total_commitments(chunk) <= 6);
            assert!(!chunk.is_empty());
        }
    }

    #[test]
    fn oversized_single_entry_becomes_its_own_chunk() {
        // One entry alone exceeds the cap — it must still be emitted, alone.
        let delta = vec![commitment_with(2), commitment_with(100), commitment_with(2)];
        let chunks = chunk_by_commitments(&delta, 8);
        assert_eq!(chunks.len(), 3);
        assert_eq!(total_commitments(chunks[1]), 100);
    }

    #[test]
    fn small_delta_is_a_single_chunk() {
        let delta = vec![commitment_with(1)];
        let chunks = chunk_by_commitments(&delta, DEFAULT_MAX_COMMITMENTS_PER_RELAY);
        assert_eq!(chunks.len(), 1);
    }

    /// End-to-end: fork Arc Mainnet, impersonate the relay operator, and drive
    /// the **real** chunked relay path (`chunk_by_commitments` + `reduce` +
    /// `sendMessage`) chunk-by-chunk through the *currently deployed* gateway
    /// and satellite. Asserts the satellite's keccak chain advances from a zero
    /// head all the way to the live source tip.
    ///
    /// Needs `WORLDCHAIN_RPC_URL` + `ARC_RPC_URL` and a local `anvil`.
    #[tokio::test]
    #[ignore = "forks Arc Mainnet; needs WORLDCHAIN_RPC_URL + ARC_RPC_URL + anvil"]
    async fn cold_start_chunked_catch_up_reaches_source_tip_on_fork() -> eyre::Result<()> {
        use crate::{
            bindings::{IGateway, IWorldIDSatellite},
            relay::encode_evm_v1_address,
            satellite::permissioned::build_chain_head_attribute,
        };
        use alloy::{
            node_bindings::Anvil,
            primitives::{Address, U256, address},
            providers::{Provider, ProviderBuilder, ext::AnvilApi},
            rpc::types::{Filter, TransactionRequest},
            sol_types::SolEvent,
        };

        const SOURCE: Address = address!("12E8f92fE5901c17341E4A445F6CF991fFc2909E");
        const ARC_GATEWAY: Address = address!("2940Ce2f0f852230Cde632e203D327513b090206");
        const ARC_SATELLITE: Address = address!("304E14e4dC0508C0927e3b307a2C18422C07E394");
        const RELAYER: Address = address!("6348A4a4dF173F68eB28A452Ca6c13493e447aF1");
        const ANCHOR_CHAIN_ID: u64 = 480;
        const DEPLOYMENT_BLOCK: u64 = 29_732_292;

        let (Ok(wc_url), Ok(arc_url)) = (
            std::env::var("WORLDCHAIN_RPC_URL"),
            std::env::var("ARC_RPC_URL"),
        ) else {
            eprintln!("skipping: set WORLDCHAIN_RPC_URL and ARC_RPC_URL");
            return Ok(());
        };

        // ── Reconstruct the full backlog (the cold-start delta from head 0x0). ──
        let wc = ProviderBuilder::new().connect_http(wc_url.parse()?);
        let topic = IWorldIDSource::ChainCommitted::SIGNATURE_HASH;
        let latest = wc.get_block_number().await?;
        let mut delta: Vec<Arc<ChainCommitment>> = Vec::new();
        let (mut from, chunk) = (DEPLOYMENT_BLOCK, 50_000u64);
        while from <= latest {
            let to = (from + chunk - 1).min(latest);
            let filter = Filter::new()
                .address(SOURCE)
                .event_signature(topic)
                .from_block(from)
                .to_block(to);
            for log in wc.get_logs(&filter).await? {
                let ev = IWorldIDSource::ChainCommitted::decode_log(&log.inner)?;
                delta.push(Arc::new(ChainCommitment {
                    chain_head: ev.keccakChain,
                    block_number: ev.blockNumber.to::<u64>(),
                    chain_id: ev.chainId.to::<u64>(),
                    commitment_payload: ev.commitment.clone(),
                    timestamp: 0,
                }));
            }
            from = to + 1;
        }
        let target_head = delta.last().expect("backlog non-empty").chain_head;
        let target_len: usize = delta.iter().map(|c| commitment_count(c)).sum();
        println!(
            "backlog: {} events / {} commitments → tip {target_head}",
            delta.len(),
            target_len
        );

        // ── Fork Arc and impersonate the relay operator (gateway owner). ────────
        let anvil = Anvil::new().fork(arc_url).spawn();
        let fork = ProviderBuilder::new().connect_http(anvil.endpoint_url());
        fork.anvil_impersonate_account(RELAYER).await?;
        fork.anvil_set_balance(RELAYER, U256::from(10u128.pow(20)))
            .await?;

        let satellite = IWorldIDSatellite::new(ARC_SATELLITE, &fork);
        let start = satellite.KECCAK_CHAIN().call().await?;
        assert_eq!(start.head, B256::ZERO, "satellite must start cold");
        assert_eq!(start.length, 0);

        // ── Drive the production chunking path chunk-by-chunk. ──────────────────
        let recipient = encode_evm_v1_address(ANCHOR_CHAIN_ID, ARC_SATELLITE);
        let chunks = chunk_by_commitments(&delta, DEFAULT_MAX_COMMITMENTS_PER_RELAY);
        let n_chunks = chunks.len();
        for (i, chunk) in chunks.into_iter().enumerate() {
            let merged = reduce(chunk)?;
            let calldata = IGateway::sendMessageCall {
                recipient: recipient.clone().into(),
                payload: merged.commitment_payload.clone(),
                attributes: vec![build_chain_head_attribute(merged.chain_head)],
            }
            .abi_encode();
            let tx = TransactionRequest::default()
                .from(RELAYER)
                .to(ARC_GATEWAY)
                .input(calldata.into());
            let receipt = fork.send_transaction(tx).await?.get_receipt().await?;
            assert!(
                receipt.status(),
                "chunk {} of {n_chunks} reverted on-chain",
                i + 1
            );
            let now = satellite.KECCAK_CHAIN().call().await?;
            println!(
                "  chunk {:>2}/{n_chunks}: {:>2} events, gas {:>8} → head {} (len {})",
                i + 1,
                chunk.len(),
                receipt.gas_used,
                now.head,
                now.length
            );
        }

        // ── The satellite must now sit at the live source tip. ──────────────────
        let end = satellite.KECCAK_CHAIN().call().await?;
        assert_eq!(
            end.head, target_head,
            "satellite head must reach source tip"
        );
        assert_eq!(
            end.length as usize, target_len,
            "all commitments must apply"
        );

        let sat_root = satellite.LATEST_ROOT().call().await?;
        let src_root = IWorldIDSource::new(SOURCE, &wc)
            .LATEST_ROOT()
            .call()
            .await?;
        assert_eq!(sat_root, src_root, "satellite root must equal source root");
        println!("caught up to tip: head {} root {sat_root}", end.head);

        Ok(())
    }
}
