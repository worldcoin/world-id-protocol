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
    primitives::{ChainCommitment, KeccakChain, reduce},
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

    /// Whether an entry carrying more commitments than
    /// [`Self::max_commitments_per_relay`] may be split across several
    /// transactions.
    ///
    /// Only sound where the destination's chain head is asserted by the relay
    /// operator. `hashChained` folds one commitment at a time with no
    /// batch-level binding, so the head after a prefix of an entry is itself a
    /// valid chain state the satellite will accept. Adapters that prove the
    /// head against source-chain state can only attest heads the source
    /// actually emitted, so they must keep every entry whole.
    fn splittable(&self) -> bool {
        false
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
                        // The head may fall inside an entry: a split relay that
                        // stopped part-way through one (failed part, timeout,
                        // restart) leaves the destination on an intermediate
                        // head the log never indexed. Re-derive the outstanding
                        // commitments before falling back to a re-sync, which
                        // cannot resolve such a head either.
                        match log
                            .since(B256::ZERO)
                            .and_then(|all| resume_suffix(&all, local_head))
                        {
                            Some(suffix) => {
                                tracing::info!(
                                    head = %local_head,
                                    entries = suffix.len(),
                                    "resuming mid-entry after a partial split relay"
                                );
                                suffix
                            }
                            None => {
                                local_head = resync_head(&satellite, &log, local_head).await;
                                continue;
                            }
                        }
                    }
                };

                // Relay the delta in bounded chunks so a large backlog (e.g. a
                // cold-start from a zero head) is never submitted as a single
                // oversized transaction. Each chunk ends on a real on-chain
                // chain head, so the satellite applies them incrementally; on
                // the first failure we stop and retry the remainder (from the
                // now-advanced `local_head`) on the next head change.
                let max_commitments = satellite.max_commitments_per_relay();

                // A single source entry can itself exceed `max_commitments`:
                // the source batches everything accumulated since its previous
                // `propagateState`, so a stall on that side emits one large
                // entry. Chunking alone cannot help, because it never splits an
                // entry — so where the gateway lets the relay attest
                // intermediate heads, split it instead of wedging forever.
                let delta = if satellite.splittable() {
                    match split_oversized(delta, local_head, max_commitments) {
                        Ok(split) => split,
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "failed to split oversized entry, skipping this round"
                            );
                            continue;
                        }
                    }
                } else {
                    delta
                };

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

/// Locates a head that falls *inside* an entry and returns the commitments
/// still outstanding from there.
///
/// Splitting relays attests intermediate heads, and the log only indexes heads
/// the source actually emitted — so after a failed part, a timeout, or a
/// restart, the destination can sit on a head `CommitmentLog::since` cannot
/// resolve. Folding the log forward re-derives where that head sits, and the
/// remainder of its entry is emitted as one entry ending on the entry's real
/// (indexed) head, which puts the relay back on indexed heads as soon as it
/// lands.
///
/// Returns `None` if `head` is not an interior head of any entry, which is the
/// ordinary case and leaves the caller to fall back to a destination re-query.
fn resume_suffix(
    entries: &[Arc<ChainCommitment>],
    head: B256,
) -> Option<Vec<Arc<ChainCommitment>>> {
    let mut running = B256::ZERO;

    for (idx, entry) in entries.iter().enumerate() {
        let commits =
            Vec::<IWorldIDSource::Commitment>::abi_decode_params(&entry.commitment_payload).ok()?;

        let mut folded = running;
        for (applied, commit) in commits.iter().enumerate() {
            folded = KeccakChain::new(folded, 0).hash_chained(std::slice::from_ref(commit));

            // A match on the final commitment is the entry's own head, which
            // the log already indexes — `since` handles that case.
            if folded == head && applied + 1 < commits.len() {
                let remainder = commits[applied + 1..].to_vec();
                let mut out = Vec::with_capacity(entries.len() - idx);
                out.push(Arc::new(ChainCommitment {
                    chain_head: entry.chain_head,
                    block_number: entry.block_number,
                    chain_id: entry.chain_id,
                    commitment_payload: remainder.abi_encode_params().into(),
                    timestamp: entry.timestamp,
                }));
                out.extend(entries[idx + 1..].iter().cloned());
                return Some(out);
            }
        }

        running = entry.chain_head;
    }

    None
}

/// Splits any entry carrying more than `max_commitments` commitments into
/// several entries of at most that size, each ending on a locally recomputed
/// chain head.
///
/// `start_head` is the head the destination is currently at; heads are folded
/// forward from there exactly as `Lib.hashChained` does on-chain, so every
/// emitted entry ends on a head the satellite will accept. Entries already
/// within the limit are passed through untouched, and the fold over each split
/// entry must reproduce that entry's own head — otherwise the payload and head
/// disagree and we refuse to relay rather than attest something unverified.
///
/// Only call this for satellites whose [`Satellite::splittable`] is true.
fn split_oversized(
    delta: Vec<Arc<ChainCommitment>>,
    start_head: B256,
    max_commitments: usize,
) -> Result<Vec<Arc<ChainCommitment>>> {
    if !delta
        .iter()
        .any(|entry| commitment_count(entry) > max_commitments)
    {
        return Ok(delta);
    }

    let mut out = Vec::with_capacity(delta.len());
    let mut head = start_head;

    for entry in delta {
        let commits =
            Vec::<IWorldIDSource::Commitment>::abi_decode_params(&entry.commitment_payload)?;

        if commits.len() <= max_commitments {
            head = entry.chain_head;
            out.push(entry);
            continue;
        }

        let parts = commits.len().div_ceil(max_commitments);
        tracing::info!(
            block_number = entry.block_number,
            commitments = commits.len(),
            max_commitments,
            parts,
            "splitting oversized entry"
        );

        for group in commits.chunks(max_commitments) {
            head = KeccakChain::new(head, 0).hash_chained(group);
            out.push(Arc::new(ChainCommitment {
                chain_head: head,
                block_number: entry.block_number,
                chain_id: entry.chain_id,
                commitment_payload: group.abi_encode_params().into(),
                timestamp: entry.timestamp,
            }));
        }

        eyre::ensure!(
            head == entry.chain_head,
            "split of entry at block {} did not reproduce its chain head \
             (expected {}, folded to {})",
            entry.block_number,
            entry.chain_head,
            head,
        );
    }

    Ok(out)
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

    /// Decodes an entry's payload back into individual commitments.
    fn commits_of(entry: &ChainCommitment) -> Vec<IWorldIDSource::Commitment> {
        Vec::<IWorldIDSource::Commitment>::abi_decode_params(&entry.commitment_payload).unwrap()
    }

    /// Builds an entry of `n` commitments whose `chain_head` is the real fold
    /// from `start`, as the source emits and the satellite recomputes it.
    fn chained_commitment(start: B256, n: usize) -> Arc<ChainCommitment> {
        let entry = commitment_with(n);
        let head = KeccakChain::new(start, 0).hash_chained(&commits_of(&entry));
        Arc::new(ChainCommitment {
            chain_head: head,
            ..(*entry).clone()
        })
    }

    #[test]
    fn split_preserves_commitments_and_reproduces_the_head() {
        let start = B256::with_last_byte(0xAA);
        let entry = chained_commitment(start, 38);
        let original = commits_of(&entry);

        let split = split_oversized(vec![entry.clone()], start, 8).unwrap();

        assert_eq!(split.len(), 5, "38 commitments at a cap of 8 is 5 parts");
        assert!(split.iter().all(|e| commitment_count(e) <= 8));

        // Every commitment survives, in order.
        let flat: Vec<_> = split.iter().flat_map(|e| commits_of(e)).collect();
        assert_eq!(flat.len(), original.len());
        assert!(
            flat.iter()
                .zip(original.iter())
                .all(|(a, b)| a.blockHash == b.blockHash && a.data == b.data)
        );

        // Each part ends on the head the satellite will fold to, and the last
        // one lands exactly on the entry's own head.
        let mut head = start;
        for part in &split {
            head = KeccakChain::new(head, 0).hash_chained(&commits_of(part));
            assert_eq!(part.chain_head, head);
        }
        assert_eq!(head, entry.chain_head);
    }

    #[test]
    fn split_leaves_entries_within_the_cap_untouched() {
        let start = B256::ZERO;
        let delta = vec![commitment_with(2), commitment_with(8)];

        let split = split_oversized(delta.clone(), start, 8).unwrap();

        assert_eq!(split.len(), delta.len());
        assert!(
            split
                .iter()
                .zip(delta.iter())
                .all(|(a, b)| Arc::ptr_eq(a, b)),
            "entries within the cap must pass through untouched"
        );
    }

    #[test]
    fn split_rejects_an_entry_whose_head_disagrees_with_its_payload() {
        let start = B256::ZERO;
        let bad = Arc::new(ChainCommitment {
            chain_head: B256::with_last_byte(0xFF), // not the fold of the payload
            ..(*commitment_with(20)).clone()
        });

        let err = split_oversized(vec![bad], start, 8).unwrap_err();
        assert!(
            err.to_string().contains("did not reproduce its chain head"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resume_suffix_recovers_from_an_intermediate_head() {
        // The log holds entries as the source emitted them.
        let mut head = B256::ZERO;
        let mut entries = Vec::new();
        for n in [2usize, 38, 3] {
            let entry = chained_commitment(head, n);
            head = entry.chain_head;
            entries.push(entry);
        }
        let final_head = head;

        // Relay splits the 38-commitment entry and lands only its first part,
        // leaving the destination on a head the log never indexed.
        let split = split_oversized(entries.clone(), B256::ZERO, 8).unwrap();
        let stranded = split[1].chain_head; // first part of the oversized entry
        assert!(
            !entries.iter().any(|e| e.chain_head == stranded),
            "the stranded head must not be one the log indexes"
        );

        let suffix = resume_suffix(&entries, stranded).expect("must resolve the intermediate head");

        // The outstanding commitments are exactly those not yet applied, and
        // folding them from the stranded head reaches the source tip.
        let mut folded = stranded;
        for entry in &suffix {
            folded = KeccakChain::new(folded, 0).hash_chained(&commits_of(entry));
            assert_eq!(entry.chain_head, folded);
        }
        assert_eq!(folded, final_head, "resuming must reach the source tip");
        assert_eq!(
            suffix.iter().map(|e| commitment_count(e)).sum::<usize>(),
            38 - 8 + 3,
            "only the unapplied commitments are relayed"
        );
    }

    #[test]
    fn resume_suffix_ignores_heads_the_log_already_indexes() {
        let mut head = B256::ZERO;
        let mut entries = Vec::new();
        for n in [2usize, 5] {
            let entry = chained_commitment(head, n);
            head = entry.chain_head;
            entries.push(entry);
        }

        // An entry's own head is resolvable by `since`, so this must decline.
        assert!(resume_suffix(&entries, entries[0].chain_head).is_none());
        // As must a head belonging to no entry at all.
        assert!(resume_suffix(&entries, B256::with_last_byte(0x99)).is_none());
    }

    #[test]
    fn split_then_chunk_keeps_every_chunk_within_the_cap() {
        // A mixed delta, including the shape Tempo wedged on: one huge entry
        // surrounded by ordinary ones.
        let start = B256::ZERO;
        let mut head = start;
        let mut delta = Vec::new();
        for n in [2usize, 38, 1, 85, 3] {
            let entry = chained_commitment(head, n);
            head = entry.chain_head;
            delta.push(entry);
        }
        let total: usize = delta.iter().map(|e| commitment_count(e)).sum();

        let split = split_oversized(delta, start, 8).unwrap();
        assert_eq!(
            split.iter().map(|e| commitment_count(e)).sum::<usize>(),
            total
        );

        for chunk in chunk_by_commitments(&split, 8) {
            assert!(
                total_commitments(chunk) <= 8,
                "chunk of {} exceeds the cap after splitting",
                total_commitments(chunk)
            );
        }
        assert_eq!(
            split.last().unwrap().chain_head,
            head,
            "final head preserved"
        );
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
