mod ethereum_mpt;
mod permissioned;

pub use ethereum_mpt::EthereumMptSatellite;
pub use permissioned::PermissionedSatellite;
use tracing::Instrument;

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use alloy::primitives::{B256, Bytes};
use eyre::Result;

use crate::{
    log::CommitmentLog,
    primitives::{ChainCommitment, reduce},
};

/// Maximum time to wait for a single relay attempt (proof + transaction).
const RELAY_TIMEOUT: Duration = Duration::from_secs(600);

/// A destination chain that can receive bridged World ID state.
pub trait Satellite: Send + Sync {
    /// Human-readable name for logging (e.g. "ethereum-mainnet", "base-sepolia").
    fn name(&self) -> &str;

    /// The chain ID of this destination.
    fn chain_id(&self) -> u64;

    /// Queries the destination chain's current keccak chain head.
    ///
    /// Used on startup to determine which commitments the destination has
    /// already received, so the relay can send any missing ones.
    fn remote_chain_head<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<B256>> + Send + 'a>>;

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

                let count = delta.len();
                let merged = reduce(&delta)?;
                let target_head = merged.chain_head;

                tracing::debug!(
                    commitments = count,
                    target = %target_head,
                    "relaying delta"
                );

                match tokio::time::timeout(RELAY_TIMEOUT, satellite.relay(&merged)).await {
                    Ok(Ok(tx_hash)) => {
                        local_head = target_head;
                        tracing::info!(%tx_hash, head = %local_head, "relay succeeded");
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "relay failed, will retry on next head");
                    }
                    Err(_) => {
                        tracing::warn!(
                            "relay timed out after {RELAY_TIMEOUT:?}, will retry on next head"
                        );
                    }
                }
            }
        }
        .instrument(span)
        .await
    })
}

/// Re-queries the destination chain when the local head is not found in the log.
async fn resync_head(
    satellite: &impl Satellite,
    log: &CommitmentLog,
    stale_head: B256,
) -> B256 {
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
