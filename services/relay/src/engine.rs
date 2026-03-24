use std::sync::Arc;

use eyre::Result;
use futures_util::StreamExt;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use crate::{cli::WorldChain, log::CommitmentLog, satellite::Satellite, stream};

/// The core relay engine.
///
/// Monitors World Chain registry events, maintains the commitment log, and
/// coordinates satellite relay tasks. Uses concrete `WorldChain` (no generics)
/// since the provider is always `Arc<DynProvider>`.
pub struct Engine {
    world_chain: WorldChain,
    log: Arc<CommitmentLog>,
    tasks: JoinSet<(String, Result<()>)>,
}

impl Engine {
    pub fn new(world_chain: WorldChain) -> Self {
        let log = Arc::new(CommitmentLog::new());
        Self {
            world_chain,
            log,
            tasks: JoinSet::new(),
        }
    }

    /// Access the shared commitment log (for satellite task construction).
    pub fn log(&self) -> &Arc<CommitmentLog> {
        &self.log
    }

    /// Spawns a satellite task that listens for new commitments and relays them.
    pub fn spawn_satellite(&mut self, satellite: impl Satellite + 'static) {
        let name = satellite.name().to_owned();
        let log = self.log().clone();

        self.tasks.spawn(async move {
            let result = crate::satellite::spawn_satellite(satellite, log).await;
            (name, result)
        });
    }

    /// Checks whether there is new state to propagate by comparing the
    /// latest root on WorldIDSource vs WorldIDRegistry, and checking for
    /// pending issuer/OPRF key updates.
    async fn should_propagate(&self) -> Result<bool> {
        // Check if the registry has a newer root than the source.
        let source_root = self
            .world_chain
            .world_id_source()
            .LATEST_ROOT()
            .call()
            .await?;
        let registry_root = self
            .world_chain
            .world_id_registry()
            .getLatestRoot()
            .call()
            .await?;

        let root_changed = source_root != registry_root;
        let has_keys = self.log.has_pending_keys();

        if root_changed {
            debug!(source = %source_root, registry = %registry_root, "root changed");
        }
        if has_keys {
            debug!("pending issuer/OPRF key updates");
        }

        Ok(root_changed || has_keys)
    }

    /// Calls `propagateState` on the WorldIDSource contract for any pending
    /// state (root changes, issuer keys, OPRF keys).
    ///
    /// Returns `Ok(())` if there is nothing to propagate or if the transaction
    /// succeeds. Propagation failures are logged but never fatal -- the engine
    /// will retry on the next tick.
    async fn propagate(&self) -> Result<()> {
        match self.should_propagate().await {
            Ok(false) => {
                debug!("propagation tick: nothing to propagate");
                return Ok(());
            }
            Err(e) => {
                warn!(error = %e, "failed to check propagation state");
                return Ok(());
            }
            Ok(true) => {}
        }

        let (issuers, oprfs) = self.log.pending_propagation_ids();

        info!(issuers = issuers.len(), oprfs = oprfs.len(), "propagating");

        let result = self
            .world_chain
            .world_id_source()
            .propagateState(issuers, oprfs)
            .send()
            .await;

        match result {
            Ok(pending) => {
                let receipt = pending.get_receipt().await?;
                if receipt.status() {
                    info!(hash = %receipt.transaction_hash, "propagateState succeeded");
                    self.log.clear_pending_propagation();
                } else {
                    warn!(hash = %receipt.transaction_hash, "propagateState reverted on-chain");
                }
            }
            // Simulation reverts are expected when nothing has changed.
            // Always clear pending regardless of the error to avoid retrying
            // the same state indefinitely.
            Err(e) => {
                debug!(error = %e, "propagateState simulation reverted");
                self.log.clear_pending_propagation();
            }
        }
        Ok(())
    }

    /// Runs the relay engine loop. Never returns under normal operation.
    pub async fn run(&mut self) -> Result<()> {
        // Start the live event stream BEFORE backfill so we don't miss
        // events that occur during backfill. Duplicate ChainCommitted events
        // are harmless — commit_chained deduplicates by chain head.
        let mut events = stream::registry_stream(&self.world_chain).await?;

        // Backfill historical ChainCommitted events from genesis so the
        // in-memory log contains every commit the source has ever made.
        // Satellites query the destination chain's head and use log.since()
        // to send any commits the destination hasn't received yet.
        info!("backfilling historical ChainCommitted events");
        stream::backfill_commitments(&self.world_chain, &self.log).await?;

        info!("backfill complete, starting satellite relay loop");

        // Signal satellites that the log is ready — they can now safely
        // query log.since() and get the full historical delta.
        self.log.mark_ready();

        let mut tick = tokio::time::interval(self.world_chain.bridge_interval());

        info!(
            source = %self.world_chain.world_id_source().address(),
            tick = ?self.world_chain.bridge_interval(),
            "relay engine started"
        );

        loop {
            tokio::select! {
                Some(result) = events.next() => {
                    match result {
                        Ok(commitment) => {
                            info!(event = %commitment, "received event from World Chain");
                            self.log.insert(commitment);
                        }
                        Err(e) => warn!(error = %e, "failed to decode event"),
                    }
                }

                _ = tick.tick() => {
                    if let Err(e) = self.propagate().await {
                        warn!(error = %e, "propagation failed");
                    }
                }

                // Monitor satellite tasks.
                Some(result) = self.tasks.join_next() => {
                    match result {
                        Ok((name, Ok(()))) => info!(%name, "satellite task exited"),
                        Ok((name, Err(e))) => error!(%name, error = %e, "satellite task failed"),
                        Err(e) => error!(error = %e, "satellite task panicked"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bindings::{ICommitment, IWorldIDSource},
        primitives::{ChainCommitment, KeccakChain, reduce},
    };
    use alloy::sol_types::{SolCall, SolValue};
    use alloy_primitives::{B256, Bytes, U256};

    /// Builds a valid ABI-encoded `updateRoot(root, timestamp, proofId)` call.
    fn encode_update_root(root: U256) -> Bytes {
        ICommitment::updateRootCall {
            _0: root,
            _1: U256::from(1u64),
            _2: B256::ZERO,
        }
        .abi_encode()
        .into()
    }

    fn make_sol_commitment(block_hash: B256, root: U256) -> IWorldIDSource::Commitment {
        IWorldIDSource::Commitment {
            blockHash: block_hash,
            data: encode_update_root(root),
        }
    }

    fn make_chain_commitment_from(
        chain: &mut KeccakChain,
        block_number: u64,
        root: U256,
    ) -> ChainCommitment {
        let commits = vec![make_sol_commitment(
            B256::from([block_number as u8; 32]),
            root,
        )];
        let head = chain.hash_chained(&commits);
        chain.commit_chained(&commits);
        ChainCommitment {
            chain_head: head,
            block_number,
            chain_id: 480,
            commitment_payload: commits.abi_encode_params().into(),
            timestamp: block_number * 100,
        }
    }

    #[test]
    fn merge_arc_commitments_concatenates_payloads() {
        let mut chain = KeccakChain::new(B256::ZERO, 0);

        let c1 = Arc::new(make_chain_commitment_from(
            &mut chain,
            1,
            U256::from(100u64),
        ));
        let c2 = Arc::new(make_chain_commitment_from(
            &mut chain,
            2,
            U256::from(200u64),
        ));

        let merged = reduce(&[c1.clone(), c2.clone()]).expect("merge should succeed");

        // The merged commitment should inherit metadata from the last entry.
        assert_eq!(merged.chain_head, c2.chain_head);
        assert_eq!(merged.block_number, c2.block_number);
        assert_eq!(merged.chain_id, c2.chain_id);
        assert_eq!(merged.timestamp, c2.timestamp);

        // Decode the merged payload and verify it contains both commitments.
        let decoded =
            Vec::<IWorldIDSource::Commitment>::abi_decode_params(&merged.commitment_payload)
                .expect("merged payload should decode");
        assert_eq!(
            decoded.len(),
            2,
            "merged payload should contain 2 commitments"
        );

        // Verify the block hashes match the originals.
        assert_eq!(decoded[0].blockHash, B256::from([1u8; 32]));
        assert_eq!(decoded[1].blockHash, B256::from([2u8; 32]));
    }
}
