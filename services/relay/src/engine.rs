use std::sync::Arc;

use alloy::providers::{DynProvider, Provider};
use alloy_primitives::U160;
use eyre::Result;
use futures_util::StreamExt;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::{
    cli::chain::WorldChain,
    log::{CommitmentEventHook, SourceStateLog},
    satellite::Satellite,
    stream::{self, RegistryEventHooks},
};

/// The core relay engine.
pub struct Engine<P: Provider = Arc<DynProvider>> {
    world_chain: WorldChain<P>,
    log: Arc<SourceStateLog>,
    tasks: JoinSet<(String, Result<()>)>,
}

impl<P: Provider> Engine<P> {
    pub fn new(world_chain: WorldChain<P>) -> Self {
        let log = Arc::new(SourceStateLog::new());
        Self {
            world_chain,
            log,
            tasks: JoinSet::new(),
        }
    }

    /// Access the shared commitment log (for satellite task construction).
    pub fn log(&self) -> &Arc<SourceStateLog> {
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

    /// Runs the relay engine loop. Never returns under normal operation.
    pub async fn run(&mut self) -> Result<()> {
        stream::backfill_commitments(&self.world_chain, &self.log, 0).await?;

        let hooks = RegistryEventHooks::new().register(CommitmentEventHook {
            log: self.log.clone(),
        });

        let mut state_stream = stream::merged_registry_stream(&self.world_chain, hooks).await?;

        let mut tick = tokio::time::interval(self.world_chain.bridge_interval());

        info!(
            source = %self.world_chain.world_id_source().address(),
            tick = ?self.world_chain.bridge_interval(),
            "relay engine started"
        );

        loop {
            tokio::select! {
                _ = state_stream.next() => {}

                _ = tick.tick() => {
                    if !self.log.has_pending() {
                        continue;
                    }

                    let (issuers, oprfs) = self.log.pending_propagation_ids();
                    if issuers.is_empty() && oprfs.is_empty() {
                        continue;
                    }

                    info!(issuers = issuers.len(), oprfs = oprfs.len(), "propagating");

                    let pending = self.world_chain.world_id_source().propagateState(issuers, oprfs.iter().map(|id| U160::from(*id)).collect()).send().await?;
                    let tx = *pending.tx_hash();

                    let receipt = pending.get_receipt().await?;

                    if receipt.status() {
                        info!(hash = %&tx, "propagateState succeeded");
                    } else {
                        warn!(hash = %&tx, "propagateState transaction reverted");
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
        primitives::{BlockTimestampAndLogIndex, KeccakChain, reduce},
        proof::ChainCommitment,
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
            position: BlockTimestampAndLogIndex {
                timestamp: block_number * 100,
                log_index: 0,
            },
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
        assert_eq!(merged.position.timestamp, c2.position.timestamp);

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
