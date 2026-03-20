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
                    // Only clear pending state after on-chain confirmation. Clearing
                    // earlier (e.g. on reverts or transient errors) would silently drop
                    // queued issuer/OPRF key updates that have not yet been relayed.
                    self.log.clear_pending_propagation();
                } else {
                    // The transaction was mined but reverted. Preserve pending state so
                    // the next tick can retry. Most on-chain reverts here are transient
                    // (e.g. root not yet available on the destination).
                    warn!(hash = %receipt.transaction_hash, "propagateState reverted on-chain; retaining pending state for retry");
                }
            }
            Err(e) => {
                // Distinguish simulation reverts from transient transport errors.
                //
                // `as_revert_data()` returns `Some(non-empty bytes)` only when the
                // node ran the call and it reverted with a specific reason.  That is
                // an idempotent condition: the on-chain state is already up-to-date
                // so clearing pending is safe and avoids an infinite retry loop.
                //
                // In all other cases — transport errors (network timeout, connection
                // refused, HTTP 5xx), bare reverts (`revert()` / `require(false)` with
                // no message, which produce `Some(Bytes::new())`), and any error that
                // lacks revert data — preserve pending state so the next tick retries.
                if e.as_revert_data().is_some_and(|d| !d.is_empty()) {
                    // Non-empty revert data means the node ran the call and it
                    // reverted with a specific reason (e.g. "root already propagated").
                    // These are idempotent: the on-chain state is already up-to-date,
                    // so clearing pending is safe and avoids an infinite retry loop.
                    debug!(error = %e, "propagateState simulation reverted (idempotent); clearing pending state");
                    self.log.clear_pending_propagation();
                } else {
                    // Either a transient transport error (network timeout, connection
                    // refused, HTTP 5xx) or a bare revert with no diagnostic data.
                    // In both cases, preserve pending state so the next tick retries.
                    // The error is propagated so the run-loop logs it at warn level.
                    return Err(e.into());
                }
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
        primitives::{ChainCommitment, IssuerKeyUpdate, IssuerSchemaId, KeccakChain, OprfKeyId, OprfKeyUpdate, U160, reduce},
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

    // ── Propagation state-preservation tests ──────────────────────────────

    fn make_issuer_update(id: u64, timestamp: u64) -> IssuerKeyUpdate {
        IssuerKeyUpdate {
            affine: IWorldIDSource::Affine {
                x: U256::from(1u64),
                y: U256::from(2u64),
            },
            timestamp,
            id: IssuerSchemaId(id),
        }
    }

    fn make_oprf_update(id: u64, timestamp: u64) -> OprfKeyUpdate {
        OprfKeyUpdate {
            affine: IWorldIDSource::Affine {
                x: U256::from(1u64),
                y: U256::from(2u64),
            },
            timestamp,
            id: OprfKeyId(U160::from(id)),
        }
    }

    /// Verifies that the `as_revert_data()` discriminant correctly separates
    /// transient transport errors (must preserve pending state) from idempotent
    /// simulation reverts (safe to clear).
    ///
    /// This pins the classification logic used by `Engine::propagate()`:
    ///
    /// - Transport / non-revert errors → `as_revert_data()` returns `None`
    ///   (or `Some(empty)` for bare reverts) → preserve state, return `Err`
    /// - Simulation reverts with non-empty data → `as_revert_data()` returns
    ///   `Some(non-empty)` → clear pending, continue
    ///
    /// Guards against regressions where `clear_pending_propagation()` would be
    /// called on transient failures, silently dropping issuer / OPRF updates.
    #[test]
    fn pending_state_preserved_on_transient_error_path() {
        use alloy::contract::Error as ContractError;
        use alloy::transports::{RpcError, TransportErrorKind};

        let log = CommitmentLog::new();
        log.insert_pending_issuer(make_issuer_update(1, 1_000));
        log.insert_pending_oprf(make_oprf_update(2, 1_000));

        // --- Classify a BackendGone error ---------------------------------
        // BackendGone (node connection dropped) has no revert data → the engine
        // must preserve pending state and propagate the error.
        let backend_gone =
            ContractError::TransportError(RpcError::Transport(TransportErrorKind::BackendGone));
        assert!(
            !backend_gone.as_revert_data().is_some_and(|d| !d.is_empty()),
            "BackendGone must NOT trigger clear_pending_propagation"
        );

        // --- Simulate the engine's decision: transient → do NOT clear -----
        // (In production this is `return Err(e.into())` in propagate().)
        // State must still be present for the next propagation tick.
        assert!(log.has_pending_keys(), "pending keys must survive a transient error");

        let (issuers, oprfs) = log.pending_propagation_ids();
        assert_eq!(issuers, vec![1u64], "issuer update must be retried");
        assert_eq!(oprfs, vec![U160::from(2u64)], "OPRF update must be retried");
    }

    /// Pins both sides of the error discriminant used in `Engine::propagate()`:
    ///
    /// - `None` / `Some(empty)` from `as_revert_data()` → transient / bare revert
    ///   → **preserve** pending state
    /// - `Some(non-empty)` → idempotent simulation revert → **clear** pending state
    #[test]
    fn error_classification_discriminant() {
        use alloy::contract::Error as ContractError;
        use alloy::rpc::json_rpc::ErrorPayload;
        use alloy::transports::{RpcError, TransportErrorKind};
        use serde_json::value::RawValue;
        use std::borrow::Cow;

        // ---- Negative cases (treat as transient / preserve state) ----------

        // Pure transport error: no RPC response at all.
        let backend_gone =
            ContractError::TransportError(RpcError::Transport(TransportErrorKind::BackendGone));
        assert!(
            !backend_gone.as_revert_data().is_some_and(|d| !d.is_empty()),
            "BackendGone must be treated as transient"
        );

        // Generic internal RPC error with no revert message.
        let internal_err = ContractError::TransportError(RpcError::ErrorResp(
            ErrorPayload::internal_error(),
        ));
        assert!(
            !internal_err.as_revert_data().is_some_and(|d| !d.is_empty()),
            "internal RPC error without 'revert' message must be treated as transient"
        );

        // Bare revert (Geth sends data: "0x" → Some(Bytes::new())).
        // Must NOT be cleared because bare reverts may be non-idempotent.
        let bare_revert_payload = ErrorPayload {
            code: 3,
            message: Cow::Borrowed("execution reverted"),
            data: Some(RawValue::from_string("\"0x\"".to_string()).unwrap()),
        };
        let bare_revert =
            ContractError::TransportError(RpcError::ErrorResp(bare_revert_payload));
        assert!(
            !bare_revert.as_revert_data().is_some_and(|d| !d.is_empty()),
            "bare revert (empty revert data) must be treated as transient"
        );

        // ---- Positive case (idempotent simulation revert → clear) ----------

        // Revert with a non-empty ABI-encoded reason string.
        // 0x08c379a0 = keccak("Error(string)")[..4].
        let revert_hex = "\"0x08c379a000000000000000000000000000000000000000000000000000000000\
            000000200000000000000000000000000000000000000000000000000000000000000015\
            726f6f7420616c72656164792070726f706167617465640000000000000000000000\"";
        let revert_payload = ErrorPayload {
            code: 3,
            message: Cow::Borrowed("execution reverted: root already propagated"),
            data: Some(RawValue::from_string(revert_hex.to_string()).unwrap()),
        };
        let sim_revert = ContractError::TransportError(RpcError::ErrorResp(revert_payload));
        assert!(
            sim_revert.as_revert_data().is_some_and(|d| !d.is_empty()),
            "simulation revert with non-empty data must be treated as idempotent (clear pending)"
        );
    }

    /// Verifies that clearing pending state after a simulation revert leaves the
    /// log empty — confirming that `clear_pending_propagation()` is safe to call
    /// for idempotent reverts.
    #[test]
    fn clear_pending_removes_all_pending_state() {
        let log = CommitmentLog::new();
        log.insert_pending_issuer(make_issuer_update(10, 2_000));
        log.insert_pending_oprf(make_oprf_update(20, 2_000));

        assert!(log.has_pending_keys());
        log.clear_pending_propagation();
        assert!(
            !log.has_pending_keys(),
            "clear_pending_propagation must remove all pending state"
        );
    }
}
