use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use alloy::sol_types::{SolInterface, SolValue};
use alloy_primitives::{B256, U160, keccak256};
use dashmap::DashMap;
use eyre::{Result, ensure};
use parking_lot::{Mutex, RwLock};
use tokio::sync::watch;
use tracing::{debug, trace};

use crate::{
    bindings::{ICommitment::ICommitmentCalls, IWorldIDSource},
    primitives::{
        ChainCommitment, KeccakChain, PubKeyCommitment, PubKeyId, RootCommitment, StateCommitment,
    },
    stream::EventHook,
};

pub type CommitmentKey = B256;

/// Tracks the chain position at which a specific commitment key was finalized.
#[allow(dead_code)]
struct FinalizationRecord {
    chain_head: B256,
    chain_index: usize,
    block_timestamp: u64,
}

/// Decodes commitment keys from a raw ABI-encoded `Commitment[]` payload.
///
/// Each element's `data` field is an ABI-encoded function call
/// (`updateRoot`, `setIssuerPubkey`, or `setOprfPubkey`) that identifies the
/// state slot being committed.
pub fn decode_commitment_keys(payload: &[u8]) -> Result<Vec<B256>> {
    let commits = Vec::<IWorldIDSource::Commitment>::abi_decode_params(payload)?;
    let mut keys = Vec::with_capacity(commits.len());

    for c in &commits {
        let call = ICommitmentCalls::abi_decode(&c.data)?;
        let key = match call {
            ICommitmentCalls::updateRoot(c) => keccak256(c._0.as_le_bytes_trimmed()),
            ICommitmentCalls::setIssuerPubkey(c) => {
                keccak256(U160::from(c._0).as_le_bytes_trimmed())
            }
            ICommitmentCalls::setOprfPubkey(c) => keccak256(c._0.as_le_bytes_trimmed()),
        };
        keys.push(key);
    }

    Ok(keys)
}

// ── HistoricalCommitmentLog ─────────────────────────────────────────────────

/// A verified, indexed, append-only log of the keccak chain.
///
/// Every committed `ChainCommitment` is verified against the local keccak
/// chain replica before being accepted. Secondary indices provide O(1) lookup
/// by chain head and by commitment key, enabling fast delta queries and
/// finalization checks.
pub struct SourceStateLog {
    /// Ordered chain entries.
    entries: RwLock<VecDeque<Arc<ChainCommitment>>>,
    /// Pending credential issuer key updates that have yet to be finalized on-chain.
    pending_issuer_keys: DashMap<PubKeyId, PubKeyCommitment>,
    /// Pending OPRF key updates that have yet to be finalized on-chain.
    pending_oprf_keys: DashMap<PubKeyId, PubKeyCommitment>,
    /// Pending merkle roots that have yet to be finalized on-chain.
    pending_roots: DashMap<B256, RootCommitment>,
    /// Absolute index of the first entry (advances when entries are pruned).
    base_index: AtomicUsize,
    /// Maps `chain_head` to the absolute index of the entry that produced it.
    head_index: DashMap<B256, usize>,
    /// Maps each commitment key to the most recent finalization record.
    key_index: DashMap<CommitmentKey, FinalizationRecord>,
    /// Local keccak chain replica used for hash-chain integrity verification.
    local_chain: Mutex<KeccakChain>,
    /// Canonical chain head broadcaster.
    head: watch::Sender<B256>,
}

impl Default for SourceStateLog {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceStateLog {
    /// Creates a new empty log starting from the zero chain head.
    pub fn new() -> Self {
        let (head_tx, _) = watch::channel(B256::ZERO);
        Self {
            entries: RwLock::new(VecDeque::new()),
            base_index: AtomicUsize::new(0),
            head_index: DashMap::new(),
            key_index: DashMap::new(),
            local_chain: Mutex::new(KeccakChain::new(B256::ZERO, 0)),
            head: head_tx,
            pending_issuer_keys: DashMap::new(),
            pending_oprf_keys: DashMap::new(),
            pending_roots: DashMap::new(),
        }
    }

    /// Returns separated pending IDs for `propagateState(issuerSchemaIds, oprfKeyIds)`.
    pub fn pending_propagation_ids(&self) -> (Vec<u64>, Vec<u64>) {
        let issuers: Vec<u64> = self
            .pending_issuer_keys
            .iter()
            .map(|e| e.key().to::<u64>())
            .collect();
        let oprfs: Vec<u64> = self
            .pending_oprf_keys
            .iter()
            .map(|e| e.key().to::<u64>())
            .collect();
        (issuers, oprfs)
    }

    /// Insert pending updates that have yet to be finalized on-chain.
    pub fn insert_pending_root(&self, root: RootCommitment) {
        let ts = root.position.timestamp;
        let key = keccak256(root.root.as_le_bytes_trimmed());
        if let Some(existing) = self.pending_roots.get(&key) {
            if existing.position.timestamp >= ts {
                return;
            }
        }

        let is_ahead = self
            .entries
            .read()
            .back()
            .is_none_or(|c| root.position.timestamp > c.position.timestamp);
        if is_ahead {
            self.pending_roots.insert(key, root);
        }
    }

    pub fn has_pending(&self) -> bool {
        !self.pending_issuer_keys.is_empty()
            || !self.pending_oprf_keys.is_empty()
            || !self.pending_roots.is_empty()
    }

    /// Insert a pending credential issuer key update.
    pub fn insert_pending_issuer_key(&self, pub_key: PubKeyCommitment) {
        let ts = pub_key.position.timestamp;
        if let Some(existing) = self.pending_issuer_keys.get(&pub_key.id) {
            if existing.position.timestamp >= ts {
                return;
            }
        }

        let is_ahead = self
            .entries
            .read()
            .back()
            .is_none_or(|c| pub_key.position.timestamp > c.position.timestamp);
        if is_ahead {
            self.pending_issuer_keys.insert(pub_key.id, pub_key);
        }
    }

    /// Insert a pending OPRF key update.
    pub fn insert_pending_oprf_key(&self, pub_key: PubKeyCommitment) {
        let ts = pub_key.position.timestamp;
        if let Some(existing) = self.pending_oprf_keys.get(&pub_key.id) {
            if existing.position.timestamp >= ts {
                return;
            }
        }

        let is_ahead = self
            .entries
            .read()
            .back()
            .is_none_or(|c| pub_key.position.timestamp > c.position.timestamp);
        if is_ahead {
            self.pending_oprf_keys.insert(pub_key.id, pub_key);
        }
    }

    /// Verifies and commits a `ChainCommitment` to the log.
    ///
    /// The commitment is verified against the local keccak chain replica:
    /// 1. Duplicate heads are silently skipped (idempotent).
    /// 2. Chain ID and block number must be monotonically non-decreasing
    ///    relative to the most recent entry.
    /// 3. The hash chain must extend correctly from the current local head.
    pub fn commit_chained(&self, commitment: Arc<ChainCommitment>) -> Result<()> {
        // Duplicate detection — idempotent skip.
        if self.head_index.contains_key(&commitment.chain_head) {
            trace!(
                chain_head = %commitment.chain_head,
                "duplicate chain head, skipping"
            );
            return Ok(());
        }

        // Monotonicity check against the last entry.
        {
            let entries = self.entries.read();
            if let Some(last) = entries.back() {
                ensure!(
                    commitment.chain_id == last.chain_id,
                    "chain ID mismatch: expected {}, got {}",
                    last.chain_id,
                    commitment.chain_id,
                );
                ensure!(
                    commitment.block_number >= last.block_number,
                    "block number regression: last={}, got={}",
                    last.block_number,
                    commitment.block_number,
                );
            }
        }

        // Hash chain verification.
        let sol_commits =
            Vec::<IWorldIDSource::Commitment>::abi_decode_params(&commitment.commitment_payload)?;

        {
            let mut chain = self.local_chain.lock();
            let expected_head = chain.hash_chained(&sol_commits);
            ensure!(
                expected_head == commitment.chain_head,
                "keccak chain integrity failure: expected {expected_head}, got {}",
                commitment.chain_head,
            );
            chain.commit_chained(&sol_commits);
        }

        // Compute absolute index for this entry.
        let base = self.base_index.load(Ordering::Acquire);
        let abs_index = {
            let entries = self.entries.read();
            base + entries.len()
        };

        // Index the chain head.
        self.head_index.insert(commitment.chain_head, abs_index);

        // Decode and index individual commitment keys.
        let keys = decode_commitment_keys(&commitment.commitment_payload)?;
        for key in keys {
            self.key_index.insert(
                key,
                FinalizationRecord {
                    chain_head: commitment.chain_head,
                    chain_index: abs_index,
                    block_timestamp: commitment.position.timestamp,
                },
            );
        }

        // Append entry.
        {
            let mut entries = self.entries.write();
            entries.push_back(commitment);
        }

        // Broadcast new canonical head.
        let _ = self.head.send(
            self.entries
                .read()
                .back()
                .map_or(B256::ZERO, |e| e.chain_head),
        );

        debug!(
            chain_head = %self.head(),
            index = abs_index,
            "chain commitment appended"
        );

        Ok(())
    }

    /// Returns all chain commitments since `from_head` (exclusive).
    ///
    /// If `from_head` is `B256::ZERO`, returns all entries. Returns `None` if
    /// `from_head` is not found in the log (the caller is behind the pruning
    /// horizon or has a stale head).
    pub fn since(&self, from_head: B256) -> Option<Vec<Arc<ChainCommitment>>> {
        let entries = self.entries.read();
        let base = self.base_index.load(Ordering::Acquire);

        if from_head == B256::ZERO {
            return Some(entries.iter().cloned().collect());
        }

        let abs_index = self.head_index.get(&from_head)?;
        let relative = abs_index.saturating_sub(base);

        // Start from the entry after `from_head`.
        Some(entries.iter().skip(relative + 1).cloned().collect())
    }

    /// Returns `true` if `key` was finalized at or after `since_ts`.
    ///
    /// O(1) lookup via the key index.
    pub fn is_finalized_since(&self, key: &CommitmentKey, since_ts: u64) -> bool {
        self.key_index
            .get(key)
            .map(|record| record.block_timestamp >= since_ts)
            .unwrap_or(false)
    }

    /// Returns `true` if `key` was finalized at or before the chain entry
    /// identified by `at_head`.
    ///
    /// This is a chain-relative check: it verifies that the key's finalization
    /// index is less than or equal to the index of `at_head`.
    pub fn is_finalized_at(&self, key: &CommitmentKey, at_head: &B256) -> bool {
        let Some(head_ref) = self.head_index.get(at_head) else {
            return false;
        };
        let head_idx = *head_ref;

        self.key_index
            .get(key)
            .map(|record| record.chain_index <= head_idx)
            .unwrap_or(false)
    }

    /// Returns the current canonical chain head.
    pub fn head(&self) -> B256 {
        *self.head.borrow()
    }

    /// Returns a watch receiver that yields each new canonical chain head.
    pub fn subscribe(&self) -> watch::Receiver<B256> {
        self.head.subscribe()
    }

    /// Returns `true` if the given chain head exists in the log.
    pub fn contains_head(&self, head: &B256) -> bool {
        self.head_index.contains_key(head)
    }

    /// Prunes entries before the given absolute index.
    ///
    /// Entries with an absolute index strictly less than `up_to` are removed.
    /// The corresponding `head_index` entries are cleaned up as well.
    pub fn prune_before(&self, up_to: usize) {
        let mut entries = self.entries.write();
        let base = self.base_index.load(Ordering::Acquire);

        let to_remove = up_to.saturating_sub(base);
        let to_remove = to_remove.min(entries.len());

        for entry in entries.drain(..to_remove) {
            self.head_index.remove(&entry.chain_head);
        }

        self.base_index.store(base + to_remove, Ordering::Release);
    }

    /// Returns the number of entries currently in the log.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Returns `true` if the log contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

// ── LogHook ─────────────────────────────────────────────────────────────────

/// A `StateHook` that commits `ChainCommitted` events to a
/// `HistoricalCommitmentLog`.
pub struct CommitmentEventHook {
    pub log: Arc<SourceStateLog>,
}

impl EventHook for CommitmentEventHook {
    fn matches(&self, _c: &StateCommitment) -> bool {
        true
    }

    fn on_event(&self, c: &StateCommitment) {
        if let StateCommitment::ChainCommitted(cc) = c {
            if let Err(e) = self.log.commit_chained(Arc::new(cc.clone())) {
                tracing::error!(error = %e, "failed to commit chain commitment to log");
            }
        } else {
            match c {
                StateCommitment::CredentialIssuerPubKey(p) => {
                    self.log.insert_pending_issuer_key(p.clone());
                }
                StateCommitment::OprfPubKey(p) => {
                    self.log.insert_pending_oprf_key(p.clone());
                }
                StateCommitment::RootCommitment(r) => {
                    self.log.insert_pending_root(r.clone());
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bindings::ICommitment, primitives::BlockTimestampAndLogIndex};
    use alloy::sol_types::SolCall;
    use alloy_primitives::{Bytes, U256};

    /// Builds a valid ABI-encoded `updateRoot(root, timestamp, proofId)` call
    /// suitable for use as the `data` field in an `IWorldIDSource::Commitment`.
    fn encode_update_root(root: U256) -> Bytes {
        ICommitment::updateRootCall {
            _0: root,
            _1: U256::from(1u64),
            _2: B256::ZERO,
        }
        .abi_encode()
        .into()
    }

    /// Builds a single `IWorldIDSource::Commitment` with a valid inner call payload.
    fn make_sol_commitment(block_hash: B256) -> IWorldIDSource::Commitment {
        IWorldIDSource::Commitment {
            blockHash: block_hash,
            data: encode_update_root(U256::from(42u64)),
        }
    }

    /// Builds a `ChainCommitment` whose hash chain is valid relative to the
    /// supplied `KeccakChain`. Advances the chain as a side effect.
    fn make_chain_commitment(chain: &mut KeccakChain, block_number: u64) -> ChainCommitment {
        let commits = vec![make_sol_commitment(B256::from([block_number as u8; 32]))];
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

    fn make_pubkey_commitment(id: u64, timestamp: u64) -> PubKeyCommitment {
        PubKeyCommitment {
            affine: IWorldIDSource::Affine {
                x: U256::from(1u64),
                y: U256::from(2u64),
            },
            position: BlockTimestampAndLogIndex {
                timestamp,
                log_index: 0,
            },
            id: PubKeyId::from(id),
        }
    }

    // ── commit_chained tests ────────────────────────────────────────────────

    #[test]
    fn commit_chained_verifies_hash() {
        let log = SourceStateLog::new();
        let mut chain = KeccakChain::new(B256::ZERO, 0);
        let commitment = make_chain_commitment(&mut chain, 1);
        let result = log.commit_chained(Arc::new(commitment));
        assert!(
            result.is_ok(),
            "commit_chained should succeed for a valid commitment"
        );
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn commit_chained_rejects_bad_hash() {
        let log = SourceStateLog::new();
        let mut chain = KeccakChain::new(B256::ZERO, 0);
        let mut commitment = make_chain_commitment(&mut chain, 1);
        // Corrupt the chain head so it no longer matches the hash chain.
        commitment.chain_head = B256::from([0xffu8; 32]);
        let result = log.commit_chained(Arc::new(commitment));
        assert!(
            result.is_err(),
            "commit_chained should reject a mismatched chain head"
        );
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn commit_chained_idempotent() {
        let log = SourceStateLog::new();
        let mut chain = KeccakChain::new(B256::ZERO, 0);
        let commitment = Arc::new(make_chain_commitment(&mut chain, 1));

        let r1 = log.commit_chained(Arc::clone(&commitment));
        assert!(r1.is_ok());
        assert_eq!(log.len(), 1);

        // Second insertion of the same commitment should be silently skipped.
        let r2 = log.commit_chained(commitment);
        assert!(r2.is_ok());
        assert_eq!(log.len(), 1);
    }

    // ── since tests ─────────────────────────────────────────────────────────

    #[test]
    fn since_returns_delta() {
        let log = SourceStateLog::new();
        let mut chain = KeccakChain::new(B256::ZERO, 0);

        let c1 = make_chain_commitment(&mut chain, 1);
        let c2 = make_chain_commitment(&mut chain, 2);
        let c3 = make_chain_commitment(&mut chain, 3);

        let head_1 = c1.chain_head;
        log.commit_chained(Arc::new(c1)).unwrap();
        log.commit_chained(Arc::new(c2)).unwrap();
        log.commit_chained(Arc::new(c3)).unwrap();
        assert_eq!(log.len(), 3);

        let delta = log
            .since(head_1)
            .expect("since should return Some for a known head");
        assert_eq!(
            delta.len(),
            2,
            "since(head_1) should return the 2nd and 3rd entries"
        );
    }

    #[test]
    fn since_zero_returns_all() {
        let log = SourceStateLog::new();
        let mut chain = KeccakChain::new(B256::ZERO, 0);

        let c1 = make_chain_commitment(&mut chain, 1);
        let c2 = make_chain_commitment(&mut chain, 2);
        let c3 = make_chain_commitment(&mut chain, 3);

        log.commit_chained(Arc::new(c1)).unwrap();
        log.commit_chained(Arc::new(c2)).unwrap();
        log.commit_chained(Arc::new(c3)).unwrap();

        let all = log
            .since(B256::ZERO)
            .expect("since(ZERO) should return Some");
        assert_eq!(all.len(), 3, "since(ZERO) should return all entries");
    }

    // ── pending propagation tests ───────────────────────────────────────────

    #[test]
    fn pending_propagation_ids_separates_types() {
        let log = SourceStateLog::new();
        log.insert_pending_issuer_key(make_pubkey_commitment(1, 1000));
        log.insert_pending_oprf_key(make_pubkey_commitment(2, 1000));

        let (issuers, oprfs) = log.pending_propagation_ids();
        assert_eq!(issuers, vec![1u64]);
        assert_eq!(oprfs, vec![2u64]);
    }

    // ── has_pending tests ───────────────────────────────────────────────────

    #[test]
    fn has_pending_empty_and_nonempty() {
        let log = SourceStateLog::new();
        assert!(
            !log.has_pending(),
            "fresh log should have no pending entries"
        );

        log.insert_pending_issuer_key(make_pubkey_commitment(1, 1000));
        assert!(
            log.has_pending(),
            "log with a pending key should report has_pending"
        );
    }

    // ── prune tests ─────────────────────────────────────────────────────────

    #[test]
    fn prune_before_cleans_entries() {
        let log = SourceStateLog::new();
        let mut chain = KeccakChain::new(B256::ZERO, 0);

        let c1 = make_chain_commitment(&mut chain, 1);
        let c2 = make_chain_commitment(&mut chain, 2);
        let c3 = make_chain_commitment(&mut chain, 3);

        let head_1 = c1.chain_head;
        log.commit_chained(Arc::new(c1)).unwrap();
        log.commit_chained(Arc::new(c2)).unwrap();
        log.commit_chained(Arc::new(c3)).unwrap();
        assert_eq!(log.len(), 3);

        // Prune entries with absolute index < 2 (removes entries at indices 0 and 1).
        log.prune_before(2);
        assert_eq!(log.len(), 1, "only one entry should remain after pruning");

        // The pruned head should no longer be reachable via `since`.
        let result = log.since(head_1);
        assert!(result.is_none(), "since a pruned head should return None");
    }
}
