use std::{collections::VecDeque, hash::Hash, sync::Arc};

use alloy::sol_types::SolValue;
use alloy_primitives::{B256, keccak256};
use dashmap::DashMap;
use eyre::{Result, ensure};
use parking_lot::{Mutex, RwLock};
use tokio::sync::watch;
use tracing::{debug, trace};

use crate::{
    bindings::IWorldIDSource,
    primitives::{
        ChainCommitment, IssuerKeyUpdate, IssuerSchemaId, KeccakChain, OprfKeyId, OprfKeyUpdate,
        RootCommitment, StateCommitment, U160,
    },
};

// ── CommitmentLog ───────────────────────────────────────────────────────────

/// A verified, indexed, append-only log of the keccak chain.
///
/// Every committed `ChainCommitment` is verified against the local keccak
/// chain replica before being accepted. A secondary index provides O(1)
/// lookup by chain head, enabling fast delta queries.
pub struct CommitmentLog {
    /// Ordered chain entries.
    entries: RwLock<VecDeque<Arc<ChainCommitment>>>,
    /// Pending credential issuer key updates that have yet to be finalized on-chain.
    pending_issuers: DashMap<IssuerSchemaId, IssuerKeyUpdate>,
    /// Pending OPRF key updates that have yet to be finalized on-chain.
    pending_oprfs: DashMap<OprfKeyId, OprfKeyUpdate>,
    /// Pending merkle roots that have yet to be finalized on-chain.
    pending_roots: DashMap<B256, RootCommitment>,
    /// Maps `chain_head` to the index of the entry in the VecDeque.
    head_index: DashMap<B256, usize>,
    /// Local keccak chain replica used for hash-chain integrity verification.
    local_chain: Mutex<KeccakChain>,
    /// Canonical chain head broadcaster.
    cursor_tx: watch::Sender<B256>,
}

impl Default for CommitmentLog {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitmentLog {
    /// Creates a new empty log starting from the zero chain head.
    pub fn new() -> Self {
        let (cursor_tx, _) = watch::channel(B256::ZERO);
        Self {
            entries: RwLock::new(VecDeque::new()),
            head_index: DashMap::new(),
            local_chain: Mutex::new(KeccakChain::new(B256::ZERO, 0)),
            cursor_tx,
            pending_issuers: DashMap::new(),
            pending_oprfs: DashMap::new(),
            pending_roots: DashMap::new(),
        }
    }

    /// Dispatches a `StateCommitment` into the appropriate log storage.
    pub fn insert(&self, commitment: StateCommitment) {
        match commitment {
            StateCommitment::ChainCommitted(cc) => {
                if let Err(e) = self.commit_chained(Arc::new(cc)) {
                    tracing::error!(error = %e, "failed to commit chain commitment");
                }
            }
            StateCommitment::IssuerPubKey(p) => self.insert_pending_issuer(p),
            StateCommitment::OprfPubKey(p) => self.insert_pending_oprf(p),
            StateCommitment::RootCommitment(r) => self.insert_pending_root(r),
        }
    }

    /// Returns separated pending IDs for `propagateState(issuerSchemaIds, oprfKeyIds)`.
    pub fn pending_propagation_ids(&self) -> (Vec<u64>, Vec<U160>) {
        let issuers = self.pending_issuers.iter().map(|e| e.key().0).collect();
        let oprfs = self.pending_oprfs.iter().map(|e| e.key().0).collect();
        (issuers, oprfs)
    }

    /// Clears all pending state after a successful `propagateState`.
    pub fn clear_pending_propagation(&self) {
        self.pending_issuers.clear();
        self.pending_oprfs.clear();
        self.pending_roots.clear();
    }

    /// Returns `true` if there are any pending (non-chain) updates.
    pub fn has_pending(&self) -> bool {
        !self.pending_issuers.is_empty()
            || !self.pending_oprfs.is_empty()
            || !self.pending_roots.is_empty()
    }

    // ── Pending insert methods ──────────────────────────────────────────────

    /// Insert a pending merkle-root update.
    pub fn insert_pending_root(&self, root: RootCommitment) {
        let ts = root.timestamp;
        let key = keccak256(root.root.as_le_bytes_trimmed());
        let tail_ts = self.tail_timestamp();
        insert_if_newer(&self.pending_roots, key, root, ts, |r| r.timestamp, tail_ts);
    }

    /// Insert a pending credential issuer key update.
    pub fn insert_pending_issuer(&self, update: IssuerKeyUpdate) {
        let ts = update.timestamp;
        let key = update.id;
        let tail_ts = self.tail_timestamp();
        insert_if_newer(
            &self.pending_issuers,
            key,
            update,
            ts,
            |u| u.timestamp,
            tail_ts,
        );
    }

    /// Insert a pending OPRF key update.
    pub fn insert_pending_oprf(&self, update: OprfKeyUpdate) {
        let ts = update.timestamp;
        let key = update.id;
        let tail_ts = self.tail_timestamp();
        insert_if_newer(
            &self.pending_oprfs,
            key,
            update,
            ts,
            |u| u.timestamp,
            tail_ts,
        );
    }

    /// Returns the timestamp of the most recent chain entry, if any.
    fn tail_timestamp(&self) -> Option<u64> {
        self.entries.read().back().map(|c| c.timestamp)
    }

    // ── Chain commitment ────────────────────────────────────────────────────

    /// Verifies and commits a `ChainCommitment` to the log.
    ///
    /// The commitment is verified against the local keccak chain replica:
    /// 1. Duplicate heads are silently skipped (idempotent).
    /// 2. Chain ID and block number must be monotonically non-decreasing
    ///    relative to the most recent entry.
    /// 3. The hash chain must extend correctly from the current local head.
    pub fn commit_chained(&self, commitment: Arc<ChainCommitment>) -> Result<()> {
        // Duplicate detection -- idempotent skip.
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

        // Append entry and capture the insertion index in one write-lock section.
        let (index, new_head) = {
            let mut entries = self.entries.write();
            let index = entries.len();
            let new_head = commitment.chain_head;
            entries.push_back(commitment);
            (index, new_head)
        };

        // Index the chain head.
        self.head_index.insert(new_head, index);

        // Broadcast new canonical head.
        let _ = self.cursor_tx.send(new_head);

        debug!(
            chain_head = %self.head(),
            index,
            "chain commitment appended"
        );

        Ok(())
    }

    // ── Query methods ───────────────────────────────────────────────────────

    /// Returns all chain commitments since `cursor` (exclusive).
    ///
    /// If `cursor` is `B256::ZERO`, returns all entries. Returns `None` if
    /// `cursor` is not found in the log (the caller has a stale head).
    pub fn since(&self, cursor: B256) -> Option<Vec<Arc<ChainCommitment>>> {
        let entries = self.entries.read();

        if cursor == B256::ZERO {
            return Some(entries.iter().cloned().collect());
        }

        let &idx = self.head_index.get(&cursor)?.value();
        Some(entries.iter().skip(idx + 1).cloned().collect())
    }

    /// Returns the current canonical chain head.
    pub fn head(&self) -> B256 {
        *self.cursor_tx.borrow()
    }

    /// Returns a watch receiver that yields each new canonical chain head.
    pub fn subscribe(&self) -> watch::Receiver<B256> {
        self.cursor_tx.subscribe()
    }

    /// Returns `true` if the given chain head exists in the log.
    pub fn contains_head(&self, head: &B256) -> bool {
        self.head_index.contains_key(head)
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

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Inserts `value` into `map` only if it is newer than any existing entry
/// and newer than the tail of the chain log.
fn insert_if_newer<K: Eq + Hash, V: Clone>(
    map: &DashMap<K, V>,
    key: K,
    value: V,
    ts: u64,
    get_ts: impl Fn(&V) -> u64,
    tail_ts: Option<u64>,
) {
    if let Some(existing) = map.get(&key)
        && get_ts(&existing) >= ts
    {
        return;
    }
    if tail_ts.is_some_and(|tail| ts <= tail) {
        return;
    }
    map.insert(key, value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::KeccakChain;
    use alloy::sol_types::SolCall;
    use alloy_primitives::{Bytes, U256};

    /// Builds a valid ABI-encoded `updateRoot(root, timestamp, proofId)` call
    /// suitable for use as the `data` field in an `IWorldIDSource::Commitment`.
    fn encode_update_root(root: U256) -> Bytes {
        use crate::bindings::ICommitment;
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
            timestamp: block_number * 100,
        }
    }

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

    // ── commit_chained tests ────────────────────────────────────────────────

    #[test]
    fn commit_chained_verifies_hash() {
        let log = CommitmentLog::new();
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
        let log = CommitmentLog::new();
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
        let log = CommitmentLog::new();
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
        let log = CommitmentLog::new();
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
        let log = CommitmentLog::new();
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
        let log = CommitmentLog::new();
        log.insert_pending_issuer(make_issuer_update(1, 1000));
        log.insert_pending_oprf(make_oprf_update(2, 1000));

        let (issuers, oprfs) = log.pending_propagation_ids();
        assert_eq!(issuers, vec![1u64]);
        assert_eq!(oprfs, vec![U160::from(2u64)]);
    }

    // ── has_pending tests ───────────────────────────────────────────────────

    #[test]
    fn has_pending_empty_and_nonempty() {
        let log = CommitmentLog::new();
        assert!(
            !log.has_pending(),
            "fresh log should have no pending entries"
        );

        log.insert_pending_issuer(make_issuer_update(1, 1000));
        assert!(
            log.has_pending(),
            "log with a pending key should report has_pending"
        );
    }
}
