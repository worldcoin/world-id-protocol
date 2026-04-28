use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use alloy::sol_types::SolValue;
use alloy_primitives::B256;
use dashmap::DashMap;
use eyre::{Result, ensure};
use parking_lot::{Mutex, RwLock};
use tokio::sync::watch;
use tracing::{debug, trace};

use crate::{
    bindings::IWorldIDSource,
    primitives::{
        ChainCommitment, IssuerKeyUpdate, IssuerSchemaId, KeccakChain, OprfKeyId, OprfKeyUpdate,
        StateCommitment, U160,
    },
};

// ── PendingSnapshot ─────────────────────────────────────────────────────────

/// A snapshot of pending issuer/OPRF key updates drained from the log.
///
/// Holds both the IDs needed for `propagateState` and the full entries so
/// they can be restored on failure via [`CommitmentLog::restore_pending`].
pub struct PendingSnapshot {
    issuers: HashMap<IssuerSchemaId, IssuerKeyUpdate>,
    oprfs: HashMap<OprfKeyId, OprfKeyUpdate>,
}

impl PendingSnapshot {
    /// Returns the issuer schema IDs for the `propagateState` call.
    pub fn issuer_ids(&self) -> Vec<u64> {
        self.issuers.keys().map(|k| k.0).collect()
    }

    /// Returns the OPRF key IDs for the `propagateState` call.
    pub fn oprf_ids(&self) -> Vec<U160> {
        self.oprfs.keys().map(|k| k.0).collect()
    }

    /// Returns `true` if there are no pending updates.
    pub fn is_empty(&self) -> bool {
        self.issuers.is_empty() && self.oprfs.is_empty()
    }
}

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
    pending_issuers: Mutex<HashMap<IssuerSchemaId, IssuerKeyUpdate>>,
    /// Pending OPRF key updates that have yet to be finalized on-chain.
    pending_oprfs: Mutex<HashMap<OprfKeyId, OprfKeyUpdate>>,
    /// Maps `chain_head` to the index of the entry in the VecDeque.
    head_index: DashMap<B256, usize>,
    /// Local keccak chain replica used for hash-chain integrity verification.
    local_chain: Mutex<KeccakChain>,
    /// Canonical chain head broadcaster.
    cursor_tx: watch::Sender<B256>,
    /// Keeps the watch channel open even when no satellites have subscribed yet.
    /// Without this, `cursor_tx.send()` silently fails during backfill because
    /// the channel is "closed" (all receivers dropped).
    _cursor_rx: watch::Receiver<B256>,
    /// Flag indicating backfill is complete and the log is ready.
    ready_flag: AtomicBool,
    /// Signals that the log is ready for satellite consumption (backfill complete).
    ready_notify: tokio::sync::Notify,
}

impl Default for CommitmentLog {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitmentLog {
    /// Creates a new empty log starting from the zero chain head.
    pub fn new() -> Self {
        let (cursor_tx, cursor_rx) = watch::channel(B256::ZERO);
        Self {
            entries: RwLock::new(VecDeque::new()),
            head_index: DashMap::new(),
            local_chain: Mutex::new(KeccakChain::new(B256::ZERO, 0)),
            cursor_tx,
            _cursor_rx: cursor_rx,
            pending_issuers: Mutex::new(HashMap::new()),
            pending_oprfs: Mutex::new(HashMap::new()),
            ready_flag: AtomicBool::new(false),
            ready_notify: tokio::sync::Notify::new(),
        }
    }

    /// Signals that backfill is complete and the log is ready for satellite use.
    pub fn mark_ready(&self) {
        self.ready_flag.store(true, Ordering::Release);
        self.ready_notify.notify_waiters();
    }

    /// Waits until the log is ready (backfill complete).
    ///
    /// # Race-free design
    ///
    /// We subscribe to the [`Notify`] **before** reading `ready_flag`.
    /// [`Notified::enable`] registers this task as a waiter immediately
    /// (without polling), so any `notify_waiters()` call that arrives after
    /// `enable()` — even before we hit the `.await` — will resolve the future.
    /// The flag check then handles the complementary case where `mark_ready()`
    /// already completed before we even entered this function.
    ///
    /// Without this ordering, a `notify_waiters()` that fires in the window
    /// between the flag load returning `false` and the `.await` being polled
    /// would be silently dropped, leaving the caller blocked forever.
    pub async fn wait_ready(&self) {
        let notified = self.ready_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if self.ready_flag.load(Ordering::Acquire) {
            return;
        }

        notified.await;
    }

    /// Dispatches a `StateCommitment` into the appropriate log storage.
    pub fn insert(&self, commitment: StateCommitment) {
        match commitment {
            StateCommitment::ChainCommitted(cc) => {
                debug!(
                    block = cc.block_number,
                    chain_head = %cc.chain_head,
                    "processing ChainCommitted event"
                );
                if let Err(e) = self.commit_chained(Arc::new(cc)) {
                    tracing::error!(error = %e, "failed to commit chain commitment");
                }
            }
            StateCommitment::IssuerPubKey(p) => {
                debug!(issuer_schema_id = p.id.0, "received IssuerPubKey update");
                self.insert_pending_issuer(p);
            }
            StateCommitment::OprfPubKey(p) => {
                debug!(oprf_key_id = %p.id.0, "received OprfPubKey update");
                self.insert_pending_oprf(p);
            }
            StateCommitment::RootCommitment(r) => {
                debug!(root = %r.root, timestamp = r.timestamp, "received RootRecorded event");
                // Roots are propagated automatically via ChainCommitted — no
                // pending state needed. We just log the event.
            }
        }
    }

    /// Atomically drains all pending entries.
    ///
    /// On propagation failure, call [`restore_pending`] to re-insert them.
    pub fn take_pending(&self) -> PendingSnapshot {
        PendingSnapshot {
            issuers: std::mem::take(&mut *self.pending_issuers.lock()),
            oprfs: std::mem::take(&mut *self.pending_oprfs.lock()),
        }
    }

    /// Re-inserts previously drained entries for retry.
    ///
    /// Entries inserted concurrently (newer events) take precedence.
    pub fn restore_pending(&self, snapshot: PendingSnapshot) {
        let mut issuers = self.pending_issuers.lock();
        for (k, v) in snapshot.issuers {
            issuers.entry(k).or_insert(v);
        }
        let mut oprfs = self.pending_oprfs.lock();
        for (k, v) in snapshot.oprfs {
            oprfs.entry(k).or_insert(v);
        }
    }

    // ── Pending insert methods ──────────────────────────────────────────────

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
fn insert_if_newer<K: Eq + Hash, V>(
    map: &Mutex<HashMap<K, V>>,
    key: K,
    value: V,
    ts: u64,
    get_ts: impl Fn(&V) -> u64,
    tail_ts: Option<u64>,
) {
    if tail_ts.is_some_and(|tail| ts <= tail) {
        return;
    }
    let mut map = map.lock();
    if let Some(existing) = map.get(&key)
        && get_ts(existing) >= ts
    {
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

    fn make_sol_commitment(block_hash: B256) -> IWorldIDSource::Commitment {
        IWorldIDSource::Commitment {
            blockHash: block_hash,
            data: encode_update_root(U256::from(42u64)),
        }
    }

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

        let r2 = log.commit_chained(commitment);
        assert!(r2.is_ok());
        assert_eq!(log.len(), 1);
    }

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

    #[test]
    fn take_pending_drains_and_separates_types() {
        let log = CommitmentLog::new();
        log.insert_pending_issuer(make_issuer_update(1, 1000));
        log.insert_pending_oprf(make_oprf_update(2, 1000));

        let snapshot = log.take_pending();
        assert_eq!(snapshot.issuer_ids(), vec![1u64]);
        assert_eq!(snapshot.oprf_ids(), vec![U160::from(2u64)]);

        // Maps should now be empty after drain.
        let empty = log.take_pending();
        assert!(empty.is_empty());
    }

    #[test]
    fn restore_pending_re_inserts_entries() {
        let log = CommitmentLog::new();
        log.insert_pending_issuer(make_issuer_update(1, 1000));

        let snapshot = log.take_pending();
        assert!(log.take_pending().is_empty());

        log.restore_pending(snapshot);
        let restored = log.take_pending();
        assert_eq!(restored.issuer_ids(), vec![1u64]);
    }

    // ── wait_ready() race-condition tests ───────────────────────────────────

    /// `wait_ready()` must return immediately when the log is already ready.
    #[tokio::test]
    async fn wait_ready_returns_immediately_when_already_ready() {
        let log = CommitmentLog::new();
        log.mark_ready();

        tokio::time::timeout(std::time::Duration::from_millis(50), log.wait_ready())
            .await
            .expect("wait_ready() should return immediately when log is already ready");
    }

    /// `wait_ready()` must wake up after a concurrent `mark_ready()`.
    ///
    /// A `oneshot` channel is used as a reliable rendezvous: the waiter task
    /// signals that it has entered `wait_ready()` before the producer fires,
    /// so we exercise the slow path (flag not yet set when the waiter starts).
    #[tokio::test]
    async fn wait_ready_wakes_on_mark_ready() {
        use std::sync::Arc;
        use tokio::sync::oneshot;

        let log = Arc::new(CommitmentLog::new());
        let log_clone = Arc::clone(&log);

        let (tx, rx) = oneshot::channel::<()>();

        let waiter = tokio::spawn(async move {
            // Signal that we are about to enter wait_ready().
            // The future is already armed by enable() inside wait_ready() before
            // the send completes on the other side, so the ordering is safe.
            let _ = tx.send(());
            log_clone.wait_ready().await;
        });

        // Wait until the waiter task is live, then fire mark_ready().
        rx.await.unwrap();
        log.mark_ready();

        tokio::time::timeout(std::time::Duration::from_millis(500), waiter)
            .await
            .expect("wait_ready() hung after mark_ready() was called")
            .unwrap();
    }

    /// All concurrent `wait_ready()` callers must be woken by a single
    /// `mark_ready()` call (validates `notify_waiters()` broadcast semantics).
    #[tokio::test]
    async fn wait_ready_wakes_all_concurrent_waiters() {
        use std::sync::Arc;

        let log = Arc::new(CommitmentLog::new());
        let handles: Vec<_> = (0..10)
            .map(|_| {
                let log = Arc::clone(&log);
                tokio::spawn(async move { log.wait_ready().await })
            })
            .collect();

        // Allow spawned tasks to register their `Notified` futures.
        tokio::task::yield_now().await;

        log.mark_ready();

        for handle in handles {
            tokio::time::timeout(std::time::Duration::from_millis(500), handle)
                .await
                .expect("wait_ready() hung — one or more waiters were not woken")
                .unwrap();
        }
    }

    /// Regression test for the lost-notification race.
    ///
    /// **The bug (old code):**
    /// ```text
    /// satellite:   ready_flag.load() -> false   // flag not yet set
    /// producer:    ready_flag.store(true)
    ///              notify.notify_waiters()       // no registered waiters → lost
    /// satellite:   notify.notified().await       // hangs forever
    /// ```
    ///
    /// **The fix:** call `notified()` + `enable()` *before* the flag check,
    /// so the task is a registered waiter before `notify_waiters()` can fire.
    ///
    /// This test exercises the underlying `Notify` primitive directly with a
    /// deterministic interleaving: `notify_waiters()` fires *after* `enable()`
    /// but *before* `.await`.  The future must resolve immediately, not hang.
    #[tokio::test]
    async fn notified_enable_captures_notify_waiters_fired_before_await() {
        let notify = tokio::sync::Notify::new();

        // Consumer: subscribe and arm the future.
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable(); // registered — can't miss a subsequent wakeup

        // Producer: fires AFTER enable() but BEFORE .await.
        // This is the exact losing interleaving that the old code suffered from.
        notify.notify_waiters();

        // The future must resolve immediately — the notification must not be lost.
        tokio::time::timeout(std::time::Duration::from_millis(50), notified)
            .await
            .expect("notification fired after enable() must not be lost");
    }

    /// Stress-tests the race across many iterations with real multi-thread
    /// concurrency so CPU-level interleaving between `enable()` and
    /// `notify_waiters()` is exercised.
    ///
    /// Without the `enable()`-before-flag-check fix, some iterations would
    /// occasionally hang. With the fix every iteration must complete within
    /// the timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wait_ready_concurrent_stress() {
        use std::sync::Arc;

        for _ in 0..100 {
            let log = Arc::new(CommitmentLog::new());
            let log_clone = Arc::clone(&log);

            // Waiter starts immediately — races with mark_ready() below.
            let waiter = tokio::spawn(async move {
                log_clone.wait_ready().await;
            });

            // mark_ready() fires without yielding, maximising the race window.
            log.mark_ready();

            tokio::time::timeout(std::time::Duration::from_millis(200), waiter)
                .await
                .expect("wait_ready() hung — notification was lost (iteration failed)")
                .unwrap();
        }
    }
}
