use std::{
    cmp::Ordering,
    ops::{Deref, DerefMut},
};

use crate::batcher::types::{FinalizedBatch, OpEnvelopeInner, OpStatus};
use alloy::primitives::{Address, U256};
use std::collections::{BTreeSet, HashMap};

/// Tracks nonce state per signer for dependency ordering.
///
/// Ensures operations are included in correct nonce order and
/// detects nonce gaps that would cause transaction failures.
#[derive(Debug, Default)]
pub struct NonceTracker {
    /// Last confirmed on-chain nonce per signer
    confirmed: HashMap<Address, U256>,
    /// Nonces currently in pending batches
    pending: HashMap<Address, BTreeSet<U256>>,
}

impl NonceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the confirmed nonce for a signer from chain state
    pub fn set_confirmed(&mut self, signer: Address, nonce: U256) {
        self.confirmed.insert(signer, nonce);
        // Clean up any pending nonces that are now confirmed
        if let Some(pending_set) = self.pending.get_mut(&signer) {
            pending_set.retain(|&n| n > nonce);
        }
    }

    /// Get the confirmed nonce for a signer
    pub fn get_confirmed(&self, signer: &Address) -> U256 {
        self.confirmed.get(signer).copied().unwrap_or(U256::ZERO)
    }

    /// Get the next expected nonce for a signer (confirmed + pending)
    pub fn next_expected(&self, signer: &Address) -> U256 {
        let confirmed = self.get_confirmed(signer);
        self.pending
            .get(signer)
            .and_then(|s| s.last().copied())
            .map(|last_pending| last_pending + U256::from(1))
            .unwrap_or(confirmed)
    }

    /// Check if an operation can be included (no nonce gap)
    ///
    /// An operation is ready if its nonce is exactly the next expected nonce.
    pub fn is_ready(&self, op: &OpEnvelopeInner) -> bool {
        let next = self.next_expected(&op.signer);
        op.nonce == next
    }

    /// Check if an operation has a nonce that's already been used
    pub fn is_stale(&self, op: &OpEnvelopeInner) -> bool {
        let confirmed = self.get_confirmed(&op.signer);
        op.nonce < confirmed
    }

    /// Check if an operation has a nonce gap (too high)
    pub fn has_gap(&self, op: &OpEnvelopeInner) -> bool {
        let next = self.next_expected(&op.signer);
        op.nonce > next
    }

    /// Mark an operation's nonce as pending (in a batch)
    pub fn mark_pending(&mut self, op: &OpEnvelopeInner) {
        self.pending.entry(op.signer).or_default().insert(op.nonce);
    }

    /// Remove an operation's nonce from pending
    pub fn unmark_pending(&mut self, op: &OpEnvelopeInner) {
        if let Some(set) = self.pending.get_mut(&op.signer) {
            set.remove(&op.nonce);
            if set.is_empty() {
                self.pending.remove(&op.signer);
            }
        }
    }

    /// Update state after a batch is finalized
    pub fn confirm_batch(&mut self, batch: &FinalizedBatch) {
        // Find the highest successful nonce per signer
        let mut max_nonces: HashMap<Address, U256> = HashMap::new();

        for (id, status) in &batch.statuses {
            if let OpStatus::Finalized { .. } = status {
                // We need the original operation to get signer/nonce
                // This would typically be passed separately or stored
                // For now, we assume the batch updates confirmed externally
            }
        }

        // Clean up pending sets
        for (signer, max_nonce) in max_nonces {
            if let Some(current) = self.confirmed.get(&signer) {
                if max_nonce > *current {
                    self.set_confirmed(signer, max_nonce + U256::from(1));
                }
            }
        }
    }

    /// Get all ready operations for a signer in nonce order
    pub fn get_ready_sequence<'a>(
        &self,
        signer: &Address,
        ops: &'a [OpEnvelopeInner],
    ) -> Vec<&'a OpEnvelopeInner> {
        let mut signer_ops: Vec<_> = ops.iter().filter(|op| op.signer == *signer).collect();

        // Sort by nonce
        signer_ops.sort_by_key(|op| op.nonce);

        // Take contiguous sequence starting from next expected
        let mut next = self.next_expected(signer);
        let mut ready = Vec::new();

        for op in signer_ops {
            if op.nonce == next {
                ready.push(op);
                next += U256::from(1);
            } else if op.nonce > next {
                // Gap found, stop here
                break;
            }
            // Skip ops with nonce < next (stale)
        }

        ready
    }

    /// Partition operations into ready vs blocked
    pub fn partition_by_readiness(
        &self,
        ops: Vec<OpEnvelopeInner>,
    ) -> (Vec<OpEnvelopeInner>, Vec<OpEnvelopeInner>) {
        let mut ready = Vec::new();
        let mut blocked = Vec::new();

        // Group by signer
        let mut by_signer: HashMap<Address, Vec<OpEnvelopeInner>> = HashMap::new();
        for op in ops {
            by_signer.entry(op.signer).or_default().push(op);
        }

        // Process each signer's ops
        for (signer, mut signer_ops) in by_signer {
            signer_ops.sort_by_key(|op| op.nonce);

            let mut next = self.next_expected(&signer);
            let mut in_sequence = true;

            for op in signer_ops {
                if in_sequence && op.nonce == next {
                    ready.push(op);
                    next += U256::from(1);
                } else {
                    in_sequence = false;
                    blocked.push(op);
                }
            }
        }

        (ready, blocked)
    }

    /// Get statistics about current state
    pub fn stats(&self) -> NonceTrackerStats {
        NonceTrackerStats {
            tracked_signers: self.confirmed.len(),
            pending_nonces: self.pending.values().map(|s| s.len()).sum(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NonceTrackerStats {
    pub tracked_signers: usize,
    pub pending_nonces: usize,
}

/// Trait for policy wrapper types that can be used in a BinaryHeap.
///
/// Each policy is a newtype wrapper around `OpEnvelopeInner` that implements
/// `Ord` according to its ordering strategy.
///
/// # Example
///
/// ```ignore
/// use std::collections::BinaryHeap;
///
/// let mut heap: BinaryHeap<GreedyCreateFirst> = BinaryHeap::new();
/// heap.push(GreedyCreateFirst::new(op));
///
/// // Operations are popped in policy-defined order
/// while let Some(envelope) = heap.pop() {
///     process(envelope.into_inner());
/// }
/// ```
pub trait OrderingPolicy: Ord + Eq + Clone + Send + Sync + 'static {
    type T: Into<Priority>;

    fn new(inner: OpEnvelopeInner) -> Self;

    fn into_inner(self) -> OpEnvelopeInner;

    fn name() -> &'static str;

    /// Compare two operations for ordering.
    fn cmp(&self, other: &Self) -> Ordering;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum Priority {
    CreateAccount = 1,
    Other = 0,
}

impl From<OpEnvelopeInner> for Priority {
    fn from(op: OpEnvelopeInner) -> Self {
        match op.op {
            crate::batcher::types::Operation::CreateAccount(_) => Priority::CreateAccount,
            _ => Priority::Other,
        }
    }
}

/// Ordering rules (in precedence):
/// 1. Higher priority class first (Critical > High > Normal)
/// 2. Within same priority, older operations first (FIFO by received_at)
#[derive(Debug, Clone)]
pub struct SignupFifoOrdering<T: Into<Priority>>(pub T);

impl SignupFifoOrdering<OpEnvelopeInner> {
    fn compare(a: &OpEnvelopeInner, b: &OpEnvelopeInner) -> Ordering {
        let a_priority: Priority = a.clone().into();
        let b_priority: Priority = b.clone().into();
        let ord = a_priority.partial_cmp(&b_priority);

        match ord {
            Some(Ordering::Equal) => a.received_at.cmp(&b.received_at),
            Some(other) => other,
            None => a.received_at.cmp(&b.received_at),
        }
    }
}

impl OrderingPolicy for SignupFifoOrdering<OpEnvelopeInner> {
    type T = OpEnvelopeInner;

    fn new(inner: OpEnvelopeInner) -> Self {
        Self(inner)
    }

    fn into_inner(self) -> OpEnvelopeInner {
        self.0
    }

    fn name() -> &'static str {
        "signup_fifo"
    }

    fn cmp(&self, other: &Self) -> Ordering {
        Self::compare(&self.0, &other.0)
    }
}

impl Deref for SignupFifoOrdering<OpEnvelopeInner> {
    type Target = OpEnvelopeInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SignupFifoOrdering<OpEnvelopeInner> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialEq for SignupFifoOrdering<OpEnvelopeInner> {
    fn eq(&self, other: &Self) -> bool {
        self.0.id == other.0.id
    }
}

impl Eq for SignupFifoOrdering<OpEnvelopeInner> {}

impl Ord for SignupFifoOrdering<OpEnvelopeInner> {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap is a max-heap (pops greatest first).
        // We reverse so that "Less" (higher priority) comes out first.
        Self::compare(&self.0, &other.0).reverse()
    }
}

impl PartialOrd for SignupFifoOrdering<OpEnvelopeInner> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(<Self as Ord>::cmp(self, other))
    }
}

impl From<OpEnvelopeInner> for SignupFifoOrdering<OpEnvelopeInner> {
    fn from(inner: OpEnvelopeInner) -> Self {
        SignupFifoOrdering(inner)
    }
}

impl SignupFifoOrdering<OpEnvelopeInner> {
    /// Create a new wrapper from inner data
    pub fn new(inner: OpEnvelopeInner) -> Self {
        Self(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batcher::types::{CreateAccountOp, Operation};
    use alloy::primitives::Bytes;
    use std::time::Instant;
    use uuid::Uuid;

    fn make_op(signer: Address, nonce: u64) -> OpEnvelopeInner {
        OpEnvelopeInner {
            id: Uuid::new_v4(),
            op: Operation::CreateAccount(CreateAccountOp {
                initial_commitment: U256::ZERO,
                signature: Bytes::new(),
            }),
            received_at: Instant::now().into(),
            signer,
            nonce: U256::from(nonce),
        }
    }

    #[test]
    fn test_initial_state() {
        let tracker = NonceTracker::new();
        let signer = Address::repeat_byte(1);

        assert_eq!(tracker.get_confirmed(&signer), U256::ZERO);
        assert_eq!(tracker.next_expected(&signer), U256::ZERO);
    }

    #[test]
    fn test_is_ready() {
        let mut tracker = NonceTracker::new();
        let signer = Address::repeat_byte(1);

        tracker.set_confirmed(signer, U256::from(5));

        let op_ready = make_op(signer, 5);
        let op_stale = make_op(signer, 3);
        let op_gap = make_op(signer, 7);

        assert!(tracker.is_ready(&op_ready));
        assert!(!tracker.is_ready(&op_stale));
        assert!(!tracker.is_ready(&op_gap));
    }

    #[test]
    fn test_pending_tracking() {
        let mut tracker = NonceTracker::new();
        let signer = Address::repeat_byte(1);

        tracker.set_confirmed(signer, U256::from(0));

        let op0 = make_op(signer, 0);
        let op1 = make_op(signer, 1);
        let op2 = make_op(signer, 2);

        assert!(tracker.is_ready(&op0));
        tracker.mark_pending(&op0);

        // Now op1 should be ready
        assert!(tracker.is_ready(&op1));
        assert!(!tracker.is_ready(&op2)); // Gap

        tracker.mark_pending(&op1);
        assert!(tracker.is_ready(&op2));
    }

    #[test]
    fn test_partition() {
        let mut tracker = NonceTracker::new();
        let signer = Address::repeat_byte(1);

        tracker.set_confirmed(signer, U256::from(0));

        let ops = vec![
            make_op(signer, 0),
            make_op(signer, 1),
            make_op(signer, 3), // Gap at 2
            make_op(signer, 4),
        ];

        let (ready, blocked) = tracker.partition_by_readiness(ops);

        assert_eq!(ready.len(), 2); // 0 and 1
        assert_eq!(blocked.len(), 2); // 3 and 4 (blocked by gap)
    }

    #[test]
    fn test_multiple_signers() {
        let mut tracker = NonceTracker::new();
        let signer1 = Address::repeat_byte(1);
        let signer2 = Address::repeat_byte(2);

        tracker.set_confirmed(signer1, U256::from(0));
        tracker.set_confirmed(signer2, U256::from(5));

        let ops = vec![
            make_op(signer1, 0),
            make_op(signer1, 1),
            make_op(signer2, 5),
            make_op(signer2, 6),
        ];

        let (ready, blocked) = tracker.partition_by_readiness(ops);

        assert_eq!(ready.len(), 4); // All ready
        assert_eq!(blocked.len(), 0);
    }
}
