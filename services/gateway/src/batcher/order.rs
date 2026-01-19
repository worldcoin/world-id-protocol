use std::{
    cmp::Ordering,
    ops::{Deref, DerefMut},
};

use crate::batcher::types::OpEnvelopeInner;
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
pub trait OrderingPolicy:
    Ord + Eq + Clone + Send + Sync + Deref<Target = OpEnvelopeInner> + 'static
{
    fn new(inner: OpEnvelopeInner) -> Self;

    fn into_inner(self) -> OpEnvelopeInner;

    fn name() -> &'static str;
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
    fn new(inner: OpEnvelopeInner) -> Self {
        Self(inner)
    }

    fn into_inner(self) -> OpEnvelopeInner {
        self.0
    }

    fn name() -> &'static str {
        "signup_fifo"
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
}
