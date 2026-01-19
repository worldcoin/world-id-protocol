use std::{
    cmp::Ordering,
    ops::{Deref, DerefMut},
};

use crate::batcher::types::OpEnvelopeInner;

pub trait OrderingPolicy:
    Ord + Eq + Clone + Send + Sync + Deref<Target = OpEnvelopeInner> + 'static
{
    fn new(inner: OpEnvelopeInner) -> Self;

    fn into_inner(self) -> OpEnvelopeInner;
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Other = 0,
    CreateAccount = 1,
}

impl From<&OpEnvelopeInner> for Priority {
    fn from(op: &OpEnvelopeInner) -> Self {
        match op.op {
            crate::batcher::types::Operation::CreateAccount(_) => Priority::CreateAccount,
            _ => Priority::Other,
        }
    }
}

/// Ordering rules (in precedence):
/// 1. Priority (CreateAccount > Other)
/// 2. Received time (earlier = higher priority)
#[derive(Debug, Clone)]
pub struct SignupFifoOrdering(OpEnvelopeInner);

impl OrderingPolicy for SignupFifoOrdering {
    fn new(inner: OpEnvelopeInner) -> Self {
        Self(inner)
    }

    fn into_inner(self) -> OpEnvelopeInner {
        self.0
    }
}

impl Deref for SignupFifoOrdering {
    type Target = OpEnvelopeInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SignupFifoOrdering {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialEq for SignupFifoOrdering {
    fn eq(&self, other: &Self) -> bool {
        self.0.id == other.0.id
    }
}

impl Eq for SignupFifoOrdering {}

impl Ord for SignupFifoOrdering {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap is a max-heap (pops greatest first).
        // We want higher priority and earlier received_at to come out first.
        let self_priority = Priority::from(&self.0);
        let other_priority = Priority::from(&other.0);

        // Compare by priority first (higher = greater)
        match self_priority.cmp(&other_priority) {
            Ordering::Equal => {
                // Same priority: earlier received_at should come out first (be "greater")
                other.0.received_at.cmp(&self.0.received_at)
            }
            ord => ord,
        }
    }
}

impl PartialOrd for SignupFifoOrdering {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<OpEnvelopeInner> for SignupFifoOrdering {
    fn from(inner: OpEnvelopeInner) -> Self {
        SignupFifoOrdering(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batcher::types::{CreateAccountOp, InsertAuthenticatorOp, Operation};
    use alloy::primitives::{Address, Bytes, U256};
    use std::collections::BinaryHeap;
    use tokio::time::Instant;
    use uuid::Uuid;

    fn make_create_op() -> OpEnvelopeInner {
        OpEnvelopeInner {
            id: Uuid::new_v4(),
            op: Operation::CreateAccount(CreateAccountOp {
                initial_commitment: U256::ZERO,
                signature: Bytes::new(),
            }),
            received_at: Instant::now(),
            signer: Address::ZERO,
            nonce: U256::ZERO,
        }
    }

    fn make_insert_op() -> OpEnvelopeInner {
        OpEnvelopeInner {
            id: Uuid::new_v4(),
            op: Operation::InsertAuthenticator(InsertAuthenticatorOp {
                leaf_index: U256::ZERO,
                new_authenticator_address: Address::ZERO,
                pubkey_id: 0,
                new_authenticator_pubkey: U256::ZERO,
                old_commit: U256::ZERO,
                new_commit: U256::ZERO,
                signature: Bytes::new(),
                sibling_nodes: vec![],
                nonce: U256::ZERO,
            }),
            received_at: Instant::now(),
            signer: Address::ZERO,
            nonce: U256::ZERO,
        }
    }

    #[test]
    fn test_create_account_has_higher_priority() {
        let create_op = make_create_op();
        let insert_op = make_insert_op();

        let create_wrapped = SignupFifoOrdering::new(create_op);
        let insert_wrapped = SignupFifoOrdering::new(insert_op);

        // CreateAccount should be greater (higher priority)
        assert!(create_wrapped > insert_wrapped);
    }

    #[test]
    fn test_heap_pops_create_account_first() {
        let mut heap: BinaryHeap<SignupFifoOrdering> = BinaryHeap::new();

        // Add insert first, then create
        heap.push(SignupFifoOrdering::new(make_insert_op()));
        heap.push(SignupFifoOrdering::new(make_create_op()));

        // Should pop CreateAccount first (higher priority)
        let first = heap.pop().unwrap();
        assert!(matches!(first.0.op, Operation::CreateAccount(_)));

        let second = heap.pop().unwrap();
        assert!(matches!(second.0.op, Operation::InsertAuthenticator(_)));
    }
}
