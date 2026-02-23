use alloy_primitives::{B256, Bytes};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeccakChain {
    pub head: B256,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Commitment {
    pub block_hash: B256,
    pub data: Bytes
}

impl KeccakChain {
    pub fn new(head: B256, length: u64) -> Self {
        Self { head, length }
    }

    /// Updates the chain head by applying the given commitments in order.
    pub fn commit_chained(&mut self, commitments: &[Commitment]) {
        for commitment in commitments {
            self.head = alloy_primitives::keccak256([self.head, commitment.block_hash, commitment.data.as_ref()]);
            self.length += 1;
        }
    }

    /// Computes the hash of the chain after applying the given commitments, without modifying the chain itself.
    pub fn hash_chained(&self, commitments: &[Commitment]) -> B256 {
        let mut hash = self.head;
        for commitment in commitments {
            hash = alloy_primitives::keccak256([hash, commitment.block_hash, commitment.data.as_ref()]);
        }
        hash
    }
}