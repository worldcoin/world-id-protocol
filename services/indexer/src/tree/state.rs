use std::sync::Arc;

use alloy::primitives::U256;
use semaphore_rs_trees::lazy::Canonical;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::{MerkleTree, PoseidonHasher, TreeError, TreeResult};

/// Thread-safe wrapper around the Merkle tree and its configuration.
#[derive(Clone)]
pub struct TreeState {
    inner: Arc<TreeStateInner>,
}

struct TreeStateInner {
    tree: RwLock<MerkleTree<PoseidonHasher, Canonical>>,
    tree_depth: usize,
}

impl TreeState {
    /// Create a new `TreeState` with an existing tree and depth.
    pub fn new(tree: MerkleTree<PoseidonHasher, Canonical>, tree_depth: usize) -> Self {
        Self {
            inner: Arc::new(TreeStateInner {
                tree: RwLock::new(tree),
                tree_depth,
            }),
        }
    }

    /// Create a new `TreeState` with an empty tree of the given depth.
    pub fn new_empty(tree_depth: usize) -> Self {
        let tree = MerkleTree::<PoseidonHasher>::new(tree_depth, U256::ZERO);
        Self::new(tree, tree_depth)
    }

    /// Returns the configured depth.
    pub fn depth(&self) -> usize {
        self.inner.tree_depth
    }

    /// Returns the tree capacity (2^depth).
    pub fn capacity(&self) -> usize {
        1usize << self.inner.tree_depth
    }

    /// Acquire a read lock on the tree.
    pub async fn read(&self) -> RwLockReadGuard<'_, MerkleTree<PoseidonHasher, Canonical>> {
        self.inner.tree.read().await
    }

    /// Acquire a write lock on the tree.
    pub async fn write(&self) -> RwLockWriteGuard<'_, MerkleTree<PoseidonHasher, Canonical>> {
        self.inner.tree.write().await
    }

    /// Convenience method to get the current root.
    pub async fn root(&self) -> U256 {
        self.read().await.root()
    }

    /// Set a leaf value at the given index.
    ///
    /// Returns an error if the index is out of range.
    pub async fn set_leaf_at_index(&self, leaf_index: usize, value: U256) -> TreeResult<()> {
        let capacity = self.capacity();
        if leaf_index >= capacity {
            return Err(TreeError::LeafIndexOutOfRange {
                leaf_index,
                tree_depth: self.inner.tree_depth,
            });
        }

        let mut tree = self.write().await;
        take_mut::take(&mut *tree, |tree| {
            tree.update_with_mutation(leaf_index, &value)
        });
        Ok(())
    }

    /// Update commitment at the given leaf index.
    ///
    /// Returns an error if the leaf index is zero (reserved) or out of range.
    pub async fn update_commitment(
        &self,
        leaf_index: U256,
        new_commitment: U256,
    ) -> TreeResult<()> {
        if leaf_index == U256::ZERO {
            return Err(TreeError::ZeroLeafIndex);
        }
        let leaf_index = leaf_index.as_limbs()[0] as usize;
        self.set_leaf_at_index(leaf_index, new_commitment).await
    }

    /// Atomically replace the entire tree.
    pub async fn replace(&self, new_tree: MerkleTree<PoseidonHasher, Canonical>) {
        let mut tree = self.write().await;
        *tree = new_tree;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_new_empty() {
        let state = TreeState::new_empty(6);
        assert_eq!(state.depth(), 6);
        assert_eq!(state.capacity(), 64);
    }

    #[tokio::test]
    async fn test_set_leaf_at_index() {
        let state = TreeState::new_empty(6);
        let value = U256::from(42u64);

        state.set_leaf_at_index(1, value).await.unwrap();

        let tree = state.read().await;
        assert_eq!(tree.get_leaf(1), value);
    }

    #[tokio::test]
    async fn test_set_leaf_out_of_range() {
        let state = TreeState::new_empty(6);
        let result = state.set_leaf_at_index(100, U256::from(1u64)).await;
        assert!(matches!(result, Err(TreeError::LeafIndexOutOfRange { .. })));
    }

    #[tokio::test]
    async fn test_update_commitment() {
        let state = TreeState::new_empty(6);
        let commitment = U256::from(123u64);

        state
            .update_commitment(U256::from(5u64), commitment)
            .await
            .unwrap();

        let tree = state.read().await;
        assert_eq!(tree.get_leaf(5), commitment);
    }

    #[tokio::test]
    async fn test_update_tree_with_zero_index() {
        let state = TreeState::new_empty(6);
        let result = state
            .update_commitment(U256::ZERO, U256::from(1u64))
            .await;
        assert!(matches!(result, Err(TreeError::ZeroLeafIndex)));
    }

    #[tokio::test]
    async fn test_replace() {
        let state = TreeState::new_empty(6);
        let initial_root = state.root().await;

        // Create a new tree with a different value
        let mut new_tree = MerkleTree::<PoseidonHasher>::new(6, U256::ZERO);
        new_tree = new_tree.update_with_mutation(1, &U256::from(999u64));
        let new_root = new_tree.root();

        state.replace(new_tree).await;

        assert_ne!(initial_root, state.root().await);
        assert_eq!(new_root, state.root().await);
    }
}
