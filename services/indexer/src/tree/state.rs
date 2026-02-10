use std::{path::Path, sync::Arc};

use alloy::primitives::U256;
use semaphore_rs_storage::MmapVec;
use semaphore_rs_trees::cascading::CascadingMerkleTree;
use semaphore_rs_trees::proof::InclusionProof;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::{MerkleTree, PoseidonHasher, TreeError, TreeResult};
use crate::{db::WorldTreeEventId, tree::cached_tree::set_arbitrary_leaf};

/// Thread-safe wrapper around the Merkle tree and its configuration.
#[derive(Clone, Debug)]
pub struct TreeState {
    inner: Arc<TreeStateInner>,
}

#[derive(Debug)]
struct TreeStateInner {
    tree: RwLock<CascadingMerkleTree<PoseidonHasher, MmapVec<U256>>>,
    tree_depth: usize,
    last_synced_event_id: RwLock<WorldTreeEventId>,
}

impl TreeState {
    /// Create a new `TreeState` with an existing tree, depth, and sync cursor.
    pub fn new(
        tree: CascadingMerkleTree<PoseidonHasher, MmapVec<U256>>,
        tree_depth: usize,
        last_synced_event_id: WorldTreeEventId,
    ) -> Self {
        Self {
            inner: Arc::new(TreeStateInner {
                tree: RwLock::new(tree),
                tree_depth,
                last_synced_event_id: RwLock::new(last_synced_event_id),
            }),
        }
    }

    /// Create a new `TreeState` with an empty tree of the given depth.
    pub unsafe fn new_empty(tree_depth: usize, path: impl AsRef<Path>) -> eyre::Result<Self> {
        let storage = unsafe { MmapVec::create_from_path(path)? };
        let tree = MerkleTree::new(storage, tree_depth, &U256::ZERO);
        Ok(Self::new(tree, tree_depth, WorldTreeEventId::default()))
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
    pub async fn read(
        &self,
    ) -> RwLockReadGuard<'_, CascadingMerkleTree<PoseidonHasher, MmapVec<U256>>> {
        self.inner.tree.read().await
    }

    /// Acquire a write lock on the tree.
    pub async fn write(
        &self,
    ) -> RwLockWriteGuard<'_, CascadingMerkleTree<PoseidonHasher, MmapVec<U256>>> {
        self.inner.tree.write().await
    }

    /// Convenience method to get the current root.
    pub async fn root(&self) -> U256 {
        self.read().await.root()
    }

    /// Atomically read leaf value, inclusion proof, and root under a single
    /// read lock to guarantee consistency.
    pub async fn leaf_proof_and_root(
        &self,
        leaf_index: usize,
    ) -> (U256, InclusionProof<PoseidonHasher>, U256) {
        let tree = self.read().await;
        (
            tree.get_leaf(leaf_index),
            tree.proof(leaf_index),
            tree.root(),
        )
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
        set_arbitrary_leaf(&mut tree, leaf_index, value);
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
    pub async fn replace(&self, new_tree: MerkleTree) {
        let mut tree = self.write().await;
        *tree = new_tree;
    }

    /// Get the last synced event ID.
    pub async fn last_synced_event_id(&self) -> WorldTreeEventId {
        *self.inner.last_synced_event_id.read().await
    }

    /// Set the last synced event ID.
    pub async fn set_last_synced_event_id(&self, id: WorldTreeEventId) {
        *self.inner.last_synced_event_id.write().await = id;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_file() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("tree_state_test_{}.tmp", uuid::Uuid::new_v4()));
        path
    }

    #[tokio::test]
    async fn test_new_empty() -> eyre::Result<()> {
        let state = unsafe { TreeState::new_empty(6, tmp_file())? };
        assert_eq!(state.depth(), 6);
        assert_eq!(state.capacity(), 64);
        Ok(())
    }

    #[tokio::test]
    async fn test_set_leaf_at_index() -> eyre::Result<()> {
        let state = unsafe { TreeState::new_empty(6, tmp_file())? };
        let value = U256::from(42u64);

        state.set_leaf_at_index(1, value).await.unwrap();

        let tree = state.read().await;
        assert_eq!(tree.get_leaf(1), value);

        Ok(())
    }

    #[tokio::test]
    async fn test_set_leaf_out_of_range() -> eyre::Result<()> {
        let state = unsafe { TreeState::new_empty(6, tmp_file())? };
        let result = state.set_leaf_at_index(100, U256::from(1u64)).await;
        assert!(matches!(result, Err(TreeError::LeafIndexOutOfRange { .. })));

        Ok(())
    }

    #[tokio::test]
    async fn test_update_commitment() -> eyre::Result<()> {
        let state = unsafe { TreeState::new_empty(6, tmp_file())? };
        let commitment = U256::from(123u64);

        state
            .update_commitment(U256::from(5u64), commitment)
            .await
            .unwrap();

        let tree = state.read().await;
        assert_eq!(tree.get_leaf(5), commitment);

        Ok(())
    }

    #[tokio::test]
    async fn test_update_tree_with_zero_index() -> eyre::Result<()> {
        let state = unsafe { TreeState::new_empty(6, tmp_file())? };
        let result = state.update_commitment(U256::ZERO, U256::from(1u64)).await;
        assert!(matches!(result, Err(TreeError::ZeroLeafIndex)));

        Ok(())
    }

    #[tokio::test]
    async fn test_leaf_proof_and_root() -> eyre::Result<()> {
        let state = unsafe { TreeState::new_empty(6, tmp_file())? };
        let value = U256::from(42u64);
        state.set_leaf_at_index(3, value).await.unwrap();

        let (leaf, _proof, root) = state.leaf_proof_and_root(3).await;
        assert_eq!(leaf, value);
        assert_eq!(root, state.root().await);

        Ok(())
    }
}
