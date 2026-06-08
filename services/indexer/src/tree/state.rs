use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
};

use alloy::primitives::U256;
use semaphore_rs_hasher::Hasher;
use semaphore_rs_storage::MmapVec;
use semaphore_rs_trees::{cascading::CascadingMerkleTree, proof::InclusionProof};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::{MerkleTree, PoseidonHasher, TreeError, TreeResult};
use crate::{
    batch::{Batch, BatchRootCheck},
    db::WorldIdRegistryEventId,
    tree::cached_tree::set_arbitrary_leaf,
};

/// Thread-safe wrapper around the Merkle tree and its configuration.
#[derive(Clone, Debug)]
pub struct TreeState {
    inner: Arc<TreeStateInner>,
}

#[derive(Debug)]
struct TreeStateInner {
    tree: RwLock<CascadingMerkleTree<PoseidonHasher, MmapVec<U256>>>,
    tree_depth: usize,
    last_synced_event_id: RwLock<WorldIdRegistryEventId>,
    last_batch_id: RwLock<u64>,
}

impl TreeState {
    /// Create a new `TreeState` with an existing tree, depth, and sync cursor.
    pub fn new(
        tree: CascadingMerkleTree<PoseidonHasher, MmapVec<U256>>,
        tree_depth: usize,
        last_synced_event_id: WorldIdRegistryEventId,
    ) -> Self {
        Self::new_with_batch_id(tree, tree_depth, last_synced_event_id, 0)
    }

    /// Create a new `TreeState` with an existing tree, depth, event cursor, and batch cursor.
    pub fn new_with_batch_id(
        tree: CascadingMerkleTree<PoseidonHasher, MmapVec<U256>>,
        tree_depth: usize,
        last_synced_event_id: WorldIdRegistryEventId,
        last_batch_id: u64,
    ) -> Self {
        Self {
            inner: Arc::new(TreeStateInner {
                tree: RwLock::new(tree),
                tree_depth,
                last_synced_event_id: RwLock::new(last_synced_event_id),
                last_batch_id: RwLock::new(last_batch_id),
            }),
        }
    }

    /// Create a new `TreeState` with an empty tree of the given depth.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe because it performs memory-mapped file operations for the tree cache.
    /// The caller must ensure that the cache file is not concurrently accessed or modified
    /// by other processes while the tree is using it.
    pub unsafe fn new_empty(tree_depth: usize, path: impl AsRef<Path>) -> eyre::Result<Self> {
        let storage = unsafe { MmapVec::create_from_path(path)? };
        let tree = MerkleTree::new(storage, tree_depth, &U256::ZERO);
        Ok(Self::new(
            tree,
            tree_depth,
            WorldIdRegistryEventId::default(),
        ))
    }

    /// Returns the configured depth.
    pub fn depth(&self) -> usize {
        self.inner.tree_depth
    }

    /// Returns the tree capacity (2^depth).
    pub fn capacity(&self) -> usize {
        1usize << self.inner.tree_depth
    }

    /// Returns the number of inserted leaves in the tree.
    pub async fn num_leaves(&self) -> usize {
        self.inner.tree.read().await.num_leaves()
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

    /// Get the value of a single leaf.
    pub async fn get_leaf(&self, leaf_index: usize) -> U256 {
        self.read().await.get_leaf(leaf_index)
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
    pub async fn last_synced_event_id(&self) -> WorldIdRegistryEventId {
        *self.inner.last_synced_event_id.read().await
    }

    /// Set the last synced event ID.
    pub async fn set_last_synced_event_id(&self, id: WorldIdRegistryEventId) {
        *self.inner.last_synced_event_id.write().await = id;
    }

    /// Get the last processed sync batch id.
    pub async fn last_batch_id(&self) -> u64 {
        *self.inner.last_batch_id.read().await
    }

    /// Set the last processed sync batch id.
    pub async fn set_last_batch_id(&self, id: u64) {
        *self.inner.last_batch_id.write().await = id;
    }

    /// Simulate a batch non-mutatingly and compare against its expected root.
    pub async fn simulate_batch(&self, batch: &Batch) -> TreeResult<BatchRootCheck> {
        let simulated = self.simulate_root(&batch.simulation_changes()).await?;
        if simulated == batch.header.expected_root {
            Ok(BatchRootCheck::Match)
        } else {
            Ok(BatchRootCheck::Mismatch { simulated })
        }
    }

    /// Compute a simulated Merkle root after applying `changes` without
    /// modifying the real tree.
    ///
    /// `changes` is a slice of `(leaf_index, new_value)` pairs.
    ///
    /// The algorithm reuses internal nodes from the real tree wherever the
    /// subtree under that node contains no dirty leaf, so only O(dirty_leaves
    /// × tree_depth) hash operations and `get_node` calls are needed — no
    /// full tree clone.
    pub async fn simulate_root(&self, changes: &[(usize, U256)]) -> TreeResult<U256> {
        if changes.is_empty() {
            return Ok(self.root().await);
        }

        let tree = self.read().await;
        let depth = tree.depth();

        let capacity = 1usize << depth;

        // Validate leaf indices up-front.
        for &(leaf_index, _) in changes {
            if leaf_index >= capacity {
                return Err(TreeError::LeafIndexOutOfRange {
                    leaf_index,
                    tree_depth: depth,
                });
            }
        }

        // We compute the root bottom-up using a node cache.
        //
        // Key: (level_from_leaves, offset)
        //   level_from_leaves = 0  → leaf level
        //   level_from_leaves = depth → root
        //
        // We only populate the cache for nodes that are on a dirty path; all
        // other nodes are read directly from the real tree via get_node().
        let mut cache: HashMap<(usize, usize), U256> = HashMap::new();

        // Seed the cache with changed leaves (level 0). Duplicate indices are
        // processed in order so the last entry wins, matching collect() behaviour.
        for &(leaf_index, new_value) in changes {
            cache.insert((0, leaf_index), new_value);
        }

        // Walk up from level 0 (leaves) to level `depth` (root).
        // At each level, find which parent nodes need recomputation: those
        // whose subtree contains at least one dirty leaf.
        for level in 0..depth {
            // Collect the set of parent offsets that need updating.
            let dirty_parents: HashSet<usize> = cache
                .keys()
                .filter(|(l, _)| *l == level)
                .map(|(_, offset)| offset >> 1)
                .collect();

            for parent_offset in dirty_parents {
                let childs_left = parent_offset * 2;
                let childs_right = childs_left + 1;

                // `get_node` uses depth-from-root convention:
                //   depth_from_root = depth - level_from_leaves
                let node_depth_from_root = depth - level;

                let left = cache
                    .get(&(level, childs_left))
                    .copied()
                    .unwrap_or_else(|| tree.get_node(node_depth_from_root, childs_left));

                let right = cache
                    .get(&(level, childs_right))
                    .copied()
                    .unwrap_or_else(|| tree.get_node(node_depth_from_root, childs_right));

                let parent = PoseidonHasher::hash_node(&left, &right);
                cache.insert((level + 1, parent_offset), parent);
            }
        }

        cache
            .get(&(depth, 0))
            .copied()
            .ok_or(TreeError::SimulationMissingRoot)
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

    fn make_tree(depth: usize) -> TreeState {
        unsafe { TreeState::new_empty(depth, tmp_file()).unwrap() }
    }

    #[tokio::test]
    async fn simulate_single_leaf_no_change() {
        let state = make_tree(4);
        let root_before = state.root().await;
        let simulated = state.simulate_root(&[]).await.unwrap();
        assert_eq!(root_before, simulated);
    }

    #[tokio::test]
    async fn simulate_single_leaf_matches_actual_set() {
        let state = make_tree(4);

        let new_val = U256::from(42u64);
        let simulated = state.simulate_root(&[(0, new_val)]).await.unwrap();

        state.set_leaf_at_index(0, new_val).await.unwrap();
        let actual_root = state.root().await;

        assert_eq!(simulated, actual_root);
    }

    #[tokio::test]
    async fn simulate_multiple_independent_leaves() {
        let state = make_tree(4);

        let val_a = U256::from(10u64);
        let val_b = U256::from(20u64);

        let simulated = state
            .simulate_root(&[(0, val_a), (1, val_b)])
            .await
            .unwrap();

        state.set_leaf_at_index(0, val_a).await.unwrap();
        state.set_leaf_at_index(1, val_b).await.unwrap();
        let actual_root = state.root().await;

        assert_eq!(simulated, actual_root);
    }

    #[tokio::test]
    async fn simulate_does_not_mutate_tree() {
        let state = make_tree(4);
        let root_before = state.root().await;

        state
            .simulate_root(&[(0, U256::from(99u64))])
            .await
            .unwrap();

        assert_eq!(state.root().await, root_before);
    }

    #[tokio::test]
    async fn simulate_out_of_range_leaf_errors() {
        let state = make_tree(2);
        let result = state.simulate_root(&[(4, U256::from(1u64))]).await;
        assert!(matches!(result, Err(TreeError::LeafIndexOutOfRange { .. })));
    }

    #[tokio::test]
    async fn simulate_on_non_empty_tree() {
        let state = make_tree(4);
        state.set_leaf_at_index(0, U256::from(10u64)).await.unwrap();
        state.set_leaf_at_index(3, U256::from(30u64)).await.unwrap();

        let new_val = U256::from(99u64);
        let simulated = state.simulate_root(&[(0, new_val)]).await.unwrap();

        state.set_leaf_at_index(0, new_val).await.unwrap();
        assert_eq!(simulated, state.root().await);
    }

    #[tokio::test]
    async fn simulate_duplicate_leaf_in_changes_last_wins() {
        let state = make_tree(4);

        let first_val = U256::from(11u64);
        let last_val = U256::from(22u64);

        let changes = [(0, first_val), (0, last_val)];
        let simulated = state.simulate_root(&changes).await.unwrap();

        state.set_leaf_at_index(0, last_val).await.unwrap();
        assert_eq!(simulated, state.root().await);
    }

    #[tokio::test]
    async fn simulate_last_leaf_in_tree() {
        let state = make_tree(3);
        let last_index = (1usize << 3) - 1;

        let val = U256::from(77u64);
        let simulated = state.simulate_root(&[(last_index, val)]).await.unwrap();

        state.set_leaf_at_index(last_index, val).await.unwrap();
        assert_eq!(simulated, state.root().await);
    }

    #[tokio::test]
    async fn simulate_leaves_in_different_subtrees() {
        let state = make_tree(3);

        let val_a = U256::from(1u64);
        let val_b = U256::from(2u64);
        let simulated = state
            .simulate_root(&[(0, val_a), (7, val_b)])
            .await
            .unwrap();

        state.set_leaf_at_index(0, val_a).await.unwrap();
        state.set_leaf_at_index(7, val_b).await.unwrap();
        assert_eq!(simulated, state.root().await);
    }

    #[tokio::test]
    async fn simulate_batch_matches_actual_set() {
        let state = make_tree(4);
        let new_val = U256::from(42u64);
        state.set_leaf_at_index(0, new_val).await.unwrap();
        let batch = crate::batch::Batch {
            header: crate::batch::BatchHeader {
                kind: crate::batch::BatchKind::Forward,
                expected_root: state.root().await,
                next_leaf_index: 2,
                origin: crate::batch::BatchOrigin {
                    block_number: 1,
                    log_index: 0,
                    onchain_timestamp: 1,
                },
            },
            changes: vec![crate::batch::LeafChange::new(0, new_val)],
        };

        match state.simulate_batch(&batch).await.unwrap() {
            crate::batch::BatchRootCheck::Match => {}
            crate::batch::BatchRootCheck::Mismatch { .. } => {
                panic!("expected batch simulation to match");
            }
        }
    }

    #[tokio::test]
    async fn simulate_batch_reports_mismatch() {
        let state = make_tree(4);
        let batch = crate::batch::Batch {
            header: crate::batch::BatchHeader {
                kind: crate::batch::BatchKind::Forward,
                expected_root: U256::from(999),
                next_leaf_index: 2,
                origin: crate::batch::BatchOrigin {
                    block_number: 1,
                    log_index: 0,
                    onchain_timestamp: 1,
                },
            },
            changes: vec![crate::batch::LeafChange::new(0, U256::from(42))],
        };

        match state.simulate_batch(&batch).await.unwrap() {
            crate::batch::BatchRootCheck::Match => panic!("expected mismatch"),
            crate::batch::BatchRootCheck::Mismatch { simulated } => {
                assert_ne!(simulated, batch.header.expected_root);
            }
        }
    }
}
