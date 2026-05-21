use std::{collections::HashMap, sync::Arc};

use alloy::primitives::U256;
use semaphore_rs_hasher::Hasher;
use semaphore_rs_trees::proof::InclusionProof;

use super::{PoseidonHasher, TreeError, TreeResult, TreeState};
use crate::db::WorldIdRegistryEventId;

/// Wraps [`TreeState`] with a copy-free root simulation capability for batch commits.
#[derive(Clone, Debug)]
pub struct VersionedTreeState {
    inner: Arc<TreeState>,
}

impl VersionedTreeState {
    pub fn new(tree: TreeState) -> Self {
        Self {
            inner: Arc::new(tree),
        }
    }

    /// Delegate: current Merkle root.
    pub async fn root(&self) -> U256 {
        self.inner.root().await
    }

    /// Delegate: tree depth.
    pub fn depth(&self) -> usize {
        self.inner.depth()
    }

    /// Delegate: atomically read leaf, proof, and root.
    pub async fn leaf_proof_and_root(
        &self,
        leaf_index: usize,
    ) -> (U256, InclusionProof<PoseidonHasher>, U256) {
        self.inner.leaf_proof_and_root(leaf_index).await
    }

    /// Set a leaf value.
    pub async fn set_leaf_at_index(
        &self,
        leaf_index: usize,
        value: U256,
        _event_id: WorldIdRegistryEventId,
    ) -> TreeResult<()> {
        self.inner.set_leaf_at_index(leaf_index, value).await
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

        let tree = self.inner.read().await;
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
            let dirty_parents: std::collections::HashSet<usize> = cache
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

    /// Delegate: last synced event ID.
    pub async fn last_synced_event_id(&self) -> WorldIdRegistryEventId {
        self.inner.last_synced_event_id().await
    }

    /// Delegate: set last synced event ID.
    pub async fn set_last_synced_event_id(&self, id: WorldIdRegistryEventId) {
        self.inner.set_last_synced_event_id(id).await
    }

    /// Expose the inner [`TreeState`] for operations not covered here
    /// (e.g. `replace`, `update_commitment`).
    pub fn tree_state(&self) -> &TreeState {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::WorldIdRegistryEventId;

    fn tmp_file() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("versioned_tree_test_{}.tmp", uuid::Uuid::new_v4()));
        p
    }

    fn event_id(block: u64) -> WorldIdRegistryEventId {
        WorldIdRegistryEventId {
            block_number: block,
            log_index: 0,
        }
    }

    fn make_versioned(depth: usize) -> VersionedTreeState {
        let state = unsafe { TreeState::new_empty(depth, tmp_file()).unwrap() };
        VersionedTreeState::new(state)
    }

    #[tokio::test]
    async fn simulate_single_leaf_no_change() {
        let v = make_versioned(4);
        let root_before = v.root().await;
        let simulated = v.simulate_root(&[]).await.unwrap();
        assert_eq!(root_before, simulated);
    }

    #[tokio::test]
    async fn simulate_single_leaf_matches_actual_set() {
        let v = make_versioned(4);

        let new_val = U256::from(42u64);
        let simulated = v.simulate_root(&[(0, new_val)]).await.unwrap();

        v.set_leaf_at_index(0, new_val, event_id(1)).await.unwrap();
        let actual_root = v.root().await;

        assert_eq!(simulated, actual_root);
    }

    #[tokio::test]
    async fn simulate_multiple_independent_leaves() {
        let v = make_versioned(4);

        let val_a = U256::from(10u64);
        let val_b = U256::from(20u64);

        let simulated = v.simulate_root(&[(0, val_a), (1, val_b)]).await.unwrap();

        v.set_leaf_at_index(0, val_a, event_id(1)).await.unwrap();
        v.set_leaf_at_index(1, val_b, event_id(2)).await.unwrap();
        let actual_root = v.root().await;

        assert_eq!(simulated, actual_root);
    }

    #[tokio::test]
    async fn simulate_does_not_mutate_tree() {
        let v = make_versioned(4);
        let root_before = v.root().await;

        v.simulate_root(&[(0, U256::from(99u64))]).await.unwrap();

        assert_eq!(v.root().await, root_before);
    }

    #[tokio::test]
    async fn simulate_out_of_range_leaf_errors() {
        let v = make_versioned(2);
        let result = v.simulate_root(&[(4, U256::from(1u64))]).await;
        assert!(matches!(result, Err(TreeError::LeafIndexOutOfRange { .. })));
    }

    #[tokio::test]
    async fn simulate_on_non_empty_tree() {
        let v = make_versioned(4);
        v.set_leaf_at_index(0, U256::from(10u64), event_id(1))
            .await
            .unwrap();
        v.set_leaf_at_index(3, U256::from(30u64), event_id(2))
            .await
            .unwrap();

        let new_val = U256::from(99u64);
        let simulated = v.simulate_root(&[(0, new_val)]).await.unwrap();

        v.set_leaf_at_index(0, new_val, event_id(3)).await.unwrap();
        assert_eq!(simulated, v.root().await);
    }

    #[tokio::test]
    async fn simulate_duplicate_leaf_in_changes_last_wins() {
        let v = make_versioned(4);

        let first_val = U256::from(11u64);
        let last_val = U256::from(22u64);

        let changes = [(0, first_val), (0, last_val)];
        let simulated = v.simulate_root(&changes).await.unwrap();

        v.set_leaf_at_index(0, last_val, event_id(1)).await.unwrap();
        assert_eq!(simulated, v.root().await);
    }

    #[tokio::test]
    async fn simulate_last_leaf_in_tree() {
        let v = make_versioned(3);
        let last_index = (1usize << 3) - 1;

        let val = U256::from(77u64);
        let simulated = v.simulate_root(&[(last_index, val)]).await.unwrap();

        v.set_leaf_at_index(last_index, val, event_id(1))
            .await
            .unwrap();
        assert_eq!(simulated, v.root().await);
    }

    #[tokio::test]
    async fn simulate_leaves_in_different_subtrees() {
        let v = make_versioned(3);

        let val_a = U256::from(1u64);
        let val_b = U256::from(2u64);
        let simulated = v.simulate_root(&[(0, val_a), (7, val_b)]).await.unwrap();

        v.set_leaf_at_index(0, val_a, event_id(1)).await.unwrap();
        v.set_leaf_at_index(7, val_b, event_id(2)).await.unwrap();
        assert_eq!(simulated, v.root().await);
    }
}
