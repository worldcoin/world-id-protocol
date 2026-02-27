use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use alloy::primitives::U256;
use semaphore_rs_hasher::Hasher;
use semaphore_rs_trees::proof::InclusionProof;
use tokio::sync::RwLock;

use super::{PoseidonHasher, TreeError, TreeResult, TreeState};
use crate::db::WorldIdRegistryEventId;

/// A single recorded change to a leaf.
#[derive(Debug)]
struct LeafVersion {
    event_id: WorldIdRegistryEventId,
    old_value: U256,
}

/// Per-leaf change log, oldest entry first.
type LeafLog = VecDeque<LeafVersion>;

/// Wraps [`TreeState`] with a bounded per-leaf change history and a
/// copy-free simulation capability.
///
/// History is retained for at most `max_block_age` blocks.
/// At 2 s/block:
///   -  900 blocks ≈ 30 minutes
///   - 5 400 blocks ≈  3 hours
///   - 10 800 blocks ≈  6 hours
#[derive(Clone, Debug)]
pub struct VersionedTreeState {
    inner: Arc<VersionedTreeStateInner>,
}

#[derive(Debug)]
struct VersionedTreeStateInner {
    tree: TreeState,
    history: RwLock<HashMap<usize, LeafLog>>,
    max_block_age: u64,
}

impl VersionedTreeState {
    pub fn new(tree: TreeState, max_block_age: u64) -> Self {
        Self {
            inner: Arc::new(VersionedTreeStateInner {
                tree,
                history: RwLock::new(HashMap::new()),
                max_block_age,
            }),
        }
    }

    /// Delegate: current Merkle root.
    pub async fn root(&self) -> U256 {
        self.inner.tree.root().await
    }

    /// Delegate: tree depth.
    pub fn depth(&self) -> usize {
        self.inner.tree.depth()
    }

    /// Delegate: atomically read leaf, proof, and root.
    pub async fn leaf_proof_and_root(
        &self,
        leaf_index: usize,
    ) -> (U256, InclusionProof<PoseidonHasher>, U256) {
        self.inner.tree.leaf_proof_and_root(leaf_index).await
    }

    /// Set a leaf, recording the change in history.
    ///
    /// `event_id` is the `(block_number, log_index)` of the event that caused
    /// this change; it is used as the version key for pruning.
    pub async fn set_leaf_at_index(
        &self,
        leaf_index: usize,
        value: U256,
        event_id: WorldIdRegistryEventId,
    ) -> TreeResult<()> {
        let old_value = self.inner.tree.get_leaf(leaf_index).await;

        self.inner.tree.set_leaf_at_index(leaf_index, value).await?;

        let mut history = self.inner.history.write().await;
        history
            .entry(leaf_index)
            .or_default()
            .push_back(LeafVersion {
                event_id,
                old_value,
            });

        Ok(())
    }

    /// Roll back the in-memory tree to the state it was in at `target`.
    ///
    /// For every leaf that was modified after `target`, the leaf is restored
    /// to the value it held at `target` by replaying the recorded history in
    /// reverse. History entries after `target` are discarded.
    ///
    /// Returns an error if the history for any affected leaf has already been
    /// pruned past the rollback point.
    pub async fn rollback_to(&self, target: WorldIdRegistryEventId) -> TreeResult<()> {
        let mut history = self.inner.history.write().await;

        for (leaf_index, log) in history.iter_mut() {
            // Find and discard all versions strictly after target, restoring
            // the leaf to what it was before each such version was applied.
            while log.back().is_some_and(|v| v.event_id > target) {
                let version = log.pop_back().expect("checked above");
                self.inner
                    .tree
                    .set_leaf_at_index(*leaf_index, version.old_value)
                    .await?;
            }
        }

        // Drop empty logs.
        history.retain(|_, log| !log.is_empty());

        Ok(())
    }

    /// Discard all history entries whose `block_number` is older than
    /// `current_block - max_block_age`.
    pub async fn prune(&self, current_block: u64) {
        let cutoff = current_block.saturating_sub(self.inner.max_block_age);
        let mut history = self.inner.history.write().await;
        history.retain(|_, log| {
            // Drop entries older than the cutoff from the front.
            while log
                .front()
                .is_some_and(|v| v.event_id.block_number < cutoff)
            {
                log.pop_front();
            }
            !log.is_empty()
        });
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

        // Build dirty-leaf map: leaf_index → new_value.
        let dirty: HashMap<usize, U256> = changes.iter().copied().collect();

        let tree = self.inner.tree.read().await;
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

        // Seed the cache with dirty leaves (level 0).
        for (&leaf_index, &new_value) in &dirty {
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
                let left_offset = parent_offset * 2;
                let right_offset = left_offset + 1;

                // `get_node` uses depth-from-root convention:
                //   depth_from_root = depth - level_from_leaves
                let node_depth_from_root = depth - level;

                let left = cache
                    .get(&(level, left_offset))
                    .copied()
                    .unwrap_or_else(|| tree.get_node(node_depth_from_root, left_offset));

                let right = cache
                    .get(&(level, right_offset))
                    .copied()
                    .unwrap_or_else(|| tree.get_node(node_depth_from_root, right_offset));

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
        self.inner.tree.last_synced_event_id().await
    }

    /// Delegate: set last synced event ID.
    pub async fn set_last_synced_event_id(&self, id: WorldIdRegistryEventId) {
        self.inner.tree.set_last_synced_event_id(id).await
    }

    /// Expose the inner [`TreeState`] for operations not covered here
    /// (e.g. `replace`, `update_commitment`).
    pub fn tree_state(&self) -> &TreeState {
        &self.inner.tree
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
        VersionedTreeState::new(state, 1000)
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

        // Simulate setting leaf 0 to value 42.
        let new_val = U256::from(42u64);
        let simulated = v.simulate_root(&[(0, new_val)]).await.unwrap();

        // Actually apply the change and check we get the same root.
        v.set_leaf_at_index(0, new_val, event_id(1)).await.unwrap();
        let actual_root = v.root().await;

        assert_eq!(simulated, actual_root);
    }

    #[tokio::test]
    async fn simulate_multiple_independent_leaves() {
        let v = make_versioned(4);

        let val_a = U256::from(10u64);
        let val_b = U256::from(20u64);

        // Leaves 0 and 1 share a parent — this exercises the dirty-path merge.
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
    async fn prune_removes_old_entries() {
        let v = make_versioned(4);

        v.set_leaf_at_index(0, U256::from(1u64), event_id(100))
            .await
            .unwrap();
        v.set_leaf_at_index(1, U256::from(2u64), event_id(200))
            .await
            .unwrap();

        // Prune at block 1150: entries with block_number < 1150 - 1000 = 150
        // → leaf 0 (block 100) should be removed, leaf 1 (block 200) kept.
        v.prune(1150).await;

        let history = v.inner.history.read().await;
        assert!(
            !history.contains_key(&0),
            "leaf 0 history should have been pruned"
        );
        assert!(
            history.contains_key(&1),
            "leaf 1 history should be retained"
        );
    }

    #[tokio::test]
    async fn simulate_out_of_range_leaf_errors() {
        let v = make_versioned(2); // capacity = 4 leaves (2^2)
        let result = v.simulate_root(&[(4, U256::from(1u64))]).await;
        assert!(matches!(result, Err(TreeError::LeafIndexOutOfRange { .. })));
    }

    #[tokio::test]
    async fn rollback_single_leaf() {
        let v = make_versioned(4);
        let root_initial = v.root().await;

        v.set_leaf_at_index(0, U256::from(42u64), event_id(10))
            .await
            .unwrap();
        assert_ne!(v.root().await, root_initial);

        // Roll back to before event at block 10 — use a target before it.
        v.rollback_to(event_id(9)).await.unwrap();
        assert_eq!(v.root().await, root_initial);
    }

    #[tokio::test]
    async fn rollback_partial() {
        let v = make_versioned(4);

        v.set_leaf_at_index(0, U256::from(1u64), event_id(10))
            .await
            .unwrap();
        let root_after_first = v.root().await;

        v.set_leaf_at_index(0, U256::from(2u64), event_id(20))
            .await
            .unwrap();
        assert_ne!(v.root().await, root_after_first);

        // Roll back to event 10 (inclusive) — the first change stays.
        v.rollback_to(event_id(10)).await.unwrap();
        assert_eq!(v.root().await, root_after_first);
    }

    #[tokio::test]
    async fn rollback_multiple_leaves() {
        let v = make_versioned(4);
        let root_initial = v.root().await;

        v.set_leaf_at_index(0, U256::from(1u64), event_id(10))
            .await
            .unwrap();
        v.set_leaf_at_index(1, U256::from(2u64), event_id(11))
            .await
            .unwrap();

        v.rollback_to(event_id(9)).await.unwrap();
        assert_eq!(v.root().await, root_initial);
    }

    #[tokio::test]
    async fn rollback_clears_history_after_target() {
        let v = make_versioned(4);

        v.set_leaf_at_index(0, U256::from(1u64), event_id(10))
            .await
            .unwrap();
        v.set_leaf_at_index(0, U256::from(2u64), event_id(20))
            .await
            .unwrap();

        v.rollback_to(event_id(10)).await.unwrap();

        let history = v.inner.history.read().await;
        let log = history.get(&0).expect("leaf 0 history should remain");
        assert_eq!(log.len(), 1, "only the entry at block 10 should remain");
        assert_eq!(log[0].event_id, event_id(10));
    }

    // --- simulate_root edge cases ---

    #[tokio::test]
    async fn simulate_on_non_empty_tree() {
        // Set up a tree with existing state, then simulate a change on top.
        let v = make_versioned(4);
        v.set_leaf_at_index(0, U256::from(10u64), event_id(1))
            .await
            .unwrap();
        v.set_leaf_at_index(3, U256::from(30u64), event_id(2))
            .await
            .unwrap();

        let new_val = U256::from(99u64);
        let simulated = v.simulate_root(&[(0, new_val)]).await.unwrap();

        // Apply for real and compare.
        v.set_leaf_at_index(0, new_val, event_id(3)).await.unwrap();
        assert_eq!(simulated, v.root().await);
    }

    #[tokio::test]
    async fn simulate_duplicate_leaf_in_changes_last_wins() {
        // If the same leaf appears twice in changes, the last value should win
        // (HashMap deduplication keeps the last inserted value for a given key
        // since iter() is used to build the map).
        let v = make_versioned(4);

        let first_val = U256::from(11u64);
        let last_val = U256::from(22u64);

        // Build changes with the same index twice; slice order determines which
        // survives into the HashMap (last occurrence via collected iterator).
        let changes = [(0, first_val), (0, last_val)];
        let simulated = v.simulate_root(&changes).await.unwrap();

        v.set_leaf_at_index(0, last_val, event_id(1)).await.unwrap();
        assert_eq!(simulated, v.root().await);
    }

    #[tokio::test]
    async fn simulate_last_leaf_in_tree() {
        // Exercises the right boundary: last valid leaf index (capacity - 1).
        let v = make_versioned(3); // capacity = 8
        let last_index = (1usize << 3) - 1; // 7

        let val = U256::from(77u64);
        let simulated = v.simulate_root(&[(last_index, val)]).await.unwrap();

        v.set_leaf_at_index(last_index, val, event_id(1))
            .await
            .unwrap();
        assert_eq!(simulated, v.root().await);
    }

    #[tokio::test]
    async fn simulate_leaves_in_different_subtrees() {
        // Leaves 0 and 7 in a depth-3 tree (capacity 8) are in opposite halves
        // of the tree. Their paths share only the root node, so all intermediate
        // nodes on each path are read from the real tree.
        let v = make_versioned(3);

        let val_a = U256::from(1u64);
        let val_b = U256::from(2u64);
        let simulated = v.simulate_root(&[(0, val_a), (7, val_b)]).await.unwrap();

        v.set_leaf_at_index(0, val_a, event_id(1)).await.unwrap();
        v.set_leaf_at_index(7, val_b, event_id(2)).await.unwrap();
        assert_eq!(simulated, v.root().await);
    }

    // --- rollback edge cases ---

    #[tokio::test]
    async fn rollback_to_exact_last_event_is_noop() {
        // Rolling back to the exact event_id of the last change should leave
        // the tree unchanged (the condition is strictly-after, not >=).
        let v = make_versioned(4);
        let val = U256::from(55u64);
        v.set_leaf_at_index(0, val, event_id(10)).await.unwrap();
        let root_after = v.root().await;

        v.rollback_to(event_id(10)).await.unwrap();

        assert_eq!(v.root().await, root_after);
        // Leaf value must still be val.
        assert_eq!(v.inner.tree.get_leaf(0).await, val);
    }

    #[tokio::test]
    async fn rollback_empty_history_is_noop() {
        let v = make_versioned(4);
        let root = v.root().await;

        v.rollback_to(event_id(0)).await.unwrap();

        assert_eq!(v.root().await, root);
    }

    #[tokio::test]
    async fn rollback_restores_correct_leaf_value() {
        // Verify the actual leaf value, not just the root.
        let v = make_versioned(4);
        let original_val = U256::from(1u64);
        let updated_val = U256::from(2u64);

        v.set_leaf_at_index(5, original_val, event_id(10))
            .await
            .unwrap();
        v.set_leaf_at_index(5, updated_val, event_id(20))
            .await
            .unwrap();

        assert_eq!(v.inner.tree.get_leaf(5).await, updated_val);

        v.rollback_to(event_id(10)).await.unwrap();

        assert_eq!(v.inner.tree.get_leaf(5).await, original_val);
    }

    #[tokio::test]
    async fn rollback_respects_log_index_ordering() {
        // Two events in the same block, different log indices.
        // Rolling back to (block=5, log=0) should undo (block=5, log=1).
        let v = make_versioned(4);

        let val_a = U256::from(1u64);
        let val_b = U256::from(2u64);

        let eid_a = WorldIdRegistryEventId {
            block_number: 5,
            log_index: 0,
        };
        let eid_b = WorldIdRegistryEventId {
            block_number: 5,
            log_index: 1,
        };

        v.set_leaf_at_index(0, val_a, eid_a).await.unwrap();
        let root_after_a = v.root().await;

        v.set_leaf_at_index(0, val_b, eid_b).await.unwrap();
        assert_ne!(v.root().await, root_after_a);

        v.rollback_to(eid_a).await.unwrap();
        assert_eq!(v.root().await, root_after_a);
        assert_eq!(v.inner.tree.get_leaf(0).await, val_a);
    }

    #[tokio::test]
    async fn rollback_past_history_restores_zero() {
        // Rollback to before the very first change brings the leaf back to zero
        // (the empty-tree value), and history for that leaf is removed.
        let v = make_versioned(4);
        let root_empty = v.root().await;

        v.set_leaf_at_index(2, U256::from(7u64), event_id(5))
            .await
            .unwrap();

        v.rollback_to(event_id(4)).await.unwrap();

        assert_eq!(v.root().await, root_empty);
        assert_eq!(v.inner.tree.get_leaf(2).await, U256::ZERO);

        let history = v.inner.history.read().await;
        assert!(!history.contains_key(&2), "history entry should be removed");
    }

    // --- prune edge cases ---

    #[tokio::test]
    async fn prune_no_op_when_current_block_less_than_max_block_age() {
        // current_block (5) < max_block_age (1000): cutoff = 0, nothing removed.
        let v = make_versioned(4);
        v.set_leaf_at_index(0, U256::from(1u64), event_id(3))
            .await
            .unwrap();

        v.prune(5).await;

        let history = v.inner.history.read().await;
        assert!(history.contains_key(&0), "entry should not be pruned");
    }

    #[tokio::test]
    async fn prune_partial_leaf_log() {
        // A leaf has two history entries. Only the older one should be pruned.
        let v = make_versioned(4);

        v.set_leaf_at_index(0, U256::from(1u64), event_id(100))
            .await
            .unwrap();
        v.set_leaf_at_index(0, U256::from(2u64), event_id(500))
            .await
            .unwrap();

        // Prune at block 1050: cutoff = 1050 - 1000 = 50.
        // block 100 >= 50 → NOT removed. Both entries stay.
        v.prune(1050).await;
        {
            let history = v.inner.history.read().await;
            assert_eq!(history[&0].len(), 2, "both entries should remain");
        }

        // Prune at block 1150: cutoff = 150.
        // block 100 < 150 → removed; block 500 >= 150 → kept.
        v.prune(1150).await;
        {
            let history = v.inner.history.read().await;
            assert_eq!(history[&0].len(), 1, "only the newer entry should remain");
            assert_eq!(history[&0][0].event_id, event_id(500));
        }
    }

    #[tokio::test]
    async fn prune_does_not_modify_tree() {
        // Pruning history must never change leaf values in the tree.
        let v = make_versioned(4);
        let val = U256::from(42u64);
        v.set_leaf_at_index(0, val, event_id(10)).await.unwrap();
        let root_before = v.root().await;

        v.prune(10_000).await; // prune everything

        assert_eq!(v.root().await, root_before);
        assert_eq!(v.inner.tree.get_leaf(0).await, val);
    }
}
