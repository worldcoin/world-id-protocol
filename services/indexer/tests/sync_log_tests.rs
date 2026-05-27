mod helpers;

use std::{fs, path::PathBuf};

use alloy::primitives::U256;
use helpers::db_helpers::create_unique_test_db;
use world_id_indexer::tree::{
    TreeError, TreeState,
    cached_tree::{init_tree, sync_from_db},
};

fn temp_cache_path() -> PathBuf {
    std::env::temp_dir().join(format!("sync_log_test_{}.mmap", uuid::Uuid::new_v4()))
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_file(path);
}

async fn root_for_leaves(tree_depth: usize, leaves: &[(usize, U256)]) -> U256 {
    let path = temp_cache_path();
    let tree = unsafe { TreeState::new_empty(tree_depth, &path).unwrap() };
    for &(leaf_index, value) in leaves {
        tree.set_leaf_at_index(leaf_index, value).await.unwrap();
    }
    let root = tree.root().await;
    cleanup(&path);
    root
}

#[tokio::test]
async fn test_bootstrap_uses_latest_sync_log_row_per_leaf() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;
    let cache_path = temp_cache_path();

    db.sync_log()
        .insert_leaf_update(1, U256::from(100))
        .await
        .unwrap();
    db.sync_log()
        .insert_leaf_update(1, U256::from(400))
        .await
        .unwrap();
    db.sync_log().insert_rollback_leaf(2, None).await.unwrap();

    let expected_root = root_for_leaves(6, &[(1, U256::from(400)), (2, U256::ZERO)]).await;
    let checkpoint_id = db
        .sync_log()
        .insert_root_verification(expected_root, 3)
        .await
        .unwrap();

    let tree = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(tree.root().await, expected_root);
    assert_eq!(tree.get_leaf(1).await, U256::from(400));
    assert_eq!(tree.get_leaf(2).await, U256::ZERO);
    assert_eq!(tree.last_sync_id().await, checkpoint_id);

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_incremental_sync_applies_rows_at_checkpoint() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;
    let cache_path = temp_cache_path();

    let tree = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };

    db.sync_log()
        .insert_leaf_update(1, U256::from(100))
        .await
        .unwrap();
    db.sync_log()
        .insert_leaf_update(1, U256::from(400))
        .await
        .unwrap();

    let expected_root = root_for_leaves(6, &[(1, U256::from(400))]).await;
    let checkpoint_id = db
        .sync_log()
        .insert_root_verification(expected_root, 2)
        .await
        .unwrap();

    let processed = sync_from_db(db, &tree).await.unwrap();
    assert_eq!(processed, 3);
    assert_eq!(tree.root().await, expected_root);
    assert_eq!(tree.get_leaf(1).await, U256::from(400));
    assert_eq!(tree.last_sync_id().await, checkpoint_id);

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_incremental_sync_detects_root_mismatch() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;
    let cache_path = temp_cache_path();

    let tree = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };

    db.sync_log()
        .insert_leaf_update(1, U256::from(100))
        .await
        .unwrap();
    db.sync_log()
        .insert_root_verification(U256::from(999), 2)
        .await
        .unwrap();

    let result = sync_from_db(db, &tree).await;
    assert!(matches!(result, Err(TreeError::RootMismatch { .. })));

    cleanup(&cache_path);
}
