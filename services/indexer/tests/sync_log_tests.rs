mod helpers;

use std::{fs, path::PathBuf};

use alloy::primitives::U256;
use helpers::db_helpers::{create_unique_test_db, seed_batch, seed_forward_batch, test_batch_origin};
use world_id_indexer::{
    batch::BatchKind,
    tree::{
        TreeState,
        cache_metadata::{
            CacheStatus, metadata_path, read_metadata, write_clean_metadata, write_dirty_metadata,
        },
        cached_tree::{init_tree, sync_from_db},
    },
};

fn temp_cache_path() -> PathBuf {
    std::env::temp_dir().join(format!("sync_log_test_{}.mmap", uuid::Uuid::new_v4()))
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(metadata_path(path));
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
async fn test_bootstrap_uses_latest_sync_batch_row_per_leaf() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;
    let cache_path = temp_cache_path();

    let expected_root = root_for_leaves(6, &[(1, U256::from(400)), (2, U256::ZERO)]).await;
    let checkpoint_id = seed_batch(
        db,
        BatchKind::Forward,
        expected_root,
        3,
        test_batch_origin(100, 0),
        &[
            (1, Some(U256::from(100))),
            (1, Some(U256::from(400))),
            (2, None),
        ],
    )
    .await
    .unwrap();

    let tree = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(tree.root().await, expected_root);
    assert_eq!(tree.get_leaf(1).await, U256::from(400));
    assert_eq!(tree.get_leaf(2).await, U256::ZERO);
    assert_eq!(tree.last_batch_id().await, checkpoint_id);
    assert!(metadata_path(&cache_path).exists());

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_incremental_sync_applies_batches_at_checkpoint() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;
    let cache_path = temp_cache_path();

    let tree = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };

    let expected_root = root_for_leaves(6, &[(1, U256::from(400))]).await;
    let checkpoint_id = seed_forward_batch(
        db,
        expected_root,
        2,
        &[(1, Some(U256::from(100))), (1, Some(U256::from(400)))],
    )
    .await
    .unwrap();

    let processed = sync_from_db(db, &tree).await.unwrap();
    assert_eq!(processed, 2);
    assert_eq!(tree.root().await, expected_root);
    assert_eq!(tree.get_leaf(1).await, U256::from(400));
    assert_eq!(tree.last_batch_id().await, checkpoint_id);

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_incremental_sync_detects_root_mismatch() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;
    let cache_path = temp_cache_path();

    let tree = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };

    seed_forward_batch(
        db,
        U256::from(999),
        2,
        &[(1, Some(U256::from(100)))],
    )
    .await
    .unwrap();

    let result = sync_from_db(db, &tree).await;
    assert!(matches!(
        result,
        Err(world_id_indexer::tree::TreeError::RootMismatch { .. })
    ));

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_restore_clean_cache_on_restart() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;
    let cache_path = temp_cache_path();

    let first_root = root_for_leaves(6, &[(1, U256::from(100))]).await;
    let first_checkpoint = seed_forward_batch(
        db,
        first_root,
        2,
        &[(1, Some(U256::from(100)))],
    )
    .await
    .unwrap();

    let tree = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(tree.last_batch_id().await, first_checkpoint);
    drop(tree);

    let second_root = root_for_leaves(6, &[(1, U256::from(400))]).await;
    let second_checkpoint = seed_forward_batch(
        db,
        second_root,
        2,
        &[(1, Some(U256::from(400)))],
    )
    .await
    .unwrap();

    let restored = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(restored.root().await, second_root);
    assert_eq!(restored.get_leaf(1).await, U256::from(400));
    assert_eq!(restored.last_batch_id().await, second_checkpoint);

    let metadata = read_metadata(&metadata_path(&cache_path)).unwrap();
    assert!(matches!(
        metadata.status,
        CacheStatus::Clean {
            last_verified_batch_id
        } if last_verified_batch_id == second_checkpoint
    ));

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_restore_falls_back_on_root_mismatch() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;
    let cache_path = temp_cache_path();

    let expected_root = root_for_leaves(6, &[(1, U256::from(100))]).await;
    let checkpoint_id = seed_forward_batch(
        db,
        expected_root,
        2,
        &[(1, Some(U256::from(100)))],
    )
    .await
    .unwrap();

    let tree = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    drop(tree);

    let updated_root = root_for_leaves(6, &[(1, U256::from(400))]).await;
    seed_forward_batch(
        db,
        updated_root,
        2,
        &[(1, Some(U256::from(400)))],
    )
    .await
    .unwrap();

    write_clean_metadata(&cache_path, 6, checkpoint_id).unwrap();

    let rebuilt = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(rebuilt.root().await, updated_root);
    assert_eq!(rebuilt.get_leaf(1).await, U256::from(400));

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_restore_falls_back_on_depth_mismatch() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;
    let cache_path = temp_cache_path();

    let expected_root = root_for_leaves(6, &[(1, U256::from(100))]).await;
    seed_forward_batch(
        db,
        expected_root,
        2,
        &[(1, Some(U256::from(100)))],
    )
    .await
    .unwrap();

    let tree = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    drop(tree);

    write_clean_metadata(&cache_path, 4, 2).unwrap();

    let rebuilt = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(rebuilt.root().await, expected_root);

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_dirty_cache_recovery_on_restart() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;
    let cache_path = temp_cache_path();

    let first_root = root_for_leaves(6, &[(1, U256::from(100))]).await;
    let base_batch_id = seed_forward_batch(
        db,
        first_root,
        2,
        &[(1, Some(U256::from(100)))],
    )
    .await
    .unwrap();

    let tree = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(tree.root().await, first_root);
    drop(tree);

    let target_root = root_for_leaves(6, &[(1, U256::from(400))]).await;
    let target_batch_id = seed_forward_batch(
        db,
        target_root,
        2,
        &[(1, Some(U256::from(400)))],
    )
    .await
    .unwrap();

    write_dirty_metadata(&cache_path, 6, base_batch_id, target_batch_id).unwrap();

    let recovered = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(recovered.root().await, target_root);
    assert_eq!(recovered.get_leaf(1).await, U256::from(400));
    assert_eq!(recovered.last_batch_id().await, target_batch_id);

    let metadata = read_metadata(&metadata_path(&cache_path)).unwrap();
    assert!(matches!(
        metadata.status,
        CacheStatus::Clean {
            last_verified_batch_id
        } if last_verified_batch_id == target_batch_id
    ));

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_missing_metadata_rebuilds() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;
    let cache_path = temp_cache_path();

    let expected_root = root_for_leaves(6, &[(1, U256::from(100))]).await;
    seed_forward_batch(
        db,
        expected_root,
        2,
        &[(1, Some(U256::from(100)))],
    )
    .await
    .unwrap();

    let tree = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    drop(tree);

    let _ = fs::remove_file(metadata_path(&cache_path));

    let rebuilt = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(rebuilt.root().await, expected_root);
    assert!(metadata_path(&cache_path).exists());

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_restore_applies_rollback_batches_after_checkpoint() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;
    let cache_path = temp_cache_path();

    let first_root = root_for_leaves(6, &[(1, U256::from(100))]).await;
    let base_batch_id = seed_forward_batch(
        db,
        first_root,
        2,
        &[(1, Some(U256::from(100)))],
    )
    .await
    .unwrap();

    let tree = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(tree.get_leaf(1).await, U256::from(100));
    drop(tree);

    let rolled_back_root = root_for_leaves(6, &[(1, U256::from(400))]).await;
    let target_batch_id = seed_batch(
        db,
        BatchKind::Rollback,
        rolled_back_root,
        2,
        test_batch_origin(100, 1),
        &[(1, Some(U256::from(400)))],
    )
    .await
    .unwrap();

    let restored = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(restored.root().await, rolled_back_root);
    assert_eq!(restored.get_leaf(1).await, U256::from(400));
    assert_eq!(restored.last_batch_id().await, target_batch_id);
    assert!(base_batch_id < target_batch_id);

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_dirty_recovery_falls_back_when_target_checkpoint_missing() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;
    let cache_path = temp_cache_path();

    let expected_root = root_for_leaves(6, &[(1, U256::from(100))]).await;
    let base_batch_id = seed_forward_batch(
        db,
        expected_root,
        2,
        &[(1, Some(U256::from(100)))],
    )
    .await
    .unwrap();

    let tree = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    drop(tree);

    write_dirty_metadata(&cache_path, 6, base_batch_id, 999_999).unwrap();

    let rebuilt = unsafe { init_tree(db, &cache_path, 6).await.unwrap() };
    assert_eq!(rebuilt.root().await, expected_root);

    let metadata = read_metadata(&metadata_path(&cache_path)).unwrap();
    assert!(matches!(
        metadata.status,
        CacheStatus::Clean {
            last_verified_batch_id
        } if last_verified_batch_id == base_batch_id
    ));

    cleanup(&cache_path);
}

#[tokio::test]
async fn test_rollback_reuses_chain_position_across_batches() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let origin = test_batch_origin(200, 5);
    let root = root_for_leaves(6, &[(1, U256::from(100))]).await;

    seed_batch(
        db,
        BatchKind::Forward,
        root,
        2,
        origin,
        &[(1, Some(U256::from(100)))],
    )
    .await
    .unwrap();

    seed_batch(
        db,
        BatchKind::Rollback,
        root,
        2,
        origin,
        &[(1, Some(U256::from(100)))],
    )
    .await
    .unwrap();

    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sync_batch WHERE block_number = $1 AND log_index = $2"
        )
        .bind(origin.block_number as i64)
        .bind(origin.log_index as i64)
        .fetch_one(db.pool())
        .await
        .unwrap(),
        2
    );
}
