mod helpers;

use alloy::primitives::{Address, U256};
use helpers::db_helpers::{create_unique_test_db, insert_test_world_tree_root};
use semaphore_rs_storage::MmapVec;
use world_id_indexer::{
    blockchain::{AccountCreatedEvent, BlockchainEvent, RegistryEvent},
    db::{DB, IsolationLevel},
    tree::{MerkleTree, cached_tree::init_tree},
};

/// Insert a leaf assignment without running the blockchain worker.
async fn insert_leaf(db: &DB, block: u64, log: u64, leaf: u64, value: u64) {
    db.world_id_registry_events()
        .insert_event(&BlockchainEvent {
            block_number: block,
            log_index: log,
            block_hash: U256::ZERO,
            tx_hash: U256::ZERO,
            details: RegistryEvent::AccountCreated(AccountCreatedEvent {
                leaf_index: leaf,
                recovery_address: Address::ZERO,
                authenticator_addresses: vec![],
                authenticator_pubkeys: vec![],
                offchain_signer_commitment: U256::from(value),
            }),
        })
        .await
        .unwrap();
}

/// An unchanged cache resumes at the latest occurrence of its root, without decoding history.
#[tokio::test]
async fn unchanged_cache_skips_history_and_uses_latest_root_position() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tree.mmap");
    let storage = unsafe { MmapVec::create_from_path(&path).unwrap() };
    let tree = MerkleTree::new_with_leaves(storage, 6, &U256::ZERO, &[U256::ZERO, U256::from(11)]);
    let root = tree.root();
    drop(tree);

    insert_test_world_tree_root(db, 10, 1, root, U256::ZERO)
        .await
        .unwrap();
    insert_leaf(db, 10, 2, 1, 99).await;
    // Decoding this obsolete event would fail if replay started at genesis or the older root.
    sqlx::query("UPDATE world_id_registry_events SET event_data = '{}' WHERE log_index = 2")
        .execute(db.pool())
        .await
        .unwrap();
    insert_test_world_tree_root(db, 10, 3, root, U256::ZERO)
        .await
        .unwrap();

    let state = unsafe { init_tree(db, &path, 6).await.unwrap() };
    assert_eq!(state.root().await, root);
    assert_eq!(state.last_synced_event_id().await, (10, 3).into());
    let tree = state.read().await;
    assert_eq!(tree.get_leaf(1), U256::from(11));
    assert!(tree.verify(U256::from(11), &tree.proof(1)));
}

/// Replay applies only the delta and stops at a recorded root, even with later leaf events.
#[tokio::test]
async fn cache_replay_validates_root_proofs_and_cursor() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tree.mmap");
    let storage = unsafe { MmapVec::create_from_path(&path).unwrap() };
    let tree = MerkleTree::new_with_leaves(
        storage,
        6,
        &U256::ZERO,
        &[U256::ZERO, U256::from(11), U256::from(22)],
    );
    let root = tree.root();
    drop(tree);

    let expected_storage =
        unsafe { MmapVec::create_from_path(dir.path().join("expected.mmap")).unwrap() };
    let expected = MerkleTree::new_with_leaves(
        expected_storage,
        6,
        &U256::ZERO,
        &[
            U256::ZERO,
            U256::from(11),
            U256::from(33),
            U256::ZERO,
            U256::from(44),
        ],
    );

    // Historical assignments precede the cached root and must not be replayed.
    insert_leaf(db, 10, 0, 1, 99).await;
    insert_test_world_tree_root(db, 10, 1, root, U256::ZERO)
        .await
        .unwrap();
    insert_leaf(db, 10, 2, 2, 30).await;
    insert_leaf(db, 10, 3, 2, 33).await;
    insert_leaf(db, 10, 4, 1, 11).await;
    // Cross the 10,000-event page boundary with unchanged assignments to the same leaf.
    sqlx::query(
        r#"
            INSERT INTO world_id_registry_events
                (block_number, log_index, block_hash, tx_hash, event_type, leaf_index, event_data)
            SELECT block_number, n, block_hash, tx_hash, event_type, leaf_index, event_data
            FROM world_id_registry_events CROSS JOIN generate_series(5, 10005) AS n
            WHERE block_number = 10 AND log_index = 4
        "#,
    )
    .execute(db.pool())
    .await
    .unwrap();
    insert_leaf(db, 11, 0, 4, 44).await;
    insert_test_world_tree_root(db, 11, 1, expected.root(), U256::ZERO)
        .await
        .unwrap();
    insert_leaf(db, 11, 2, 1, 55).await;

    let state = unsafe { init_tree(db, &path, 6).await.unwrap() };
    assert_eq!(state.root().await, expected.root());
    assert_eq!(state.last_synced_event_id().await, (11, 1).into());
    {
        let tree = state.read().await;
        assert_eq!(tree.num_leaves(), expected.num_leaves());
        for leaf in 0..expected.num_leaves() {
            let value = expected.get_leaf(leaf);
            assert_eq!(tree.get_leaf(leaf), value);
            assert_eq!(tree.proof(leaf).root(value), expected.root());
        }
    }
    drop(state);

    let restored = unsafe { init_tree(db, &path, 6).await.unwrap() };
    assert_eq!(restored.root().await, expected.root());
    assert_eq!(restored.last_synced_event_id().await, (11, 1).into());
}

/// Event pages and root boundaries remain consistent across concurrent replacement and append.
#[tokio::test]
async fn replay_pages_use_one_snapshot_and_inclusive_upper_boundary() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    insert_test_world_tree_root(db, 10, 1, U256::from(1), U256::ZERO)
        .await
        .unwrap();
    insert_leaf(db, 10, 2, 1, 11).await;
    insert_test_world_tree_root(db, 10, 3, U256::from(2), U256::ZERO)
        .await
        .unwrap();
    let mut tx = db
        .transaction(IsolationLevel::RepeatableRead)
        .await
        .unwrap();
    let from = tx
        .world_id_registry_events()
        .await
        .unwrap()
        .get_event_id_by_root(&U256::from(1))
        .await
        .unwrap()
        .unwrap();
    let target = tx
        .world_id_registry_events()
        .await
        .unwrap()
        .get_latest_root_recorded()
        .await
        .unwrap()
        .unwrap();
    let through = (target.block_number, target.log_index).into();

    db.world_id_registry_events()
        .delete_after_event(&from)
        .await
        .unwrap();
    insert_leaf(db, 10, 2, 1, 99).await;
    insert_test_world_tree_root(db, 10, 3, U256::from(3), U256::ZERO)
        .await
        .unwrap();
    insert_test_world_tree_root(db, 11, 0, U256::from(4), U256::ZERO)
        .await
        .unwrap();

    let page = tx
        .world_id_registry_events()
        .await
        .unwrap()
        .get_after_until(from, through, 1)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(
        world_id_indexer::tree::extract_leaf_commitment(&page[0].details),
        Some((1, U256::from(11)))
    );
    let next = (page[0].block_number, page[0].log_index).into();
    let page = tx
        .world_id_registry_events()
        .await
        .unwrap()
        .get_after_until(next, through, 1)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!((page[0].block_number, page[0].log_index), (10, 3));
    assert!(
        matches!(&page[0].details, RegistryEvent::RootRecorded(event) if event.root == target.details.root)
    );
    assert!(
        tx.world_id_registry_events()
            .await
            .unwrap()
            .get_after_until(through, through, 1)
            .await
            .unwrap()
            .is_empty()
    );
    tx.commit().await.unwrap();
}

/// A replay whose leaf data disagrees with its recorded root must not be served.
#[tokio::test]
async fn replay_root_mismatch_returns_error_and_deletes_cache() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tree.mmap");
    let storage = unsafe { MmapVec::create_from_path(&path).unwrap() };
    let tree = MerkleTree::new_with_leaves(storage, 6, &U256::ZERO, &[U256::ZERO, U256::from(11)]);
    insert_test_world_tree_root(db, 10, 1, tree.root(), U256::ZERO)
        .await
        .unwrap();
    drop(tree);
    insert_leaf(db, 10, 2, 1, 22).await;
    insert_test_world_tree_root(db, 10, 3, U256::from(123), U256::ZERO)
        .await
        .unwrap();

    let error = unsafe { init_tree(db, &path, 6).await.unwrap_err() };
    assert!(error.to_string().contains("root mismatch"), "{error:?}");
    assert!(!path.exists());
}

/// A cache interrupted between leaf updates keeps the existing delete-and-exit behavior.
#[tokio::test]
async fn interrupted_cache_is_rejected_despite_valid_internal_hashes() {
    let test_db = create_unique_test_db().await;
    let db = test_db.db();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tree.mmap");
    let storage = unsafe { MmapVec::create_from_path(&path).unwrap() };
    let mut tree = MerkleTree::new_with_leaves(
        storage,
        6,
        &U256::ZERO,
        &[U256::ZERO, U256::from(11), U256::from(22)],
    );
    insert_test_world_tree_root(db, 10, 1, tree.root(), U256::ZERO)
        .await
        .unwrap();
    tree.set_leaf(1, U256::from(33));
    tree.validate().unwrap();
    drop(tree);

    let error = unsafe { init_tree(db, &path, 6).await.unwrap_err() };
    assert!(
        error.to_string().contains("restored root not found in DB"),
        "{error:?}"
    );
    assert!(!path.exists());
}
