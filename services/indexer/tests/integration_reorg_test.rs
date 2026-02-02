mod common;
mod helpers;

use alloy::primitives::U256;
use helpers::db_helpers::*;
use serial_test::serial;
use world_id_indexer::db::WorldTreeEventType;

/// Test that reorg scenarios are handled correctly
/// This test simulates a reorg by:
/// 1. Creating events at block N
/// 2. Simulating a reorg by creating different events at the same block N with different log indices
/// 3. Verifying that the compound primary key (block_number, log_index) handles this correctly
#[tokio::test]
#[serial]
async fn test_reorg_with_compound_primary_key() {
    let (db, db_name) = create_unique_test_db().await;

    let block_number = 100;
    let leaf_index = U256::from(1);
    let commitment1 = U256::from(111);
    let commitment2 = U256::from(222);

    // Original chain: Insert event at (block=100, log_index=0)
    insert_test_world_tree_event(
        &db,
        block_number,
        0,
        leaf_index,
        WorldTreeEventType::AccountCreated,
        U256::from(1000),
        commitment1,
    )
    .await
    .unwrap();

    // Simulate reorg: Different event at same block but different log_index
    insert_test_world_tree_event(
        &db,
        block_number,
        1, // Different log_index
        leaf_index,
        WorldTreeEventType::AccountCreated,
        U256::from(2000),
        commitment2,
    )
    .await
    .unwrap();

    // Both events should exist (compound key allows both)
    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(
        count, 2,
        "Both events should exist with different log indices"
    );

    // Get specific event
    let event1 = db
        .world_tree_events()
        .get_event((block_number, 0))
        .await
        .unwrap();
    let event2 = db
        .world_tree_events()
        .get_event((block_number, 1))
        .await
        .unwrap();

    assert!(event1.is_some());
    assert!(event2.is_some());
    assert_eq!(event1.unwrap().offchain_signer_commitment, commitment1);
    assert_eq!(event2.unwrap().offchain_signer_commitment, commitment2);

    cleanup_test_db(&db_name).await;
}

/// Test that events can be re-indexed after a reorg
/// This simulates the scenario where:
/// 1. Events are indexed from the canonical chain
/// 2. A reorg occurs, invalidating some events
/// 3. New events are indexed from the new canonical chain
#[tokio::test]
#[serial]
async fn test_reorg_reindexing() {
    let (db, db_name) = create_unique_test_db().await;

    let leaf_index = U256::from(1);
    let initial_commitment = U256::from(100);
    let reorg_commitment = U256::from(200);

    // Original chain: block 100, log_index 0
    insert_test_world_tree_event(
        &db,
        100,
        0,
        leaf_index,
        WorldTreeEventType::AccountCreated,
        U256::from(1000),
        initial_commitment,
    )
    .await
    .unwrap();

    // Original chain: block 101, log_index 0
    insert_test_world_tree_event(
        &db,
        101,
        0,
        leaf_index,
        WorldTreeEventType::AccountUpdated,
        U256::from(1001),
        initial_commitment,
    )
    .await
    .unwrap();

    // Verify original chain has 2 events
    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(count, 2);

    // Simulate reorg: Block 101 is invalid, replace with new event
    // In real scenario, the application would delete events from reorged blocks
    // and re-index from the fork point
    sqlx::query("DELETE FROM world_tree_events WHERE block_number >= $1")
        .bind(101i64)
        .execute(db.pool())
        .await
        .unwrap();

    // Verify block 101 was removed
    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(count, 1);

    // Re-index with new canonical chain events
    insert_test_world_tree_event(
        &db,
        101,
        0,
        leaf_index,
        WorldTreeEventType::AccountUpdated,
        U256::from(2001), // Different tx_hash
        reorg_commitment, // Different commitment
    )
    .await
    .unwrap();

    // Verify new event was added
    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(count, 2);

    let event = db
        .world_tree_events()
        .get_event((101, 0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.offchain_signer_commitment, reorg_commitment);
    assert_eq!(event.tx_hash, U256::from(2001));

    cleanup_test_db(&db_name).await;
}

/// Test that root events handle reorgs correctly
#[tokio::test]
#[serial]
async fn test_reorg_root_events() {
    let (db, db_name) = create_unique_test_db().await;

    let block_number = 100;
    let original_root = U256::from(5555);
    let reorg_root = U256::from(6666);

    // Original chain: root at (block=100, log_index=0)
    insert_test_world_tree_root(&db, block_number, 0, original_root, U256::from(1000))
        .await
        .unwrap();

    // Simulate reorg: different root at same block, different log_index
    insert_test_world_tree_root(&db, block_number, 1, reorg_root, U256::from(2000))
        .await
        .unwrap();

    // Both roots should exist
    let count = count_world_tree_roots(db.pool()).await.unwrap();
    assert_eq!(
        count, 2,
        "Both root events should exist with different log indices"
    );

    // Verify each root
    let root1 = db
        .world_tree_roots()
        .get_root((block_number, 0))
        .await
        .unwrap()
        .unwrap();
    let root2 = db
        .world_tree_roots()
        .get_root((block_number, 1))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(root1.root, original_root);
    assert_eq!(root2.root, reorg_root);

    cleanup_test_db(&db_name).await;
}

/// Test handling of duplicate events during reorg recovery
#[tokio::test]
#[serial]
async fn test_reorg_duplicate_event_handling() {
    let (db, db_name) = create_unique_test_db().await;

    let block_number = 100;
    let log_index = 0;
    let leaf_index = U256::from(1);
    let commitment = U256::from(123);

    // Insert event first time
    db.world_tree_events()
        .insert_event(
            &leaf_index,
            WorldTreeEventType::AccountCreated,
            &commitment,
            block_number,
            &U256::from(1000),
            log_index,
        )
        .await
        .unwrap();

    // Try to insert same event again (same block_number, log_index)
    // This should fail due to unique constraint on compound primary key
    let result = db
        .world_tree_events()
        .insert_event(
            &leaf_index,
            WorldTreeEventType::AccountCreated,
            &commitment,
            block_number,
            &U256::from(1000),
            log_index,
        )
        .await;

    assert!(
        result.is_err(),
        "Duplicate event should fail with unique constraint violation"
    );

    // Should still have only one event
    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(count, 1);

    cleanup_test_db(&db_name).await;
}

/// Test that events from different blocks can coexist
/// This tests normal operation alongside reorg scenarios
#[tokio::test]
#[serial]
async fn test_multiple_blocks_with_events() {
    let (db, db_name) = create_unique_test_db().await;

    // Insert events across multiple blocks
    for block in 100..105 {
        for log_idx in 0..3 {
            insert_test_world_tree_event(
                &db,
                block,
                log_idx,
                U256::from(block * 10 + log_idx),
                WorldTreeEventType::AccountCreated,
                U256::from(block * 1000 + log_idx),
                U256::from(block * 100 + log_idx),
            )
            .await
            .unwrap();
        }
    }

    // Verify all events were inserted
    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(count, 15, "5 blocks * 3 events = 15 events");

    // Simulate reorg: remove blocks >= 103
    sqlx::query("DELETE FROM world_tree_events WHERE block_number >= $1")
        .bind(103i64)
        .execute(db.pool())
        .await
        .unwrap();

    // Should have only events from blocks 100-102
    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(count, 9, "3 blocks * 3 events = 9 events remaining");

    // Verify we can still query specific events
    let event = db.world_tree_events().get_event((101, 1)).await.unwrap();
    assert!(event.is_some());

    cleanup_test_db(&db_name).await;
}

/// Test transaction isolation during reorg scenarios
#[tokio::test]
#[serial]
async fn test_reorg_transaction_isolation() {
    let (db, db_name) = create_unique_test_db().await;

    use world_id_indexer::db::IsolationLevel;

    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();

    // Insert events in transaction
    tx.world_tree_events()
        .await
        .unwrap()
        .insert_event(
            &U256::from(1),
            WorldTreeEventType::AccountCreated,
            &U256::from(100),
            100,
            &U256::from(1000),
            0,
        )
        .await
        .unwrap();

    tx.world_tree_events()
        .await
        .unwrap()
        .insert_event(
            &U256::from(2),
            WorldTreeEventType::AccountCreated,
            &U256::from(200),
            101,
            &U256::from(1001),
            0,
        )
        .await
        .unwrap();

    // Before commit, events should not be visible outside transaction
    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(count, 0, "Events not committed yet");

    // Commit transaction
    tx.commit().await.unwrap();

    // Now events should be visible
    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(count, 2, "Events committed atomically");

    cleanup_test_db(&db_name).await;
}
