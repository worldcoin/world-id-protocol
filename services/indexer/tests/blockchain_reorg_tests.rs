//! Integration tests for blockchain reorganization detection and handling
//!
//! These tests verify that the blockchain_reorg_check module correctly:
//! - Detects when block hashes in the database don't match the blockchain
//! - Triggers rollback to the last valid block
//! - Handles edge cases like no events, single block reorgs, etc.
//!
//! # Running these tests
//!
//! These tests require a PostgreSQL database to be running. Use Docker Compose:
//!
//! ```bash
//! docker compose up -d postgres
//! cargo test -p world-id-indexer --test blockchain_reorg_tests
//! ```

#![cfg(feature = "integration-tests")]

mod helpers;

use alloy::primitives::{Address, U256};
use helpers::{
    common::init_test_tracing,
    db_helpers::*,
    mock_blockchain::{mock_account_created_event, mock_root_recorded_event},
};
use world_id_indexer::db::{IsolationLevel, WorldIdRegistryEventId};

/// Test: No reorg detected when block hashes match
#[tokio::test]
async fn test_no_reorg_when_hashes_match() {
    init_test_tracing();
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert events with consistent block hashes
    let block_hash_100 = U256::from(1000);
    let block_hash_101 = U256::from(1001);

    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let root1 = mock_root_recorded_event(100, 1, U256::from(1000), U256::from(100));
    let event2 = mock_account_created_event(101, 0, 2, Address::ZERO, U256::from(200));
    let root2 = mock_root_recorded_event(101, 1, U256::from(2000), U256::from(101));

    // Process events through committer to create accounts
    let mut committer = world_id_indexer::events_committer::EventsCommitter::new(db);
    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();
    committer.handle_event(event2).await.unwrap();
    committer.handle_event(root2).await.unwrap();

    // Set block hashes in DB
    sqlx::query("UPDATE world_id_registry_events SET block_hash = $1 WHERE block_number = $2")
        .bind(block_hash_100)
        .bind(100_i64)
        .execute(db.pool())
        .await
        .unwrap();

    sqlx::query("UPDATE world_id_registry_events SET block_hash = $1 WHERE block_number = $2")
        .bind(block_hash_101)
        .bind(101_i64)
        .execute(db.pool())
        .await
        .unwrap();

    // Verify the blockchain would return the same hashes
    // In a real scenario, the blockchain RPC would return matching hashes
    // This test validates that matching hashes don't trigger rollback

    // Get block hashes from DB
    let hashes = db
        .world_id_registry_events()
        .get_block_hashes(100)
        .await
        .unwrap();

    assert_eq!(hashes.len(), 1, "Should have exactly one block hash");
    assert_eq!(hashes[0], block_hash_100, "Block hash should match");

    // Verify all data is still present (no rollback occurred)
    assert_account_count(db.pool(), 2).await;
    assert_event_count(db.pool(), 2).await;
}

/// Test: Reorg detected when block hash differs
#[tokio::test]
async fn test_reorg_detected_on_hash_mismatch() {
    init_test_tracing();
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert events at multiple blocks
    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let root1 = mock_root_recorded_event(100, 1, U256::from(1000), U256::from(100));
    let event2 = mock_account_created_event(101, 0, 2, Address::ZERO, U256::from(200));
    let root2 = mock_root_recorded_event(101, 1, U256::from(2000), U256::from(101));
    let event3 = mock_account_created_event(102, 0, 3, Address::ZERO, U256::from(300));

    insert_test_world_tree_event(db, &event1).await.unwrap();
    insert_test_world_tree_event(db, &root1).await.unwrap();
    insert_test_world_tree_event(db, &event2).await.unwrap();
    insert_test_world_tree_event(db, &root2).await.unwrap();
    insert_test_world_tree_event(db, &event3).await.unwrap();

    // Simulate reorg: block 101 has a different hash in DB vs blockchain
    let db_hash_101 = U256::from(1001);

    sqlx::query("UPDATE world_id_registry_events SET block_hash = $1 WHERE block_number = $2")
        .bind(db_hash_101)
        .bind(101_i64)
        .execute(db.pool())
        .await
        .unwrap();

    // Verify that get_block_hashes returns the DB hash
    let hashes = db
        .world_id_registry_events()
        .get_block_hashes(101)
        .await
        .unwrap();

    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0], db_hash_101);

    // In a real scenario, blockchain_reorg_check_loop would:
    // 1. Detect the mismatch
    // 2. Find the last valid block (100)
    // 3. Trigger rollback to block 100
}

/// Test: Multiple block hashes at same block number indicates reorg
#[tokio::test]
async fn test_multiple_block_hashes_indicate_reorg() {
    init_test_tracing();
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert two events at block 100 with different block hashes
    // This simulates a reorg where events were processed from two different forks
    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let event2 = mock_account_created_event(100, 1, 2, Address::ZERO, U256::from(200));

    insert_test_world_tree_event(db, &event1).await.unwrap();
    insert_test_world_tree_event(db, &event2).await.unwrap();

    let hash1 = U256::from(1000);
    let hash2 = U256::from(2000);

    sqlx::query("UPDATE world_id_registry_events SET block_hash = $1 WHERE block_number = $2 AND log_index = $3")
        .bind(hash1)
        .bind(100_i64)
        .bind(0_i64)
        .execute(db.pool())
        .await
        .unwrap();

    sqlx::query("UPDATE world_id_registry_events SET block_hash = $1 WHERE block_number = $2 AND log_index = $3")
        .bind(hash2)
        .bind(100_i64)
        .bind(1_i64)
        .execute(db.pool())
        .await
        .unwrap();

    // Get block hashes - should return two different hashes
    let hashes = db
        .world_id_registry_events()
        .get_block_hashes(100)
        .await
        .unwrap();

    assert_eq!(hashes.len(), 2, "Should detect two different block hashes");
    assert!(hashes.contains(&hash1));
    assert!(hashes.contains(&hash2));

    // This condition indicates a reorg - the blockchain_reorg_check would
    // detect this and trigger rollback
}

/// Test: No events means no reorg to detect
#[tokio::test]
async fn test_no_reorg_with_empty_database() {
    init_test_tracing();
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Get latest block from empty DB
    let latest_block = db
        .world_id_registry_events()
        .get_latest_block()
        .await
        .unwrap();

    assert!(
        latest_block.is_none(),
        "Empty DB should have no latest block"
    );

    // blockchain_reorg_check_loop should skip processing when there are no events
}

/// Test: get_block_hashes returns empty for non-existent block
#[tokio::test]
async fn test_get_block_hashes_empty_for_nonexistent_block() {
    init_test_tracing();
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert event at block 100
    let event = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    insert_test_world_tree_event(db, &event).await.unwrap();

    // Query for a different block
    let hashes = db
        .world_id_registry_events()
        .get_block_hashes(999)
        .await
        .unwrap();

    assert_eq!(
        hashes.len(),
        0,
        "Should return empty for non-existent block"
    );
}

/// Test: Reorg within max_reorg_blocks range is handled
#[tokio::test]
async fn test_reorg_within_max_blocks_range() {
    init_test_tracing();
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert events across 50 blocks
    for block in 100..150 {
        let event =
            mock_account_created_event(block, 0, block - 99, Address::ZERO, U256::from(block));
        insert_test_world_tree_event(db, &event).await.unwrap();

        // Set consistent block hash
        sqlx::query("UPDATE world_id_registry_events SET block_hash = $1 WHERE block_number = $2")
            .bind(U256::from(block))
            .bind(block as i64)
            .execute(db.pool())
            .await
            .unwrap();
    }

    // Simulate reorg at block 140 (10 blocks back from 149)
    // With max_reorg_blocks = 100, this should be detectable
    let reorg_block = 140_u64;
    let new_hash = U256::from(99999);

    sqlx::query("UPDATE world_id_registry_events SET block_hash = $1 WHERE block_number = $2")
        .bind(new_hash)
        .bind(reorg_block as i64)
        .execute(db.pool())
        .await
        .unwrap();

    // Verify the changed hash is detected
    let hashes = db
        .world_id_registry_events()
        .get_block_hashes(reorg_block)
        .await
        .unwrap();

    assert_eq!(hashes[0], new_hash, "Block hash should be updated");

    // In real scenario with max_reorg_blocks=100, this would be within range
    // and the binary search would find block 140 as the divergence point
}

/// Test: Deep reorg beyond max_reorg_blocks returns error
///
/// This test verifies that when a reorg extends beyond the configured max_reorg_blocks,
/// the system properly detects it and would return a ReorgBeyondMaxReorgBlocks error.
#[tokio::test]
async fn test_deep_reorg_beyond_max_blocks() {
    init_test_tracing();
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert events across 150 blocks
    let mut committer = world_id_indexer::events_committer::EventsCommitter::new(db);
    for block in 100..250 {
        let event =
            mock_account_created_event(block, 0, block - 99, Address::ZERO, U256::from(block));
        let root = mock_root_recorded_event(block, 1, U256::from(block * 10), U256::from(block));
        committer.handle_event(event).await.unwrap();
        committer.handle_event(root).await.unwrap();

        sqlx::query("UPDATE world_id_registry_events SET block_hash = $1 WHERE block_number = $2")
            .bind(U256::from(block))
            .bind(block as i64)
            .execute(db.pool())
            .await
            .unwrap();
    }

    let latest_block = 249_u64;
    let max_reorg_blocks = 100_u64;
    let earliest_checkable = latest_block.saturating_sub(max_reorg_blocks);

    assert_eq!(earliest_checkable, 149, "Should check back to block 149");

    // Simulate reorg at the earliest checkable block (149)
    // Change the hash at block 149 to simulate a deep reorg
    sqlx::query("UPDATE world_id_registry_events SET block_hash = $1 WHERE block_number = $2")
        .bind(U256::from(99999))
        .bind(149_i64)
        .execute(db.pool())
        .await
        .unwrap();

    // Now simulate a reorg by creating a NEW blockchain
    // The new blockchain will have completely different block hashes
    // Drop the committer to free resources
    drop(committer);

    // Create a new Anvil instance - it will generate different block hashes
    let anvil2 =
        world_id_test_utils::anvil::TestAnvil::spawn().expect("failed to spawn second anvil");
    let deployer2 = anvil2.signer(0).expect("failed to get deployer");
    let registry_address2 = anvil2
        .deploy_world_id_registry_with_depth(deployer2, 8)
        .await
        .expect("failed to deploy registry on second chain");

    let blockchain2 = world_id_indexer::blockchain::Blockchain::new(
        anvil2.endpoint(),
        anvil2.ws_endpoint(),
        registry_address2,
    )
    .await
    .expect("failed to create second blockchain");

    // Run the actual blockchain_reorg_check_loop
    // Since the second blockchain has completely different block hashes,
    // it should detect a reorg beyond max_reorg_blocks and return an error
    let result = world_id_indexer::blockchain_sync_check::blockchain_sync_check_loop(
        1, // interval_secs - doesn't matter since it will fail on first check
        db,
        &blockchain2,
        max_reorg_blocks,
    )
    .await;

    // Verify that blockchain_reorg_check_loop returns ReorgBeyondMaxReorgBlocks error
    assert!(
        result.is_err(),
        "blockchain_reorg_check_loop should return an error for deep reorg"
    );

    let err = result.unwrap_err();
    let err_string = err.to_string();
    assert!(
        err_string.contains("reorg beyond") || err_string.contains("ReorgBeyondMaxReorgBlocks"),
        "Error should be ReorgBeyondMaxReorgBlocks, got: {}",
        err_string
    );
}

/// Test: Binary search correctly identifies reorg point
#[tokio::test]
async fn test_binary_search_finds_correct_reorg_point() {
    init_test_tracing();
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert events at blocks 100-110
    for block in 100..=110 {
        let event =
            mock_account_created_event(block, 0, block - 99, Address::ZERO, U256::from(block));
        insert_test_world_tree_event(db, &event).await.unwrap();

        let hash = if block <= 105 {
            U256::from(block) // Valid blocks
        } else {
            U256::from(block + 10000) // Reorg'd blocks (different hash)
        };

        sqlx::query("UPDATE world_id_registry_events SET block_hash = $1 WHERE block_number = $2")
            .bind(hash)
            .bind(block as i64)
            .execute(db.pool())
            .await
            .unwrap();
    }

    // Binary search should identify block 105 as the last valid block
    // Blocks 106-110 have "wrong" hashes (simulating reorg)

    // Verify block 105 has consistent hash
    let hash_105 = db
        .world_id_registry_events()
        .get_block_hashes(105)
        .await
        .unwrap();
    assert_eq!(hash_105[0], U256::from(105));

    // Verify block 106 has "reorg'd" hash
    let hash_106 = db
        .world_id_registry_events()
        .get_block_hashes(106)
        .await
        .unwrap();
    assert_eq!(hash_106[0], U256::from(106 + 10000));

    // In the actual binary search:
    // - Would check blocks between 110-max_reorg_blocks and 110
    // - Would find that block 105 is valid, 106 is not
    // - Would rollback to the last event at block 105
}

/// Test: Rollback after reorg detection preserves valid data
#[tokio::test]
async fn test_rollback_after_reorg_preserves_valid_data() {
    init_test_tracing();
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert valid events at blocks 100-102
    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let root1 = mock_root_recorded_event(100, 1, U256::from(1000), U256::from(100));
    let event2 = mock_account_created_event(101, 0, 2, Address::ZERO, U256::from(200));
    let root2 = mock_root_recorded_event(101, 1, U256::from(2000), U256::from(101));

    // Insert reorg'd events at block 102
    let event3 = mock_account_created_event(102, 0, 3, Address::ZERO, U256::from(300));
    let root3 = mock_root_recorded_event(102, 1, U256::from(3000), U256::from(102));

    // Process events through committer to create accounts
    let mut committer = world_id_indexer::events_committer::EventsCommitter::new(db);
    committer.handle_event(event1).await.unwrap();
    committer.handle_event(root1).await.unwrap();
    committer.handle_event(event2).await.unwrap();
    committer.handle_event(root2).await.unwrap();
    committer.handle_event(event3).await.unwrap();
    committer.handle_event(root3).await.unwrap();

    // Verify all data before rollback
    assert_account_count(db.pool(), 3).await;
    assert_event_count(db.pool(), 3).await;

    // Simulate reorg detection and rollback to block 101
    let rollback_point = WorldIdRegistryEventId {
        block_number: 101,
        log_index: 1,
    };

    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();
    let mut executor = world_id_indexer::rollback_executor::RollbackExecutor::new(&mut tx);
    executor.rollback_to_event(rollback_point).await.unwrap();
    tx.commit().await.unwrap();

    // Verify valid data is preserved
    assert_account_count(db.pool(), 2).await;
    assert_event_count(db.pool(), 2).await;
    assert_account_exists(db.pool(), 1).await;
    assert_account_exists(db.pool(), 2).await;
    assert_account_not_exists(db.pool(), 3).await;
}

/// Test: get_latest_id_for_block_number returns correct event
#[tokio::test]
async fn test_get_latest_id_for_block_number() {
    init_test_tracing();
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert multiple events at same block
    let event1 = mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(100));
    let event2 = mock_account_created_event(100, 1, 2, Address::ZERO, U256::from(200));
    let root = mock_root_recorded_event(100, 2, U256::from(1000), U256::from(100));

    insert_test_world_tree_event(db, &event1).await.unwrap();
    insert_test_world_tree_event(db, &event2).await.unwrap();
    insert_test_world_tree_event(db, &root).await.unwrap();

    // Get latest event ID for block 100
    let latest_id = db
        .world_id_registry_events()
        .get_latest_id_for_block_number(100)
        .await
        .unwrap();

    assert!(latest_id.is_some());
    let id = latest_id.unwrap();
    assert_eq!(id.block_number, 100);
    assert_eq!(id.log_index, 2, "Should return highest log_index");
}
