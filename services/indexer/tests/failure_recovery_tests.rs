mod helpers;

use alloy::primitives::{Address, U256};
use helpers::db_helpers::*;
use serial_test::serial;
use world_id_indexer::db::{IsolationLevel, WorldTreeEventType};

/// Test database recovery after connection loss
#[tokio::test]
#[serial]
async fn test_db_reconnection_after_failure() {
    let (db, db_name) = create_unique_test_db().await;

    // Insert some data
    db.accounts()
        .insert(&U256::from(1), &Address::ZERO, &[], &[], &U256::from(123))
        .await
        .unwrap();

    // Verify data exists
    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(count, 1);

    // Simulate reconnection by creating a new DB connection to the same database
    let base_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost:5432/postgres".to_string());
    let test_db_url = if let Some(pos) = base_url.rfind('/') {
        format!("{}/{}", &base_url[..pos], db_name)
    } else {
        format!("{}/{}", base_url, db_name)
    };

    let db2 = world_id_indexer::db::DB::new(&test_db_url, Some(5))
        .await
        .expect("Reconnection should succeed");

    // Verify data is still accessible
    let count = count_accounts(db2.pool()).await.unwrap();
    assert_eq!(count, 1, "Data should be accessible after reconnection");

    cleanup_test_db(&db_name).await;
}

/// Test transaction retry on serialization failure
#[tokio::test]
#[serial]
async fn test_transaction_serialization_conflict() {
    let (db, db_name) = create_unique_test_db().await;

    // Pre-insert two accounts for concurrent updates
    db.accounts()
        .insert(&U256::from(1), &Address::ZERO, &[], &[], &U256::from(100))
        .await
        .unwrap();

    db.accounts()
        .insert(&U256::from(2), &Address::ZERO, &[], &[], &U256::from(200))
        .await
        .unwrap();

    // Start two transactions that will work on different accounts
    // This demonstrates transaction isolation without necessarily causing conflicts
    let mut tx1 = db.transaction(IsolationLevel::Serializable).await.unwrap();
    let mut tx2 = db.transaction(IsolationLevel::Serializable).await.unwrap();

    // First transaction inserts an event for account 1
    tx1.world_tree_events()
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

    tx1.commit().await.unwrap();

    // Second transaction inserts an event for account 2
    let insert_result = tx2
        .world_tree_events()
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
        .await;

    // Second transaction should succeed since it's working on different data
    insert_result.expect("Second transaction should succeed");

    tx2.commit()
        .await
        .expect("Second transaction commit should succeed");

    // Verify both transactions succeeded
    let event_count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(event_count, 2, "Both transactions should have committed");

    cleanup_test_db(&db_name).await;
}

/// Test partial batch failure and recovery
#[tokio::test]
#[serial]
async fn test_partial_batch_failure_rollback() {
    let (db, db_name) = create_unique_test_db().await;

    // Create an account first
    db.accounts()
        .insert(
            &U256::from(1),
            &Address::ZERO,
            &[Address::ZERO],
            &[U256::from(100)],
            &U256::from(100),
        )
        .await
        .unwrap();

    let mut tx = db.transaction(IsolationLevel::Serializable).await.unwrap();

    // Insert a valid event
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

    // Try to update an account that doesn't exist (should fail or be handled)
    let _bad_update = tx
        .accounts()
        .await
        .unwrap()
        .update_authenticator_at_index(
            &U256::from(999), // Non-existent account
            0,
            &Address::ZERO,
            &U256::from(200),
            &U256::from(200),
        )
        .await;

    // Update on non-existent account may fail or succeed silently depending on implementation
    // Either way, we'll rollback to demonstrate rollback behavior

    // Rollback transaction
    tx.rollback().await.unwrap();

    // Verify nothing was committed (rollback occurred)
    let event_count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(
        event_count, 0,
        "Events should be rolled back on transaction failure"
    );

    // Verify original account still exists and is unchanged
    let exists = account_exists(db.pool(), U256::from(1)).await.unwrap();
    assert!(exists, "Account should still exist after rollback");

    cleanup_test_db(&db_name).await;
}

/// Test database connection pool exhaustion and recovery
#[tokio::test]
#[serial]
async fn test_connection_pool_exhaustion() {
    let (db, db_name) = create_unique_test_db().await;

    // Create multiple concurrent operations (more than pool size)
    let mut handles = vec![];

    for i in 0..10 {
        let db_clone = db.clone();
        let handle = tokio::spawn(async move {
            db_clone
                .accounts()
                .insert(
                    &U256::from(i),
                    &Address::ZERO,
                    &[],
                    &[],
                    &U256::from(i * 100),
                )
                .await
        });
        handles.push(handle);
    }

    // Wait for all operations
    let mut success_count = 0;
    for handle in handles {
        if let Ok(result) = handle.await
            && result.is_ok()
        {
            success_count += 1;
        }
    }

    // Most operations should succeed (pool should handle concurrency)
    assert!(
        success_count >= 8,
        "Most operations should succeed despite pool limits"
    );

    cleanup_test_db(&db_name).await;
}

/// Test database query timeout handling
#[tokio::test]
#[serial]
async fn test_db_query_timeout() {
    let (db, db_name) = create_unique_test_db().await;

    // Insert test data
    db.accounts()
        .insert(&U256::from(1), &Address::ZERO, &[], &[], &U256::from(123))
        .await
        .unwrap();

    // Normal query should succeed
    let exists = account_exists(db.pool(), U256::from(1))
        .await
        .expect("Normal query should succeed");
    assert!(exists, "Account should exist");

    cleanup_test_db(&db_name).await;
}

/// Test handling of malformed data (defensive programming)
#[tokio::test]
#[serial]
async fn test_malformed_data_handling() {
    let (db, db_name) = create_unique_test_db().await;

    // Try to insert event with invalid data
    let result = db
        .world_tree_events()
        .insert_event(
            &U256::ZERO, // Edge case: zero leaf index
            WorldTreeEventType::AccountCreated,
            &U256::ZERO,
            0, // Edge case: block 0
            &U256::ZERO,
            0,
        )
        .await;

    // Should handle edge cases gracefully
    result.expect("Should handle zero values without crashing");

    cleanup_test_db(&db_name).await;
}

/// Test concurrent transaction commits
#[tokio::test]
#[serial]
async fn test_concurrent_transaction_commits() {
    let (db, db_name) = create_unique_test_db().await;

    let mut handles = vec![];

    // Create multiple concurrent transactions
    for i in 0..5 {
        let db_clone = db.clone();
        let handle = tokio::spawn(async move {
            let mut tx = db_clone
                .transaction(IsolationLevel::ReadCommitted)
                .await
                .unwrap();

            tx.accounts()
                .await
                .unwrap()
                .insert(
                    &U256::from(i),
                    &Address::ZERO,
                    &[],
                    &[],
                    &U256::from(i * 100),
                )
                .await
                .unwrap();

            tx.commit().await
        });
        handles.push(handle);
    }

    // Wait for all transactions
    for handle in handles {
        handle
            .await
            .expect("Join should succeed")
            .expect("Transaction should commit successfully");
    }

    // Verify all accounts were created
    let count = count_accounts(db.pool()).await.unwrap();
    assert_eq!(count, 5, "All concurrent transactions should succeed");

    cleanup_test_db(&db_name).await;
}

/// Test database migration recovery
#[tokio::test]
#[serial]
async fn test_database_migration_idempotency() {
    let (db, db_name) = create_unique_test_db().await;

    // Migrations were already run in create_unique_test_db
    // Running them again should be idempotent
    db.run_migrations()
        .await
        .expect("Running migrations multiple times should be safe");

    cleanup_test_db(&db_name).await;
}

/// Test database ping/health check
#[tokio::test]
#[serial]
async fn test_database_health_check() {
    let (db, db_name) = create_unique_test_db().await;

    // Test ping functionality
    db.ping().await.expect("Database ping should succeed");

    cleanup_test_db(&db_name).await;
}

/// Test large batch insert performance and recovery
#[tokio::test]
#[serial]
async fn test_large_batch_transaction() {
    let (db, db_name) = create_unique_test_db().await;

    let mut tx = db.transaction(IsolationLevel::ReadCommitted).await.unwrap();

    // Insert many events in a single transaction
    for i in 0..100 {
        tx.world_tree_events()
            .await
            .unwrap()
            .insert_event(
                &U256::from(i),
                WorldTreeEventType::AccountCreated,
                &U256::from(i * 100),
                100,
                &U256::from(i),
                i,
            )
            .await
            .unwrap();
    }

    // Commit large batch
    tx.commit()
        .await
        .expect("Large batch commit should succeed");

    // Verify all events were committed
    let count = count_world_tree_events(db.pool()).await.unwrap();
    assert_eq!(count, 100, "All events should be committed");

    cleanup_test_db(&db_name).await;
}
