mod helpers;

use alloy::primitives::{Address, U160, U256};
use helpers::db_helpers::*;
use sqlx::{Row, postgres::PgPoolOptions};
use uuid::Uuid;
use world_id_indexer::db::WorldTreeEventType;

/// Test that migration 0013's SQL conversion logic correctly converts bytea to bigint
/// This test verifies the actual SQL conversion formula works correctly
#[tokio::test]
async fn test_migration_0013_conversion_logic() {
    let test_db = create_unique_test_db().await;
    let pool = test_db.db.pool();

    // Create a test table with bytea column similar to the old schema
    sqlx::query(
        r#"
        CREATE TABLE test_conversion (
            id SERIAL PRIMARY KEY,
            leaf_index_old bytea NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await
    .unwrap();

    // Insert test data with different u64 values as U256 bytea
    let test_values = vec![1u64, 42u64, 1000u64, u64::MAX];

    for val in &test_values {
        let u256_val = U256::from(*val);
        sqlx::query("INSERT INTO test_conversion (leaf_index_old) VALUES ($1)")
            .bind(&u256_val)
            .execute(pool)
            .await
            .unwrap();
    }

    // Apply the same conversion logic as migration 0013
    sqlx::query(
        r#"
        ALTER TABLE test_conversion ADD COLUMN leaf_index_new bigint
        "#,
    )
    .execute(pool)
    .await
    .unwrap();

    // Use the same conversion formula from the migration
    sqlx::query(
        r#"
        UPDATE test_conversion SET leaf_index_new = (
            ('x' || encode(substring(leaf_index_old from length(leaf_index_old) - 7 for 8), 'hex'))::bit(64)::bigint
        )
        "#
    )
    .execute(pool)
    .await
    .unwrap();

    // Verify the conversion worked correctly
    for val in &test_values {
        let result: (i64,) =
            sqlx::query_as("SELECT leaf_index_new FROM test_conversion WHERE leaf_index_old = $1")
                .bind(&U256::from(*val))
                .fetch_one(pool)
                .await
                .unwrap();

        assert_eq!(
            result.0 as u64, *val,
            "Conversion failed for value {}. Expected {}, got {}",
            val, val, result.0 as u64
        );
    }
}

/// Test that migration 0013 correctly converts leaf_index from bytea (U256) to bigint (u64)
/// This test creates a database with the OLD schema, inserts data, runs migration, and verifies conversion
#[tokio::test]
#[ignore] // This test requires manually excluding migration 0013, run manually if needed
async fn test_migration_0013_converts_bytea_to_bigint() {
    let unique_name = format!("test_db_{}", Uuid::new_v4().to_string().replace('-', "_"));
    let base_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost:5432/postgres".to_string());

    // Connect to postgres database to create our test database
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&base_url)
        .await
        .expect("Failed to connect to postgres");

    sqlx::query(&format!("CREATE DATABASE {}", unique_name))
        .execute(&pool)
        .await
        .expect("Failed to create test database");

    // Connect to the new database
    let test_db_url = if let Some(pos) = base_url.rfind('/') {
        let (_base, path_and_query) = base_url.split_at(pos + 1);
        let query_start = path_and_query.find('?');
        let query_str = query_start.map(|idx| &path_and_query[idx..]).unwrap_or("");
        format!("{}{}{}", &base_url[..pos + 1], unique_name, query_str)
    } else {
        format!("{}/{}", base_url, unique_name)
    };

    let test_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&test_db_url)
        .await
        .expect("Failed to connect to test database");

    // Run migrations UP TO but NOT INCLUDING migration 0013
    // We need to manually specify which migrations to run
    let migration_path = std::path::Path::new("migrations");

    // Run migrations 0001 through 0012 (excluding 0013)
    for migration_file in [
        "0001_init.sql",
        "0002_update_events.sql",
        "0003_rename_to_accounts.sql",
        "0004_add_created_at_index.sql",
        "0005_rename_account_index_to_leaf_index.sql",
        "0006_rename_to_world_id_events.sql",
        "0007_drop_checkpoints_table.sql",
        "0008_change_column_types.sql",
        "0009_rename_new_commitment_to_offchain_signer_commitment.sql",
        "0010_rename_to_world_tree_events.sql",
        "0011_create_world_tree_roots.sql",
        "0012_drop_unique_root_constraint.sql",
    ] {
        let migration_content = std::fs::read_to_string(migration_path.join(migration_file))
            .expect(&format!(
                "Failed to read migration file: {}",
                migration_file
            ));

        // Split migration file by semicolons and execute each statement separately
        for statement in migration_content.split(';') {
            let trimmed = statement.trim();
            if !trimmed.is_empty() && !trimmed.starts_with("--") {
                sqlx::query(trimmed)
                    .execute(&test_pool)
                    .await
                    .expect(&format!(
                        "Failed to run migration statement from: {}",
                        migration_file
                    ));
            }
        }
    }

    // Now we have the OLD schema with leaf_index as bytea
    // Insert test data using the old bytea format

    // Test values
    let leaf_index_1_u64 = 1u64;
    let leaf_index_2_u64 = 42u64;
    let leaf_index_max_u64 = u64::MAX;

    // Convert u64 to U256 bytea format (32 bytes, big-endian)
    let leaf_index_1_u256 = U256::from(leaf_index_1_u64);
    let leaf_index_2_u256 = U256::from(leaf_index_2_u64);
    let leaf_index_max_u256 = U256::from(leaf_index_max_u64);

    let commitment_1 = U256::from(456);
    let commitment_2 = U256::from(789);
    let commitment_max = U256::from(999);

    let recovery_address_u160: U160 = Address::ZERO.into();

    // Insert into accounts table with bytea leaf_index
    sqlx::query(
        r#"
        INSERT INTO accounts (
            leaf_index,
            recovery_address,
            authenticator_addresses,
            authenticator_pubkeys,
            offchain_signer_commitment
        ) VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(&leaf_index_1_u256)
    .bind(&recovery_address_u160)
    .bind(sqlx::types::Json(Vec::<String>::new()))
    .bind(sqlx::types::Json(Vec::<String>::new()))
    .bind(&commitment_1)
    .execute(&test_pool)
    .await
    .expect("Failed to insert account 1");

    sqlx::query(
        r#"
        INSERT INTO accounts (
            leaf_index,
            recovery_address,
            authenticator_addresses,
            authenticator_pubkeys,
            offchain_signer_commitment
        ) VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(&leaf_index_2_u256)
    .bind(&recovery_address_u160)
    .bind(sqlx::types::Json(Vec::<String>::new()))
    .bind(sqlx::types::Json(Vec::<String>::new()))
    .bind(&commitment_2)
    .execute(&test_pool)
    .await
    .expect("Failed to insert account 2");

    sqlx::query(
        r#"
        INSERT INTO accounts (
            leaf_index,
            recovery_address,
            authenticator_addresses,
            authenticator_pubkeys,
            offchain_signer_commitment
        ) VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(&leaf_index_max_u256)
    .bind(&recovery_address_u160)
    .bind(sqlx::types::Json(Vec::<String>::new()))
    .bind(sqlx::types::Json(Vec::<String>::new()))
    .bind(&commitment_max)
    .execute(&test_pool)
    .await
    .expect("Failed to insert account max");

    // Insert into world_tree_events table with bytea leaf_index
    sqlx::query(
        r#"
        INSERT INTO world_tree_events (
            block_number,
            log_index,
            leaf_index,
            event_type,
            offchain_signer_commitment,
            tx_hash
        ) VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(100i64)
    .bind(0i64)
    .bind(&leaf_index_1_u256)
    .bind("account_created")
    .bind(&commitment_1)
    .bind(&U256::from(999))
    .execute(&test_pool)
    .await
    .expect("Failed to insert event 1");

    sqlx::query(
        r#"
        INSERT INTO world_tree_events (
            block_number,
            log_index,
            leaf_index,
            event_type,
            offchain_signer_commitment,
            tx_hash
        ) VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(101i64)
    .bind(1i64)
    .bind(&leaf_index_2_u256)
    .bind("account_updated")
    .bind(&commitment_2)
    .bind(&U256::from(999))
    .execute(&test_pool)
    .await
    .expect("Failed to insert event 2");

    sqlx::query(
        r#"
        INSERT INTO world_tree_events (
            block_number,
            log_index,
            leaf_index,
            event_type,
            offchain_signer_commitment,
            tx_hash
        ) VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(102i64)
    .bind(2i64)
    .bind(&leaf_index_max_u256)
    .bind("account_created")
    .bind(&commitment_max)
    .bind(&U256::from(999))
    .execute(&test_pool)
    .await
    .expect("Failed to insert event max");

    // Verify data was inserted as bytea
    let type_before: (String,) = sqlx::query_as(
        r#"
        SELECT data_type
        FROM information_schema.columns
        WHERE table_name = 'accounts' AND column_name = 'leaf_index'
        "#,
    )
    .fetch_one(&test_pool)
    .await
    .unwrap();
    assert_eq!(
        type_before.0, "bytea",
        "leaf_index should be bytea before migration"
    );

    // NOW RUN MIGRATION 0013
    let migration_13_content =
        std::fs::read_to_string(migration_path.join("0013_change_leaf_index_to_bigint.sql"))
            .expect("Failed to read migration 0013");

    // Split migration file by semicolons and execute each statement separately
    for statement in migration_13_content.split(';') {
        let trimmed = statement.trim();
        if !trimmed.is_empty() && !trimmed.starts_with("--") {
            sqlx::query(trimmed)
                .execute(&test_pool)
                .await
                .expect("Failed to run migration 0013 statement");
        }
    }

    // Verify the column type changed to bigint
    let type_after: (String,) = sqlx::query_as(
        r#"
        SELECT data_type
        FROM information_schema.columns
        WHERE table_name = 'accounts' AND column_name = 'leaf_index'
        "#,
    )
    .fetch_one(&test_pool)
    .await
    .unwrap();
    assert_eq!(
        type_after.0, "bigint",
        "leaf_index should be bigint after migration"
    );

    let type_after_events: (String,) = sqlx::query_as(
        r#"
        SELECT data_type
        FROM information_schema.columns
        WHERE table_name = 'world_tree_events' AND column_name = 'leaf_index'
        "#,
    )
    .fetch_one(&test_pool)
    .await
    .unwrap();
    assert_eq!(
        type_after_events.0, "bigint",
        "leaf_index should be bigint after migration in world_tree_events"
    );

    // Verify the data was correctly converted
    // Check accounts table
    let account_1: (i64,) =
        sqlx::query_as("SELECT leaf_index FROM accounts WHERE offchain_signer_commitment = $1")
            .bind(&commitment_1)
            .fetch_one(&test_pool)
            .await
            .unwrap();
    assert_eq!(
        account_1.0 as u64, leaf_index_1_u64,
        "Account 1 leaf_index should be correctly converted"
    );

    let account_2: (i64,) =
        sqlx::query_as("SELECT leaf_index FROM accounts WHERE offchain_signer_commitment = $1")
            .bind(&commitment_2)
            .fetch_one(&test_pool)
            .await
            .unwrap();
    assert_eq!(
        account_2.0 as u64, leaf_index_2_u64,
        "Account 2 leaf_index should be correctly converted"
    );

    let account_max: (i64,) =
        sqlx::query_as("SELECT leaf_index FROM accounts WHERE offchain_signer_commitment = $1")
            .bind(&commitment_max)
            .fetch_one(&test_pool)
            .await
            .unwrap();
    assert_eq!(
        account_max.0 as u64, leaf_index_max_u64,
        "Account max leaf_index should be correctly converted"
    );

    // Check world_tree_events table
    let event_1: (i64,) =
        sqlx::query_as("SELECT leaf_index FROM world_tree_events WHERE block_number = 100")
            .fetch_one(&test_pool)
            .await
            .unwrap();
    assert_eq!(
        event_1.0 as u64, leaf_index_1_u64,
        "Event 1 leaf_index should be correctly converted"
    );

    let event_2: (i64,) =
        sqlx::query_as("SELECT leaf_index FROM world_tree_events WHERE block_number = 101")
            .fetch_one(&test_pool)
            .await
            .unwrap();
    assert_eq!(
        event_2.0 as u64, leaf_index_2_u64,
        "Event 2 leaf_index should be correctly converted"
    );

    let event_max: (i64,) =
        sqlx::query_as("SELECT leaf_index FROM world_tree_events WHERE block_number = 102")
            .fetch_one(&test_pool)
            .await
            .unwrap();
    assert_eq!(
        event_max.0 as u64, leaf_index_max_u64,
        "Event max leaf_index should be correctly converted"
    );

    // Cleanup
    drop(test_pool);
    cleanup_test_db(&unique_name).await;
}

/// Test that migration works with the current code after migration is applied
#[tokio::test]
async fn test_migration_0013_leaf_index_to_bigint() {
    // Create a unique test database (migrations already applied)
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert test data - these will use the bigint schema since migrations already ran
    let leaf_index_1 = U256::from(1);
    let leaf_index_2 = U256::from(42);
    let leaf_index_max = U256::from(u64::MAX);

    let recovery_address = Address::ZERO;
    let auth_addresses = vec![Address::ZERO];
    let auth_pubkeys = vec![U256::from(123)];
    let commitment_1 = U256::from(456);
    let commitment_2 = U256::from(789);
    let commitment_max = U256::from(999);

    // Insert accounts
    db.accounts()
        .insert(
            u64::try_from(leaf_index_1).unwrap(),
            &recovery_address,
            &auth_addresses,
            &auth_pubkeys,
            &commitment_1,
        )
        .await
        .unwrap();

    db.accounts()
        .insert(
            u64::try_from(leaf_index_2).unwrap(),
            &recovery_address,
            &auth_addresses,
            &auth_pubkeys,
            &commitment_2,
        )
        .await
        .unwrap();

    db.accounts()
        .insert(
            u64::try_from(leaf_index_max).unwrap(),
            &recovery_address,
            &auth_addresses,
            &auth_pubkeys,
            &commitment_max,
        )
        .await
        .unwrap();

    // Insert world tree events
    db.world_tree_events()
        .insert_event(
            u64::try_from(leaf_index_1).unwrap(),
            WorldTreeEventType::AccountCreated,
            &commitment_1,
            100,
            &U256::from(999),
            0,
        )
        .await
        .unwrap();

    db.world_tree_events()
        .insert_event(
            u64::try_from(leaf_index_2).unwrap(),
            WorldTreeEventType::AccountUpdated,
            &commitment_2,
            101,
            &U256::from(999),
            1,
        )
        .await
        .unwrap();

    db.world_tree_events()
        .insert_event(
            u64::try_from(leaf_index_max).unwrap(),
            WorldTreeEventType::AccountCreated,
            &commitment_max,
            102,
            &U256::from(999),
            2,
        )
        .await
        .unwrap();

    // Verify the data is correctly stored and can be retrieved

    // Check accounts table - verify leaf_index is stored as bigint
    let pool = db.pool();

    // Query to check the data type of leaf_index column
    let type_query = sqlx::query(
        r#"
        SELECT data_type
        FROM information_schema.columns
        WHERE table_name = 'accounts' AND column_name = 'leaf_index'
        "#,
    )
    .fetch_one(pool)
    .await
    .unwrap();

    let data_type: String = type_query.get("data_type");
    assert_eq!(
        data_type, "bigint",
        "leaf_index should be bigint type in accounts table"
    );

    // Query to check the data type of leaf_index column in world_tree_events
    let type_query = sqlx::query(
        r#"
        SELECT data_type
        FROM information_schema.columns
        WHERE table_name = 'world_tree_events' AND column_name = 'leaf_index'
        "#,
    )
    .fetch_one(pool)
    .await
    .unwrap();

    let data_type: String = type_query.get("data_type");
    assert_eq!(
        data_type, "bigint",
        "leaf_index should be bigint type in world_tree_events table"
    );

    // Verify accounts can be retrieved correctly
    let account_1 = db
        .accounts()
        .get_account(u64::try_from(leaf_index_1).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account_1.leaf_index, 1);
    assert_eq!(account_1.offchain_signer_commitment, commitment_1);

    let account_2 = db
        .accounts()
        .get_account(u64::try_from(leaf_index_2).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account_2.leaf_index, 42);
    assert_eq!(account_2.offchain_signer_commitment, commitment_2);

    let account_max = db
        .accounts()
        .get_account(u64::try_from(leaf_index_max).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account_max.leaf_index, u64::MAX);
    assert_eq!(account_max.offchain_signer_commitment, commitment_max);

    // Verify events can be retrieved correctly
    let event_1 = db
        .world_tree_events()
        .get_event((100, 0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event_1.leaf_index, 1);
    assert_eq!(event_1.offchain_signer_commitment, commitment_1);

    let event_2 = db
        .world_tree_events()
        .get_event((101, 1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event_2.leaf_index, 42);
    assert_eq!(event_2.offchain_signer_commitment, commitment_2);

    let event_max = db
        .world_tree_events()
        .get_event((102, 2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event_max.leaf_index, u64::MAX);
    assert_eq!(event_max.offchain_signer_commitment, commitment_max);

    // Verify streaming works correctly
    use futures_util::StreamExt;

    let mut stream = db
        .accounts()
        .stream_leaf_index_and_offchain_signer_commitment();

    let mut count = 0;
    while let Some(result) = stream.next().await {
        let (leaf_idx, _commitment) = result.unwrap();
        assert!(leaf_idx == 1 || leaf_idx == 42 || leaf_idx == u64::MAX);
        count += 1;
    }
    assert_eq!(count, 3, "Should stream all 3 accounts");
}

/// Test that leaf_index values outside u64 range are properly rejected
#[tokio::test]
async fn test_leaf_index_out_of_range_rejected() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Try to insert a leaf_index larger than u64::MAX
    let leaf_index_too_large = U256::from(u64::MAX) + U256::from(1);

    // The conversion itself should fail
    let conversion_result = u64::try_from(leaf_index_too_large);
    assert!(
        conversion_result.is_err(),
        "Should reject leaf_index larger than u64::MAX"
    );

    // Verify the error is about the value being too large
    let err_msg = conversion_result.unwrap_err().to_string();
    assert!(
        err_msg.contains("too large") || err_msg.contains("Overflow"),
        "Error message should indicate the issue: {}",
        err_msg
    );
}

/// Test that leaf_index comparison and ordering works correctly after migration
#[tokio::test]
async fn test_leaf_index_ordering_after_migration() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    // Insert accounts in non-sequential order
    let indices = vec![100u64, 5, 50, 1, 200];

    for idx in &indices {
        db.accounts()
            .insert(
                *idx as u64,
                &Address::ZERO,
                &[],
                &[],
                &U256::from(*idx as u128 * 10),
            )
            .await
            .unwrap();
    }

    // Verify ordering works correctly with streaming
    use futures_util::StreamExt;

    let mut stream = db
        .accounts()
        .stream_leaf_index_and_offchain_signer_commitment();

    let mut last_index = 0u64;
    let mut count = 0;

    while let Some(result) = stream.next().await {
        let (leaf_idx, _) = result.unwrap();
        // Verify ascending order
        assert!(
            leaf_idx > last_index || count == 0,
            "Leaf indices should be in ascending order. Got {} after {}",
            leaf_idx,
            last_index
        );
        last_index = leaf_idx;
        count += 1;
    }

    assert_eq!(count, 5, "Should retrieve all 5 accounts in order");
    assert_eq!(last_index, 200, "Last index should be 200");
}

/// Test that queries with leaf_index work correctly after migration
#[tokio::test]
async fn test_leaf_index_queries_after_migration() {
    let test_db = create_unique_test_db().await;
    let db = &test_db.db;

    let leaf_index = 12345u64;
    let commitment = U256::from(67890);

    // Insert account
    db.accounts()
        .insert(
            leaf_index,
            &Address::ZERO,
            &[Address::from([1u8; 20])],
            &[U256::from(111)],
            &commitment,
        )
        .await
        .unwrap();

    // Test get_account query
    let account = db
        .accounts()
        .get_account(leaf_index)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.leaf_index, 12345);

    // Test get_offchain_signer_commitment_and_authenticator_pubkeys_by_leaf_index query
    let result = db
        .accounts()
        .get_offchain_signer_commitment_and_authenticator_pubkeys_by_leaf_index(leaf_index)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(result.0, commitment);
    assert_eq!(result.1, vec![U256::from(111)]);

    // Test update operations work with leaf_index
    let new_commitment = U256::from(99999);
    db.accounts()
        .update_authenticator_at_index(
            leaf_index,
            0,
            &Address::from([2u8; 20]),
            &U256::from(222),
            &new_commitment,
        )
        .await
        .unwrap();

    let updated_account = db
        .accounts()
        .get_account(leaf_index)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated_account.offchain_signer_commitment, new_commitment);
}
