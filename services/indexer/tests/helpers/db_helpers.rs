#![allow(dead_code)]

use alloy::primitives::{Address, U256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;
use world_id_indexer::db::{DB, DBResult, WorldTreeEventType, WorldTreeRootEventType};

/// RAII guard that ensures test database cleanup on drop
pub struct TestDatabase {
    pub db: DB,
    db_url: String,
    db_name: Option<String>,
}

impl TestDatabase {
    /// Get a reference to the underlying DB
    pub fn db(&self) -> &DB {
        &self.db
    }

    /// Get the database URL
    pub fn db_url(&self) -> &str {
        &self.db_url
    }

    /// Get the database name
    pub fn db_name(&self) -> &str {
        self.db_name.as_ref().expect("Database already cleaned up")
    }

    /// Explicitly cleanup the test database
    /// This is called automatically on drop, but you can call it explicitly
    /// if you want to handle cleanup errors
    pub async fn cleanup(mut self) {
        if let Some(db_name) = self.db_name.take() {
            cleanup_test_db(&db_name).await;
        }
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        if let Some(db_name) = self.db_name.take() {
            // Best effort cleanup - spawn a thread with its own runtime
            // This is not ideal but necessary since Drop is synchronous
            let _ = std::thread::spawn(move || {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    rt.block_on(async {
                        cleanup_test_db(&db_name).await;
                    });
                }
            })
            .join();
        }
    }
}

/// Creates a unique test database for isolation between tests
/// Returns a TestDatabase guard that will automatically cleanup on drop
pub async fn create_unique_test_db() -> TestDatabase {
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
    // Replace just the database name while preserving query parameters
    let test_db_url = if let Some(pos) = base_url.rfind('/') {
        let (_base, path_and_query) = base_url.split_at(pos + 1);
        // Split database name from query string
        let query_start = path_and_query.find('?');
        let query_str = query_start.map(|idx| &path_and_query[idx..]).unwrap_or("");
        format!("{}{}{}", &base_url[..pos + 1], unique_name, query_str)
    } else {
        format!("{}/{}", base_url, unique_name)
    };
    let db = DB::new(&test_db_url, Some(5))
        .await
        .expect("Failed to connect to test database");

    db.run_migrations().await.expect("Failed to run migrations");

    TestDatabase {
        db,
        db_url: test_db_url,
        db_name: Some(unique_name),
    }
}

/// Cleanup test database
pub async fn cleanup_test_db(db_name: &str) {
    let base_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost:5432/postgres".to_string());

    if let Ok(pool) = PgPoolOptions::new()
        .max_connections(1)
        .connect(&base_url)
        .await
    {
        // Terminate connections to the database first
        let _ = sqlx::query(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}'",
            db_name
        ))
        .execute(&pool)
        .await;

        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {}", db_name))
            .execute(&pool)
            .await;
    }
}

/// Insert a test account directly into the database
pub async fn insert_test_account(
    db: &DB,
    leaf_index: u64,
    recovery_address: Address,
    commitment: U256,
) -> DBResult<()> {
    db.accounts()
        .insert(leaf_index, &recovery_address, &[], &[], &commitment)
        .await
}

/// Insert a test world tree event directly into the database
pub async fn insert_test_world_tree_event(
    db: &DB,
    block_number: u64,
    log_index: u64,
    leaf_index: u64,
    event_type: WorldTreeEventType,
    tx_hash: U256,
    commitment: U256,
) -> DBResult<()> {
    db.world_tree_events()
        .insert_event(
            leaf_index,
            event_type,
            &commitment,
            block_number,
            &tx_hash,
            log_index,
        )
        .await
}

/// Insert a test world tree root event directly into the database
pub async fn insert_test_world_tree_root(
    db: &DB,
    block_number: u64,
    log_index: u64,
    root: U256,
    timestamp: U256,
) -> DBResult<()> {
    db.world_tree_roots()
        .insert_event(
            block_number,
            log_index,
            WorldTreeRootEventType::RootRecorded,
            &U256::ZERO,
            &root,
            &timestamp,
        )
        .await
}

/// Count accounts in the database
pub async fn count_accounts(pool: &PgPool) -> DBResult<i64> {
    let (count,): (i64,) =
        sqlx::query_as::<sqlx::Postgres, (i64,)>("SELECT COUNT(*) FROM accounts")
            .fetch_one(pool)
            .await?;
    Ok(count)
}

/// Count world tree events in the database
pub async fn count_world_tree_events(pool: &PgPool) -> DBResult<i64> {
    let (count,): (i64,) =
        sqlx::query_as::<sqlx::Postgres, (i64,)>("SELECT COUNT(*) FROM world_tree_events")
            .fetch_one(pool)
            .await?;
    Ok(count)
}

/// Count world tree roots in the database
pub async fn count_world_tree_roots(pool: &PgPool) -> DBResult<i64> {
    let (count,): (i64,) =
        sqlx::query_as::<sqlx::Postgres, (i64,)>("SELECT COUNT(*) FROM world_tree_roots")
            .fetch_one(pool)
            .await?;
    Ok(count)
}

/// Check if account exists by leaf index
pub async fn account_exists(pool: &PgPool, leaf_index: u64) -> DBResult<bool> {
    let count: (i64,) = sqlx::query_as::<sqlx::Postgres, (i64,)>(
        "SELECT COUNT(*) FROM accounts WHERE leaf_index = $1",
    )
    .bind(leaf_index as i64)
    .fetch_one(pool)
    .await?;

    Ok(count.0 > 0)
}

// Assertion helpers to reduce test boilerplate

/// Assert that the number of accounts matches expected count
pub async fn assert_account_count(pool: &PgPool, expected: i64) {
    let actual = count_accounts(pool)
        .await
        .expect("Failed to count accounts");
    assert_eq!(
        actual, expected,
        "Expected {} accounts but found {}",
        expected, actual
    );
}

/// Assert that the number of world tree events matches expected count
pub async fn assert_event_count(pool: &PgPool, expected: i64) {
    let actual = count_world_tree_events(pool)
        .await
        .expect("Failed to count events");
    assert_eq!(
        actual, expected,
        "Expected {} events but found {}",
        expected, actual
    );
}

/// Assert that the number of world tree roots matches expected count
pub async fn assert_root_count(pool: &PgPool, expected: i64) {
    let actual = count_world_tree_roots(pool)
        .await
        .expect("Failed to count roots");
    assert_eq!(
        actual, expected,
        "Expected {} roots but found {}",
        expected, actual
    );
}

/// Assert that an account exists with the given leaf index
pub async fn assert_account_exists(pool: &PgPool, leaf_index: u64) {
    let exists = account_exists(pool, leaf_index)
        .await
        .expect("Failed to check account existence");
    assert!(
        exists,
        "Expected account with leaf_index {} to exist",
        leaf_index
    );
}

/// Assert that an account does not exist with the given leaf index
pub async fn assert_account_not_exists(pool: &PgPool, leaf_index: u64) {
    let exists = account_exists(pool, leaf_index)
        .await
        .expect("Failed to check account existence");
    assert!(
        !exists,
        "Expected account with leaf_index {} to not exist",
        leaf_index
    );
}
