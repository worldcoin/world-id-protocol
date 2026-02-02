use alloy::primitives::{Address, U256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;
use world_id_indexer::db::{DB, DBResult, WorldTreeEventType, WorldTreeRootEventType};

/// Creates a unique test database for isolation between tests
pub async fn create_unique_test_db() -> (DB, String) {
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
    // Properly replace just the database name in the URL
    let test_db_url = if let Some(pos) = base_url.rfind('/') {
        format!("{}/{}", &base_url[..pos], unique_name)
    } else {
        format!("{}/{}", base_url, unique_name)
    };
    let db = DB::new(&test_db_url, Some(5))
        .await
        .expect("Failed to connect to test database");

    db.run_migrations().await.expect("Failed to run migrations");

    (db, unique_name)
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
#[allow(dead_code)]
pub async fn insert_test_account(
    db: &DB,
    leaf_index: U256,
    recovery_address: Address,
    commitment: U256,
) -> DBResult<()> {
    db.accounts()
        .insert(&leaf_index, &recovery_address, &[], &[], &commitment)
        .await
}

/// Insert a test world tree event directly into the database
#[allow(dead_code)]
pub async fn insert_test_world_tree_event(
    db: &DB,
    block_number: u64,
    log_index: u64,
    leaf_index: U256,
    event_type: WorldTreeEventType,
    tx_hash: U256,
    commitment: U256,
) -> DBResult<()> {
    db.world_tree_events()
        .insert_event(
            &leaf_index,
            event_type,
            &commitment,
            block_number,
            &tx_hash,
            log_index,
        )
        .await
}

/// Insert a test world tree root event directly into the database
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
pub async fn count_world_tree_roots(pool: &PgPool) -> DBResult<i64> {
    let (count,): (i64,) =
        sqlx::query_as::<sqlx::Postgres, (i64,)>("SELECT COUNT(*) FROM world_tree_roots")
            .fetch_one(pool)
            .await?;
    Ok(count)
}

/// Check if account exists by leaf index
#[allow(dead_code)]
pub async fn account_exists(pool: &PgPool, leaf_index: U256) -> DBResult<bool> {
    let count: (i64,) = sqlx::query_as::<sqlx::Postgres, (i64,)>(
        "SELECT COUNT(*) FROM accounts WHERE leaf_index = $1",
    )
    .bind(leaf_index)
    .fetch_one(pool)
    .await?;

    Ok(count.0 > 0)
}
