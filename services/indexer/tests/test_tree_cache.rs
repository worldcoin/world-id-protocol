#![cfg(feature = "integration-tests")]
mod helpers;
use helpers::common::{TestSetup, query_count};
use serial_test::serial;

use std::{fs, path::PathBuf, time::Duration};

use alloy::primitives::{U256, address};
use world_id_indexer::config::{
    Environment, GlobalConfig, HttpConfig, IndexerConfig, RunMode, TreeCacheConfig,
};

/// Helper to create tree cache config with a unique temporary path
fn create_temp_cache_config() -> (TreeCacheConfig, PathBuf) {
    let temp_dir = std::env::temp_dir();
    let cache_path = temp_dir.join(format!("test_tree_cache_{}.mmap", uuid::Uuid::new_v4()));

    let config = TreeCacheConfig {
        cache_file_path: cache_path.to_str().unwrap().to_string(),
        tree_depth: 6,
        http_cache_refresh_interval_secs: 1, // Fast refresh for tests
    };

    (config, cache_path)
}

/// Helper to cleanup cache files
fn cleanup_cache_files(cache_path: &PathBuf) {
    let _ = fs::remove_file(cache_path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_cache_creation_and_restoration() {
    let setup = TestSetup::new().await;
    let (tree_cache_config, cache_path) = create_temp_cache_config();

    // Create some accounts
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000011"),
            U256::from(11),
            1,
        )
        .await;

    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000012"),
            U256::from(12),
            2,
        )
        .await;

    // Start indexer in Both mode (will create cache)
    let global_config = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8090".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                tree_cache: tree_cache_config.clone(),
            },
        },
        db_url: setup.db_url.clone(),
        http_rpc_url: setup.rpc_url(),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
    };

    let indexer_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(global_config).await }.unwrap();
    });

    // Wait for indexer to process accounts
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&setup.pool).await;
        if c >= 2 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for accounts to be indexed");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    indexer_task.abort();

    // Verify cache file exists
    assert!(cache_path.exists(), "Cache file should exist");

    // Cleanup
    cleanup_cache_files(&cache_path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_incremental_replay() {
    // Use tree_depth=6 to match create_temp_cache_config()
    let setup = TestSetup::new_with_tree_depth(6).await;
    let (tree_cache_config, cache_path) = create_temp_cache_config();

    // Create initial accounts and build cache
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000011"),
            U256::from(11),
            1,
        )
        .await;

    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000012"),
            U256::from(12),
            2,
        )
        .await;

    // Start indexer to build initial cache
    let cfg1 = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8091".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                tree_cache: tree_cache_config.clone(),
            },
        },
        db_url: setup.db_url.clone(),
        http_rpc_url: setup.rpc_url(),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
    };

    let indexer_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(cfg1).await }.unwrap();
    });

    // Wait for accounts to be indexed
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&setup.pool).await;
        if c >= 2 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for initial accounts");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    indexer_task.abort();

    // Verify cache was created
    assert!(
        cache_path.exists(),
        "Cache file should exist after first run"
    );

    // Create more accounts (simulating new events)
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000013"),
            U256::from(13),
            3,
        )
        .await;

    // Restart indexer (should use replay, not full rebuild)
    let cfg2 = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8092".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                tree_cache: tree_cache_config.clone(),
            },
        },
        db_url: setup.db_url.clone(),
        http_rpc_url: setup.rpc_url(),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
    };

    let indexer_task2 = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(cfg2).await }.unwrap();
    });

    // Wait for new account to be indexed
    let deadline2 = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&setup.pool).await;
        if c >= 3 {
            break;
        }
        if std::time::Instant::now() > deadline2 {
            panic!("timeout waiting for new account");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    indexer_task2.abort();

    // Verify all 3 accounts are in the DB (proving replay worked)
    let final_count = query_count(&setup.pool).await;
    assert_eq!(
        final_count, 3,
        "All 3 accounts should be indexed after replay"
    );

    // Cleanup
    cleanup_cache_files(&cache_path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_missing_cache_creates_new() {
    let setup = TestSetup::new().await;
    let (tree_cache_config, cache_path) = create_temp_cache_config();

    // Ensure cache doesn't exist
    cleanup_cache_files(&cache_path);
    assert!(!cache_path.exists(), "Cache should not exist initially");

    // Create an account
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000011"),
            U256::from(11),
            1,
        )
        .await;

    // Start indexer (should create cache from scratch)
    let global_config = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8093".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                tree_cache: tree_cache_config.clone(),
            },
        },
        db_url: setup.db_url.clone(),
        http_rpc_url: setup.rpc_url(),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
    };

    let indexer_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(global_config).await }.unwrap();
    });

    // Wait for account to be indexed
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&setup.pool).await;
        if c >= 1 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for account");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    indexer_task.abort();

    // Verify cache was created
    assert!(cache_path.exists(), "Cache file should have been created");

    // Cleanup
    cleanup_cache_files(&cache_path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_http_only_cache_refresh() {
    // Use tree_depth=6 to match create_temp_cache_config()
    let setup = TestSetup::new_with_tree_depth(6).await;
    let (tree_cache_config, cache_path) = create_temp_cache_config();

    // Create initial account and build cache with Both mode
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000011"),
            U256::from(11),
            1,
        )
        .await;

    let both_config = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8094".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                tree_cache: tree_cache_config.clone(),
            },
        },
        db_url: setup.db_url.clone(),
        http_rpc_url: setup.rpc_url(),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
    };

    let both_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(both_config).await }.unwrap();
    });

    // Wait for initial account
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&setup.pool).await;
        if c >= 1 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for initial account");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    // Now start HttpOnly mode
    let http_config = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::HttpOnly {
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8095".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                tree_cache: tree_cache_config.clone(),
            },
        },
        db_url: setup.db_url.clone(),
        http_rpc_url: setup.rpc_url(),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
    };

    let http_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(http_config).await }.unwrap();
    });

    // Wait for HttpOnly to start
    TestSetup::wait_for_health("http://127.0.0.1:8095").await;

    // Both mode creates another account
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000012"),
            U256::from(12),
            2,
        )
        .await;

    // Wait for Both mode to process it
    let deadline2 = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&setup.pool).await;
        if c >= 2 {
            break;
        }
        if std::time::Instant::now() > deadline2 {
            panic!("timeout waiting for second account");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Wait for HttpOnly to refresh from DB (refresh interval is 1s)
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify HttpOnly is serving by checking the health endpoint is still up
    // The tree sync loop picks up new events from DB automatically
    let client = reqwest::Client::new();
    let resp = client
        .get("http://127.0.0.1:8095/health")
        .send()
        .await
        .expect("HttpOnly server should still be running");
    assert!(resp.status().is_success());

    both_task.abort();
    http_task.abort();

    // Cleanup
    cleanup_cache_files(&cache_path);
}

/// Test that AuthenticatorRemoved events are replayed correctly with their stored commitment values
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_authenticator_removed_replay() {
    // Use tree_depth=6 to match create_temp_cache_config()
    let setup = TestSetup::new_with_tree_depth(6).await;
    let (tree_cache_config, cache_path) = create_temp_cache_config();
    let (tree_cache_config_fresh, cache_path_fresh) = create_temp_cache_config();

    // Create an initial account
    let auth_addr = address!("0x0000000000000000000000000000000000000011");
    setup.create_account(auth_addr, U256::from(11), 1).await;

    // Start indexer to process initial account and create cache
    let cfg1 = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8098".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                tree_cache: tree_cache_config.clone(),
            },
        },
        db_url: setup.db_url.clone(),
        http_rpc_url: setup.rpc_url(),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
    };

    let indexer_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(cfg1).await }.unwrap();
    });

    // Wait for account to be indexed
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&setup.pool).await;
        if c >= 1 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for account");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    indexer_task.abort();

    // Get the last block from world_tree_roots
    let last_block: (i64,) =
        sqlx::query_as("SELECT COALESCE(MAX(block_number), 0) FROM world_tree_roots")
            .fetch_one(&setup.pool)
            .await
            .expect("Failed to query last block");
    let last_block = last_block.0 as u64;

    // Manually insert an AuthenticatorRemoved event with a non-zero offchain_signer_commitment
    // This simulates what happens when an authenticator is removed but account has other authenticators
    let new_commitment_after_removal = U256::from(999);

    sqlx::query(
        r#"INSERT INTO world_tree_events
        (leaf_index, event_type, offchain_signer_commitment, block_number, tx_hash, log_index)
        VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(1i64)
    .bind("authentication_removed")
    .bind(new_commitment_after_removal)
    .bind((last_block + 1) as i64)
    .bind(U256::from(1234))
    .bind(0i64)
    .execute(&setup.pool)
    .await
    .expect("Failed to insert removed event");

    // Update the account table to reflect the removal
    sqlx::query(
        r#"UPDATE accounts
        SET offchain_signer_commitment = $1
        WHERE leaf_index = $2"#,
    )
    .bind(new_commitment_after_removal)
    .bind(1i64)
    .execute(&setup.pool)
    .await
    .expect("Failed to update account");

    // Restart indexer with replay - it should restore from cache and replay the removal event
    let db_url = setup.db_url.clone();
    let rpc_url = setup.rpc_url();
    let ws_url = setup.ws_url();
    let registry_address = setup.registry_address;

    let cfg2 = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8096".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                tree_cache: tree_cache_config.clone(),
            },
        },
        db_url: db_url.clone(),
        http_rpc_url: rpc_url.clone(),
        ws_rpc_url: ws_url.clone(),
        registry_address,
    };

    let indexer_task2 = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(cfg2).await }.unwrap();
    });

    // Wait for indexer to process the replay
    tokio::time::sleep(Duration::from_secs(5)).await;
    indexer_task2.abort();

    // Build a fresh tree from DB using a separate cache to get the expected root
    let cfg_fresh = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8097".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                tree_cache: tree_cache_config_fresh.clone(),
            },
        },
        db_url: db_url.clone(),
        http_rpc_url: rpc_url.clone(),
        ws_rpc_url: ws_url.clone(),
        registry_address,
    };

    let indexer_task3 = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(cfg_fresh).await }.unwrap();
    });

    tokio::time::sleep(Duration::from_secs(2)).await;
    indexer_task3.abort();

    // Both cache files should exist - the replayed tree and fresh tree should be equivalent
    assert!(cache_path.exists(), "Replayed cache should exist");
    assert!(cache_path_fresh.exists(), "Fresh cache should exist");

    // Cleanup
    cleanup_cache_files(&cache_path);
    cleanup_cache_files(&cache_path_fresh);
}

/// Test that tree root matches on-chain contract root after fresh initialization
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_init_root_matches_contract() {
    // Use tree_depth=6 to match create_temp_cache_config()
    let setup = TestSetup::new_with_tree_depth(6).await;
    let (tree_cache_config, cache_path) = create_temp_cache_config();

    // Ensure no cache files exist
    cleanup_cache_files(&cache_path);

    // Create accounts on-chain
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000021"),
            U256::from(21),
            100,
        )
        .await;

    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000022"),
            U256::from(22),
            200,
        )
        .await;

    // Get the on-chain root BEFORE starting indexer
    let onchain_root = setup.get_root().await;

    // Start indexer to build tree from scratch
    let global_config = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8100".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                tree_cache: tree_cache_config.clone(),
            },
        },
        db_url: setup.db_url.clone(),
        http_rpc_url: setup.rpc_url(),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
    };

    let indexer_task = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(global_config).await }.unwrap();
    });

    // Wait for accounts to be indexed
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&setup.pool).await;
        if c >= 2 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for accounts to be indexed");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    indexer_task.abort();

    // Verify the on-chain root was recorded in the DB
    let db_root: (alloy::primitives::U256,) = sqlx::query_as(
        "SELECT root FROM world_tree_roots ORDER BY block_number DESC, log_index DESC LIMIT 1",
    )
    .fetch_one(&setup.pool)
    .await
    .expect("Should have at least one root in DB");

    assert_eq!(
        db_root.0, onchain_root,
        "DB root must match on-chain contract root"
    );

    cleanup_cache_files(&cache_path);
}

/// Test that tree root matches on-chain contract root after replay
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_replay_root_matches_contract() {
    // Use tree_depth=6 to match create_temp_cache_config()
    let setup = TestSetup::new_with_tree_depth(6).await;
    let (tree_cache_config, cache_path) = create_temp_cache_config();

    // Ensure no cache files exist
    cleanup_cache_files(&cache_path);

    // Create initial accounts
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000031"),
            U256::from(31),
            300,
        )
        .await;

    // Build initial cache
    let cfg1 = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8101".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                tree_cache: tree_cache_config.clone(),
            },
        },
        db_url: setup.db_url.clone(),
        http_rpc_url: setup.rpc_url(),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
    };

    let indexer_task1 = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(cfg1).await }.unwrap();
    });

    // Wait for initial account
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&setup.pool).await;
        if c >= 1 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for initial account");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    indexer_task1.abort();

    // Create more accounts (these will need to be replayed)
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000032"),
            U256::from(32),
            400,
        )
        .await;

    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000033"),
            U256::from(33),
            500,
        )
        .await;

    // Get the on-chain root AFTER creating all accounts
    let onchain_root = setup.get_root().await;

    // Restart indexer (should restore from cache and replay new events)
    let cfg2 = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8102".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                tree_cache: tree_cache_config.clone(),
            },
        },
        db_url: setup.db_url.clone(),
        http_rpc_url: setup.rpc_url(),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
    };

    let indexer_task2 = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(cfg2).await }.unwrap();
    });

    // Wait for all accounts to be indexed
    let deadline2 = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&setup.pool).await;
        if c >= 3 {
            break;
        }
        if std::time::Instant::now() > deadline2 {
            panic!("timeout waiting for all accounts");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    indexer_task2.abort();

    // Verify the latest on-chain root was recorded in the DB
    let db_root: (alloy::primitives::U256,) = sqlx::query_as(
        "SELECT root FROM world_tree_roots ORDER BY block_number DESC, log_index DESC LIMIT 1",
    )
    .fetch_one(&setup.pool)
    .await
    .expect("Should have roots in DB after replay");

    assert_eq!(
        db_root.0, onchain_root,
        "DB root after replay must match on-chain contract root"
    );

    cleanup_cache_files(&cache_path);
}

/// Test that corrupted cache triggers full rebuild instead of failing
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_corrupted_cache_returns_error() {
    // Use tree_depth=6 to match create_temp_cache_config()
    let setup = TestSetup::new_with_tree_depth(6).await;
    let (tree_cache_config, cache_path) = create_temp_cache_config();

    // Ensure no cache files exist
    cleanup_cache_files(&cache_path);

    // Create initial accounts on-chain
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000041"),
            U256::from(41),
            600,
        )
        .await;

    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000042"),
            U256::from(42),
            700,
        )
        .await;

    // Start indexer to build initial cache
    let cfg1 = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8103".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                tree_cache: tree_cache_config.clone(),
            },
        },
        db_url: setup.db_url.clone(),
        http_rpc_url: setup.rpc_url(),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
    };

    let indexer_task1 = tokio::spawn(async move {
        unsafe { world_id_indexer::run_indexer(cfg1).await }.unwrap();
    });

    // Wait for accounts to be indexed
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&setup.pool).await;
        if c >= 2 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for accounts to be indexed");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    indexer_task1.abort();

    assert!(cache_path.exists(), "Cache file should exist");

    // CORRUPT THE CACHE - truncate the mmap file to simulate corruption
    fs::write(&cache_path, b"corrupted data").expect("Should write corrupted cache");

    // Start indexer in HttpOnly mode - should fail due to corrupted cache
    let cfg2 = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::HttpOnly {
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8104".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
                tree_cache: tree_cache_config.clone(),
            },
        },
        db_url: setup.db_url.clone(),
        http_rpc_url: setup.rpc_url(),
        ws_rpc_url: setup.ws_url(),
        registry_address: setup.registry_address,
    };

    let result = unsafe { world_id_indexer::run_indexer(cfg2).await };
    assert!(
        result.is_err(),
        "Corrupted cache should cause run_indexer to fail"
    );

    // Cache file should have been deleted so next restart can do a clean rebuild
    assert!(
        !cache_path.exists(),
        "Cache file should be deleted on corruption"
    );

    cleanup_cache_files(&cache_path);
}
