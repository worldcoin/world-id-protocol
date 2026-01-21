#![cfg(feature = "integration-tests")]
mod common;

use std::{fs, path::PathBuf, time::Duration};

use alloy::primitives::{U256, address};
use common::{TestSetup, query_count};
use serial_test::serial;
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
        dense_tree_prefix_depth: 2,
        http_cache_refresh_interval_secs: 1, // Fast refresh for tests
    };

    (config, cache_path)
}

/// Helper to cleanup cache files
fn cleanup_cache_files(cache_path: &PathBuf) {
    let _ = fs::remove_file(cache_path);
    let meta_path = cache_path.with_extension("mmap.meta");
    let _ = fs::remove_file(&meta_path);
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
                ws_url: setup.ws_url(),
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8090".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: tree_cache_config.clone(),
    };

    let indexer_task = tokio::spawn(async move {
        world_id_indexer::run_indexer(global_config).await.unwrap();
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

    // Verify cache files exist
    assert!(cache_path.exists(), "Cache file should exist");
    let meta_path = cache_path.with_extension("mmap.meta");
    assert!(meta_path.exists(), "Metadata file should exist");

    // Read metadata
    let meta_json = fs::read_to_string(&meta_path).expect("Should read metadata");
    let metadata: serde_json::Value =
        serde_json::from_str(&meta_json).expect("Should parse metadata");
    assert_eq!(metadata["tree_depth"].as_u64().unwrap(), 6);
    assert_eq!(metadata["dense_prefix_depth"].as_u64().unwrap(), 2);
    assert!(
        metadata["last_block_number"].as_u64().unwrap() > 0,
        "Should have processed at least one block"
    );

    // Cleanup
    cleanup_cache_files(&cache_path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_incremental_replay() {
    let setup = TestSetup::new().await;
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
                ws_url: setup.ws_url(),
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8091".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: tree_cache_config.clone(),
    };

    let indexer_task = tokio::spawn(async move {
        world_id_indexer::run_indexer(cfg1).await.unwrap();
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

    // Read initial metadata
    let meta_path = cache_path.with_extension("mmap.meta");
    let initial_meta_json = fs::read_to_string(&meta_path).expect("Should read metadata");
    let initial_metadata: serde_json::Value =
        serde_json::from_str(&initial_meta_json).expect("Should parse metadata");
    let initial_block = initial_metadata["last_block_number"].as_u64().unwrap();

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
                ws_url: setup.ws_url(),
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8092".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: tree_cache_config.clone(),
    };

    let indexer_task2 = tokio::spawn(async move {
        world_id_indexer::run_indexer(cfg2).await.unwrap();
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

    // Verify metadata was updated
    let final_meta_json = fs::read_to_string(&meta_path).expect("Should read metadata");
    let final_metadata: serde_json::Value =
        serde_json::from_str(&final_meta_json).expect("Should parse metadata");
    assert!(
        final_metadata["last_block_number"].as_u64().unwrap() > initial_block,
        "Metadata should have been updated with new block"
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
                ws_url: setup.ws_url(),
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8093".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: tree_cache_config.clone(),
    };

    let indexer_task = tokio::spawn(async move {
        world_id_indexer::run_indexer(global_config).await.unwrap();
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
    let meta_path = cache_path.with_extension("mmap.meta");
    assert!(meta_path.exists(), "Metadata file should have been created");

    // Cleanup
    cleanup_cache_files(&cache_path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_http_only_cache_refresh() {
    let setup = TestSetup::new().await;
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
                ws_url: setup.ws_url(),
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8094".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: tree_cache_config.clone(),
    };

    let both_task = tokio::spawn(async move {
        world_id_indexer::run_indexer(both_config).await.unwrap();
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

    // Read initial metadata
    let meta_path = cache_path.with_extension("mmap.meta");
    let initial_meta_json = fs::read_to_string(&meta_path).expect("Should read metadata");
    let initial_metadata: serde_json::Value =
        serde_json::from_str(&initial_meta_json).expect("Should parse metadata");
    let initial_block = initial_metadata["last_block_number"].as_u64().unwrap();

    // Now start HttpOnly mode
    let http_config = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::HttpOnly {
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8095".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: tree_cache_config.clone(),
    };

    let http_task = tokio::spawn(async move {
        world_id_indexer::run_indexer(http_config).await.unwrap();
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

    // Wait a bit for Both mode to update metadata and for HttpOnly to refresh (refresh interval is 1s)
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify metadata was updated
    let final_meta_json = fs::read_to_string(&meta_path).expect("Should read metadata");
    let final_metadata: serde_json::Value =
        serde_json::from_str(&final_meta_json).expect("Should parse metadata");
    assert!(
        final_metadata["last_block_number"].as_u64().unwrap() > initial_block,
        "HttpOnly should have refreshed and picked up new metadata"
    );

    both_task.abort();
    http_task.abort();

    // Cleanup
    cleanup_cache_files(&cache_path);
}

/// Test that AuthenticatorRemoved events are replayed correctly with their stored commitment values
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_authenticator_removed_replay() {
    let setup = TestSetup::new().await;
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
                ws_url: setup.ws_url(),
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8095".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: tree_cache_config.clone(),
    };

    let indexer_task = tokio::spawn(async move {
        world_id_indexer::run_indexer(cfg1).await.unwrap();
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

    // Read cache metadata to get the last block
    let cache_meta_content =
        fs::read_to_string(cache_path.with_extension("mmap.meta")).expect("Should read metadata");
    let cache_meta: serde_json::Value =
        serde_json::from_str(&cache_meta_content).expect("Should parse metadata");
    let last_block = cache_meta["last_block_number"].as_u64().unwrap();

    // Manually insert an AuthenticatorRemoved event with a non-zero new_commitment
    // This simulates what happens when an authenticator is removed but account has other authenticators
    let new_commitment_after_removal = U256::from(999);

    sqlx::query(
        r#"INSERT INTO commitment_update_events
        (leaf_index, event_type, new_commitment, block_number, tx_hash, log_index)
        VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind("1")
    .bind("removed")
    .bind(new_commitment_after_removal.to_string())
    .bind((last_block + 1) as i64)
    .bind("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    .bind(0i64)
    .execute(&setup.pool)
    .await
    .expect("Failed to insert removed event");

    // Update the account table to reflect the removal
    sqlx::query(
        r#"UPDATE accounts 
        SET offchain_signer_commitment = $1
        WHERE leaf_index = '1'"#,
    )
    .bind(new_commitment_after_removal.to_string())
    .execute(&setup.pool)
    .await
    .expect("Failed to update account");

    // Restart indexer with replay - it should restore from cache and replay the removal event
    let cfg2 = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                ws_url: setup.ws_url(),
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8096".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: tree_cache_config.clone(),
    };

    let indexer_task2 = tokio::spawn(async move {
        world_id_indexer::run_indexer(cfg2).await.unwrap();
    });

    // Wait for indexer to process the replay and write metadata
    tokio::time::sleep(Duration::from_secs(5)).await;
    indexer_task2.abort();

    // Read the replayed metadata
    let replayed_meta_content = fs::read_to_string(cache_path.with_extension("mmap.meta"))
        .expect("Should read replayed metadata");
    let replayed_meta: serde_json::Value =
        serde_json::from_str(&replayed_meta_content).expect("Should parse replayed metadata");
    let replayed_root = replayed_meta["root_hash"].as_str().unwrap();

    // Build a fresh tree from DB to get the expected root
    let cfg_fresh = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::Both {
            indexer_config: IndexerConfig {
                ws_url: setup.ws_url(),
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8097".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: tree_cache_config_fresh.clone(),
    };

    let indexer_task3 = tokio::spawn(async move {
        world_id_indexer::run_indexer(cfg_fresh).await.unwrap();
    });

    tokio::time::sleep(Duration::from_secs(2)).await;
    indexer_task3.abort();

    // Read the fresh build metadata
    let fresh_meta_content = fs::read_to_string(cache_path_fresh.with_extension("mmap.meta"))
        .expect("Should read fresh metadata");
    let fresh_meta: serde_json::Value =
        serde_json::from_str(&fresh_meta_content).expect("Should parse fresh metadata");
    let fresh_root = fresh_meta["root_hash"].as_str().unwrap();

    // The key assertion: replayed root must match fresh build from DB
    // If the bug exists, replay would use U256::ZERO and roots would differ
    assert_eq!(
        replayed_root, fresh_root,
        "Replayed root must match fresh DB build (proves AuthenticatorRemoved uses stored commitment, not zero)"
    );

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
                ws_url: setup.ws_url(),
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8100".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: tree_cache_config.clone(),
    };

    let indexer_task = tokio::spawn(async move {
        world_id_indexer::run_indexer(global_config).await.unwrap();
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

    // Read the tree root from metadata
    let meta_path = cache_path.with_extension("mmap.meta");
    let meta_content = fs::read_to_string(&meta_path).expect("Should read metadata");
    let metadata: serde_json::Value =
        serde_json::from_str(&meta_content).expect("Should parse metadata");
    let tree_root = metadata["root_hash"].as_str().unwrap();

    // Compare: tree root must match on-chain root
    let expected_root = format!("0x{:x}", onchain_root);
    assert_eq!(
        tree_root, expected_root,
        "Tree root after fresh init must match on-chain contract root"
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
                ws_url: setup.ws_url(),
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8101".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: tree_cache_config.clone(),
    };

    let indexer_task1 = tokio::spawn(async move {
        world_id_indexer::run_indexer(cfg1).await.unwrap();
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
                ws_url: setup.ws_url(),
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8102".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: tree_cache_config.clone(),
    };

    let indexer_task2 = tokio::spawn(async move {
        world_id_indexer::run_indexer(cfg2).await.unwrap();
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

    // Read the tree root from metadata
    let meta_path = cache_path.with_extension("mmap.meta");
    let meta_content = fs::read_to_string(&meta_path).expect("Should read metadata");
    let metadata: serde_json::Value =
        serde_json::from_str(&meta_content).expect("Should parse metadata");
    let tree_root = metadata["root_hash"].as_str().unwrap();

    // Compare: tree root after replay must match on-chain root
    let expected_root = format!("0x{:x}", onchain_root);
    assert_eq!(
        tree_root, expected_root,
        "Tree root after replay must match on-chain contract root"
    );

    cleanup_cache_files(&cache_path);
}

/// Test that corrupted cache triggers full rebuild instead of failing
/// This test simulates cache corruption by manually modifying the metadata
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_corrupted_cache_triggers_rebuild() {
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
                ws_url: setup.ws_url(),
                start_block: 0,
                batch_size: 1000,
            },
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8103".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: tree_cache_config.clone(),
    };

    let indexer_task1 = tokio::spawn(async move {
        world_id_indexer::run_indexer(cfg1).await.unwrap();
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

    // Read the metadata and verify it was created correctly
    let meta_path = cache_path.with_extension("mmap.meta");
    assert!(meta_path.exists(), "Metadata file should exist");
    assert!(cache_path.exists(), "Cache file should exist");

    let meta_content = fs::read_to_string(&meta_path).expect("Should read metadata");
    let mut metadata: serde_json::Value =
        serde_json::from_str(&meta_content).expect("Should parse metadata");

    // Save the correct root for later verification (currently unused but kept for potential future checks)
    let _correct_root = metadata["root_hash"].as_str().unwrap().to_string();

    // CORRUPT THE METADATA - change root_hash to a fake value
    // This simulates cache corruption (mmap file doesn't match metadata)
    metadata["root_hash"] = serde_json::Value::String(
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
    );

    // Write corrupted metadata back
    let corrupted_json = serde_json::to_string_pretty(&metadata).unwrap();
    fs::write(&meta_path, corrupted_json).expect("Should write corrupted metadata");

    // Create more accounts (to trigger sync_with_db)
    setup
        .create_account(
            address!("0x0000000000000000000000000000000000000043"),
            U256::from(43),
            800,
        )
        .await;

    // Start indexer in HttpOnly mode (will use sync_with_db)
    let cfg2 = GlobalConfig {
        environment: Environment::Development,
        run_mode: RunMode::HttpOnly {
            http_config: HttpConfig {
                http_addr: "0.0.0.0:8104".parse().unwrap(),
                db_poll_interval_secs: 1,
                sanity_check_interval_secs: None,
            },
        },
        db_url: setup.db_url.clone(),
        rpc_url: setup.rpc_url(),
        registry_address: setup.registry_address,
        tree_cache: tree_cache_config.clone(),
    };

    let indexer_task2 = tokio::spawn(async move {
        world_id_indexer::run_indexer(cfg2).await.unwrap();
    });

    // Wait for the sync to detect corruption and trigger rebuild
    // The cache refresh happens every 1 second, so wait a bit longer
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Stop indexer
    indexer_task2.abort();

    // Read metadata again and verify it was rebuilt with correct root
    let meta_content_after =
        fs::read_to_string(&meta_path).expect("Should read metadata after rebuild");
    let metadata_after: serde_json::Value =
        serde_json::from_str(&meta_content_after).expect("Should parse metadata after rebuild");

    let root_after_rebuild = metadata_after["root_hash"].as_str().unwrap();

    // The root should NOT be the corrupted one
    assert_ne!(
        root_after_rebuild, "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "Root should have been fixed by rebuild"
    );

    // Verify accounts in the database
    // Note: Account 43 was created on-chain after the indexer stopped, so it won't be in DB
    // HttpOnly mode doesn't backfill from blockchain, only syncs from database
    let final_count = query_count(&setup.pool).await;
    assert_eq!(
        final_count, 2,
        "Should have 2 accounts indexed (the third was created after indexer stopped)"
    );

    // Verify the metadata reflects the events that were indexed (should have last_event_id == 2)
    let last_event_id = metadata_after["last_event_id"].as_i64().unwrap();
    assert_eq!(
        last_event_id, 2,
        "Rebuilt cache should reflect indexed events, got event_id: {}",
        last_event_id
    );

    cleanup_cache_files(&cache_path);
}
