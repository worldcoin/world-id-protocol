use serial_test::serial;
use std::env;
use std::sync::Mutex;
use world_id_indexer::config::{Environment, GlobalConfig, HttpConfig, IndexerConfig, RunMode};

// Mutex to prevent parallel test execution that modifies environment variables
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Helper to set environment variable for test
fn set_env(key: &str, value: &str) {
    unsafe {
        env::set_var(key, value);
    }
}

/// Helper to clear environment variable
fn clear_env(key: &str) {
    unsafe {
        env::remove_var(key);
    }
}

/// Clear all config-related environment variables
fn clear_all_config_env() {
    unsafe {
        env::remove_var("RUN_MODE");
        env::remove_var("START_BLOCK");
        env::remove_var("HTTP_ADDR");
        env::remove_var("DATABASE_URL");
        env::remove_var("RPC_URL");
        env::remove_var("WS_URL");
        env::remove_var("REGISTRY_ADDRESS");
        env::remove_var("TREE_CACHE_FILE");
        env::remove_var("INDEXER_POLL_INTERVAL_SECONDS");
        env::remove_var("INDEXER_BATCH_SIZE");
        env::remove_var("HTTP_SANITY_CHECK_INTERVAL_SECONDS");
        env::remove_var("ENVIRONMENT");
    }
}

#[test]
fn test_environment_parsing() {
    let prod: Environment = "production".parse().unwrap();
    assert_eq!(prod, Environment::Production);

    let staging: Environment = "staging".parse().unwrap();
    assert_eq!(staging, Environment::Staging);

    let dev: Environment = "development".parse().unwrap();
    assert_eq!(dev, Environment::Development);
}

#[test]
fn test_environment_parsing_case_insensitive() {
    let prod: Environment = "PRODUCTION".parse().unwrap();
    assert_eq!(prod, Environment::Production);

    let staging: Environment = "StAgInG".parse().unwrap();
    assert_eq!(staging, Environment::Staging);
}

#[test]
fn test_invalid_environment_parsing() {
    let result: Result<Environment, _> = "invalid".parse();
    assert!(result.is_err());
}

#[test]
#[serial]
fn test_run_mode_from_env_indexer_only() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    set_env("RUN_MODE", "indexer");
    set_env("START_BLOCK", "100");

    let mode = RunMode::from_env();
    assert!(matches!(mode, RunMode::IndexerOnly { .. }));

    clear_env("RUN_MODE");
    clear_env("START_BLOCK");
}

#[test]
#[serial]
fn test_run_mode_from_env_http_only() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    set_env("RUN_MODE", "http");
    set_env("HTTP_ADDR", "127.0.0.1:8080");

    let mode = RunMode::from_env();
    assert!(matches!(mode, RunMode::HttpOnly { .. }));

    clear_env("RUN_MODE");
    clear_env("HTTP_ADDR");
}

#[test]
#[serial]
fn test_run_mode_from_env_both() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    set_env("RUN_MODE", "both");
    set_env("START_BLOCK", "100");
    set_env("HTTP_ADDR", "127.0.0.1:8080");

    let mode = RunMode::from_env();
    assert!(matches!(mode, RunMode::Both { .. }));

    clear_env("RUN_MODE");
    clear_env("START_BLOCK");
    clear_env("HTTP_ADDR");
}

#[test]
#[serial]
fn test_run_mode_default() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();
    set_env("START_BLOCK", "100");
    set_env("HTTP_ADDR", "127.0.0.1:8080");

    let mode = RunMode::from_env();
    // Default should be "both"
    assert!(matches!(mode, RunMode::Both { .. }));

    clear_all_config_env();
}

#[test]
#[should_panic(expected = "Invalid run mode")]
#[serial]
fn test_run_mode_invalid() {
    {
        let _guard = ENV_LOCK.lock().unwrap();
        set_env("RUN_MODE", "invalid_mode");
    } // Drop guard before panic

    let _ = RunMode::from_env();
}

#[test]
#[serial]
fn test_http_config_defaults() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    clear_env("HTTP_ADDR");
    clear_env("DB_POLL_INTERVAL_SECS");
    clear_env("SANITY_CHECK_INTERVAL_SECS");

    let config = HttpConfig::from_env();

    assert_eq!(config.http_addr.to_string(), "0.0.0.0:8080");
    assert_eq!(config.db_poll_interval_secs, 1);
    assert_eq!(config.sanity_check_interval_secs, None);
}

#[test]
#[serial]
fn test_http_config_custom_values() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    set_env("HTTP_ADDR", "127.0.0.1:9000");
    set_env("DB_POLL_INTERVAL_SECS", "5");
    set_env("SANITY_CHECK_INTERVAL_SECS", "60");

    let config = HttpConfig::from_env();

    assert_eq!(config.http_addr.to_string(), "127.0.0.1:9000");
    assert_eq!(config.db_poll_interval_secs, 5);
    assert_eq!(config.sanity_check_interval_secs, Some(60));

    clear_env("HTTP_ADDR");
    clear_env("DB_POLL_INTERVAL_SECS");
    clear_env("SANITY_CHECK_INTERVAL_SECS");
}

#[test]
#[serial]
fn test_http_config_sanity_check_disabled_on_zero() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    set_env("SANITY_CHECK_INTERVAL_SECS", "0");

    let config = HttpConfig::from_env();
    assert_eq!(config.sanity_check_interval_secs, None);

    clear_env("SANITY_CHECK_INTERVAL_SECS");
}

#[test]
#[serial]
fn test_indexer_config_defaults() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    clear_env("START_BLOCK");
    clear_env("BATCH_SIZE");

    let config = IndexerConfig::from_env();

    assert_eq!(config.start_block, 0);
    assert_eq!(config.batch_size, 64);
}

#[test]
#[serial]
fn test_indexer_config_custom_values() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    set_env("START_BLOCK", "12345");
    set_env("BATCH_SIZE", "128");

    let config = IndexerConfig::from_env();

    assert_eq!(config.start_block, 12345);
    assert_eq!(config.batch_size, 128);

    clear_env("START_BLOCK");
    clear_env("BATCH_SIZE");
}

#[test]
#[serial]
fn test_indexer_config_invalid_values_use_defaults() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    set_env("START_BLOCK", "invalid");
    set_env("BATCH_SIZE", "not_a_number");

    let config = IndexerConfig::from_env();

    // Invalid values should fall back to defaults
    assert_eq!(config.start_block, 0);
    assert_eq!(config.batch_size, 64);

    clear_env("START_BLOCK");
    clear_env("BATCH_SIZE");
}

#[test]
#[serial]
fn test_global_config_environment_default() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();
    set_env("DATABASE_URL", "postgresql://localhost/test");
    set_env("RPC_URL", "http://localhost:8545");
    set_env("WS_URL", "ws://localhost:8545");
    set_env(
        "REGISTRY_ADDRESS",
        "0x0000000000000000000000000000000000000001",
    );
    set_env("TREE_CACHE_FILE", "/tmp/test_cache");

    let config = GlobalConfig::from_env();
    assert_eq!(config.environment, Environment::Development);

    clear_all_config_env();
}

#[test]
#[should_panic(expected = "DATABASE_URL must be set")]
#[serial]
fn test_global_config_missing_database_url() {
    unsafe {
        let _guard = ENV_LOCK.lock().unwrap();

        clear_all_config_env();
        set_env("RPC_URL", "http://localhost:8545");
        set_env("WS_URL", "ws://localhost:8545");
        set_env(
            "REGISTRY_ADDRESS",
            "0x0000000000000000000000000000000000000001",
        );
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        drop(_guard);
    }

    let _ = GlobalConfig::from_env();
}

#[test]
#[should_panic(expected = "RPC_URL must be set")]
#[serial]
fn test_global_config_missing_rpc_url() {
    unsafe {
        let _guard = ENV_LOCK.lock().unwrap();

        clear_all_config_env();
        set_env("DATABASE_URL", "postgresql://localhost/test");
        set_env("WS_URL", "ws://localhost:8545");
        set_env(
            "REGISTRY_ADDRESS",
            "0x0000000000000000000000000000000000000001",
        );
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        drop(_guard);
    }

    let _ = GlobalConfig::from_env();
}

#[test]
#[should_panic(expected = "WS_URL must be set")]
#[serial]
fn test_global_config_missing_ws_url() {
    unsafe {
        let _guard = ENV_LOCK.lock().unwrap();

        clear_all_config_env();
        set_env("DATABASE_URL", "postgresql://localhost/test");
        set_env("RPC_URL", "http://localhost:8545");
        set_env(
            "REGISTRY_ADDRESS",
            "0x0000000000000000000000000000000000000001",
        );
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        drop(_guard);
    }

    let _ = GlobalConfig::from_env();
}

#[test]
#[should_panic(expected = "REGISTRY_ADDRESS must be set")]
#[serial]
fn test_global_config_missing_registry_address() {
    unsafe {
        let _guard = ENV_LOCK.lock().unwrap();

        clear_all_config_env();
        set_env("DATABASE_URL", "postgresql://localhost/test");
        set_env("RPC_URL", "http://localhost:8545");
        set_env("WS_URL", "ws://localhost:8545");
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        drop(_guard);
    }

    let _ = GlobalConfig::from_env();
}

#[test]
#[should_panic(expected = "REGISTRY_ADDRESS must be a valid address")]
#[serial]
fn test_global_config_invalid_registry_address() {
    unsafe {
        let _guard = ENV_LOCK.lock().unwrap();

        clear_all_config_env();
        set_env("DATABASE_URL", "postgresql://localhost/test");
        set_env("RPC_URL", "http://localhost:8545");
        set_env("WS_URL", "ws://localhost:8545");
        set_env("REGISTRY_ADDRESS", "invalid_address");
        set_env("TREE_CACHE_FILE", "/tmp/test_cache");

        drop(_guard);
    }

    let _ = GlobalConfig::from_env();
}

#[test]
#[serial]
fn test_tree_cache_config_defaults() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    set_env("TREE_CACHE_FILE", "/tmp/test_cache");
    clear_env("TREE_DEPTH");
    clear_env("TREE_DENSE_PREFIX_DEPTH");
    clear_env("TREE_HTTP_CACHE_REFRESH_INTERVAL_SECS");

    let config = world_id_indexer::config::TreeCacheConfig::from_env().unwrap();

    assert_eq!(config.cache_file_path, "/tmp/test_cache");
    assert_eq!(config.tree_depth, 30);
    assert_eq!(config.dense_tree_prefix_depth, 26);
    assert_eq!(config.http_cache_refresh_interval_secs, 30);

    clear_env("TREE_CACHE_FILE");
}

#[test]
#[serial]
fn test_tree_cache_config_custom_values() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    set_env("TREE_CACHE_FILE", "/custom/path/cache");
    set_env("TREE_DEPTH", "20");
    set_env("TREE_DENSE_PREFIX_DEPTH", "15");
    set_env("TREE_HTTP_CACHE_REFRESH_INTERVAL_SECS", "60");

    let config = world_id_indexer::config::TreeCacheConfig::from_env().unwrap();

    assert_eq!(config.cache_file_path, "/custom/path/cache");
    assert_eq!(config.tree_depth, 20);
    assert_eq!(config.dense_tree_prefix_depth, 15);
    assert_eq!(config.http_cache_refresh_interval_secs, 60);

    clear_env("TREE_CACHE_FILE");
    clear_env("TREE_DEPTH");
    clear_env("TREE_DENSE_PREFIX_DEPTH");
    clear_env("TREE_HTTP_CACHE_REFRESH_INTERVAL_SECS");
}

#[test]
#[serial]
fn test_tree_cache_config_missing_required_field() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    clear_env("TREE_CACHE_FILE");

    let result = world_id_indexer::config::TreeCacheConfig::from_env();
    assert!(
        result.is_err(),
        "Should fail when TREE_CACHE_FILE is missing"
    );
}

#[test]
#[serial]
fn test_http_addr_parsing() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    // Valid formats
    set_env("HTTP_ADDR", "0.0.0.0:8080");
    let config = HttpConfig::from_env();
    assert_eq!(config.http_addr.to_string(), "0.0.0.0:8080");

    set_env("HTTP_ADDR", "127.0.0.1:3000");
    let config = HttpConfig::from_env();
    assert_eq!(config.http_addr.to_string(), "127.0.0.1:3000");

    clear_env("HTTP_ADDR");
}

#[test]
#[should_panic]
#[serial]
fn test_http_addr_invalid_format() {
    {
        let _guard = ENV_LOCK.lock().unwrap();
        set_env("HTTP_ADDR", "invalid:address:format");
    } // Drop guard before panic

    let _ = HttpConfig::from_env();
}

#[test]
#[serial]
fn test_batch_size_validation() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    // Very small batch size
    set_env("BATCH_SIZE", "1");
    let config = IndexerConfig::from_env();
    assert_eq!(config.batch_size, 1);

    // Very large batch size
    set_env("BATCH_SIZE", "10000");
    let config = IndexerConfig::from_env();
    assert_eq!(config.batch_size, 10000);

    clear_env("BATCH_SIZE");
}

#[test]
#[serial]
fn test_zero_start_block() {
    let _guard = ENV_LOCK.lock().unwrap();

    clear_all_config_env();

    set_env("START_BLOCK", "0");
    let config = IndexerConfig::from_env();
    assert_eq!(config.start_block, 0);

    clear_env("START_BLOCK");
}
