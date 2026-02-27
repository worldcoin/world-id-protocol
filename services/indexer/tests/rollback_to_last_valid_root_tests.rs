//! Integration tests for `rollback_to_last_valid_root`.
//!
//! These tests require a PostgreSQL database and Anvil.
//!
//! ```bash
//! docker compose up -d postgres
//! cargo test -p world-id-indexer --test rollback_to_last_valid_root_tests
//! ```

mod helpers;

use alloy::primitives::{Address, U256};
use helpers::{db_helpers::*, mock_blockchain::*};
use world_id_indexer::{
    db::WorldIdRegistryEventId,
    events_committer::EventsCommitter,
    rollback_executor::rollback_to_last_valid_root,
};

use alloy::providers::{Provider, ProviderBuilder};
use world_id_core::world_id_registry::WorldIdRegistry;
use world_id_test_utils::anvil::TestAnvil;

/// Spin up Anvil, deploy the registry, and return a registry instance + test DB.
async fn setup() -> (
    TestAnvil,
    world_id_core::world_id_registry::WorldIdRegistry::WorldIdRegistryInstance<
        alloy::providers::DynProvider,
    >,
    helpers::db_helpers::TestDatabase,
) {
    let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
    let deployer = anvil.signer(0).expect("failed to obtain deployer signer");
    let registry_address = anvil
        .deploy_world_id_registry_with_depth(deployer, 30)
        .await
        .expect("failed to deploy WorldIDRegistry");

    let provider = ProviderBuilder::new()
        .connect_http(anvil.endpoint().parse().unwrap())
        .erased();
    let registry = WorldIdRegistry::new(registry_address, provider);

    let test_db = create_unique_test_db().await;
    (anvil, registry, test_db)
}

/// No RootRecorded events in DB → returns None (nothing to roll back).
#[tokio::test]
async fn test_empty_db_returns_none() {
    let (_anvil, registry, test_db) = setup().await;
    let db = &test_db.db;

    let result = rollback_to_last_valid_root(db, &registry)
        .await
        .expect("rollback_to_last_valid_root should not error on empty DB");

    assert!(result.is_none(), "expected None for empty DB");
}

/// All roots in DB are invalid on-chain (fabricated roots) → returns None,
/// no data is deleted.
#[tokio::test]
async fn test_all_invalid_roots_returns_none() {
    let (_anvil, registry, test_db) = setup().await;
    let db = &test_db.db;

    let mut committer = EventsCommitter::new(db);

    committer
        .handle_event(mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(1)))
        .await
        .unwrap();
    committer
        .handle_event(mock_root_recorded_event(
            100,
            1,
            U256::from(0xdeadbeef_u64),
            U256::from(100),
        ))
        .await
        .unwrap();

    assert_account_count(db.pool(), 1).await;
    assert_root_count(db.pool(), 1).await;

    let result = rollback_to_last_valid_root(db, &registry)
        .await
        .expect("should not error");

    assert!(result.is_none(), "expected None — no roots are valid on-chain");

    // Nothing should have been deleted.
    assert_account_count(db.pool(), 1).await;
    assert_root_count(db.pool(), 1).await;
}

/// Two batches committed; the second batch's root is fabricated (invalid on-chain).
/// rollback_to_last_valid_root should find the first batch's root valid and roll
/// back to it, removing the second batch's data.
#[tokio::test]
async fn test_rolls_back_to_last_valid_root() {
    let (anvil, registry, test_db) = setup().await;
    let db = &test_db.db;

    // Commit a real account to the on-chain registry so its root is valid.
    let deployer = anvil.signer(0).unwrap();
    let onchain_registry = WorldIdRegistry::new(
        *registry.address(),
        ProviderBuilder::new()
            .wallet(alloy::network::EthereumWallet::from(deployer))
            .connect_http(anvil.endpoint().parse().unwrap()),
    );
    onchain_registry
        .createAccount(
            helpers::common::RECOVERY_ADDRESS,
            vec![Address::from([1u8; 20])],
            vec![U256::from(111)],
            U256::from(42),
        )
        .send()
        .await
        .expect("createAccount failed")
        .get_receipt()
        .await
        .expect("receipt failed");

    let valid_root = onchain_registry
        .currentRoot()
        .call()
        .await
        .expect("currentRoot failed");

    // Batch 1: insert a real root that the chain knows.
    let mut committer = EventsCommitter::new(db);
    committer
        .handle_event(mock_account_created_event(100, 0, 1, Address::ZERO, U256::from(1)))
        .await
        .unwrap();
    committer
        .handle_event(mock_root_recorded_event(100, 1, valid_root, U256::from(100)))
        .await
        .unwrap();

    // Batch 2: insert an account with a fabricated root (simulates a reorged block).
    committer
        .handle_event(mock_account_created_event(101, 0, 2, Address::ZERO, U256::from(2)))
        .await
        .unwrap();
    committer
        .handle_event(mock_root_recorded_event(
            101,
            1,
            U256::from(0xdeadbeef_u64),
            U256::from(101),
        ))
        .await
        .unwrap();

    assert_account_count(db.pool(), 2).await;
    assert_root_count(db.pool(), 2).await;

    let result = rollback_to_last_valid_root(db, &registry)
        .await
        .expect("rollback_to_last_valid_root failed");

    // Should have rolled back to the first batch's root event.
    assert!(result.is_some(), "expected a rollback target");
    let target = result.unwrap();
    assert_eq!(target.block_number, 100);
    assert_eq!(target.log_index, 1);

    // Second batch data should be gone.
    assert_account_count(db.pool(), 1).await;
    assert_root_count(db.pool(), 1).await;
    assert_account_exists(db.pool(), 1).await;
    assert_account_not_exists(db.pool(), 2).await;
}

/// If the latest root is already valid (no reorg), rollback_to_last_valid_root
/// rolls back to it — effectively a no-op on the data.
#[tokio::test]
async fn test_no_rollback_needed_when_latest_root_is_valid() {
    let (anvil, registry, test_db) = setup().await;
    let db = &test_db.db;

    let deployer = anvil.signer(0).unwrap();
    let onchain_registry = WorldIdRegistry::new(
        *registry.address(),
        ProviderBuilder::new()
            .wallet(alloy::network::EthereumWallet::from(deployer))
            .connect_http(anvil.endpoint().parse().unwrap()),
    );
    onchain_registry
        .createAccount(
            helpers::common::RECOVERY_ADDRESS,
            vec![Address::from([2u8; 20])],
            vec![U256::from(222)],
            U256::from(99),
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let valid_root = onchain_registry.currentRoot().call().await.unwrap();

    let mut committer = EventsCommitter::new(db);
    committer
        .handle_event(mock_account_created_event(200, 0, 1, Address::ZERO, U256::from(1)))
        .await
        .unwrap();
    committer
        .handle_event(mock_root_recorded_event(200, 1, valid_root, U256::from(200)))
        .await
        .unwrap();

    assert_account_count(db.pool(), 1).await;

    let result = rollback_to_last_valid_root(db, &registry)
        .await
        .expect("should not fail");

    // Rolled back to the last (and only) root — data intact.
    assert!(result.is_some());
    let target = result.unwrap();
    assert_eq!(
        target,
        WorldIdRegistryEventId {
            block_number: 200,
            log_index: 1
        }
    );

    assert_account_count(db.pool(), 1).await;
    assert_root_count(db.pool(), 1).await;
}
