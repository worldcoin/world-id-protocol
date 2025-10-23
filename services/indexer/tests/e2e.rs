use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::{address, Address, U256};
use alloy::providers::ProviderBuilder;
use sqlx::{postgres::PgPoolOptions, PgPool};
use test_utils::anvil::TestAnvil;
use world_id_core::account_registry::AccountRegistry;

const RECOVERY_ADDRESS: Address = address!("0x0000000000000000000000000000000000000001");

async fn query_count(pool: &PgPool) -> i64 {
    let rec: (i64,) = sqlx::query_as("select count(*) from account_created_events")
        .fetch_one(pool)
        .await
        .expect("query count");
    rec.0
}

async fn reset_db(pool: &PgPool) {
    sqlx::query("truncate table account_created_events, checkpoints")
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires additional setup"]
async fn e2e_backfill_and_live_sync() {
    // Use externally provided Postgres URL (e.g. via docker-compose or local postgres)
    let db_url =
        std::env::var("E2E_DATABASE_URL").expect("E2E_DATABASE_URL must be set for e2e test");

    // Connect pool (will be used for assertions)
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .unwrap();
    // Ensure schema exists before any queries
    world_id_indexer::init_db(&pool).await.unwrap();

    // Reset DB
    reset_db(&pool).await;

    // Start local anvil instance and deploy the AccountRegistry
    let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
    let deployer = anvil
        .signer(0)
        .expect("failed to obtain deployer signer from anvil");
    let registry_addr = anvil
        .deploy_account_registry(deployer.clone())
        .await
        .expect("failed to deploy AccountRegistry");
    let rpc_url = anvil.endpoint().to_string();
    let ws_url = anvil.ws_endpoint().to_string();

    let registry_contract = AccountRegistry::new(
        registry_addr,
        ProviderBuilder::new()
            .wallet(EthereumWallet::from(deployer.clone()))
            .connect_http(rpc_url.parse().expect("invalid anvil endpoint url")),
    );

    // Pre-insert a couple accounts before starting indexer (backfill test)
    let pre_accounts = [
        (
            address!("0x0000000000000000000000000000000000000011"),
            11u64,
            1u64,
        ),
        (
            address!("0x0000000000000000000000000000000000000012"),
            12u64,
            2u64,
        ),
    ];

    for (auth_addr, pubkey, commitment) in pre_accounts {
        registry_contract
            .createAccount(
                RECOVERY_ADDRESS,
                vec![auth_addr],
                vec![U256::from(pubkey)],
                U256::from(commitment),
            )
            .send()
            .await
            .expect("failed to submit createAccount transaction")
            .get_receipt()
            .await
            .expect("createAccount transaction failed");
    }

    let registry_hex = format!("{registry_addr:#x}");

    // Prepare indexer config and run in background with WS follow
    std::env::set_var("RPC_URL", &rpc_url);
    std::env::set_var("WS_URL", &ws_url);
    std::env::set_var("REGISTRY_ADDRESS", &registry_hex);
    std::env::set_var("DATABASE_URL", &db_url);
    std::env::set_var("START_BLOCK", "0");
    std::env::set_var("BATCH_SIZE", "1000");

    let indexer_task = tokio::spawn(async move {
        world_id_indexer::run_indexer(world_id_indexer::GlobalConfig::from_env())
            .await
            .unwrap();
    });

    // Allow time for backfill (poll until >= 2)
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&pool).await;
        println!("Backfill count: {c}");
        if c >= 2 {
            assert!(c == 2, "backfill count is not 2");
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for backfill; count {c}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Live insert more accounts while WS stream is active
    let live_accounts = [
        (
            address!("0x0000000000000000000000000000000000000013"),
            13u64,
            3u64,
        ),
        (
            address!("0x0000000000000000000000000000000000000014"),
            14u64,
            4u64,
        ),
    ];

    for (auth_addr, pubkey, commitment) in live_accounts {
        registry_contract
            .createAccount(
                RECOVERY_ADDRESS,
                vec![auth_addr],
                vec![U256::from(pubkey)],
                U256::from(commitment),
            )
            .send()
            .await
            .expect("failed to submit live createAccount transaction")
            .get_receipt()
            .await
            .expect("live createAccount transaction failed");
    }

    // Wait for live sync
    let deadline2 = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c2 = query_count(&pool).await;
        println!("Live sync count: {c2}");
        if c2 >= 4 {
            assert!(c2 == 4, "live sync count is not 4");
            break;
        }
        if std::time::Instant::now() > deadline2 {
            panic!("timeout waiting for live sync; count {c2}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Verify proof endpoint is working
    let client = reqwest::Client::builder().build().unwrap();
    let base = "http://127.0.0.1:8080";
    let resp = client.get(format!("{base}/proof/1")).send().await;

    assert!(resp.is_ok(), "proof request failed");
    let resp = resp.unwrap();
    assert!(resp.status().is_success(), "proof request failed");

    tracing::info!("proof response: {:?}", resp.text().await.unwrap());

    // Cleanup
    indexer_task.abort();
    drop(anvil);
    reset_db(&pool).await;
}
