use std::process::{Command, Stdio};
use std::time::Duration;

use regex::Regex;
use sqlx::{postgres::PgPoolOptions, PgPool};

const ANVIL_PORT: u16 = 8547;
const ANVIL_HTTP_URL: &str = "http://127.0.0.1:8547";
const ANVIL_WS_URL: &str = "ws://127.0.0.1:8547";
const ANVIL_MNEMONIC: &str = "test test test test test test test test test test test junk";
const DEFAULT_RECOVERY_ADDRESS: &str = "0x0000000000000000000000000000000000000001";

fn start_anvil() -> std::process::Child {
    // Ensure anvil is available
    let mut cmd = Command::new("anvil");
    cmd.arg("-p")
        .arg(ANVIL_PORT.to_string())
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--mnemonic")
        .arg(ANVIL_MNEMONIC)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.spawn().expect("failed to start anvil")
}

fn deploy_registry() -> String {
    // Use the Foundry script to handle linking and deployment
    let mut cmd = Command::new("forge");
    cmd.current_dir("../../contracts")
        .arg("script")
        .arg("script/AuthenticatorRegistry.s.sol:CounterScript")
        .arg("--fork-url")
        .arg(ANVIL_HTTP_URL)
        .arg("--broadcast")
        .arg("--mnemonics")
        .arg(ANVIL_MNEMONIC)
        .arg("--mnemonic-indexes")
        .arg("0")
        .arg("-vvvv");
    let output = cmd.output().expect("failed to run forge script");
    assert!(
        output.status.success(),
        "forge script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"AuthenticatorRegistry deployed to:\s*(0x[0-9a-fA-F]{40})").unwrap();
    let addr = re
        .captures(&stdout)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .expect(&format!(
            "failed to parse deployed address from script output: {}",
            stdout
        ));
    addr
}

fn cast_create_account(registry: &str, recovery: &str, auth: &str, commitment: &str) {
    let mut cmd = Command::new("cast");
    cmd.arg("send")
        .arg("--rpc-url")
        .arg(ANVIL_HTTP_URL)
        .arg("--mnemonic")
        .arg(ANVIL_MNEMONIC)
        .arg("--mnemonic-index")
        .arg("0")
        .arg(registry)
        .arg("createAccount(address,address[],uint256)")
        .arg(recovery)
        .arg(format!("[{}]", auth))
        .arg(commitment);
    let output = cmd.output().expect("failed to run cast send");
    assert!(
        output.status.success(),
        "cast send failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn query_count(pool: &PgPool) -> i64 {
    let rec: (i64,) = sqlx::query_as("select count(*) from account_created_events")
        .fetch_one(pool)
        .await
        .expect("query count");
    rec.0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    authtree_indexer::init_db(&pool).await.unwrap();

    // Start anvil
    let mut anvil = start_anvil();
    // Give anvil a moment
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Deploy registry
    let registry_addr = deploy_registry();

    // Pre-insert a couple accounts before starting indexer (backfill test)
    cast_create_account(
        &registry_addr,
        DEFAULT_RECOVERY_ADDRESS,
        "0x0000000000000000000000000000000000000011",
        "1",
    );
    cast_create_account(
        &registry_addr,
        DEFAULT_RECOVERY_ADDRESS,
        "0x0000000000000000000000000000000000000012",
        "2",
    );

    // Prepare indexer config and run in background with WS follow
    std::env::set_var("RPC_URL", ANVIL_HTTP_URL);
    std::env::set_var("WS_URL", ANVIL_WS_URL);
    std::env::set_var("REGISTRY_ADDRESS", &registry_addr);
    std::env::set_var("DATABASE_URL", &db_url);
    std::env::set_var("START_BLOCK", "0");
    std::env::set_var("BATCH_SIZE", "1000");

    let indexer_task = tokio::spawn(async move {
        authtree_indexer::run_from_env().await.unwrap();
    });

    // Allow time for backfill (poll until >= 2)
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c = query_count(&pool).await;
        println!("Backfill count: {}", c);
        if c >= 2 {
            assert!(c == 2, "backfill count is not 2");
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("timeout waiting for backfill; count {}", c);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Live insert more accounts while WS stream is active
    cast_create_account(
        &registry_addr,
        DEFAULT_RECOVERY_ADDRESS,
        "0x0000000000000000000000000000000000000013",
        "3",
    );
    cast_create_account(
        &registry_addr,
        DEFAULT_RECOVERY_ADDRESS,
        "0x0000000000000000000000000000000000000014",
        "4",
    );

    // Wait for live sync
    let deadline2 = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let c2 = query_count(&pool).await;
        println!("Live sync count: {}", c2);
        if c2 >= 4 {
            assert!(c2 == 4, "live sync count is not 4");
            break;
        }
        if std::time::Instant::now() > deadline2 {
            panic!("timeout waiting for live sync; count {}", c2);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Cleanup
    indexer_task.abort();
    let _ = anvil.kill();

    // Empty the DB tables created by the indexer
    sqlx::query("truncate table account_created_events, checkpoints")
        .execute(&pool)
        .await
        .unwrap();
}
