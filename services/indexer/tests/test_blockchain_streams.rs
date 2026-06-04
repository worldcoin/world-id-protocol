#![cfg(feature = "integration-tests")]

use std::time::Duration;

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256, address},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
};
use eddsa_babyjubjub::EdDSAPrivateKey;
use futures_util::{StreamExt, TryStreamExt};
use world_id_indexer::blockchain::{Blockchain, BlockchainError, BlockchainEvent, RegistryEvent};
use world_id_registries::world_id::WorldIdRegistry;
use world_id_services_common::ProviderArgs;
use world_id_test_utils::anvil::TestAnvil;

const RECOVERY_ADDRESS: Address = address!("0x0000000000000000000000000000000000000001");

/// Anvil mines instantly on a single node, so there are no reorgs and we can
/// poll right up to the chain head.
const CONFIRMATIONS: u64 = 0;
const POLL_INTERVAL: Duration = Duration::from_millis(200);

fn random_pubkey() -> U256 {
    let sk = EdDSAPrivateKey::random(&mut rand::thread_rng());
    U256::from_le_slice(&sk.public().to_compressed_bytes().unwrap())
}

async fn create_accounts(
    rpc_endpoint: &str,
    signer: PrivateKeySigner,
    registry_address: Address,
    start_index: u64,
    count: u64,
) -> u64 {
    let registry = WorldIdRegistry::new(
        registry_address,
        ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer))
            .connect_http(rpc_endpoint.parse().unwrap()),
    );

    for i in 0..count {
        let index = start_index + i;
        let auth_addr = Address::from_word(U256::from(index).into());
        registry
            .createAccount(
                RECOVERY_ADDRESS,
                vec![auth_addr],
                vec![random_pubkey()],
                U256::from(index),
            )
            .send()
            .await
            .unwrap_or_else(|_| panic!("failed to submit createAccount tx for index {index}"))
            .get_receipt()
            .await
            .unwrap_or_else(|_| panic!("createAccount tx failed for index {index}"));
    }

    start_index + count
}

/// Tests the full `poll_events` pipeline that backfills historical logs and then
/// keeps polling for newly confirmed logs.
///
/// Scenario:
///   1. **Backfill**: 100 accounts are created before the stream starts. The
///      first poll emits all of their logs in one batched range.
///   2. **Gap**: 30 accounts are created *after* the backfill is consumed. They
///      land on-chain in later blocks and are picked up by a subsequent poll.
///   3. **Live**: A spawned task creates 5 more accounts after a delay so they
///      arrive on an even later poll.
///   4. **Verification**: All collected events are compared against a ground
///      truth `get_logs` query, decoded through `RegistryEvent::decode`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_poll_events() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    // --- Setup ---
    let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
    let deployer = anvil.signer(0).expect("failed to get deployer");
    let registry_address = anvil
        .deploy_world_id_registry_with_depth(deployer, 8)
        .await
        .expect("failed to deploy registry");

    let provider = ProviderArgs::new()
        .with_http_urls([anvil.endpoint()])
        .http()
        .await
        .expect("failed to build provider");

    let blockchain = Blockchain::new(provider.clone(), registry_address);

    let http_provider =
        ProviderBuilder::new().connect_http(anvil.endpoint().parse::<url::Url>().unwrap());

    let from_block = http_provider
        .get_block_number()
        .await
        .expect("failed to get block number");

    // --- Phase 1: Create backfill accounts ---
    let backfill_count: u64 = 100;
    let gap_count: u64 = 30;
    let live_count: u64 = 5;

    let next_index = create_accounts(
        anvil.endpoint(),
        anvil.signer(0).unwrap(),
        registry_address,
        1,
        backfill_count,
    )
    .await;

    // Compute logs-per-account empirically from the backfill accounts.
    let backfill_log_count = http_provider
        .get_logs(
            &Filter::new()
                .address(registry_address)
                .event_signature(RegistryEvent::signatures())
                .from_block(from_block + 1),
        )
        .await
        .expect("failed to count backfill logs")
        .len();
    assert!(backfill_log_count > 0, "expected some backfill logs");
    let logs_per_account = backfill_log_count as u64 / backfill_count;

    let mut stream = blockchain.poll_events(from_block + 1, 2, CONFIRMATIONS, POLL_INTERVAL);

    // Consume all backfill events
    let mut stream_events: Vec<BlockchainEvent<RegistryEvent>> = tokio::time::timeout(
        Duration::from_secs(30),
        stream.by_ref().take(backfill_log_count).try_collect(),
    )
    .await
    .expect("timed out waiting for backfill events")
    .expect("backfill stream error");

    // Create gap accounts
    let next_index = create_accounts(
        anvil.endpoint(),
        anvil.signer(0).unwrap(),
        registry_address,
        next_index,
        gap_count,
    )
    .await;

    // Spawn task for live accounts
    let task_endpoint = anvil.endpoint().to_string();
    let task_signer = anvil.signer(0).unwrap();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;

        create_accounts(
            &task_endpoint,
            task_signer,
            registry_address,
            next_index,
            live_count,
        )
        .await;
    });

    // Consume gap + live events
    let remaining = (logs_per_account * (gap_count + live_count)) as usize;

    let gap_live_events: Vec<BlockchainEvent<RegistryEvent>> = tokio::time::timeout(
        Duration::from_secs(30),
        stream.by_ref().take(remaining).try_collect(),
    )
    .await
    .expect("timed out waiting for gap/live events")
    .expect("gap/live stream error");

    stream_events.extend(gap_live_events);

    // Ground truth
    let expected_logs = http_provider
        .get_logs(
            &Filter::new()
                .address(registry_address)
                .event_signature(RegistryEvent::signatures())
                .from_block(from_block + 1),
        )
        .await
        .expect("failed to fetch ground truth logs");

    let expected_events: Vec<BlockchainEvent<RegistryEvent>> = expected_logs
        .iter()
        .map(|log| RegistryEvent::decode(log).expect("failed to decode ground truth log"))
        .collect();

    assert_eq!(
        stream_events, expected_events,
        "stream events do not match ground truth"
    );
}

/// Tests that `poll_events` backfills a pre-existing range of logs correctly.
///
/// Scenario:
///   1. 10 accounts are created before the stream starts.
///   2. `poll_events` is polled until all backfill logs are consumed.
///   3. The collected events are compared against a ground truth `get_logs`
///      query.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_poll_events_backfill() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    // --- Setup ---
    let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
    let deployer = anvil.signer(0).expect("failed to get deployer");
    let registry_address = anvil
        .deploy_world_id_registry_with_depth(deployer, 8)
        .await
        .expect("failed to deploy registry");

    let provider = ProviderArgs::new()
        .with_http_urls([anvil.endpoint()])
        .http()
        .await
        .expect("failed to build provider");

    let blockchain = Blockchain::new(provider.clone(), registry_address);

    let http_provider =
        ProviderBuilder::new().connect_http(anvil.endpoint().parse::<url::Url>().unwrap());

    let from_block = http_provider
        .get_block_number()
        .await
        .expect("failed to get block number");

    // --- Create accounts ---
    let backfill_count: u64 = 10;

    create_accounts(
        anvil.endpoint(),
        anvil.signer(0).unwrap(),
        registry_address,
        1,
        backfill_count,
    )
    .await;

    // --- Ground truth ---
    let expected_logs = http_provider
        .get_logs(
            &Filter::new()
                .address(registry_address)
                .event_signature(RegistryEvent::signatures())
                .from_block(from_block + 1),
        )
        .await
        .expect("failed to fetch ground truth logs");

    let expected_events: Vec<BlockchainEvent<RegistryEvent>> = expected_logs
        .iter()
        .map(|log| RegistryEvent::decode(log).expect("failed to decode ground truth log"))
        .collect();

    // --- Backfill via polling ---
    let mut stream = blockchain.poll_events(from_block + 1, 2, CONFIRMATIONS, POLL_INTERVAL);

    let stream_events: Vec<BlockchainEvent<RegistryEvent>> = tokio::time::timeout(
        Duration::from_secs(30),
        stream.by_ref().take(expected_events.len()).try_collect(),
    )
    .await
    .expect("timed out waiting for backfill events")
    .expect("backfill stream error");

    assert_eq!(
        stream_events, expected_events,
        "backfill stream events do not match ground truth"
    );
}

/// Tests that the stream produced by `poll_events` yields an `Err` and then
/// terminates when an RPC error occurs.
///
/// Scenario:
///   1. 10 accounts are created so there is backfill work to do.
///   2. The stream is started with a small `batch_size` and RPC retries
///      disabled so errors propagate immediately.
///   3. A few events are consumed, then the Anvil process is killed.
///   4. The next poll yields `Err(BlockchainError::Rpc(...))`.
///   5. The stream terminates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stream_stops_on_error() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    // --- Setup ---
    let anvil = TestAnvil::spawn().expect("failed to spawn anvil");
    let deployer = anvil.signer(0).expect("failed to get deployer");
    let registry_address = anvil
        .deploy_world_id_registry_with_depth(deployer, 8)
        .await
        .expect("failed to deploy registry");

    let provider = ProviderArgs::new()
        .with_http_urls([anvil.endpoint()])
        .with_max_rpc_retries(0)
        .http()
        .await
        .expect("failed to build provider");

    let blockchain = Blockchain::new(provider.clone(), registry_address);

    let http_provider =
        ProviderBuilder::new().connect_http(anvil.endpoint().parse::<url::Url>().unwrap());

    let from_block = http_provider
        .get_block_number()
        .await
        .expect("failed to get block number");

    // Create enough accounts so backfill has work to do.
    let backfill_count: u64 = 10;

    create_accounts(
        anvil.endpoint(),
        anvil.signer(0).unwrap(),
        registry_address,
        1,
        backfill_count,
    )
    .await;

    let mut stream = blockchain.poll_events(from_block + 1, 2, CONFIRMATIONS, POLL_INTERVAL);

    // Consume a small number of events so the backfill is partway through.
    let _partial: Vec<BlockchainEvent<RegistryEvent>> = tokio::time::timeout(
        Duration::from_secs(30),
        stream.by_ref().take(5).try_collect(),
    )
    .await
    .expect("timed out consuming partial backfill")
    .expect("unexpected error in partial backfill");

    // Kill Anvil — all subsequent RPC calls will fail.
    drop(anvil);

    // There can still be buffered Ok events fetched before the anvil process
    // was killed. Drain until the first non-Ok item appears.
    let error_event = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match stream.next().await {
                Some(Ok(_)) => continue,
                other => break other,
            }
        }
    })
    .await
    .expect("timed out waiting for error after anvil kill");

    // After killing Anvil the stream must stop with an RPC error.
    assert!(
        matches!(error_event, Some(Err(BlockchainError::Rpc(_)))),
        "expected an RPC error after killing anvil, got {error_event:?}"
    );

    // Stream must terminate immediately after the first error.
    let terminated = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timed out waiting for stream termination");

    assert!(
        terminated.is_none(),
        "expected None immediately after first error, got {terminated:?}"
    );
}
