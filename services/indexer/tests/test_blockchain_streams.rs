#![cfg(feature = "integration-tests")]

use std::time::Duration;

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256, address},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
};
use futures_util::{StreamExt, TryStreamExt};
use test_utils::anvil::TestAnvil;
use world_id_core::{EdDSAPrivateKey, world_id_registry::WorldIdRegistry};
use world_id_indexer::blockchain::{Blockchain, BlockchainEvent, RegistryEvent};

const RECOVERY_ADDRESS: Address = address!("0x0000000000000000000000000000000000000001");

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

/// Tests the full `stream_world_tree_events` pipeline that combines backfill,
/// gap-fill, and live WebSocket streaming into a single ordered stream.
///
/// Scenario:
///   1. **Backfill**: 100 accounts are created before the stream starts. The
///      stream is polled until all backfill events are consumed, which
///      deterministically drives the backfill to completion and commits
///      `last_block`.
///   2. **Gap**: 30 accounts are created *after* the backfill finishes. They
///      land on-chain in blocks after `last_block`, so the WS stage's gap-fill
///      must fetch them via HTTP.
///   3. **Live**: A spawned task creates 5 accounts after a delay so the WS
///      subscription is already established. These arrive as live WS events.
///   4. **Verification**: All collected events are compared against a ground
///      truth `get_logs` query, decoded through `RegistryEvent::decode`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stream_world_tree_events() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    // --- Setup ---
    let anvil = TestAnvil::spawn_automine().expect("failed to spawn anvil");
    let deployer = anvil.signer(0).expect("failed to get deployer");
    let registry_address = anvil
        .deploy_world_id_registry_with_depth(deployer, 8)
        .await
        .expect("failed to deploy registry");

    let blockchain = Blockchain::new(anvil.endpoint(), anvil.ws_endpoint(), registry_address)
        .await
        .expect("failed to create Blockchain");

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

    let mut stream = blockchain
        .stream_world_tree_events(from_block + 1, 2)
        .expect("failed to create stream");

    // Consume all backfill events
    let mut stream_events: Vec<BlockchainEvent<RegistryEvent>> = tokio::time::timeout(
        Duration::from_secs(30),
        stream.by_ref().take(backfill_log_count).try_collect(),
    )
    .await
    .expect("timed out waiting for backfill events")
    .expect("backfill stream error");

    // Create gap accounts
    let backfill_last_block = stream_events.last().unwrap().block_number;

    let next_index = create_accounts(
        anvil.endpoint(),
        anvil.signer(0).unwrap(),
        registry_address,
        next_index,
        gap_count,
    )
    .await;

    // All gap blocks are mined now, before the WS subscription starts.
    let gap_last_block = http_provider
        .get_block_number()
        .await
        .expect("failed to get gap block number");

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

    // Verify the gap-fill actually ran: events from blocks after the backfill
    // but at or before gap_last_block were mined before the WS subscription
    // started, so they can only have arrived via the HTTP gap-fill path.
    let gap_fill_count = gap_live_events
        .iter()
        .filter(|e| e.block_number > backfill_last_block && e.block_number <= gap_last_block)
        .count();
    assert!(
        gap_fill_count > 0,
        "no events from the gap block range — secondary backfill did not run"
    );

    stream_events.extend(gap_live_events);

    // Ground truth logs
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
