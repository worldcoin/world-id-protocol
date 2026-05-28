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

/// Tests that `pull_events` emits events created after an empty poll round.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pull_events_emits_after_poll() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

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

    let poll_interval = Duration::from_millis(200);
    let stream = blockchain.pull_events(from_block + 1, 2, poll_interval);

    let endpoint = anvil.endpoint().to_string();
    let signer = anvil.signer(0).unwrap();
    let create_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        create_accounts(&endpoint, signer, registry_address, 1, 3).await;
    });

    create_handle.await.expect("account creation task failed");

    let expected_logs = http_provider
        .get_logs(
            &Filter::new()
                .address(registry_address)
                .event_signature(RegistryEvent::signatures())
                .from_block(from_block + 1),
        )
        .await
        .expect("failed to fetch ground truth logs");

    let expected_count = expected_logs.len();
    assert!(
        expected_count > 0,
        "expected some logs after account creation"
    );

    let stream_events: Vec<BlockchainEvent<RegistryEvent>> = tokio::time::timeout(
        Duration::from_secs(30),
        stream.take(expected_count).try_collect(),
    )
    .await
    .expect("timed out waiting for pull events")
    .expect("pull stream error");

    let expected_events: Vec<BlockchainEvent<RegistryEvent>> = expected_logs
        .iter()
        .map(|log| RegistryEvent::decode(log).expect("failed to decode ground truth log"))
        .collect();

    assert_eq!(
        stream_events, expected_events,
        "pull stream events do not match ground truth"
    );
}

/// Tests that the pull stream yields an error and terminates when RPC fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pull_stream_stops_on_error() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

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

    create_accounts(
        anvil.endpoint(),
        anvil.signer(0).unwrap(),
        registry_address,
        1,
        5,
    )
    .await;

    let mut stream = blockchain.pull_events(from_block + 1, 2, Duration::from_millis(100));

    let _partial: Vec<BlockchainEvent<RegistryEvent>> = tokio::time::timeout(
        Duration::from_secs(30),
        stream.by_ref().take(3).try_collect(),
    )
    .await
    .expect("timed out consuming partial pull stream")
    .expect("unexpected error in partial pull stream");

    drop(anvil);

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

    assert!(
        matches!(error_event, Some(Err(BlockchainError::Rpc(_)))),
        "expected Rpc error after killing anvil, got {error_event:?}"
    );

    let terminated = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("timed out waiting for stream termination");

    assert!(
        terminated.is_none(),
        "expected None immediately after first error, got {terminated:?}"
    );
}
