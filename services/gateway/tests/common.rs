use alloy::primitives::Address;
use reqwest::{Client, StatusCode};
use std::time::Duration;
use testcontainers_modules::{
    redis::{REDIS_PORT, Redis},
    testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _},
};
use world_id_gateway::{
    BatchPolicyConfig, GatewayConfig, GatewayHandle, SignerArgs, defaults, spawn_gateway_for_tests,
};
use world_id_primitives::api_types::{GatewayRequestState, GatewayStatusResponse};
use world_id_services_common::ProviderArgs;
use world_id_test_utils::anvil::TestAnvil;

/// Default Anvil test private key (account 0). This is a well-known development
/// key, not a real secret.
pub(crate) const GW_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
pub(crate) const RPC_FORK_URL: &str = "https://reth-ethereum.ithaca.xyz/rpc";

/// A running gateway + anvil + Redis stack for integration tests.
///
/// All three variants of the test-gateway setup share this struct.  The
/// `chain_id` and `redis_url` fields are always populated so that test files
/// requiring them (e.g. `test_inflight.rs`) can use the shared type.
#[allow(dead_code)]
pub(crate) struct TestGateway {
    pub(crate) client: Client,
    pub(crate) base_url: String,
    pub(crate) registry_addr: Address,
    pub(crate) rpc_url: String,
    pub(crate) chain_id: u64,
    pub(crate) redis_url: String,
    pub(crate) _handle: GatewayHandle,
    pub(crate) _anvil: TestAnvil,
    // Keep the Redis container alive for the duration of the test.
    pub(crate) _redis: ContainerAsync<Redis>,
}

/// Spawn a test gateway backed by a forked anvil chain and a Redis container.
///
/// * `batch_ms` – when `None` the gateway uses `BatchPolicyConfig::default()`
///   and the standard sweeper/stale thresholds.  Pass `Some(ms)` to configure
///   a custom batch window (used by `test_inflight.rs`).
#[allow(dead_code)]
pub(crate) async fn spawn_test_gateway(batch_ms: Option<u64>) -> TestGateway {
    let mut fork_url = std::env::var("TESTS_RPC_FORK_URL").unwrap_or_default();
    if fork_url.is_empty() {
        fork_url = RPC_FORK_URL.to_string();
    }
    let anvil = TestAnvil::spawn_fork(&fork_url).expect("failed to spawn forked anvil");
    let deployer = anvil.signer(0).expect("failed to fetch deployer signer");
    let registry_addr = anvil
        .deploy_world_id_registry(deployer)
        .await
        .expect("failed to deploy WorldIDRegistry");
    let rpc_url = anvil.endpoint().to_string();
    let chain_id = anvil.instance.chain_id();

    let signer_args = SignerArgs::from_wallet(GW_PRIVATE_KEY.to_string());
    let (redis_url, redis_container) = start_redis().await;

    let cfg = match batch_ms {
        None => GatewayConfig {
            registry_addr,
            provider: ProviderArgs {
                http: Some(vec![rpc_url.parse().unwrap()]),
                signer: Some(signer_args),
                ..Default::default()
            },
            max_create_batch_size: 10,
            max_ops_batch_size: 10,
            listen_addr: (std::net::Ipv4Addr::LOCALHOST, 0).into(),
            redis_url: redis_url.clone(),
            request_timeout_secs: 10,
            rate_limit_window_secs: None,
            rate_limit_max_requests: None,
            sweeper_interval_secs: defaults::SWEEPER_INTERVAL_SECS,
            stale_queued_threshold_secs: defaults::STALE_QUEUED_THRESHOLD_SECS,
            stale_submitted_threshold_secs: defaults::STALE_SUBMITTED_THRESHOLD_SECS,
            batch_policy: BatchPolicyConfig::default(),
        },
        Some(ms) => {
            let max_wait_secs = (ms / 1000).max(1);
            let reeval_ms = ms.min(200);
            GatewayConfig {
                registry_addr,
                provider: ProviderArgs {
                    http: Some(vec![rpc_url.parse().unwrap()]),
                    signer: Some(signer_args),
                    ..Default::default()
                },
                batch_policy: BatchPolicyConfig {
                    max_wait_secs,
                    reeval_ms,
                    ..BatchPolicyConfig::default()
                },
                listen_addr: (std::net::Ipv4Addr::LOCALHOST, 0).into(),
                max_create_batch_size: 10,
                max_ops_batch_size: 10,
                redis_url: redis_url.clone(),
                request_timeout_secs: 10,
                rate_limit_window_secs: None,
                rate_limit_max_requests: None,
                sweeper_interval_secs: max_wait_secs + 1,
                stale_queued_threshold_secs: max_wait_secs + 1,
                stale_submitted_threshold_secs: 600,
            }
        }
    };

    let handle = spawn_gateway_for_tests(cfg).await.expect("spawn gateway");
    let addr = handle.listen_addr;
    let base_url = format!("http://{}:{}", addr.ip(), addr.port());

    let client = Client::builder().build().unwrap();
    wait_http_ready(&client, addr.port()).await;

    TestGateway {
        client,
        base_url,
        registry_addr,
        rpc_url,
        chain_id,
        redis_url,
        _handle: handle,
        _anvil: anvil,
        _redis: redis_container,
    }
}

/// Start a fresh Redis container and return its URL plus the container handle.
///
/// The container is automatically stopped and removed when the returned
/// `ContainerAsync<Redis>` is dropped — keep it alive for the duration of the
/// test that needs the Redis instance.
#[allow(dead_code)]
pub(crate) async fn start_redis() -> (String, ContainerAsync<Redis>) {
    // Use redis:latest so CI (which already pulls this tag via docker-compose)
    // can start the container from the local image cache with no network pull.
    let container = Redis::default()
        .with_tag("latest")
        .start()
        .await
        .expect("failed to start Redis container");
    let host = container
        .get_host()
        .await
        .expect("failed to get Redis host");
    let port = container
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("failed to get Redis port");
    let url = format!("redis://{host}:{port}");
    (url, container)
}

#[allow(dead_code)]
pub(crate) async fn wait_http_ready(client: &Client, port: u16) {
    let base = format!("http://127.0.0.1:{}", port);
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    loop {
        if let Ok(resp) = client.get(format!("{}/health", base)).send().await
            && resp.status().is_success()
        {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!("gateway not ready");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Wait for a request to reach finalized state, using a base URL string.
#[allow(dead_code)]
pub(crate) async fn wait_for_finalized(
    client: &Client,
    base: &str,
    request_id: impl std::fmt::Display,
) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    loop {
        let resp = client
            .get(format!("{}/status/{}", base, request_id))
            .send()
            .await
            .unwrap();
        let status_code = resp.status();
        if status_code == StatusCode::NOT_FOUND {
            panic!("request {request_id} not found");
        }
        if !status_code.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            panic!(
                "status check for {request_id} failed: {} body={}",
                status_code, body_text
            );
        }
        let body: GatewayStatusResponse = resp.json().await.unwrap();
        match body.status {
            GatewayRequestState::Finalized { tx_hash } => return tx_hash,
            GatewayRequestState::Failed { error, .. } => {
                panic!("request {request_id} failed: {error}");
            }
            _ => {
                if std::time::Instant::now() > deadline {
                    panic!("timeout waiting for request {request_id} to finalize");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
