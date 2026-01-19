//! Load testing for the World ID Gateway.
//!
//! Run with: `cargo test --test load_test --release -- --nocapture`
//!
//! Environment variables:
//! - `LOAD_TEST_CONCURRENCY`: Number of concurrent workers (default: 50)
//! - `LOAD_TEST_DURATION_SECS`: Test duration in seconds (default: 30)
//! - `LOAD_TEST_REQUESTS_PER_WORKER`: Max requests per worker (default: 100)
//! - `TESTS_RPC_FORK_URL`: RPC URL for forking (default: https://reth-ethereum.ithaca.xyz/rpc)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ::common::ProviderArgs;
use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use alloy::signers::local::PrivateKeySigner;
use reqwest::{Client, StatusCode};
use test_utils::anvil::TestAnvil;
use tokio::sync::Semaphore;
use world_id_core::types::{GatewayStatusResponse, InsertAuthenticatorRequest};
use world_id_core::world_id_registry::{
    domain as ag_domain, sign_insert_authenticator, WorldIdRegistry,
};
use world_id_gateway::{spawn_gateway_for_tests, GatewayConfig, SignerArgs};

mod common;

const GW_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const GW_PORT: u16 = 4200;
const RPC_FORK_URL: &str = "https://reth-ethereum.ithaca.xyz/rpc";

fn default_sibling_nodes() -> Vec<String> {
    vec![
        "0x0",
        "0x228981b886e5effb2c05a6be7ab4a05fde6bf702a2d039e46c87057dd729ef97",
        "0x218fbf2e2f12f0475d3dcf2e0ab1bd4b9ab528e954738c18c4b7c9b5f4b84964",
        "0x2e16a8d602271ea50b5a1bd35b854610ef0bddf8f385bdeb0bb31c4562fa0cd6",
        "0x2b44a101801fa0b810feb3d82c25e71b88bc6f4aeecd9fcdc2152b1f3c38d044",
        "0x19f2fcaf65567ab8803e4fb84e67854815d83a4e1b7be24c6814ba2ba9bdc5ca",
        "0x1a3bd772e2782ad018b9c451bf66c3b0ad223a0e68347fae11c78681bf6478df",
        "0x34d4539eb24682272ab024133ca575c1cade051f9fdce5948b6b806767e225b",
        "0x2971eb2b9cd60a1270db7ab8aada485f64fae5a5e85bed736c67329c410fffee",
        "0x2ef220cf75c94a6bc8f4900fe8153ce53132c2de05163d55ecd0fd13519104b4",
        "0x2075381e03f1e1f60029fc3079d49b918c967b58e2655b1770c86ca3984ab65c",
        "0x1d4789eb40dffb09091a0690d88df7ff993c23d172e866a93631f6792909118c",
        "0x2b082d0afac14544d746c924d6fc882f6931b7b6aacd796c82d7fe81ce33ce4c",
        "0x175c16bc97822dba5fdf5580638d4983831dab655f5095bde23b6685f61981cd",
        "0xc4b05c87053bf236ef505872eac4304546d3c4f989b1d19b93ef9115e883f66",
        "0x2d7e044c16807771000769efac4e9147a90359c5f58da39880697de3afdd6d56",
        "0x18b029a33a590d748323e8d6cb8ac7636cdff4a154ddb7e19ac9cb6845adff69",
        "0x1e45bd2b39d74ef50d211fc7303d55a06478517cd44887308ba40cb6d4d44216",
        "0x189b2c3495c37308649a0c3e9fe3dd06e83612e9cb1528833acf358bc9b43271",
        "0xec11644818dab9d62fdacacda9fdc5d2fb6f4627a332e3b25bbbc7dfb0672e7",
        "0x119827e780a1850d7b7e34646edc1ce918211c26dda4e13bcd1611f6f81c3680",
        "0x84449b11bad2bd26ab39b799cccb9408c4f3bcdbef4210f5cd6544d821c85c6",
        "0x2f313f5eaf87dd5e81f34e8ef6b98c2928272ba35b80821267b95176775a5dd",
        "0x2d01ab8332efd3bcd5d4fe99cdb66d809fbf6a1a84c931942ea40fb5cf4ebdaa",
        "0x2adfa5bb110a920158ca367f5cfa6f632aeb78a9a7b1f2d9c0d29f2a197c244b",
        "0x1045e59b73045e7bb07ad0bd51e8b5ec08c2b71abc64eaec485ad91a2a528ea8",
        "0x1549ebd6196d7d303bf4791a3b33c08809f19e5ebf9a5ef5ba438d3ec4d9a324",
        "0x305e08a953165f5d8e4560d619ca03d05c06e7514dfb7f7a2a25dfaf558907dc",
        "0xfb5add1601d2850978d2c5b2de15426a50b7c766c5939843637f759a34ab617",
        "0x232052690c527bf35f76a2fd8db54c96f1dd28d009e19c6d00af6d389188fac5",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

// ============================================================================
// Metrics Collection
// ============================================================================

#[derive(Default)]
struct LoadTestMetrics {
    total_requests: AtomicU64,
    successful_requests: AtomicU64,
    failed_requests: AtomicU64,
    status_2xx: AtomicU64,
    status_4xx: AtomicU64,
    status_5xx: AtomicU64,
    latencies_ms: Mutex<Vec<u64>>,
}

impl LoadTestMetrics {
    fn record_request(&self, status: StatusCode, latency: Duration) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.latencies_ms
            .lock()
            .unwrap()
            .push(latency.as_millis() as u64);

        if status.is_success() {
            self.successful_requests.fetch_add(1, Ordering::Relaxed);
            self.status_2xx.fetch_add(1, Ordering::Relaxed);
        } else if status.is_client_error() {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
            self.status_4xx.fetch_add(1, Ordering::Relaxed);
        } else if status.is_server_error() {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
            self.status_5xx.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_error(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.failed_requests.fetch_add(1, Ordering::Relaxed);
    }

    fn summary(&self, duration: Duration) -> MetricsSummary {
        let total = self.total_requests.load(Ordering::Relaxed);
        let successful = self.successful_requests.load(Ordering::Relaxed);
        let failed = self.failed_requests.load(Ordering::Relaxed);
        let status_2xx = self.status_2xx.load(Ordering::Relaxed);
        let status_4xx = self.status_4xx.load(Ordering::Relaxed);
        let status_5xx = self.status_5xx.load(Ordering::Relaxed);

        let mut latencies = self.latencies_ms.lock().unwrap().clone();
        latencies.sort_unstable();

        let (p50, p95, p99, avg) = if latencies.is_empty() {
            (0, 0, 0, 0.0)
        } else {
            let p50_idx = latencies.len() / 2;
            let p95_idx = (latencies.len() as f64 * 0.95) as usize;
            let p99_idx = (latencies.len() as f64 * 0.99) as usize;
            let sum: u64 = latencies.iter().sum();
            (
                latencies[p50_idx],
                latencies[p95_idx.min(latencies.len() - 1)],
                latencies[p99_idx.min(latencies.len() - 1)],
                sum as f64 / latencies.len() as f64,
            )
        };

        let rps = total as f64 / duration.as_secs_f64();

        MetricsSummary {
            total_requests: total,
            successful_requests: successful,
            failed_requests: failed,
            status_2xx,
            status_4xx,
            status_5xx,
            latency_p50_ms: p50,
            latency_p95_ms: p95,
            latency_p99_ms: p99,
            latency_avg_ms: avg,
            requests_per_second: rps,
            duration,
        }
    }
}

struct MetricsSummary {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    status_2xx: u64,
    status_4xx: u64,
    status_5xx: u64,
    latency_p50_ms: u64,
    latency_p95_ms: u64,
    latency_p99_ms: u64,
    latency_avg_ms: f64,
    requests_per_second: f64,
    duration: Duration,
}

impl std::fmt::Display for MetricsSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\n{:=^60}", " Load Test Results ")?;
        writeln!(f, "Duration: {:.2}s", self.duration.as_secs_f64())?;
        writeln!(f)?;
        writeln!(f, "Requests:")?;
        writeln!(f, "  Total:      {}", self.total_requests)?;
        writeln!(f, "  Successful: {}", self.successful_requests)?;
        writeln!(f, "  Failed:     {}", self.failed_requests)?;
        writeln!(f)?;
        writeln!(f, "Status Codes:")?;
        writeln!(f, "  2xx: {}", self.status_2xx)?;
        writeln!(f, "  4xx: {}", self.status_4xx)?;
        writeln!(f, "  5xx: {}", self.status_5xx)?;
        writeln!(f)?;
        writeln!(f, "Latency:")?;
        writeln!(f, "  p50:  {}ms", self.latency_p50_ms)?;
        writeln!(f, "  p95:  {}ms", self.latency_p95_ms)?;
        writeln!(f, "  p99:  {}ms", self.latency_p99_ms)?;
        writeln!(f, "  avg:  {:.2}ms", self.latency_avg_ms)?;
        writeln!(f)?;
        writeln!(f, "Throughput: {:.2} req/s", self.requests_per_second)?;
        writeln!(f, "{:=^60}", "")
    }
}

// ============================================================================
// Test Gateway Setup
// ============================================================================

struct LoadTestGateway {
    client: Client,
    base_url: String,
    registry_addr: Address,
    rpc_url: String,
    _handle: world_id_gateway::GatewayHandle,
    _anvil: TestAnvil,
}

async fn spawn_load_test_gateway(port: u16) -> LoadTestGateway {
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

    let signer_args = SignerArgs::from_wallet(GW_PRIVATE_KEY.to_string());
    let cfg = GatewayConfig {
        registry_addr,
        provider: ProviderArgs {
            http: Some(vec![rpc_url.parse().unwrap()]),
            signer: Some(signer_args),
            ..Default::default()
        },
        batch_ms: 100, // Faster batching for load tests
        listen_addr: (std::net::Ipv4Addr::LOCALHOST, port).into(),
        max_create_batch_size: 50,
        max_ops_batch_size: 50,
        redis_url: None,
        metrics: Default::default(),
    };
    let handle = spawn_gateway_for_tests(cfg).await.expect("spawn gateway");

    let client = Client::builder()
        .pool_max_idle_per_host(100)
        .build()
        .unwrap();
    common::wait_http_ready(&client, port).await;

    LoadTestGateway {
        client,
        base_url: format!("http://127.0.0.1:{port}"),
        registry_addr,
        rpc_url,
        _handle: handle,
        _anvil: anvil,
    }
}

// ============================================================================
// Load Test: Create Account Throughput
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore] // Run with: cargo test --test load_test load_test_create_account -- --ignored --nocapture
async fn load_test_create_account() {
    let concurrency: usize = std::env::var("LOAD_TEST_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let duration_secs: u64 = std::env::var("LOAD_TEST_DURATION_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let requests_per_worker: usize = std::env::var("LOAD_TEST_REQUESTS_PER_WORKER")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    println!("\nStarting load test: create-account");
    println!("  Concurrency: {concurrency}");
    println!("  Duration: {duration_secs}s");
    println!("  Max requests per worker: {requests_per_worker}");

    let gw = spawn_load_test_gateway(GW_PORT).await;
    let metrics = Arc::new(LoadTestMetrics::default());
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let start = Instant::now();

    let mut handles = Vec::new();

    for worker_id in 0..concurrency {
        let client = gw.client.clone();
        let base_url = gw.base_url.clone();
        let metrics = metrics.clone();
        let semaphore = semaphore.clone();

        let handle = tokio::spawn(async move {
            for i in 0..requests_per_worker {
                if Instant::now() >= deadline {
                    break;
                }

                let _permit = semaphore.acquire().await.unwrap();

                // Generate unique wallet address per request
                let signer = PrivateKeySigner::random();
                let wallet_addr: Address = signer.address();

                let body = serde_json::json!({
                    "recovery_address": wallet_addr.to_string(),
                    "authenticator_addresses": [wallet_addr.to_string()],
                    "authenticator_pubkeys": [format!("{}", (worker_id * 1000 + i))],
                    "offchain_signer_commitment": "0x1",
                });

                let req_start = Instant::now();
                match client
                    .post(format!("{}/create-account", base_url))
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let latency = req_start.elapsed();
                        metrics.record_request(resp.status(), latency);
                    }
                    Err(_) => {
                        metrics.record_error();
                    }
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let duration = start.elapsed();
    let summary = metrics.summary(duration);
    println!("{summary}");

    // Assertions
    assert!(
        summary.successful_requests > 0,
        "Should have at least some successful requests"
    );
    assert!(
        summary.latency_p99_ms < 5000,
        "p99 latency should be under 5s"
    );
}

// ============================================================================
// Load Test: Status Endpoint Throughput
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn load_test_status_endpoint() {
    let concurrency: usize = std::env::var("LOAD_TEST_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let duration_secs: u64 = std::env::var("LOAD_TEST_DURATION_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    println!("\nStarting load test: status endpoint");
    println!("  Concurrency: {concurrency}");
    println!("  Duration: {duration_secs}s");

    let gw = spawn_load_test_gateway(GW_PORT + 1).await;

    // First create some accounts to have valid request IDs
    let mut request_ids = Vec::new();
    for _ in 0..10 {
        let signer = PrivateKeySigner::random();
        let wallet_addr: Address = signer.address();
        let body = serde_json::json!({
            "recovery_address": wallet_addr.to_string(),
            "authenticator_addresses": [wallet_addr.to_string()],
            "authenticator_pubkeys": ["100"],
            "offchain_signer_commitment": "0x1",
        });
        if let Ok(resp) = gw
            .client
            .post(format!("{}/create-account", gw.base_url))
            .json(&body)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(accepted) = resp.json::<GatewayStatusResponse>().await {
                    request_ids.push(accepted.request_id);
                }
            }
        }
    }

    if request_ids.is_empty() {
        println!("Warning: No request IDs created, using random UUIDs");
        for _ in 0..10 {
            request_ids.push(uuid::Uuid::new_v4().to_string());
        }
    }

    let request_ids = Arc::new(request_ids);
    let metrics = Arc::new(LoadTestMetrics::default());
    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let start = Instant::now();

    let mut handles = Vec::new();

    for _ in 0..concurrency {
        let client = gw.client.clone();
        let base_url = gw.base_url.clone();
        let metrics = metrics.clone();
        let request_ids = request_ids.clone();

        let handle = tokio::spawn(async move {
            let mut counter = 0u64;
            while Instant::now() < deadline {
                let id = &request_ids[counter as usize % request_ids.len()];
                let req_start = Instant::now();
                match client
                    .get(format!("{}/status/{}", base_url, id))
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let latency = req_start.elapsed();
                        metrics.record_request(resp.status(), latency);
                    }
                    Err(_) => {
                        metrics.record_error();
                    }
                }
                counter += 1;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let duration = start.elapsed();
    let summary = metrics.summary(duration);
    println!("{summary}");

    assert!(
        summary.requests_per_second > 100.0,
        "Status endpoint should handle >100 req/s"
    );
    assert!(
        summary.latency_p95_ms < 100,
        "p95 latency should be under 100ms for status checks"
    );
}

// ============================================================================
// Load Test: Health Endpoint (Baseline)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn load_test_health_endpoint() {
    let concurrency: usize = std::env::var("LOAD_TEST_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let duration_secs: u64 = std::env::var("LOAD_TEST_DURATION_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    println!("\nStarting load test: health endpoint (baseline)");
    println!("  Concurrency: {concurrency}");
    println!("  Duration: {duration_secs}s");

    let gw = spawn_load_test_gateway(GW_PORT + 2).await;
    let metrics = Arc::new(LoadTestMetrics::default());
    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let start = Instant::now();

    let mut handles = Vec::new();

    for _ in 0..concurrency {
        let client = gw.client.clone();
        let base_url = gw.base_url.clone();
        let metrics = metrics.clone();

        let handle = tokio::spawn(async move {
            while Instant::now() < deadline {
                let req_start = Instant::now();
                match client.get(format!("{}/health", base_url)).send().await {
                    Ok(resp) => {
                        let latency = req_start.elapsed();
                        metrics.record_request(resp.status(), latency);
                    }
                    Err(_) => {
                        metrics.record_error();
                    }
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let duration = start.elapsed();
    let summary = metrics.summary(duration);
    println!("{summary}");

    assert!(
        summary.requests_per_second > 1000.0,
        "Health endpoint should handle >1000 req/s"
    );
    assert!(
        summary.latency_p99_ms < 50,
        "p99 latency should be under 50ms for health checks"
    );
}

// ============================================================================
// Load Test: Mixed Workload
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn load_test_mixed_workload() {
    let concurrency: usize = std::env::var("LOAD_TEST_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let duration_secs: u64 = std::env::var("LOAD_TEST_DURATION_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    println!("\nStarting load test: mixed workload");
    println!("  Concurrency: {concurrency}");
    println!("  Duration: {duration_secs}s");
    println!("  Workload: 70% status, 20% create-account, 10% health");

    let gw = spawn_load_test_gateway(GW_PORT + 3).await;

    // Pre-create some accounts
    let mut request_ids = Vec::new();
    for _ in 0..20 {
        let signer = PrivateKeySigner::random();
        let wallet_addr: Address = signer.address();
        let body = serde_json::json!({
            "recovery_address": wallet_addr.to_string(),
            "authenticator_addresses": [wallet_addr.to_string()],
            "authenticator_pubkeys": ["100"],
            "offchain_signer_commitment": "0x1",
        });
        if let Ok(resp) = gw
            .client
            .post(format!("{}/create-account", gw.base_url))
            .json(&body)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(accepted) = resp.json::<GatewayStatusResponse>().await {
                    request_ids.push(accepted.request_id);
                }
            }
        }
    }

    let request_ids = Arc::new(Mutex::new(request_ids));
    let metrics = Arc::new(LoadTestMetrics::default());
    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let start = Instant::now();

    let mut handles = Vec::new();

    for worker_id in 0..concurrency {
        let client = gw.client.clone();
        let base_url = gw.base_url.clone();
        let metrics = metrics.clone();
        let request_ids = request_ids.clone();

        let handle = tokio::spawn(async move {
            let mut counter = 0u64;
            while Instant::now() < deadline {
                let roll = counter % 10;
                let req_start = Instant::now();

                let result = if roll < 7 {
                    // 70% - status check
                    let maybe_id = {
                        let ids = request_ids.lock().unwrap();
                        if ids.is_empty() {
                            None
                        } else {
                            Some(ids[counter as usize % ids.len()].clone())
                        }
                    };
                    match maybe_id {
                        Some(id) => {
                            client
                                .get(format!("{}/status/{}", base_url, id))
                                .send()
                                .await
                        }
                        None => client.get(format!("{}/health", base_url)).send().await,
                    }
                } else if roll < 9 {
                    // 20% - create account
                    let signer = PrivateKeySigner::random();
                    let wallet_addr: Address = signer.address();
                    let body = serde_json::json!({
                        "recovery_address": wallet_addr.to_string(),
                        "authenticator_addresses": [wallet_addr.to_string()],
                        "authenticator_pubkeys": [format!("{}", worker_id as u64 * 10000 + counter)],
                        "offchain_signer_commitment": "0x1",
                    });
                    let resp = client
                        .post(format!("{}/create-account", base_url))
                        .json(&body)
                        .send()
                        .await;

                    // Add new request ID if successful
                    if let Ok(ref r) = resp {
                        if r.status().is_success() {
                            // Can't easily get the body here, skip adding
                        }
                    }
                    resp
                } else {
                    // 10% - health check
                    client.get(format!("{}/health", base_url)).send().await
                };

                match result {
                    Ok(resp) => {
                        let latency = req_start.elapsed();
                        metrics.record_request(resp.status(), latency);
                    }
                    Err(_) => {
                        metrics.record_error();
                    }
                }

                counter += 1;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let duration = start.elapsed();
    let summary = metrics.summary(duration);
    println!("{summary}");

    assert!(
        summary.successful_requests > summary.failed_requests,
        "Should have more successful than failed requests"
    );
}

// ============================================================================
// Load Test: Insert Authenticator Operations
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn load_test_insert_authenticator() {
    let concurrency: usize = std::env::var("LOAD_TEST_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let duration_secs: u64 = std::env::var("LOAD_TEST_DURATION_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    println!("\nStarting load test: insert-authenticator");
    println!("  Concurrency: {concurrency}");
    println!("  Duration: {duration_secs}s");

    let gw = spawn_load_test_gateway(GW_PORT + 4).await;

    // First create an account to insert authenticators into
    let signer = PrivateKeySigner::random();
    let wallet_addr: Address = signer.address();

    let body_create = serde_json::json!({
        "recovery_address": wallet_addr.to_string(),
        "authenticator_addresses": [wallet_addr.to_string()],
        "authenticator_pubkeys": ["100"],
        "offchain_signer_commitment": "0x1",
    });
    let resp = gw
        .client
        .post(format!("{}/create-account", gw.base_url))
        .json(&body_create)
        .send()
        .await
        .expect("create account");
    assert!(
        resp.status().is_success(),
        "Failed to create initial account"
    );

    let accepted: GatewayStatusResponse = resp.json().await.unwrap();
    common::wait_for_finalized(&gw.client, &gw.base_url, &accepted.request_id).await;

    // Wait for on-chain confirmation
    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer.clone()))
        .connect_http(gw.rpc_url.parse().expect("invalid anvil endpoint url"));
    let contract = WorldIdRegistry::new(gw.registry_addr, provider.clone());

    let deadline_ca = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let packed = contract
            .authenticatorAddressToPackedAccountData(wallet_addr)
            .call()
            .await
            .unwrap();
        if packed != U256::ZERO {
            break;
        }
        if std::time::Instant::now() > deadline_ca {
            panic!("timeout waiting for account creation");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let chain_id = provider.get_chain_id().await.unwrap();
    let domain = ag_domain(chain_id, gw.registry_addr);
    let nonce = Arc::new(AtomicU64::new(0));

    let metrics = Arc::new(LoadTestMetrics::default());
    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let start = Instant::now();

    let signer = Arc::new(signer);
    let domain = Arc::new(domain);

    let mut handles = Vec::new();

    for worker_id in 0..concurrency {
        let client = gw.client.clone();
        let base_url = gw.base_url.clone();
        let metrics = metrics.clone();
        let signer = signer.clone();
        let domain = domain.clone();
        let nonce = nonce.clone();

        let handle = tokio::spawn(async move {
            let mut local_counter = 0u64;
            while Instant::now() < deadline {
                let current_nonce = U256::from(nonce.fetch_add(1, Ordering::SeqCst));

                // Generate unique authenticator address
                let new_auth = Address::from_slice(
                    &[
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        0x00,
                        (worker_id >> 8) as u8,
                        worker_id as u8,
                        (local_counter >> 24) as u8,
                        (local_counter >> 16) as u8,
                        (local_counter >> 8) as u8,
                        local_counter as u8,
                        0x00,
                        0x00,
                    ][..],
                );

                let pubkey = U256::from(worker_id as u64 * 10000 + local_counter);
                let new_commit = U256::from(current_nonce.as_limbs()[0] + 2);

                // Sign the request
                let sig = match sign_insert_authenticator(
                    signer.as_ref(),
                    U256::from(1),
                    new_auth,
                    0,
                    pubkey,
                    new_commit,
                    current_nonce,
                    &domain,
                )
                .await
                {
                    Ok(s) => s,
                    Err(_) => {
                        metrics.record_error();
                        local_counter += 1;
                        continue;
                    }
                };

                let body = InsertAuthenticatorRequest {
                    leaf_index: U256::from(1),
                    new_authenticator_address: new_auth,
                    old_offchain_signer_commitment: U256::from(current_nonce.as_limbs()[0] + 1),
                    new_offchain_signer_commitment: new_commit,
                    sibling_nodes: default_sibling_nodes()
                        .iter()
                        .map(|s| s.parse().unwrap())
                        .collect(),
                    signature: sig.as_bytes().to_vec(),
                    nonce: current_nonce,
                    pubkey_id: 0,
                    new_authenticator_pubkey: pubkey,
                };

                let req_start = Instant::now();
                match client
                    .post(format!("{}/insert-authenticator", base_url))
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let latency = req_start.elapsed();
                        metrics.record_request(resp.status(), latency);
                    }
                    Err(_) => {
                        metrics.record_error();
                    }
                }

                local_counter += 1;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let duration = start.elapsed();
    let summary = metrics.summary(duration);
    println!("{summary}");

    // For insert-authenticator, we expect many 4xx due to signature/nonce issues in load test
    // The main thing is the system should be responsive
    assert!(
        summary.total_requests > 0,
        "Should have processed some requests"
    );
    assert!(
        summary.latency_p99_ms < 10000,
        "p99 latency should be under 10s"
    );
}

// ============================================================================
// Load Test: Burst Traffic
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn load_test_burst_traffic() {
    let burst_size: usize = std::env::var("LOAD_TEST_BURST_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);

    println!("\nStarting load test: burst traffic");
    println!("  Burst size: {burst_size} concurrent requests");

    let gw = spawn_load_test_gateway(GW_PORT + 5).await;
    let metrics = Arc::new(LoadTestMetrics::default());
    let start = Instant::now();

    let mut handles = Vec::new();

    // Fire all requests at once
    for i in 0..burst_size {
        let client = gw.client.clone();
        let base_url = gw.base_url.clone();
        let metrics = metrics.clone();

        let handle = tokio::spawn(async move {
            let signer = PrivateKeySigner::random();
            let wallet_addr: Address = signer.address();

            let body = serde_json::json!({
                "recovery_address": wallet_addr.to_string(),
                "authenticator_addresses": [wallet_addr.to_string()],
                "authenticator_pubkeys": [format!("{}", i)],
                "offchain_signer_commitment": "0x1",
            });

            let req_start = Instant::now();
            match client
                .post(format!("{}/create-account", base_url))
                .json(&body)
                .send()
                .await
            {
                Ok(resp) => {
                    let latency = req_start.elapsed();
                    metrics.record_request(resp.status(), latency);
                }
                Err(_) => {
                    metrics.record_error();
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let duration = start.elapsed();
    let summary = metrics.summary(duration);
    println!("{summary}");

    // For burst traffic, we care about error rate and that the system doesn't completely fail
    let error_rate = summary.failed_requests as f64 / summary.total_requests.max(1) as f64 * 100.0;
    println!("Error rate: {:.2}%", error_rate);

    assert!(
        error_rate < 50.0,
        "Error rate should be under 50% during burst"
    );
}

// ============================================================================
// Run All Load Tests
// ============================================================================
// To run all load tests, use:
//   cargo test --test load_test -- --ignored --nocapture --test-threads=1
