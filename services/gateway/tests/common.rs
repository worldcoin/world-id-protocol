use reqwest::{Client, StatusCode};
use std::time::Duration;
use testcontainers_modules::{
    redis::{REDIS_PORT, Redis},
    testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _},
};
use world_id_core::api_types::{GatewayRequestState, GatewayStatusResponse};

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
