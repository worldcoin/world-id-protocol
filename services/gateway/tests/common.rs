use reqwest::{Client, StatusCode};
use std::time::Duration;
use world_id_core::types::{GatewayRequestState, GatewayStatusResponse};

#[allow(dead_code)]
pub(crate) async fn wait_http_ready(client: &Client, port: u16) {
    let base = format!("http://127.0.0.1:{}", port);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(resp) = client.get(format!("{}/health", base)).send().await {
            if resp.status().is_success() {
                break;
            }
        }
        if std::time::Instant::now() > deadline {
            panic!("gateway not ready");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Wait for a request to reach finalized state, using a base URL string.
#[allow(dead_code)]
pub(crate) async fn wait_for_finalized(client: &Client, base: &str, request_id: &str) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let resp = client
            .get(format!("{}/status/{}", base, request_id))
            .send()
            .await
            .unwrap();
        let status_code = resp.status();
        // Retry on NOT_FOUND - tracking entry may be created asynchronously
        if status_code == StatusCode::NOT_FOUND {
            if std::time::Instant::now() > deadline {
                panic!("timeout: request {request_id} not found");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
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
