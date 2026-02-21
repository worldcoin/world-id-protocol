use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use alloy::providers::Provider;
use axum::{
    Router,
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use tokio::net::TcpListener;
use url::Url;
use world_id_services_common::{ProviderArgs, RetryConfig};

const CHAIN_ID_RESPONSE: &str = r#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#;

/// Spawn a mock JSON-RPC server that delegates each request to the given handler.
/// Returns the server URL and a shared hit counter incremented on every request.
async fn spawn_mock_rpc(
    handler: impl Fn(u32) -> Response + Clone + Send + Sync + 'static,
) -> (Url, Arc<AtomicU32>) {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let app = Router::new().route(
        "/",
        post(move || {
            let n = counter_clone.fetch_add(1, Ordering::SeqCst);
            let resp = handler(n);
            async move { resp }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let url: Url = format!("http://{addr}").parse().unwrap();
    (url, counter)
}

fn success_response() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(CHAIN_ID_RESPONSE))
        .unwrap()
}

fn build_provider_args(urls: Vec<Url>, retry: RetryConfig) -> ProviderArgs {
    ProviderArgs {
        http: Some(urls),
        signer: None,
        throttle: None,
        retry: Some(retry),
    }
}

fn fast_retry(max_retries: u32) -> RetryConfig {
    RetryConfig {
        max_retries,
        initial_backoff_ms: 10,
        timeout_secs: 10,
        ..RetryConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Test 1: Retry on transient HTTP 502 error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn retry_succeeds_on_transient_http_error() {
    let (url, counter) = spawn_mock_rpc(|n| {
        if n < 2 {
            StatusCode::BAD_GATEWAY.into_response()
        } else {
            success_response()
        }
    })
    .await;

    let provider = build_provider_args(vec![url], fast_retry(3))
        .http()
        .await
        .unwrap();

    let chain_id = provider.get_chain_id().await.unwrap();
    assert_eq!(chain_id, 1);
    assert_eq!(counter.load(Ordering::SeqCst), 3);
}

// ---------------------------------------------------------------------------
// Test 2: Parallel fallback succeeds when one endpoint times out
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fallback_succeeds_when_endpoint_times_out() {
    // Endpoint A: hangs for 5 seconds (longer than the 1s timeout).
    // The FallbackLayer queries both endpoints in parallel, so the fast
    // one wins without needing the retry layer to fire.
    let slow_counter = Arc::new(AtomicU32::new(0));
    let slow_counter_clone = slow_counter.clone();

    let slow_app = Router::new().route(
        "/",
        post(move || {
            slow_counter_clone.fetch_add(1, Ordering::SeqCst);
            async {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                success_response()
            }
        }),
    );
    let slow_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = slow_listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(slow_listener, slow_app).await.unwrap() });
    let slow_url: Url = format!("http://{slow_addr}").parse().unwrap();

    // Endpoint B: responds immediately
    let (fast_url, fast_counter) = spawn_mock_rpc(|_| success_response()).await;

    let retry = RetryConfig {
        max_retries: 3,
        initial_backoff_ms: 10,
        timeout_secs: 1,
        ..RetryConfig::default()
    };
    let provider = build_provider_args(vec![slow_url, fast_url], retry)
        .http()
        .await
        .unwrap();

    let chain_id = provider.get_chain_id().await.unwrap();
    assert_eq!(chain_id, 1);
    assert!(slow_counter.load(Ordering::SeqCst) >= 1);
    assert!(fast_counter.load(Ordering::SeqCst) >= 1);
}

// ---------------------------------------------------------------------------
// Test 3: Max retries exhausted returns error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn max_retries_exhausted_returns_error() {
    let (url, counter) = spawn_mock_rpc(|_| StatusCode::BAD_GATEWAY.into_response()).await;

    let provider = build_provider_args(vec![url], fast_retry(2))
        .http()
        .await
        .unwrap();

    let result = provider.get_chain_id().await;
    assert!(result.is_err());
    assert_eq!(counter.load(Ordering::SeqCst), 3); // 1 initial + 2 retries
}

// ---------------------------------------------------------------------------
// Test 4: Contract revert is not retried
// ---------------------------------------------------------------------------

#[tokio::test]
async fn contract_revert_not_retried() {
    let revert_response =
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted"}}"#;

    let (url, counter) = spawn_mock_rpc(move |_| {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(revert_response))
            .unwrap()
    })
    .await;

    let provider = build_provider_args(vec![url], fast_retry(3))
        .http()
        .await
        .unwrap();

    let result = provider.get_chain_id().await;
    assert!(result.is_err());
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------
// Test 5: Parallel fallback succeeds when one endpoint refuses connections
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fallback_succeeds_when_endpoint_is_dead() {
    // Bind a port then immediately drop the listener so nothing is listening.
    // The FallbackLayer queries both endpoints in parallel — the dead one
    // errors out and the live one responds, so the call succeeds without retries.
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();
    drop(dead_listener);
    let dead_url: Url = format!("http://{dead_addr}").parse().unwrap();

    let (live_url, live_counter) = spawn_mock_rpc(|_| success_response()).await;

    let provider = build_provider_args(vec![dead_url, live_url], fast_retry(3))
        .http()
        .await
        .unwrap();

    let chain_id = provider.get_chain_id().await.unwrap();
    assert_eq!(chain_id, 1);
    assert!(live_counter.load(Ordering::SeqCst) >= 1);
}

// ---------------------------------------------------------------------------
// Test 6: Single endpoint drops first connection, succeeds on retry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn retry_after_tcp_reset_on_same_endpoint() {
    use tokio::io::AsyncWriteExt;

    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let n = counter_clone.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // First connection: accept then immediately drop (TCP RST).
                drop(stream);
            } else {
                // Subsequent connections: read the request, write a raw HTTP response.
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

                    let body = CHAIN_ID_RESPONSE;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body,
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        }
    });

    let url: Url = format!("http://{addr}").parse().unwrap();
    let provider = build_provider_args(vec![url], fast_retry(3))
        .http()
        .await
        .unwrap();

    let chain_id = provider.get_chain_id().await.unwrap();
    assert_eq!(chain_id, 1);
    assert!(counter.load(Ordering::SeqCst) >= 2);
}
