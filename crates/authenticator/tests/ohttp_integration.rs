use std::sync::Arc;

use axum::{Router, body, body::Bytes, extract::Request, http::StatusCode as AxumStatusCode};
use base64::Engine as _;
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::HttpWaitStrategy},
    runners::AsyncRunner,
};
use tokio::{net::TcpListener, sync::Mutex};
use world_id_authenticator::ohttp::{OhttpClient, OhttpClientConfig};

const OHTTP_GATEWAY_IMAGE: &str = "ghcr.io/worldcoin/ohttp-tools/ohttp-gateway";
const OHTTP_GATEWAY_TAG: &str = "latest";

/// Recorded HTTP request received by the backend stub.
#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

/// Shared state between the backend stub and tests.
#[derive(Default)]
struct BackendState {
    requests: Vec<RecordedRequest>,
    next_status: Option<AxumStatusCode>,
    next_body: Option<Vec<u8>>,
}

/// Complete test fixture: backend stub + ohttp-gateway container + configured `OhttpClient`.
struct TestFixture {
    client: OhttpClient,
    state: Arc<Mutex<BackendState>>,
    _container: testcontainers::ContainerAsync<GenericImage>,
}

impl TestFixture {
    async fn start() -> eyre::Result<Self> {
        let state = Arc::new(Mutex::new(BackendState::default()));
        let state_clone = Arc::clone(&state);

        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let backend_port = listener.local_addr()?.port();

        let app = Router::new().fallback(move |req: Request| {
            let state = Arc::clone(&state_clone);
            async move {
                let method = req.method().to_string();
                let path = req.uri().path().to_string();
                let body_bytes = body::to_bytes(req.into_body(), usize::MAX)
                    .await
                    .unwrap_or_default();

                let mut st = state.lock().await;
                st.requests.push(RecordedRequest {
                    method,
                    path,
                    body: body_bytes.to_vec(),
                });

                let status = st.next_status.take().unwrap_or(AxumStatusCode::OK);
                let body = st.next_body.take().unwrap_or_else(|| body_bytes.to_vec());

                (
                    status,
                    [("content-type", "application/json")],
                    Bytes::from(body),
                )
            }
        });

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let authority_port: u16 = 9999;
        let target_rewrites = format!(
            r#"{{"localhost:{authority_port}": {{"Scheme": "http", "Host": "host.testcontainers.internal:{backend_port}"}}}}"#
        );

        let container = GenericImage::new(OHTTP_GATEWAY_IMAGE, OHTTP_GATEWAY_TAG)
            .with_exposed_port(8080.tcp())
            .with_wait_for(WaitFor::Http(Box::new(
                HttpWaitStrategy::new("/health").with_expected_status_code(200_u16),
            )))
            .with_exposed_host_port(backend_port)
            .with_env_var(
                "SEED_SECRET_KEY",
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .with_env_var(
                "ALLOWED_TARGET_ORIGINS",
                format!("localhost:{authority_port}"),
            )
            .with_env_var("TARGET_REWRITES", target_rewrites)
            .start()
            .await?;

        let host_port = container.get_host_port_ipv4(8080).await?;
        let gateway_base = format!("http://127.0.0.1:{host_port}");

        let key_bytes = reqwest::get(format!("{gateway_base}/ohttp-keys"))
            .await?
            .bytes()
            .await?;

        let target_url = format!("http://localhost:{authority_port}");
        let config = OhttpClientConfig::new(
            format!("{gateway_base}/gateway"),
            base64::engine::general_purpose::STANDARD.encode(&key_bytes),
        );

        let client = OhttpClient::new(reqwest::Client::new(), "test", &target_url, config)?;

        Ok(Self {
            client,
            state,
            _container: container,
        })
    }

    async fn last_request(&self) -> Option<RecordedRequest> {
        self.state.lock().await.requests.last().cloned()
    }
}

#[tokio::test]
async fn post_json_roundtrips_through_ohttp_gateway() -> eyre::Result<()> {
    let fixture = TestFixture::start().await?;

    let response = fixture
        .client
        .post_json("/echo", &serde_json::json!({ "hello": "world" }))
        .await?;

    assert_eq!(response.status, reqwest::StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.body)?,
        serde_json::json!({ "hello": "world" })
    );

    let req = fixture
        .last_request()
        .await
        .expect("backend received a request");
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/echo");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&req.body)?,
        serde_json::json!({ "hello": "world" })
    );

    Ok(())
}

#[tokio::test]
async fn get_roundtrips_through_ohttp_gateway() -> eyre::Result<()> {
    let fixture = TestFixture::start().await?;

    fixture.state.lock().await.next_body =
        Some(serde_json::to_vec(&serde_json::json!({ "status": "ok" }))?);

    let response = fixture.client.get("/health-check").await?;

    assert_eq!(response.status, reqwest::StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response.body)?,
        serde_json::json!({ "status": "ok" })
    );

    let req = fixture
        .last_request()
        .await
        .expect("backend received a request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/health-check");

    Ok(())
}
