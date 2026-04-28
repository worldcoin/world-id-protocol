use std::sync::Arc;

use axum::{
    Router,
    body::{self, Bytes},
    extract::Request,
    http::StatusCode as AxumStatusCode,
};
use base64::Engine as _;
use ruint::aliases::U256;
use serde_json::json;
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor, wait::HttpWaitStrategy},
    runners::AsyncRunner,
};
use tokio::{net::TcpListener, sync::Mutex};
use world_id_authenticator::{
    Authenticator, AuthenticatorConfig, AuthenticatorError,
    api_types::{
        CreateAccountRequest, GatewayRequestState, IndexerAuthenticatorPubkeysResponse,
        IndexerPackedAccountResponse, IndexerQueryRequest, IndexerSignatureNonceResponse,
        InsertAuthenticatorRequest, RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
    },
    ohttp::OhttpClientConfig,
};
use world_id_primitives::Config;

const OHTTP_GATEWAY_IMAGE: &str = "ghcr.io/worldcoin/ohttp-tools/ohttp-gateway";
const OHTTP_GATEWAY_TAG: &str = "latest";

// ---------------------------------------------------------------------------
// Recorded request
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Stub state shared between the Axum handlers and test assertions
// ---------------------------------------------------------------------------

#[derive(Default)]
struct StubState {
    requests: Vec<RecordedRequest>,
    responses: std::collections::HashMap<String, (AxumStatusCode, Vec<u8>)>,
}

impl StubState {
    fn set_response(&mut self, route_key: &str, status: AxumStatusCode, body: impl Into<Vec<u8>>) {
        self.responses
            .insert(route_key.to_owned(), (status, body.into()));
    }

    fn take_response(&mut self, route_key: &str) -> (AxumStatusCode, Vec<u8>) {
        self.responses
            .remove(route_key)
            .unwrap_or((AxumStatusCode::OK, b"{}".to_vec()))
    }
}

type SharedState = Arc<Mutex<StubState>>;

// ---------------------------------------------------------------------------
// Generic stub server (records every request, returns pre-configured responses)
// ---------------------------------------------------------------------------

async fn start_stub_server(state: SharedState) -> u16 {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let app = Router::new().fallback(move |req: Request| {
        let state = Arc::clone(&state);
        async move {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();
            let body_bytes = body::to_bytes(req.into_body(), usize::MAX)
                .await
                .unwrap_or_default();

            let mut st = state.lock().await;
            st.requests.push(RecordedRequest {
                method,
                path: path.clone(),
                body: body_bytes.to_vec(),
            });

            let (status, resp_body) = st.take_response(&path);
            (
                status,
                [("content-type", "application/json")],
                Bytes::from(resp_body),
            )
        }
    });

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    port
}

// ---------------------------------------------------------------------------
// Full OHTTP fixture: relay container + stub gateway + stub indexer
// ---------------------------------------------------------------------------

struct OhttpFixture {
    gateway_state: SharedState,
    indexer_state: SharedState,
    ohttp_gateway_config: OhttpClientConfig,
    ohttp_indexer_config: OhttpClientConfig,
    gateway_target_url: String,
    indexer_target_url: String,
    _container: testcontainers::ContainerAsync<GenericImage>,
}

impl OhttpFixture {
    async fn start() -> eyre::Result<Self> {
        let gateway_state: SharedState = Arc::new(Mutex::new(StubState::default()));
        let indexer_state: SharedState = Arc::new(Mutex::new(StubState::default()));

        let gw_port = start_stub_server(Arc::clone(&gateway_state)).await;
        let idx_port = start_stub_server(Arc::clone(&indexer_state)).await;

        let gw_authority = format!("gateway.test:{gw_port}");
        let idx_authority = format!("indexer.test:{idx_port}");

        let target_rewrites = serde_json::json!({
            &gw_authority: {"Scheme": "http", "Host": format!("host.testcontainers.internal:{gw_port}")},
            &idx_authority: {"Scheme": "http", "Host": format!("host.testcontainers.internal:{idx_port}")},
        });

        let allowed_origins = format!("{gw_authority},{idx_authority}");

        let container = GenericImage::new(OHTTP_GATEWAY_IMAGE, OHTTP_GATEWAY_TAG)
            .with_exposed_port(8080.tcp())
            .with_wait_for(WaitFor::Http(Box::new(
                HttpWaitStrategy::new("/health").with_expected_status_code(200_u16),
            )))
            .with_exposed_host_ports([gw_port, idx_port])
            .with_env_var(
                "SEED_SECRET_KEY",
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .with_env_var("ALLOWED_TARGET_ORIGINS", allowed_origins)
            .with_env_var("TARGET_REWRITES", target_rewrites.to_string())
            .start()
            .await?;

        let host_port = container.get_host_port_ipv4(8080).await?;
        let relay_base = format!("http://127.0.0.1:{host_port}");

        let key_bytes = reqwest::get(format!("{relay_base}/ohttp-keys"))
            .await?
            .bytes()
            .await?;
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(&key_bytes);

        let gateway_target_url = format!("http://{gw_authority}");
        let indexer_target_url = format!("http://{idx_authority}");

        let ohttp_gateway_config =
            OhttpClientConfig::new(format!("{relay_base}/gateway"), key_b64.clone());

        let ohttp_indexer_config = OhttpClientConfig::new(format!("{relay_base}/gateway"), key_b64);

        Ok(Self {
            gateway_state,
            indexer_state,
            ohttp_gateway_config,
            ohttp_indexer_config,
            gateway_target_url,
            indexer_target_url,
            _container: container,
        })
    }

    fn authenticator_config(&self) -> AuthenticatorConfig {
        let config = Config::new(
            None,
            31337,
            "0x0000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
            self.indexer_target_url.clone(),
            self.gateway_target_url.clone(),
            vec![],
            2,
        )
        .expect("test config should be valid");

        AuthenticatorConfig {
            config,
            ohttp_indexer: Some(self.ohttp_indexer_config.clone()),
            ohttp_gateway: Some(self.ohttp_gateway_config.clone()),
        }
    }

    #[allow(dead_code)]
    async fn gateway_requests(&self) -> Vec<RecordedRequest> {
        self.gateway_state.lock().await.requests.clone()
    }

    #[allow(dead_code)]
    async fn indexer_requests(&self) -> Vec<RecordedRequest> {
        self.indexer_state.lock().await.requests.clone()
    }

    async fn last_gateway_request(&self) -> Option<RecordedRequest> {
        self.gateway_state.lock().await.requests.last().cloned()
    }

    async fn last_indexer_request(&self) -> Option<RecordedRequest> {
        self.indexer_state.lock().await.requests.last().cloned()
    }

    async fn set_gateway_response(
        &self,
        route: &str,
        status: AxumStatusCode,
        body: impl Into<Vec<u8>>,
    ) {
        self.gateway_state
            .lock()
            .await
            .set_response(route, status, body);
    }

    async fn set_indexer_response(
        &self,
        route: &str,
        status: AxumStatusCode,
        body: impl Into<Vec<u8>>,
    ) {
        self.indexer_state
            .lock()
            .await
            .set_response(route, status, body);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn gateway_accepted_response(request_id: &str, kind: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "request_id": request_id,
        "kind": kind,
        "status": { "state": "queued" },
    }))
    .unwrap()
}

fn gateway_finalized_response(request_id: &str, kind: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "request_id": request_id,
        "kind": kind,
        "status": { "state": "finalized", "tx_hash": "0xdeadbeef" },
    }))
    .unwrap()
}

fn packed_account_response(packed: U256) -> Vec<u8> {
    serde_json::to_vec(&IndexerPackedAccountResponse {
        packed_account_data: packed,
    })
    .unwrap()
}

fn signature_nonce_response(nonce: U256) -> Vec<u8> {
    serde_json::to_vec(&IndexerSignatureNonceResponse {
        signature_nonce: nonce,
    })
    .unwrap()
}

fn authenticator_pubkeys_response(pubkeys: Vec<Option<U256>>) -> Vec<u8> {
    serde_json::to_vec(&IndexerAuthenticatorPubkeysResponse {
        authenticator_pubkeys: pubkeys,
        offchain_signer_commitment: U256::ZERO,
    })
    .unwrap()
}

const TEST_SEED: [u8; 32] = [42u8; 32];

fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn build_test_inclusion_proof(
    leaf_index: u64,
) -> world_id_primitives::merkle::AccountInclusionProof<{ world_id_primitives::TREE_DEPTH }> {
    use world_id_primitives::{
        AuthenticatorPublicKeySet, FieldElement, TREE_DEPTH,
        merkle::{AccountInclusionProof, MerkleInclusionProof},
    };

    let root = FieldElement::try_from(U256::from(0xABCDu64)).unwrap();
    let siblings: [FieldElement; TREE_DEPTH] =
        std::array::from_fn(|i| FieldElement::try_from(U256::from(i as u64)).unwrap());
    let merkle_proof = MerkleInclusionProof::new(root, leaf_index, siblings);

    let signer = world_id_primitives::Signer::from_seed_bytes(&TEST_SEED).unwrap();
    let mut key_set = AuthenticatorPublicKeySet::default();
    key_set.try_push(signer.offchain_signer_pubkey()).unwrap();

    AccountInclusionProof::new(merkle_proof, key_set)
}

/// Derive the onchain signer address from the test seed so stubs can match it.
fn test_onchain_address() -> alloy::primitives::Address {
    let signer = world_id_primitives::Signer::from_seed_bytes(&TEST_SEED).unwrap();
    signer.onchain_signer_address()
}

/// Derive the offchain pubkey compressed U256 for stub responses.
fn test_offchain_pubkey_u256() -> U256 {
    let signer = world_id_primitives::Signer::from_seed_bytes(&TEST_SEED).unwrap();
    let pk = signer.offchain_signer_pubkey().pk;
    let mut compressed = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&pk, &mut compressed).unwrap();
    U256::from_le_slice(&compressed)
}

// ---------------------------------------------------------------------------
// Tests: Gateway endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_and_poll_status_roundtrip_through_ohttp() -> eyre::Result<()> {
    let f = OhttpFixture::start().await?;

    f.set_gateway_response(
        "/create-account",
        AxumStatusCode::ACCEPTED,
        gateway_accepted_response("req-001", "create_account"),
    )
    .await;

    let config = f.authenticator_config();

    let initializing = Authenticator::register(&TEST_SEED, config, None).await?;
    assert_eq!(initializing.request_id().as_str(), "req-001");

    let gw_req = f
        .last_gateway_request()
        .await
        .expect("gateway should have received a request");
    assert_eq!(gw_req.method, "POST");
    assert_eq!(gw_req.path, "/create-account");

    let body: CreateAccountRequest = serde_json::from_slice(&gw_req.body)?;
    assert_eq!(body.authenticator_addresses.len(), 1);
    assert_eq!(body.authenticator_addresses[0], test_onchain_address());

    f.set_gateway_response(
        "/status/req-001",
        AxumStatusCode::OK,
        gateway_finalized_response("req-001", "create_account"),
    )
    .await;

    let status = initializing.poll_status().await?;
    assert!(
        matches!(status, GatewayRequestState::Finalized { .. }),
        "expected Finalized, got: {status:?}"
    );

    let status_req = f
        .last_gateway_request()
        .await
        .expect("gateway should have received status poll");
    assert_eq!(status_req.method, "GET");
    assert_eq!(status_req.path, "/status/req-001");

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests: Indexer endpoints (via Authenticator::init)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn init_fetches_packed_account_through_ohttp() -> eyre::Result<()> {
    install_crypto_provider();
    let f = OhttpFixture::start().await?;

    let packed = U256::from(1u64);
    f.set_indexer_response(
        "/packed-account",
        AxumStatusCode::OK,
        packed_account_response(packed),
    )
    .await;

    let config = f.authenticator_config();

    let auth = Authenticator::init(&TEST_SEED, config).await?;
    assert_eq!(auth.packed_account_data, packed);

    let idx_req = f
        .last_indexer_request()
        .await
        .expect("indexer should have received a request");
    assert_eq!(idx_req.method, "POST");
    assert_eq!(idx_req.path, "/packed-account");

    Ok(())
}

#[tokio::test]
async fn fetch_inclusion_proof_roundtrips_through_ohttp() -> eyre::Result<()> {
    install_crypto_provider();
    let f = OhttpFixture::start().await?;

    let leaf_index = 1u64;
    let packed = U256::from(leaf_index);

    f.set_indexer_response(
        "/packed-account",
        AxumStatusCode::OK,
        packed_account_response(packed),
    )
    .await;

    let config = f.authenticator_config();
    let auth = Authenticator::init(&TEST_SEED, config).await?;

    let proof = build_test_inclusion_proof(leaf_index);
    let expected_root: U256 = proof.inclusion_proof.root.into();

    f.set_indexer_response(
        "/inclusion-proof",
        AxumStatusCode::OK,
        serde_json::to_vec(&proof)?,
    )
    .await;

    let returned_proof = auth.fetch_inclusion_proof().await?;
    let proof_root: U256 = returned_proof.inclusion_proof.root.into();
    assert_eq!(proof_root, expected_root);

    let idx_req = f
        .last_indexer_request()
        .await
        .expect("indexer should have received inclusion-proof request");
    assert_eq!(idx_req.path, "/inclusion-proof");

    let body: IndexerQueryRequest = serde_json::from_slice(&idx_req.body)?;
    assert_eq!(body.leaf_index, leaf_index);

    Ok(())
}

#[tokio::test]
async fn fetch_authenticator_pubkeys_roundtrips_through_ohttp() -> eyre::Result<()> {
    install_crypto_provider();
    let f = OhttpFixture::start().await?;

    let packed = U256::from(1u64);
    let pubkey = test_offchain_pubkey_u256();

    f.set_indexer_response(
        "/packed-account",
        AxumStatusCode::OK,
        packed_account_response(packed),
    )
    .await;

    let config = f.authenticator_config();
    let auth = Authenticator::init(&TEST_SEED, config).await?;

    f.set_indexer_response(
        "/authenticator-pubkeys",
        AxumStatusCode::OK,
        authenticator_pubkeys_response(vec![Some(pubkey)]),
    )
    .await;

    let key_set = auth.fetch_authenticator_pubkeys().await?;
    assert!(
        key_set.get(0).is_some(),
        "expected at least one pubkey in the key set"
    );

    let idx_req = f
        .last_indexer_request()
        .await
        .expect("indexer should have received authenticator-pubkeys request");
    assert_eq!(idx_req.path, "/authenticator-pubkeys");

    Ok(())
}

#[tokio::test]
async fn signing_nonce_roundtrips_through_ohttp_when_no_rpc() -> eyre::Result<()> {
    install_crypto_provider();
    let f = OhttpFixture::start().await?;

    let packed = U256::from(1u64);
    let expected_nonce = U256::from(42u64);

    f.set_indexer_response(
        "/packed-account",
        AxumStatusCode::OK,
        packed_account_response(packed),
    )
    .await;

    let config = f.authenticator_config();
    let auth = Authenticator::init(&TEST_SEED, config).await?;

    f.set_indexer_response(
        "/signature-nonce",
        AxumStatusCode::OK,
        signature_nonce_response(expected_nonce),
    )
    .await;

    let nonce = auth.signing_nonce().await?;
    assert_eq!(nonce, expected_nonce);

    let idx_req = f
        .last_indexer_request()
        .await
        .expect("indexer should have received signature-nonce request");
    assert_eq!(idx_req.path, "/signature-nonce");

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests: Gateway mutation endpoints (insert / update / remove)
// ---------------------------------------------------------------------------

/// Sets up an initialized authenticator with the required indexer stubs
/// for mutation operations (signature-nonce + authenticator-pubkeys).
async fn init_authenticator_for_mutations(
    f: &OhttpFixture,
) -> Result<Authenticator, AuthenticatorError> {
    let packed = U256::from(1u64);
    f.set_indexer_response(
        "/packed-account",
        AxumStatusCode::OK,
        packed_account_response(packed),
    )
    .await;

    let config = f.authenticator_config();
    Authenticator::init(&TEST_SEED, config).await
}

/// Pre-seeds the indexer stubs needed by mutation methods.
async fn seed_mutation_stubs(f: &OhttpFixture, nonce: U256, pubkeys: Vec<Option<U256>>) {
    f.set_indexer_response(
        "/signature-nonce",
        AxumStatusCode::OK,
        signature_nonce_response(nonce),
    )
    .await;
    f.set_indexer_response(
        "/authenticator-pubkeys",
        AxumStatusCode::OK,
        authenticator_pubkeys_response(pubkeys),
    )
    .await;
}

#[tokio::test]
async fn insert_authenticator_roundtrips_through_ohttp() -> eyre::Result<()> {
    install_crypto_provider();
    let f = OhttpFixture::start().await?;
    let auth = init_authenticator_for_mutations(&f).await?;

    let pubkey = test_offchain_pubkey_u256();
    seed_mutation_stubs(&f, U256::ZERO, vec![Some(pubkey)]).await;

    f.set_gateway_response(
        "/insert-authenticator",
        AxumStatusCode::ACCEPTED,
        gateway_accepted_response("insert-001", "insert_authenticator"),
    )
    .await;

    let new_signer = world_id_primitives::Signer::from_seed_bytes(&[99u8; 32])?;
    let new_pubkey = new_signer.offchain_signer_pubkey();
    let new_address = new_signer.onchain_signer_address();

    let request_id = auth.insert_authenticator(new_pubkey, new_address).await?;
    assert_eq!(request_id.as_str(), "insert-001");

    let gw_req = f
        .last_gateway_request()
        .await
        .expect("gateway should have received insert-authenticator");
    assert_eq!(gw_req.method, "POST");
    assert_eq!(gw_req.path, "/insert-authenticator");

    let body: InsertAuthenticatorRequest = serde_json::from_slice(&gw_req.body)?;
    assert_eq!(body.leaf_index, 1);
    assert_eq!(body.new_authenticator_address, new_address);

    Ok(())
}

#[tokio::test]
async fn update_authenticator_roundtrips_through_ohttp() -> eyre::Result<()> {
    install_crypto_provider();
    let f = OhttpFixture::start().await?;
    let auth = init_authenticator_for_mutations(&f).await?;

    let pubkey = test_offchain_pubkey_u256();
    seed_mutation_stubs(&f, U256::ZERO, vec![Some(pubkey)]).await;

    f.set_gateway_response(
        "/update-authenticator",
        AxumStatusCode::ACCEPTED,
        gateway_accepted_response("update-001", "update_authenticator"),
    )
    .await;

    let new_signer = world_id_primitives::Signer::from_seed_bytes(&[88u8; 32])?;
    let new_pubkey = new_signer.offchain_signer_pubkey();
    let old_address = test_onchain_address();
    let new_address = new_signer.onchain_signer_address();

    let request_id = auth
        .update_authenticator(old_address, new_address, new_pubkey, 0)
        .await?;
    assert_eq!(request_id.as_str(), "update-001");

    let gw_req = f
        .last_gateway_request()
        .await
        .expect("gateway should have received update-authenticator");
    assert_eq!(gw_req.method, "POST");
    assert_eq!(gw_req.path, "/update-authenticator");

    let body: UpdateAuthenticatorRequest = serde_json::from_slice(&gw_req.body)?;
    assert_eq!(body.leaf_index, 1);
    assert_eq!(body.old_authenticator_address, old_address);
    assert_eq!(body.new_authenticator_address, new_address);

    Ok(())
}

#[tokio::test]
async fn remove_authenticator_roundtrips_through_ohttp() -> eyre::Result<()> {
    install_crypto_provider();
    let f = OhttpFixture::start().await?;
    let auth = init_authenticator_for_mutations(&f).await?;

    let pubkey = test_offchain_pubkey_u256();
    seed_mutation_stubs(&f, U256::ZERO, vec![Some(pubkey)]).await;

    f.set_gateway_response(
        "/remove-authenticator",
        AxumStatusCode::ACCEPTED,
        gateway_accepted_response("remove-001", "remove_authenticator"),
    )
    .await;

    let request_id = auth.remove_authenticator(test_onchain_address(), 0).await?;
    assert_eq!(request_id.as_str(), "remove-001");

    let gw_req = f
        .last_gateway_request()
        .await
        .expect("gateway should have received remove-authenticator");
    assert_eq!(gw_req.method, "POST");
    assert_eq!(gw_req.path, "/remove-authenticator");

    let body: RemoveAuthenticatorRequest = serde_json::from_slice(&gw_req.body)?;
    assert_eq!(body.leaf_index, 1);
    assert_eq!(body.authenticator_address, test_onchain_address());

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests: Error propagation through OHTTP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn packed_account_not_found_maps_to_account_does_not_exist() -> eyre::Result<()> {
    install_crypto_provider();
    let f = OhttpFixture::start().await?;

    let error_body = json!({
        "code": "account_does_not_exist",
        "message": "No account found for the given authenticator address",
    });

    f.set_indexer_response(
        "/packed-account",
        AxumStatusCode::NOT_FOUND,
        serde_json::to_vec(&error_body)?,
    )
    .await;

    let config = f.authenticator_config();

    let result = Authenticator::init(&TEST_SEED, config).await;
    assert!(
        matches!(result, Err(AuthenticatorError::AccountDoesNotExist)),
        "expected AccountDoesNotExist, got: {result:?}"
    );

    Ok(())
}

#[tokio::test]
async fn gateway_error_propagates_through_ohttp() -> eyre::Result<()> {
    let f = OhttpFixture::start().await?;

    f.set_gateway_response(
        "/create-account",
        AxumStatusCode::INTERNAL_SERVER_ERROR,
        b"internal error".to_vec(),
    )
    .await;

    let config = f.authenticator_config();
    let result = Authenticator::register(&TEST_SEED, config, None).await;

    match result {
        Err(AuthenticatorError::GatewayError { status, body }) => {
            assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
            assert!(
                body.contains("internal error"),
                "expected error body to contain 'internal error', got: {body}"
            );
        }
        Err(other) => panic!("expected GatewayError, got: {other}"),
        Ok(_) => panic!("expected GatewayError, got Ok"),
    }

    Ok(())
}
