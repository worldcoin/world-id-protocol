use std::{net::SocketAddr, time::Duration};

use alloy::network::EthereumWallet;
use alloy::signers::local::PrivateKeySigner;
use alloy::{
    primitives::{Address, Bytes, U256},
    providers::ProviderBuilder,
    transports::http::reqwest::Url,
};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use common::authenticator_registry::AuthenticatorRegistry;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tower_http::trace::TraceLayer;

// Public configuration and handle for embedding the gateway as a library.
#[derive(Clone, Debug)]
pub struct GatewayConfig {
    pub registry_addr: Address,
    pub rpc_url: String,
    pub wallet_key: String,
    pub batch_ms: u64,
    pub listen_addr: SocketAddr,
}

#[derive(Debug)]
pub struct GatewayHandle {
    shutdown: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<anyhow::Result<()>>,
    pub listen_addr: SocketAddr,
}

impl GatewayHandle {
    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        // Wait for server task to finish
        match self.join.await {
            Ok(res) => res,
            Err(e) => Err(anyhow::anyhow!(format!("join error: {e}"))),
        }
    }
}

#[derive(Clone)]
struct AppState {
    registry_addr: Address,
    rpc_url: String,
    wallet_key: String,
    batcher: CreateBatcherHandle,
}

#[derive(Clone)]
struct CreateBatcherHandle {
    tx: mpsc::Sender<CreateReqEnvelope>,
}

#[derive(Debug, Deserialize)]
struct CreateAccountRequest {
    // optional recovery address; if omitted or 0x0, contract treats as none
    recovery_address: Option<String>,
    // list of authenticator addresses (hex)
    authenticator_addresses: Vec<String>,
    // hex or decimal U256
    offchain_signer_commitment: String,
}

#[derive(Debug, Serialize)]
struct TxResponse {
    tx_hash: String,
}

#[derive(Debug, Deserialize)]
struct UpdateAuthenticatorRequest {
    account_index: String,
    old_authenticator_address: String,
    new_authenticator_address: String,
    old_offchain_signer_commitment: String,
    new_offchain_signer_commitment: String,
    sibling_nodes: Vec<String>,
    signature: String,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct InsertAuthenticatorRequest {
    account_index: String,
    new_authenticator_address: String,
    old_offchain_signer_commitment: String,
    new_offchain_signer_commitment: String,
    sibling_nodes: Vec<String>,
    signature: String,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct RemoveAuthenticatorRequest {
    account_index: String,
    authenticator_address: String,
    old_offchain_signer_commitment: String,
    new_offchain_signer_commitment: String,
    sibling_nodes: Vec<String>,
    signature: String,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct RecoverAccountRequest {
    account_index: String,
    new_authenticator_address: String,
    old_offchain_signer_commitment: String,
    new_offchain_signer_commitment: String,
    sibling_nodes: Vec<String>,
    signature: String,
    nonce: String,
}

static DEFAULT_BATCH_MS: Lazy<u64> = Lazy::new(|| 1000);

fn build_provider(
    rpc_url: &str,
    wallet_key: &str,
) -> anyhow::Result<impl alloy::providers::Provider + Clone> {
    let wallet = EthereumWallet::from(wallet_key.parse::<PrivateKeySigner>()?);
    let url = Url::parse(rpc_url)?;
    Ok(ProviderBuilder::new().wallet(wallet).connect_http(url))
}

// ---------- Error handling helpers ----------

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Internal(String),
}

impl ApiError {
    fn bad_req(field: &str, msg: impl ToString) -> Self {
        Self::BadRequest(format!("invalid {field}: {}", msg.to_string()))
    }
    fn internal(msg: impl ToString) -> Self {
        Self::Internal(msg.to_string())
    }
}

#[derive(Serialize)]
struct ErrorBody { error: String }

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        (status, Json(ErrorBody { error: msg })).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn req_address(field: &str, s: &str) -> ApiResult<Address> {
    parse_address(s).map_err(|e| ApiError::bad_req(field, e))
}
fn req_u256(field: &str, s: &str) -> ApiResult<U256> {
    parse_u256(s).map_err(|e| ApiError::bad_req(field, e))
}
fn req_bytes(field: &str, s: &str) -> ApiResult<Bytes> {
    parse_bytes(s).map_err(|e| ApiError::bad_req(field, e))
}
fn req_u256_vec(field: &str, v: &[String]) -> ApiResult<Vec<U256>> {
    v.iter().map(|s| req_u256(field, s)).collect()
}

// Build the application state and router; used by both bin and lib entrypoints.
fn build_app(
    registry_addr: Address,
    rpc_url: String,
    wallet_key: String,
    batch_ms: u64,
) -> Router {
    let (tx, rx) = mpsc::channel(1024);
    let batcher = CreateBatcherHandle { tx };
    let runner = CreateBatcherRunner::new(
        rpc_url.clone(),
        wallet_key.clone(),
        registry_addr,
        Duration::from_millis(batch_ms),
        rx,
    );
    tokio::spawn(runner.run());

    let state = AppState {
        registry_addr,
        rpc_url,
        wallet_key,
        batcher,
    };

    Router::new()
        .route("/health", get(health))
        // account creation (batched)
        .route("/create-account", post(create_account))
        // single tx endpoints
        .route("/update-authenticator", post(update_authenticator))
        .route("/insert-authenticator", post(insert_authenticator))
        .route("/remove-authenticator", post(remove_authenticator))
        .route("/recover-account", post(recover_account))
        // admin / utility
        .route("/init-tree", post(init_tree))
        .route("/set-root-validity-window", post(set_root_validity_window))
        .route("/is-valid-root", get(is_valid_root))
        .route("/next-account-index", get(next_account_index))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

// Public API: spawn the gateway server and return a handle with shutdown.
pub async fn spawn_gateway(cfg: GatewayConfig) -> anyhow::Result<GatewayHandle> {
    let app = build_app(cfg.registry_addr, cfg.rpc_url, cfg.wallet_key, cfg.batch_ms);

    let listener = tokio::net::TcpListener::bind(cfg.listen_addr).await?;
    let addr = listener.local_addr()?;

    let (tx, rx) = oneshot::channel::<()>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = rx.await;
    });
    let join = tokio::spawn(async move {
        server.await.map_err(|e| anyhow::anyhow!(e))
    });
    Ok(GatewayHandle {
        shutdown: Some(tx),
        join,
        listen_addr: addr,
    })
}

// Public API: run to completion (blocking future) using env vars (bin-compatible)
pub async fn run_from_env() -> anyhow::Result<()> {
    let rpc_url = std::env::var("RPC_URL").expect("RPC_URL is required");
    let wallet_key = std::env::var("WALLET_KEY").expect("WALLET_KEY (hex privkey) is required");
    let registry_addr: Address = std::env::var("REGISTRY_ADDRESS")
        .expect("REGISTRY_ADDRESS is required")
        .parse()
        .expect("invalid REGISTRY_ADDRESS");
    let batch_ms: u64 = std::env::var("RG_BATCH_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(*DEFAULT_BATCH_MS);
    let port: u16 = std::env::var("RG_PORT")
        .or_else(|_| std::env::var("PORT"))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4000);
    let listen_addr = SocketAddr::from(([127, 0, 0, 1], port));

    let app = build_app(registry_addr, rpc_url, wallet_key, batch_ms);
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status":"ok"})))
}

// ------------- createAccount (batched) -------------

#[derive(Debug)]
struct CreateReqEnvelope {
    req: CreateAccountRequest,
    resp: oneshot::Sender<anyhow::Result<String>>, // tx hash hex
}

struct CreateBatcherRunner {
    rx: mpsc::Receiver<CreateReqEnvelope>,
    rpc_url: String,
    wallet_key: String,
    registry: Address,
    window: Duration,
}

impl CreateBatcherRunner {
    fn new(
        rpc_url: String,
        wallet_key: String,
        registry: Address,
        window: Duration,
        rx: mpsc::Receiver<CreateReqEnvelope>,
    ) -> Self {
        Self {
            rx,
            rpc_url,
            wallet_key,
            registry,
            window,
        }
    }
    async fn run(mut self) {
        loop {
            // pull first item (await), then collect the rest within the window
            let first = self.rx.recv().await;
            let Some(first) = first else {
                tracing::info!("create batcher channel closed");
                return;
            };

            let mut batch = vec![first];
            let deadline = tokio::time::Instant::now() + self.window;
            while tokio::time::timeout_at(deadline, async {
                let next = self.rx.try_recv().ok();
                if let Some(req) = next {
                    batch.push(req);
                    true
                } else {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    true
                }
            })
            .await
            .is_ok()
            {}

            // Parse all
            let parsed: Vec<anyhow::Result<(Option<Address>, Vec<Address>, U256)>> =
                batch.iter().map(|e| parse_create(&e.req)).collect();

            // Build aggregated params from successful parses
            let mut recovery_addresses: Vec<Address> = Vec::new();
            let mut auths: Vec<Vec<Address>> = Vec::new();
            let mut commits: Vec<U256> = Vec::new();
            for r in &parsed {
                if let Ok((rec, asv, com)) = r {
                    recovery_addresses.push(rec.unwrap_or(Address::ZERO));
                    auths.push(asv.clone());
                    commits.push(*com);
                }
            }

            // If none valid, respond errors and continue
            if auths.is_empty() {
                for (env, res) in batch.into_iter().zip(parsed.into_iter()) {
                    let _ = env.resp.send(res.map(|_| String::new()));
                }
                continue;
            }

            // Build provider on demand
            let provider = match build_provider(&self.rpc_url, &self.wallet_key) {
                Ok(p) => p,
                Err(err) => {
                    for env in batch {
                        let _ = env
                            .resp
                            .send(Err(anyhow::anyhow!(format!("provider error: {}", err))));
                    }
                    continue;
                }
            };

            let contract = AuthenticatorRegistry::new(self.registry, provider);
            let call = contract.createManyAccounts(recovery_addresses, auths, commits);
            // Send the transaction
            let tx_res = call.send().await;
            match tx_res {
                Ok(pend) => {
                    let hash = format!("0x{:x}", pend.tx_hash());
                    for (env, res) in batch.into_iter().zip(parsed.into_iter()) {
                        let _ = env.resp.send(res.map(|_| hash.clone()));
                    }
                }
                Err(err) => {
                    for env in batch {
                        let _ = env.resp.send(Err(anyhow::anyhow!(err.to_string())));
                    }
                }
            }
        }
    }
}

fn parse_address(s: &str) -> anyhow::Result<Address> {
    s.parse()
        .map_err(|e| anyhow::anyhow!("invalid address: {}", e))
}
fn parse_u256(s: &str) -> anyhow::Result<U256> {
    s.parse()
        .map_err(|e| anyhow::anyhow!("invalid u256: {}", e))
}
fn parse_bytes(s: &str) -> anyhow::Result<Bytes> {
    s.parse()
        .map_err(|e| anyhow::anyhow!("invalid bytes: {}", e))
}

fn parse_create(
    req: &CreateAccountRequest,
) -> anyhow::Result<(Option<Address>, Vec<Address>, U256)> {
    let rec = match &req.recovery_address {
        Some(s) if !s.is_empty() => Some(parse_address(s)?),
        _ => None,
    };
    let auths: Result<Vec<_>, _> = req
        .authenticator_addresses
        .iter()
        .map(|s| parse_address(s))
        .collect();
    let auths = auths?;
    let commit = parse_u256(&req.offchain_signer_commitment)?;
    Ok((rec, auths, commit))
}

async fn create_account(
    State(state): State<AppState>,
    Json(req): Json<CreateAccountRequest>,
) -> impl IntoResponse {
    let (tx, rx) = oneshot::channel();
    let env = CreateReqEnvelope { req, resp: tx };
    if let Err(_e) = state.batcher.tx.send(env).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error":"batcher unavailable"})),
        )
            .into_response();
    }
    match tokio::time::timeout(Duration::from_secs(30), rx).await {
        Ok(Ok(Ok(hash))) => (StatusCode::OK, Json(TxResponse { tx_hash: hash })).into_response(),
        Ok(Ok(Err(err))) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": err.to_string()})),
        )
            .into_response(),
        Ok(Err(_canceled)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error":"batcher canceled"})),
        )
            .into_response(),
        Err(_elapsed) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"status":"pending"})),
        )
            .into_response(),
    }
}

// ------------- single-tx endpoints -------------

async fn update_authenticator(
    State(state): State<AppState>,
    Json(req): Json<UpdateAuthenticatorRequest>,
) -> ApiResult<impl IntoResponse> {
    let old_authenticator_address = req_address("old_authenticator_address", &req.old_authenticator_address)?;
    let new_authenticator_address = req_address("new_authenticator_address", &req.new_authenticator_address)?;
    let account_index = req_u256("account_index", &req.account_index)?;
    let old_commit = req_u256("old_offchain_signer_commitment", &req.old_offchain_signer_commitment)?;
    let new_commit = req_u256("new_offchain_signer_commitment", &req.new_offchain_signer_commitment)?;
    let sibling_nodes = req_u256_vec("sibling_nodes", &req.sibling_nodes)?;
    let signature = req_bytes("signature", &req.signature)?;
    let nonce = req_u256("nonce", &req.nonce)?;

    let provider = build_provider(&state.rpc_url, &state.wallet_key)
        .map_err(|e| ApiError::internal(format!("provider: {e}")))?;
    let contract = AuthenticatorRegistry::new(state.registry_addr, provider);
    let p = contract
        .updateAuthenticator(
            account_index,
            old_authenticator_address,
            new_authenticator_address,
            old_commit,
            new_commit,
            signature,
            sibling_nodes,
            nonce,
        )
        .send()
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok((
        StatusCode::OK,
        Json(TxResponse {
            tx_hash: format!("0x{:x}", p.tx_hash()),
        }),
    ))
}

async fn insert_authenticator(
    State(state): State<AppState>,
    Json(req): Json<InsertAuthenticatorRequest>,
) -> ApiResult<impl IntoResponse> {
    let new_authenticator_address = req_address("new_authenticator_address", &req.new_authenticator_address)?;
    let account_index = req_u256("account_index", &req.account_index)?;
    let old_commit = req_u256("old_offchain_signer_commitment", &req.old_offchain_signer_commitment)?;
    let new_commit = req_u256("new_offchain_signer_commitment", &req.new_offchain_signer_commitment)?;
    let sibling_nodes = req_u256_vec("sibling_nodes", &req.sibling_nodes)?;
    let signature = req_bytes("signature", &req.signature)?;
    let nonce = req_u256("nonce", &req.nonce)?;

    let provider = build_provider(&state.rpc_url, &state.wallet_key)
        .map_err(|e| ApiError::internal(format!("provider: {e}")))?;
    let contract = AuthenticatorRegistry::new(state.registry_addr, provider);
    let p = contract
        .insertAuthenticator(
            account_index,
            new_authenticator_address,
            old_commit,
            new_commit,
            signature,
            sibling_nodes,
            nonce,
        )
        .send()
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok((
        StatusCode::OK,
        Json(TxResponse {
            tx_hash: format!("0x{:x}", p.tx_hash()),
        }),
    ))
}

async fn remove_authenticator(
    State(state): State<AppState>,
    Json(req): Json<RemoveAuthenticatorRequest>,
) -> ApiResult<impl IntoResponse> {
    let authenticator_address = req_address("authenticator_address", &req.authenticator_address)?;
    let account_index = req_u256("account_index", &req.account_index)?;
    let old_commit = req_u256("old_offchain_signer_commitment", &req.old_offchain_signer_commitment)?;
    let new_commit = req_u256("new_offchain_signer_commitment", &req.new_offchain_signer_commitment)?;
    let sibling_nodes = req_u256_vec("sibling_nodes", &req.sibling_nodes)?;
    let signature = req_bytes("signature", &req.signature)?;
    let nonce = req_u256("nonce", &req.nonce)?;

    let provider = build_provider(&state.rpc_url, &state.wallet_key)
        .map_err(|e| ApiError::internal(format!("provider: {e}")))?;
    let contract = AuthenticatorRegistry::new(state.registry_addr, provider);
    let p = contract
        .removeAuthenticator(
            account_index,
            authenticator_address,
            old_commit,
            new_commit,
            signature,
            sibling_nodes,
            nonce,
        )
        .send()
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok((
        StatusCode::OK,
        Json(TxResponse {
            tx_hash: format!("0x{:x}", p.tx_hash()),
        }),
    ))
}

async fn recover_account(
    State(state): State<AppState>,
    Json(req): Json<RecoverAccountRequest>,
) -> ApiResult<impl IntoResponse> {
    let new_authenticator_address = req_address("new_authenticator_address", &req.new_authenticator_address)?;
    let account_index = req_u256("account_index", &req.account_index)?;
    let old_commit = req_u256("old_offchain_signer_commitment", &req.old_offchain_signer_commitment)?;
    let new_commit = req_u256("new_offchain_signer_commitment", &req.new_offchain_signer_commitment)?;
    let sibling_nodes = req_u256_vec("sibling_nodes", &req.sibling_nodes)?;
    let signature = req_bytes("signature", &req.signature)?;
    let nonce = req_u256("nonce", &req.nonce)?;

    let provider = build_provider(&state.rpc_url, &state.wallet_key)
        .map_err(|e| ApiError::internal(format!("provider: {e}")))?;
    let contract = AuthenticatorRegistry::new(state.registry_addr, provider);
    let p = contract
        .recoverAccount(
            account_index,
            new_authenticator_address,
            old_commit,
            new_commit,
            signature,
            sibling_nodes,
            nonce,
        )
        .send()
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok((
        StatusCode::OK,
        Json(TxResponse {
            tx_hash: format!("0x{:x}", p.tx_hash()),
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct InitTreeRequest {
    depth: String,
    size: String,
    side_nodes: Vec<String>,
}

async fn init_tree(
    State(state): State<AppState>,
    Json(req): Json<InitTreeRequest>,
) -> ApiResult<impl IntoResponse> {
    let depth = req_u256("depth", &req.depth)?;
    let size = req_u256("size", &req.size)?;
    let side_nodes = req_u256_vec("side_nodes", &req.side_nodes)?;
    let provider = build_provider(&state.rpc_url, &state.wallet_key)
        .map_err(|e| ApiError::internal(format!("provider: {e}")))?;
    let contract = AuthenticatorRegistry::new(state.registry_addr, provider);
    let p = contract
        .initTree(depth, size, side_nodes)
        .send()
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok((
        StatusCode::OK,
        Json(TxResponse {
            tx_hash: format!("0x{:x}", p.tx_hash()),
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct RootValidityWindowRequest {
    new_window: String,
}

async fn set_root_validity_window(
    State(state): State<AppState>,
    Json(req): Json<RootValidityWindowRequest>,
) -> ApiResult<impl IntoResponse> {
    let new_window = req_u256("new_window", &req.new_window)?;
    let provider = build_provider(&state.rpc_url, &state.wallet_key)
        .map_err(|e| ApiError::internal(format!("provider: {e}")))?;
    let contract = AuthenticatorRegistry::new(state.registry_addr, provider);
    let p = contract
        .setRootValidityWindow(new_window)
        .send()
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok((
        StatusCode::OK,
        Json(TxResponse {
            tx_hash: format!("0x{:x}", p.tx_hash()),
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct IsValidRootQuery {
    root: String,
}

async fn is_valid_root(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<IsValidRootQuery>,
) -> ApiResult<impl IntoResponse> {
    let root = req_u256("root", &q.root)?;
    let provider = build_provider(&state.rpc_url, &state.wallet_key)
        .map_err(|e| ApiError::internal(format!("provider: {e}")))?;
    let contract = AuthenticatorRegistry::new(state.registry_addr, provider);
    let valid = contract
        .isValidRoot(root)
        .call()
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok((StatusCode::OK, Json(serde_json::json!({"valid": valid}))))
}

async fn next_account_index(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let provider = build_provider(&state.rpc_url, &state.wallet_key)
        .map_err(|e| ApiError::internal(format!("provider: {e}")))?;
    let contract = AuthenticatorRegistry::new(state.registry_addr, provider);
    let v = contract
        .nextAccountIndex()
        .call()
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"nextAccountIndex": format!("0x{:x}", v)})),
    ))
}
