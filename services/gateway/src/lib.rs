use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use alloy::network::{EthereumWallet, TxSigner};
use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::{aws::AwsSigner, local::PrivateKeySigner},
    transports::http::reqwest::Url,
};
use aws_config::BehaviorVersion;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, RwLock};
use tower_http::trace::TraceLayer;
use utoipa::{IntoParams, OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use world_id_core::account_registry::AccountRegistry;
use world_id_core::types::{
    CreateAccountRequest, InsertAuthenticatorRequest, RecoverAccountRequest,
    RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
};

pub use crate::config::{GatewayConfig, SignerConfig};

mod config;
mod create_batcher;
mod ops_batcher;

use create_batcher::{CreateBatcherHandle, CreateBatcherRunner, CreateReqEnvelope};
use ops_batcher::{OpEnvelope, OpKind, OpsBatcherHandle, OpsBatcherRunner};

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
    provider: DynProvider,
    batcher: CreateBatcherHandle,
    ops_batcher: OpsBatcherHandle,
    tracker: RequestTracker,
}

#[derive(Clone)]
pub(crate) struct RequestTracker {
    inner: Arc<RwLock<std::collections::HashMap<String, RequestRecord>>>,
    seq: Arc<AtomicU64>,
}

impl RequestTracker {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(std::collections::HashMap::new())),
            seq: Arc::new(AtomicU64::new(1)),
        }
    }

    pub(crate) async fn new_request(&self, kind: RequestKind) -> String {
        let id = self.seq.fetch_add(1, Ordering::Relaxed);
        let id = format!("{id:016x}");
        let record = RequestRecord {
            kind,
            status: RequestState::Queued,
        };
        self.inner.write().await.insert(id.clone(), record);
        id
    }

    pub(crate) async fn set_status_batch(&self, ids: &[String], status: RequestState) {
        let mut map = self.inner.write().await;
        for id in ids {
            if let Some(rec) = map.get_mut(id) {
                rec.status = status.clone();
            }
        }
    }

    pub(crate) async fn set_status(&self, id: &str, status: RequestState) {
        self.set_status_batch(&[id.to_string()], status).await;
    }

    pub(crate) async fn snapshot(&self, id: &str) -> Option<RequestRecord> {
        self.inner.read().await.get(id).cloned()
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum RequestKind {
    CreateAccount,
    UpdateAuthenticator,
    InsertAuthenticator,
    RemoveAuthenticator,
    RecoverAccount,
}

#[derive(Debug, Clone, thiserror::Error, ToSchema)]
pub(crate) enum GatewayError {
    #[error("Authenticator already exists")]
    AuthenticatorAlreadyExists,
    #[error("Transaction reverted on-chain (tx: {0})")]
    TransactionReverted(String),
    #[error("Transaction confirmation error: {0}")]
    ConfirmationError(String),
    #[error("Batcher unavailable")]
    BatcherUnavailable,
    #[error("Pre-flight check failed: {0}")]
    PreFlightFailed(String),
    #[error("{0}")]
    Unknown(String),
}

impl Serialize for GatewayError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let code = match self {
            GatewayError::AuthenticatorAlreadyExists => "AUTHENTICATOR_ALREADY_EXISTS",
            GatewayError::TransactionReverted(_) => "TRANSACTION_REVERTED",
            GatewayError::ConfirmationError(_) => "CONFIRMATION_ERROR",
            GatewayError::BatcherUnavailable => "BATCHER_UNAVAILABLE",
            GatewayError::PreFlightFailed(_) => "PRE_FLIGHT_FAILED",
            GatewayError::Unknown(_) => "UNKNOWN",
        };
        serializer.serialize_str(code)
    }
}

impl GatewayError {
    pub(crate) fn from_contract_error(error: &str) -> Self {
        let msg_lower = error.to_lowercase();

        if msg_lower.contains("authenticator already exists") {
            GatewayError::AuthenticatorAlreadyExists
        } else {
            GatewayError::Unknown(error.to_string())
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum RequestState {
    Queued,
    Batching,
    Submitted {
        tx_hash: String,
    },
    Finalized {
        tx_hash: String,
    },
    Failed {
        error: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_code: Option<GatewayError>,
    },
}

impl RequestState {
    pub(crate) fn failed_from_error(err: GatewayError) -> Self {
        RequestState::Failed {
            error: err.to_string(),
            error_code: Some(err),
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
struct RequestRecord {
    kind: RequestKind,
    status: RequestState,
}

#[derive(Debug, Serialize, ToSchema)]
struct RequestStatusResponse {
    request_id: String,
    kind: RequestKind,
    status: RequestState,
}

#[derive(Debug, Serialize, ToSchema)]
struct HealthResponse {
    status: String,
}

async fn build_wallet(
    signer_config: SignerConfig,
    rpc_url: &str,
) -> anyhow::Result<EthereumWallet> {
    match signer_config {
        SignerConfig::PrivateKey(pk) => {
            let signer = pk
                .parse::<PrivateKeySigner>()
                .map_err(|e| anyhow::anyhow!("invalid private key: {e}"))?;
            Ok(EthereumWallet::from(signer))
        }
        SignerConfig::AwsKms(key_id) => {
            tracing::info!("Initializing AWS KMS signer with key_id: {}", key_id);

            // Create a temporary provider to fetch the chain ID
            let url = Url::parse(rpc_url)?;
            let temp_provider = ProviderBuilder::new().connect_http(url);
            let chain_id = temp_provider.get_chain_id().await?;
            tracing::info!("Fetched chain_id: {}", chain_id);

            // Initialize AWS KMS signer with the chain ID
            let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
            let client = aws_sdk_kms::Client::new(&config);
            let aws_signer = AwsSigner::new(client, key_id, Some(chain_id))
                .await
                .map_err(|e| anyhow::anyhow!("failed to initialize AWS KMS signer: {e}"))?;
            tracing::info!(
                "AWS KMS signer initialized with address: {}",
                aws_signer.address()
            );
            Ok(EthereumWallet::from(aws_signer))
        }
    }
}

fn build_provider(rpc_url: &str, ethereum_wallet: EthereumWallet) -> anyhow::Result<DynProvider> {
    let url = Url::parse(rpc_url)?;
    let provider = ProviderBuilder::new()
        .wallet(ethereum_wallet)
        .connect_http(url);
    Ok(provider.erased())
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Internal(String),
    #[error("{0}")]
    NotFound(String),
}

impl ApiError {
    fn bad_req(field: &str, msg: impl ToString) -> Self {
        Self::BadRequest(format!("invalid {field}: {}", msg.to_string()))
    }
}

#[derive(Serialize, ToSchema)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        };
        (status, Json(ErrorBody { error: msg })).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn req_u256(field: &str, s: &str) -> ApiResult<U256> {
    s.parse().map_err(|e| ApiError::bad_req(field, e))
}

async fn build_app(
    registry_addr: Address,
    rpc_url: String,
    signer_config: SignerConfig,
    batch_ms: u64,
    max_create_batch_size: usize,
    max_ops_batch_size: usize,
) -> anyhow::Result<Router> {
    let ethereum_wallet = build_wallet(signer_config, &rpc_url).await?;
    let provider = build_provider(&rpc_url, ethereum_wallet)?;
    tracing::info!("RPC Provider built");
    let tracker = RequestTracker::new();
    let (tx, rx) = mpsc::channel(1024);
    let batcher = CreateBatcherHandle { tx };
    let runner = CreateBatcherRunner::new(
        provider.clone(),
        registry_addr,
        Duration::from_millis(batch_ms),
        max_create_batch_size,
        rx,
        tracker.clone(),
    );
    tokio::spawn(runner.run());

    // ops batcher (insert/remove/recover/update)
    let (otx, orx) = mpsc::channel(2048);
    let ops_batcher = OpsBatcherHandle { tx: otx };
    let ops_runner = OpsBatcherRunner::new(
        provider.clone(),
        registry_addr,
        Duration::from_millis(batch_ms),
        max_ops_batch_size,
        orx,
        tracker.clone(),
    );
    tokio::spawn(ops_runner.run());

    tracing::info!("Ops batcher initialized");

    let state = AppState {
        registry_addr,
        provider,
        batcher,
        ops_batcher,
        tracker,
    };

    Ok(Router::new()
        .route("/health", get(health))
        // account creation (batched)
        .route("/create-account", post(create_account))
        .route("/status/{id}", get(request_status))
        // single tx endpoints
        .route("/update-authenticator", post(update_authenticator))
        .route("/insert-authenticator", post(insert_authenticator))
        .route("/remove-authenticator", post(remove_authenticator))
        .route("/recover-account", post(recover_account))
        // admin / utility
        .route("/is-valid-root", get(is_valid_root))
        .with_state(state)
        .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(TraceLayer::new_for_http())
        .layer(tower_http::timeout::TimeoutLayer::new(Duration::from_secs(
            30,
        ))))
}

/// For tests only: spawn the gateway server and return a handle with shutdown.
pub async fn spawn_gateway_for_tests(cfg: GatewayConfig) -> anyhow::Result<GatewayHandle> {
    let signer_config = cfg.signer_config()?;
    let app = build_app(
        cfg.registry_addr,
        cfg.rpc_url,
        signer_config,
        cfg.batch_ms,
        cfg.max_create_batch_size,
        cfg.max_ops_batch_size,
    )
    .await?;

    let listener = tokio::net::TcpListener::bind(cfg.listen_addr).await?;
    let addr = listener.local_addr()?;

    let (tx, rx) = oneshot::channel::<()>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = rx.await;
    });
    let join = tokio::spawn(async move { server.await.map_err(|e| anyhow::anyhow!(e)) });
    Ok(GatewayHandle {
        shutdown: Some(tx),
        join,
        listen_addr: addr,
    })
}

// Public API: run to completion (blocking future) using env vars (bin-compatible)
pub async fn run() -> anyhow::Result<()> {
    let cfg = GatewayConfig::from_env();
    let signer_config = cfg.signer_config()?;
    tracing::info!("Config is ready. Building app...");
    let app = build_app(
        cfg.registry_addr,
        cfg.rpc_url,
        signer_config,
        cfg.batch_ms,
        cfg.max_create_batch_size,
        cfg.max_ops_batch_size,
    )
    .await?;
    let listener = tokio::net::TcpListener::bind(cfg.listen_addr).await?;
    tracing::info!("HTTP server listening on {}", cfg.listen_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "General status check for the server", body = HealthResponse)
    ),
    tag = "Gateway"
)]
async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status":"ok"})))
}

async fn create_account(
    State(state): State<AppState>,
    Json(req): Json<CreateAccountRequest>,
) -> ApiResult<impl IntoResponse> {
    // Simulate the account creation BEFORE queueing to catch errors early
    let contract = AccountRegistry::new(state.registry_addr, state.provider.clone());
    let sim_result = contract
        .createManyAccounts(
            vec![req.recovery_address.unwrap_or(Address::ZERO)],
            vec![req.authenticator_addresses.clone()],
            vec![req.authenticator_pubkeys.clone()],
            vec![req.offchain_signer_commitment],
        )
        .call()
        .await;

    if let Err(e) = sim_result {
        let error_str = e.to_string();
        let gateway_error = GatewayError::from_contract_error(&error_str);
        return Err(ApiError::BadRequest(gateway_error.to_string()));
    }

    let id = state.tracker.new_request(RequestKind::CreateAccount).await;

    let env = CreateReqEnvelope {
        id: id.clone(),
        req,
    };

    if state.batcher.tx.send(env).await.is_err() {
        state
            .tracker
            .set_status(
                &id,
                RequestState::failed_from_error(GatewayError::BatcherUnavailable),
            )
            .await;
        return Err(ApiError::Internal("batcher unavailable".into()));
    }

    let record = state
        .tracker
        .snapshot(&id)
        .await
        .expect("request must exist immediately after insertion");

    let body = RequestStatusResponse {
        request_id: id,
        kind: record.kind,
        status: record.status,
    };

    Ok((StatusCode::ACCEPTED, Json(body)))
}

async fn update_authenticator(
    State(state): State<AppState>,
    Json(req): Json<UpdateAuthenticatorRequest>,
) -> ApiResult<impl IntoResponse> {
    let id = state
        .tracker
        .new_request(RequestKind::UpdateAuthenticator)
        .await;

    let env = OpEnvelope {
        id: id.clone(),
        kind: OpKind::Update {
            account_index: req.account_index,
            old_authenticator_address: req.old_authenticator_address,
            new_authenticator_address: req.new_authenticator_address,
            old_commit: req.old_offchain_signer_commitment,
            new_commit: req.new_offchain_signer_commitment,
            sibling_nodes: req.sibling_nodes.clone(),
            signature: Bytes::from(req.signature.clone()),
            nonce: req.nonce,
            pubkey_id: req.pubkey_id.unwrap_or(U256::from(0u64)),
            new_pubkey: req.new_authenticator_pubkey.unwrap_or(U256::from(0u64)),
        },
    };

    if state.ops_batcher.tx.send(env).await.is_err() {
        state
            .tracker
            .set_status(
                &id,
                RequestState::failed_from_error(GatewayError::BatcherUnavailable),
            )
            .await;
        return Err(ApiError::Internal("ops batcher unavailable".into()));
    }

    let record = state
        .tracker
        .snapshot(&id)
        .await
        .expect("request must exist immediately after insertion");

    let body = RequestStatusResponse {
        request_id: id,
        kind: record.kind,
        status: record.status,
    };

    Ok((StatusCode::ACCEPTED, Json(body)))
}

async fn insert_authenticator(
    State(state): State<AppState>,
    Json(req): Json<InsertAuthenticatorRequest>,
) -> ApiResult<impl IntoResponse> {
    let id = state
        .tracker
        .new_request(RequestKind::InsertAuthenticator)
        .await;
    let env = OpEnvelope {
        id: id.clone(),
        kind: OpKind::Insert {
            account_index: req.account_index,
            new_authenticator_address: req.new_authenticator_address,
            old_commit: req.old_offchain_signer_commitment,
            new_commit: req.new_offchain_signer_commitment,
            sibling_nodes: req.sibling_nodes.clone(),
            signature: Bytes::from(req.signature.clone()),
            nonce: req.nonce,
            pubkey_id: req.pubkey_id,
            new_pubkey: req.new_authenticator_pubkey,
        },
    };

    if state.ops_batcher.tx.send(env).await.is_err() {
        state
            .tracker
            .set_status(
                &id,
                RequestState::failed_from_error(GatewayError::BatcherUnavailable),
            )
            .await;
        return Err(ApiError::Internal("ops batcher unavailable".into()));
    }

    let record = state
        .tracker
        .snapshot(&id)
        .await
        .expect("request must exist immediately after insertion");

    let body = RequestStatusResponse {
        request_id: id,
        kind: record.kind,
        status: record.status,
    };

    Ok((StatusCode::ACCEPTED, Json(body)))
}

async fn remove_authenticator(
    State(state): State<AppState>,
    Json(req): Json<RemoveAuthenticatorRequest>,
) -> ApiResult<impl IntoResponse> {
    let id = state
        .tracker
        .new_request(RequestKind::RemoveAuthenticator)
        .await;
    let env = OpEnvelope {
        id: id.clone(),
        kind: OpKind::Remove {
            account_index: req.account_index,
            authenticator_address: req.authenticator_address,
            old_commit: req.old_offchain_signer_commitment,
            new_commit: req.new_offchain_signer_commitment,
            sibling_nodes: req.sibling_nodes.clone(),
            signature: Bytes::from(req.signature.clone()),
            nonce: req.nonce,
            pubkey_id: req.pubkey_id.unwrap_or(U256::from(0u64)),
            authenticator_pubkey: req.authenticator_pubkey.unwrap_or(U256::from(0u64)),
        },
    };

    if state.ops_batcher.tx.send(env).await.is_err() {
        state
            .tracker
            .set_status(
                &id,
                RequestState::failed_from_error(GatewayError::BatcherUnavailable),
            )
            .await;
        return Err(ApiError::Internal("ops batcher unavailable".into()));
    }

    let record = state
        .tracker
        .snapshot(&id)
        .await
        .expect("request must exist immediately after insertion");

    let body = RequestStatusResponse {
        request_id: id,
        kind: record.kind,
        status: record.status,
    };

    Ok((StatusCode::ACCEPTED, Json(body)))
}

async fn recover_account(
    State(state): State<AppState>,
    Json(req): Json<RecoverAccountRequest>,
) -> ApiResult<impl IntoResponse> {
    let id = state.tracker.new_request(RequestKind::RecoverAccount).await;
    let env = OpEnvelope {
        id: id.clone(),
        kind: OpKind::Recover {
            account_index: req.account_index,
            new_authenticator_address: req.new_authenticator_address,
            old_commit: req.old_offchain_signer_commitment,
            new_commit: req.new_offchain_signer_commitment,
            sibling_nodes: req.sibling_nodes.clone(),
            signature: Bytes::from(req.signature.clone()),
            nonce: req.nonce,
            new_pubkey: req.new_authenticator_pubkey.unwrap_or(U256::from(0u64)),
        },
    };

    if state.ops_batcher.tx.send(env).await.is_err() {
        state
            .tracker
            .set_status(
                &id,
                RequestState::failed_from_error(GatewayError::BatcherUnavailable),
            )
            .await;
        return Err(ApiError::Internal("ops batcher unavailable".into()));
    }

    let record = state
        .tracker
        .snapshot(&id)
        .await
        .expect("request must exist immediately after insertion");

    let body = RequestStatusResponse {
        request_id: id,
        kind: record.kind,
        status: record.status,
    };

    Ok((StatusCode::ACCEPTED, Json(body)))
}

async fn request_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let record = state
        .tracker
        .snapshot(&id)
        .await
        .ok_or_else(|| ApiError::NotFound("request not found".into()))?;

    let body = RequestStatusResponse {
        request_id: id,
        kind: record.kind,
        status: record.status,
    };

    Ok((StatusCode::OK, Json(body)))
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
struct IsValidRootQuery {
    #[schema(value_type = String, format = "decimal")]
    root: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct IsValidRootResponse {
    valid: bool,
}

async fn is_valid_root(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<IsValidRootQuery>,
) -> ApiResult<impl IntoResponse> {
    let root = req_u256("root", &q.root)?;
    let contract = AccountRegistry::new(state.registry_addr, state.provider.clone());
    let valid = contract
        .isValidRoot(root)
        .call()
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok((StatusCode::OK, Json(serde_json::json!({"valid": valid}))))
}

#[utoipa::path(
    post,
    path = "/create-account",
    request_body = CreateAccountRequest,
    responses(
        (status = 202, description = "TODO", body = RequestStatusResponse),
        (status = 500, description = "TODO", body = ErrorBody)
    ),
    tag = "Gateway"
)]
async fn _doc_create_account(_: State<AppState>, _: Json<CreateAccountRequest>) {}

#[utoipa::path(
    get,
    path = "/status/{id}",
    params(
        ("id" = String, Path, description = "TODO")
    ),
    responses(
        (status = 200, description = "TODO", body = RequestStatusResponse),
        (status = 404, description = "TODO", body = ErrorBody)
    ),
    tag = "Gateway"
)]
async fn _doc_request_status(_: State<AppState>, _: Path<String>) {}

#[utoipa::path(
    post,
    path = "/update-authenticator",
    request_body = UpdateAuthenticatorRequest,
    responses(
        (status = 202, description = "TODO", body = RequestStatusResponse),
        (status = 500, description = "TODO", body = ErrorBody)
    ),
    tag = "Gateway"
)]
async fn _doc_update_authenticator(_: State<AppState>, _: Json<UpdateAuthenticatorRequest>) {}

#[utoipa::path(
    post,
    path = "/insert-authenticator",
    request_body = InsertAuthenticatorRequest,
    responses(
        (status = 202, description = "TODO", body = RequestStatusResponse),
        (status = 500, description = "TODO", body = ErrorBody)
    ),
    tag = "Gateway"
)]
async fn _doc_insert_authenticator(_: State<AppState>, _: Json<InsertAuthenticatorRequest>) {}

#[utoipa::path(
    post,
    path = "/remove-authenticator",
    request_body = RemoveAuthenticatorRequest,
    responses(
        (status = 202, description = "TODO", body = RequestStatusResponse),
        (status = 500, description = "TODO", body = ErrorBody)
    ),
    tag = "Gateway"
)]
async fn _doc_remove_authenticator(_: State<AppState>, _: Json<RemoveAuthenticatorRequest>) {}

#[utoipa::path(
    post,
    path = "/recover-account",
    request_body = RecoverAccountRequest,
    responses(
        (status = 202, description = "TODO", body = RequestStatusResponse),
        (status = 500, description = "TODO", body = ErrorBody)
    ),
    tag = "Gateway"
)]
async fn _doc_recover_account(_: State<AppState>, _: Json<RecoverAccountRequest>) {}

#[utoipa::path(
    get,
    path = "/is-valid-root",
    params(IsValidRootQuery),
    responses(
        (status = 200, description = "TODO", body = IsValidRootResponse),
        (status = 400, description = "TODO", body = ErrorBody)
    ),
    tag = "Gateway"
)]
async fn _doc_is_valid_root(_: State<AppState>, _: axum::extract::Query<IsValidRootQuery>) {}

#[derive(OpenApi)]
#[openapi(
    paths(
        health,
        _doc_create_account,
        _doc_request_status,
        _doc_update_authenticator,
        _doc_insert_authenticator,
        _doc_remove_authenticator,
        _doc_recover_account,
        _doc_is_valid_root
    ),
    components(schemas(
        ErrorBody,
        RequestKind,
        RequestState,
        RequestStatusResponse,
        HealthResponse,
        IsValidRootQuery,
        IsValidRootResponse,
        CreateAccountRequest,
        UpdateAuthenticatorRequest,
        InsertAuthenticatorRequest,
        RemoveAuthenticatorRequest,
        RecoverAccountRequest
    )),
    tags((name = "Gateway", description = "TODO"))
)]
struct ApiDoc;
