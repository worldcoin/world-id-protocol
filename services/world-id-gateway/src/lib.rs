use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use alloy::network::EthereumWallet;
use alloy::primitives::address;
use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    transports::http::reqwest::Url,
};
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
use world_id_core::account_registry::AccountRegistry;
use world_id_core::types::{
    CreateAccountRequest, InsertAuthenticatorRequest, RecoverAccountRequest,
    RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
};

pub use crate::config::GatewayConfig;

const MULTICALL3_ADDR: Address = address!("0xca11bde05977b3631167028862be2a173976ca11");

mod config;

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
struct CreateBatcherHandle {
    tx: mpsc::Sender<CreateReqEnvelope>,
}

#[derive(Clone)]
struct OpsBatcherHandle {
    tx: mpsc::Sender<OpEnvelope>,
}

#[derive(Clone)]
struct RequestTracker {
    inner: Arc<RwLock<std::collections::HashMap<String, RequestRecord>>>,
    seq: Arc<AtomicU64>,
}

impl RequestTracker {
    fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(std::collections::HashMap::new())),
            seq: Arc::new(AtomicU64::new(1)),
        }
    }

    async fn new_request(&self, kind: RequestKind) -> String {
        let id = self.seq.fetch_add(1, Ordering::Relaxed);
        let id = format!("{id:016x}");
        let record = RequestRecord {
            kind,
            status: RequestState::Queued,
        };
        self.inner.write().await.insert(id.clone(), record);
        id
    }

    async fn set_status_batch(&self, ids: &[String], status: RequestState) {
        let mut map = self.inner.write().await;
        for id in ids {
            if let Some(rec) = map.get_mut(id) {
                rec.status = status.clone();
            }
        }
    }

    async fn set_status(&self, id: &str, status: RequestState) {
        self.set_status_batch(&[id.to_string()], status).await;
    }

    async fn snapshot(&self, id: &str) -> Option<RequestRecord> {
        self.inner.read().await.get(id).cloned()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum RequestKind {
    CreateAccount,
    UpdateAuthenticator,
    InsertAuthenticator,
    RemoveAuthenticator,
    RecoverAccount,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum RequestState {
    Queued,
    Batching,
    Submitted { tx_hash: String },
    Finalized { tx_hash: String },
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize)]
struct RequestRecord {
    kind: RequestKind,
    status: RequestState,
}

#[derive(Debug, Serialize)]
struct RequestStatusResponse {
    request_id: String,
    kind: RequestKind,
    status: RequestState,
}

alloy::sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract Multicall3 {
        struct Call3 { address target; bool allowFailure; bytes callData; }
        struct Result { bool success; bytes returnData; }
        function aggregate3(Call3[] calldata calls) payable returns (Result[] memory returnData);
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

#[derive(Serialize)]
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

fn build_app(
    registry_addr: Address,
    rpc_url: String,
    ethereum_wallet: EthereumWallet,
    batch_ms: u64,
) -> Router {
    let provider = build_provider(&rpc_url, ethereum_wallet).expect("failed to build provider");
    let tracker = RequestTracker::new();
    let (tx, rx) = mpsc::channel(1024);
    let batcher = CreateBatcherHandle { tx };
    let runner = CreateBatcherRunner::new(
        provider.clone(),
        registry_addr,
        Duration::from_millis(batch_ms),
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
        orx,
        tracker.clone(),
    );
    tokio::spawn(ops_runner.run());

    let state = AppState {
        registry_addr,
        provider,
        batcher,
        ops_batcher,
        tracker,
    };

    Router::new()
        .route("/health", get(health))
        // account creation (batched)
        .route("/create-account", post(create_account))
        .route("/status/:id", get(request_status))
        // single tx endpoints
        .route("/update-authenticator", post(update_authenticator))
        .route("/insert-authenticator", post(insert_authenticator))
        .route("/remove-authenticator", post(remove_authenticator))
        .route("/recover-account", post(recover_account))
        // admin / utility
        .route("/is-valid-root", get(is_valid_root))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(tower_http::timeout::TimeoutLayer::new(Duration::from_secs(
            30,
        )))
}

/// For tests only: spawn the gateway server and return a handle with shutdown.
pub async fn spawn_gateway_for_tests(cfg: GatewayConfig) -> anyhow::Result<GatewayHandle> {
    let app = build_app(
        cfg.registry_addr,
        cfg.rpc_url,
        cfg.ethereum_wallet,
        cfg.batch_ms,
    );

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
    let app = build_app(
        cfg.registry_addr,
        cfg.rpc_url,
        cfg.ethereum_wallet,
        cfg.batch_ms,
    );
    tracing::info!("✔️ Config is ready. Initializing HTTP server...");
    let listener = tokio::net::TcpListener::bind(cfg.listen_addr).await?;
    tracing::info!("✔️ HTTP server listening on {}", cfg.listen_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status":"ok"})))
}

#[derive(Debug)]
struct CreateReqEnvelope {
    id: String,
    req: CreateAccountRequest,
}

struct CreateBatcherRunner {
    rx: mpsc::Receiver<CreateReqEnvelope>,
    provider: DynProvider,
    registry: Address,
    window: Duration,
    tracker: RequestTracker,
}

impl CreateBatcherRunner {
    fn new(
        provider: DynProvider,
        registry: Address,
        window: Duration,
        rx: mpsc::Receiver<CreateReqEnvelope>,
        tracker: RequestTracker,
    ) -> Self {
        Self {
            rx,
            provider,
            registry,
            window,
            tracker,
        }
    }
    async fn run(mut self) {
        let provider = self.provider.clone();
        let contract = AccountRegistry::new(self.registry, provider);

        loop {
            let Some(first) = self.rx.recv().await else {
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

            let ids: Vec<String> = batch.iter().map(|env| env.id.clone()).collect();
            self.tracker
                .set_status_batch(&ids, RequestState::Batching)
                .await;

            let mut recovery_addresses: Vec<Address> = Vec::new();
            let mut auths: Vec<Vec<Address>> = Vec::new();
            let mut pubkeys: Vec<Vec<U256>> = Vec::new();
            let mut commits: Vec<U256> = Vec::new();

            for env in &batch {
                recovery_addresses.push(env.req.recovery_address.unwrap_or(Address::ZERO));
                auths.push(env.req.authenticator_addresses.clone());
                pubkeys.push(env.req.authenticator_pubkeys.clone());
                commits.push(env.req.offchain_signer_commitment);
            }

            let call = contract.createManyAccounts(recovery_addresses, auths, pubkeys, commits);
            match call.send().await {
                Ok(builder) => {
                    let hash = format!("0x{:x}", builder.tx_hash());
                    self.tracker
                        .set_status_batch(
                            &ids,
                            RequestState::Submitted {
                                tx_hash: hash.clone(),
                            },
                        )
                        .await;

                    let tracker = self.tracker.clone();
                    let ids_for_receipt = ids.clone();
                    tokio::spawn(async move {
                        match builder.get_receipt().await {
                            Ok(receipt) => {
                                if receipt.status() {
                                    tracker
                                        .set_status_batch(
                                            &ids_for_receipt,
                                            RequestState::Finalized {
                                                tx_hash: hash.clone(),
                                            },
                                        )
                                        .await;
                                } else {
                                    tracker
                                        .set_status_batch(
                                            &ids_for_receipt,
                                            RequestState::Failed {
                                                error: format!(
                                                    "transaction reverted on-chain (tx: {hash})"
                                                ),
                                            },
                                        )
                                        .await;
                                }
                            }
                            Err(err) => {
                                tracker
                                    .set_status_batch(
                                        &ids_for_receipt,
                                        RequestState::Failed {
                                            error: format!("transaction confirmation error: {err}"),
                                        },
                                    )
                                    .await;
                            }
                        }
                    });
                }
                Err(err) => {
                    tracing::error!(error = %err, "create batch send failed");
                    self.tracker
                        .set_status_batch(
                            &ids,
                            RequestState::Failed {
                                error: err.to_string(),
                            },
                        )
                        .await;
                }
            }
        }
    }
}

#[derive(Debug)]
enum OpKind {
    Update {
        account_index: U256,
        old_authenticator_address: Address,
        new_authenticator_address: Address,
        old_commit: U256,
        new_commit: U256,
        signature: Bytes,
        sibling_nodes: Vec<U256>,
        nonce: U256,
        pubkey_id: U256,
        new_pubkey: U256,
    },
    Insert {
        account_index: U256,
        new_authenticator_address: Address,
        old_commit: U256,
        new_commit: U256,
        signature: Bytes,
        sibling_nodes: Vec<U256>,
        nonce: U256,
        pubkey_id: U256,
        new_pubkey: U256,
    },
    Remove {
        account_index: U256,
        authenticator_address: Address,
        old_commit: U256,
        new_commit: U256,
        signature: Bytes,
        sibling_nodes: Vec<U256>,
        nonce: U256,
        pubkey_id: U256,
        authenticator_pubkey: U256,
    },
    Recover {
        account_index: U256,
        new_authenticator_address: Address,
        old_commit: U256,
        new_commit: U256,
        signature: Bytes,
        sibling_nodes: Vec<U256>,
        nonce: U256,
        new_pubkey: U256,
    },
}

#[derive(Debug)]
struct OpEnvelope {
    id: String,
    kind: OpKind,
}

struct OpsBatcherRunner {
    rx: mpsc::Receiver<OpEnvelope>,
    provider: DynProvider,
    registry: Address,
    window: Duration,
    tracker: RequestTracker,
}

impl OpsBatcherRunner {
    fn new(
        provider: DynProvider,
        registry: Address,
        window: Duration,
        rx: mpsc::Receiver<OpEnvelope>,
        tracker: RequestTracker,
    ) -> Self {
        Self {
            rx,
            provider,
            registry,
            window,
            tracker,
        }
    }

    async fn run(mut self) {
        let provider = self.provider.clone();
        let contract = AccountRegistry::new(self.registry, provider.clone());
        let mc = Multicall3::new(MULTICALL3_ADDR, provider);

        loop {
            let Some(first) = self.rx.recv().await else {
                tracing::info!("ops batcher channel closed");
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

            let ids: Vec<String> = batch.iter().map(|env| env.id.clone()).collect();
            self.tracker
                .set_status_batch(&ids, RequestState::Batching)
                .await;

            let mut calls: Vec<Multicall3::Call3> = Vec::with_capacity(batch.len());
            for env in &batch {
                let data: alloy::primitives::Bytes = match &env.kind {
                    OpKind::Update {
                        account_index,
                        old_authenticator_address,
                        new_authenticator_address,
                        old_commit,
                        new_commit,
                        signature,
                        sibling_nodes,
                        nonce,
                        pubkey_id,
                        new_pubkey,
                    } => contract
                        .updateAuthenticator(
                            *account_index,
                            *old_authenticator_address,
                            *new_authenticator_address,
                            *pubkey_id,
                            *new_pubkey,
                            *old_commit,
                            *new_commit,
                            signature.clone(),
                            sibling_nodes.clone(),
                            *nonce,
                        )
                        .calldata()
                        .clone(),
                    OpKind::Insert {
                        account_index,
                        new_authenticator_address,
                        old_commit,
                        new_commit,
                        signature,
                        sibling_nodes,
                        nonce,
                        pubkey_id,
                        new_pubkey,
                    } => contract
                        .insertAuthenticator(
                            *account_index,
                            *new_authenticator_address,
                            *pubkey_id,
                            *new_pubkey,
                            *old_commit,
                            *new_commit,
                            signature.clone(),
                            sibling_nodes.clone(),
                            *nonce,
                        )
                        .calldata()
                        .clone(),
                    OpKind::Remove {
                        account_index,
                        authenticator_address,
                        old_commit,
                        new_commit,
                        signature,
                        sibling_nodes,
                        nonce,
                        pubkey_id,
                        authenticator_pubkey,
                    } => contract
                        .removeAuthenticator(
                            *account_index,
                            *authenticator_address,
                            *pubkey_id,
                            *authenticator_pubkey,
                            *old_commit,
                            *new_commit,
                            signature.clone(),
                            sibling_nodes.clone(),
                            *nonce,
                        )
                        .calldata()
                        .clone(),
                    OpKind::Recover {
                        account_index,
                        new_authenticator_address,
                        old_commit,
                        new_commit,
                        signature,
                        sibling_nodes,
                        nonce,
                        new_pubkey,
                    } => contract
                        .recoverAccount(
                            *account_index,
                            *new_authenticator_address,
                            *new_pubkey,
                            *old_commit,
                            *new_commit,
                            signature.clone(),
                            sibling_nodes.clone(),
                            *nonce,
                        )
                        .calldata()
                        .clone(),
                };
                calls.push(Multicall3::Call3 {
                    target: self.registry,
                    allowFailure: false,
                    callData: data,
                });
            }

            let res = mc.aggregate3(calls).send().await;
            match res {
                Ok(builder) => {
                    let hash = format!("0x{:x}", builder.tx_hash());
                    self.tracker
                        .set_status_batch(
                            &ids,
                            RequestState::Submitted {
                                tx_hash: hash.clone(),
                            },
                        )
                        .await;

                    let tracker = self.tracker.clone();
                    let ids_for_receipt = ids.clone();
                    tokio::spawn(async move {
                        match builder.get_receipt().await {
                            Ok(receipt) => {
                                if receipt.status() {
                                    tracker
                                        .set_status_batch(
                                            &ids_for_receipt,
                                            RequestState::Finalized {
                                                tx_hash: hash.clone(),
                                            },
                                        )
                                        .await;
                                } else {
                                    tracker
                                        .set_status_batch(
                                            &ids_for_receipt,
                                            RequestState::Failed {
                                                error: format!(
                                                    "transaction reverted on-chain (tx: {hash})"
                                                ),
                                            },
                                        )
                                        .await;
                                }
                            }
                            Err(err) => {
                                tracker
                                    .set_status_batch(
                                        &ids_for_receipt,
                                        RequestState::Failed {
                                            error: format!("transaction confirmation error: {err}"),
                                        },
                                    )
                                    .await;
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "multicall3 send failed");
                    self.tracker
                        .set_status_batch(
                            &ids,
                            RequestState::Failed {
                                error: e.to_string(),
                            },
                        )
                        .await;
                }
            }
        }
    }
}

async fn create_account(
    State(state): State<AppState>,
    Json(req): Json<CreateAccountRequest>,
) -> ApiResult<impl IntoResponse> {
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
                RequestState::Failed {
                    error: "batcher unavailable".into(),
                },
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
                RequestState::Failed {
                    error: "ops batcher unavailable".into(),
                },
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
                RequestState::Failed {
                    error: "ops batcher unavailable".into(),
                },
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
                RequestState::Failed {
                    error: "ops batcher unavailable".into(),
                },
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
                RequestState::Failed {
                    error: "ops batcher unavailable".into(),
                },
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

#[derive(Debug, Deserialize)]
struct IsValidRootQuery {
    root: String,
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
