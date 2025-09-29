use std::{net::SocketAddr, time::Duration};

use alloy::network::EthereumWallet;
use alloy::primitives::address;
use alloy::signers::local::PrivateKeySigner;
use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    transports::http::reqwest::Url,
};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tower_http::trace::TraceLayer;
use world_id_core::account_registry::AccountRegistry;

const MULTICALL3_ADDR: Address = address!("0xca11bde05977b3631167028862be2a173976ca11");

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
    provider: DynProvider,
    batcher: CreateBatcherHandle,
    ops_batcher: OpsBatcherHandle,
}

#[derive(Clone)]
struct CreateBatcherHandle {
    tx: mpsc::Sender<CreateReqEnvelope>,
}

#[derive(Clone)]
struct OpsBatcherHandle {
    tx: mpsc::Sender<OpEnvelope>,
}

#[derive(Debug, Deserialize)]
struct CreateAccountRequest {
    recovery_address: Option<String>,
    authenticator_addresses: Vec<String>,
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
    pubkey_id: Option<String>,
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
    pubkey_id: Option<String>,
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
    pubkey_id: Option<String>,
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

alloy::sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract Multicall3 {
        struct Call3 { address target; bool allowFailure; bytes callData; }
        struct Result { bool success; bytes returnData; }
        function aggregate3(Call3[] calldata calls) payable returns (Result[] memory returnData);
    }
}

fn build_provider(rpc_url: &str, wallet_key: &str) -> anyhow::Result<DynProvider> {
    let wallet = EthereumWallet::from(wallet_key.parse::<PrivateKeySigner>()?);
    let url = Url::parse(rpc_url)?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(url);
    Ok(provider.erased())
}

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
        };
        (status, Json(ErrorBody { error: msg })).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn req_address(field: &str, s: &str) -> ApiResult<Address> {
    parse_address(s).map_err(|e| ApiError::bad_req(field, e))
}
fn req_u256(field: &str, s: &str) -> ApiResult<U256> {
    s.parse()
        .map_err(|e| ApiError::bad_req(field, e))
}
fn req_bytes(field: &str, s: &str) -> ApiResult<Bytes> {
    s.parse()
        .map_err(|e| ApiError::bad_req(field, e))
}
fn req_u256_vec(field: &str, v: &[String]) -> ApiResult<Vec<U256>> {
    v.iter().map(|s| req_u256(field, s)).collect()
}

fn build_app(registry_addr: Address, rpc_url: String, wallet_key: String, batch_ms: u64) -> Router {
    let provider = build_provider(&rpc_url, &wallet_key).expect("failed to build provider");
    let (tx, rx) = mpsc::channel(1024);
    let batcher = CreateBatcherHandle { tx };
    let runner = CreateBatcherRunner::new(
        provider.clone(),
        registry_addr,
        Duration::from_millis(batch_ms),
        rx,
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
    );
    tokio::spawn(ops_runner.run());

    let state = AppState {
        registry_addr,
        provider,
        batcher,
        ops_batcher,
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
        .route("/is-valid-root", get(is_valid_root))
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
    let join = tokio::spawn(async move { server.await.map_err(|e| anyhow::anyhow!(e)) });
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

#[derive(Debug)]
struct CreateReqEnvelope {
    req: CreateAccountRequest,
    resp: oneshot::Sender<anyhow::Result<String>>, // tx hash hex
}

struct CreateBatcherRunner {
    rx: mpsc::Receiver<CreateReqEnvelope>,
    provider: DynProvider,
    registry: Address,
    window: Duration,
}

impl CreateBatcherRunner {
    fn new(
        provider: DynProvider,
        registry: Address,
        window: Duration,
        rx: mpsc::Receiver<CreateReqEnvelope>,
    ) -> Self {
        Self {
            rx,
            provider,
            registry,
            window,
        }
    }
    async fn run(mut self) {
        let provider = self.provider.clone();
        let contract = AccountRegistry::new(self.registry, provider);

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

            let call = contract.createManyAccounts(recovery_addresses, auths, commits);
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
    },
    Recover {
        account_index: U256,
        new_authenticator_address: Address,
        old_commit: U256,
        new_commit: U256,
        signature: Bytes,
        sibling_nodes: Vec<U256>,
        nonce: U256,
    },
}

#[derive(Debug)]
struct OpEnvelope {
    kind: OpKind,
    resp: oneshot::Sender<anyhow::Result<String>>, // tx hash hex
}

struct OpsBatcherRunner {
    rx: mpsc::Receiver<OpEnvelope>,
    provider: DynProvider,
    registry: Address,
    window: Duration,
}

impl OpsBatcherRunner {
    fn new(
        provider: DynProvider,
        registry: Address,
        window: Duration,
        rx: mpsc::Receiver<OpEnvelope>,
    ) -> Self {
        Self {
            rx,
            provider,
            registry,
            window,
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
                    } => contract
                        .updateAuthenticator(
                            *account_index,
                            *old_authenticator_address,
                            *new_authenticator_address,
                            *pubkey_id,
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
                    } => contract
                        .insertAuthenticator(
                            *account_index,
                            *new_authenticator_address,
                            *pubkey_id,
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
                    } => contract
                        .removeAuthenticator(
                            *account_index,
                            *authenticator_address,
                            *pubkey_id,
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
                    } => contract
                        .recoverAccount(
                            *account_index,
                            *new_authenticator_address,
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
                Ok(pend) => {
                    let hash = format!("0x{:x}", pend.tx_hash());
                    for env in batch {
                        let _ = env.resp.send(Ok(hash.clone()));
                    }
                    continue;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "multicall3 send failed");
                    let err = anyhow::anyhow!(e.to_string());
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

async fn update_authenticator(
    State(state): State<AppState>,
    Json(req): Json<UpdateAuthenticatorRequest>,
) -> ApiResult<impl IntoResponse> {
    let env = OpEnvelope {
        kind: OpKind::Update {
            account_index: req_u256("account_index", &req.account_index)?,
            old_authenticator_address: req_address(
                "old_authenticator_address",
                &req.old_authenticator_address,
            )?,
            new_authenticator_address: req_address(
                "new_authenticator_address",
                &req.new_authenticator_address,
            )?,
            old_commit: req_u256(
                "old_offchain_signer_commitment",
                &req.old_offchain_signer_commitment,
            )?,
            new_commit: req_u256(
                "new_offchain_signer_commitment",
                &req.new_offchain_signer_commitment,
            )?,
            sibling_nodes: req_u256_vec("sibling_nodes", &req.sibling_nodes)?,
            signature: req_bytes("signature", &req.signature)?,
            nonce: req_u256("nonce", &req.nonce)?,
            pubkey_id: req
                .pubkey_id
                .as_deref()
                .map(|s| req_u256("pubkey_id", s))
                .transpose()?
                .unwrap_or(U256::from(0u64)),
        },
        resp: oneshot::channel().0, // placeholder, replaced below
    };
    let (tx, rx) = oneshot::channel();
    let env = OpEnvelope { resp: tx, ..env };
    state
        .ops_batcher
        .tx
        .send(env)
        .await
        .map_err(|_| ApiError::Internal("ops batcher unavailable".into()))?;
    let res = tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .map_err(|_| ApiError::Internal("ops batch timeout".into()))?;
    let inner = res.map_err(|_| ApiError::Internal("ops batch canceled".into()))?;
    let hash = inner.map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok((StatusCode::OK, Json(TxResponse { tx_hash: hash })))
}

async fn insert_authenticator(
    State(state): State<AppState>,
    Json(req): Json<InsertAuthenticatorRequest>,
) -> ApiResult<impl IntoResponse> {
    let (tx, rx) = oneshot::channel();
    let env = OpEnvelope {
        kind: OpKind::Insert {
            account_index: req_u256("account_index", &req.account_index)?,
            new_authenticator_address: req_address(
                "new_authenticator_address",
                &req.new_authenticator_address,
            )?,
            old_commit: req_u256(
                "old_offchain_signer_commitment",
                &req.old_offchain_signer_commitment,
            )?,
            new_commit: req_u256(
                "new_offchain_signer_commitment",
                &req.new_offchain_signer_commitment,
            )?,
            sibling_nodes: req_u256_vec("sibling_nodes", &req.sibling_nodes)?,
            signature: req_bytes("signature", &req.signature)?,
            nonce: req_u256("nonce", &req.nonce)?,
            pubkey_id: req
                .pubkey_id
                .as_deref()
                .map(|s| req_u256("pubkey_id", s))
                .transpose()?
                .unwrap_or(U256::from(0u64)),
        },
        resp: tx,
    };
    state
        .ops_batcher
        .tx
        .send(env)
        .await
        .map_err(|_| ApiError::Internal("ops batcher unavailable".into()))?;
    let res = tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .map_err(|_| ApiError::Internal("ops batch timeout".into()))?;
    let inner = res.map_err(|_| ApiError::Internal("ops batch canceled".into()))?;
    let hash = inner.map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok((StatusCode::OK, Json(TxResponse { tx_hash: hash })))
}

async fn remove_authenticator(
    State(state): State<AppState>,
    Json(req): Json<RemoveAuthenticatorRequest>,
) -> ApiResult<impl IntoResponse> {
    let (tx, rx) = oneshot::channel();
    let env = OpEnvelope {
        kind: OpKind::Remove {
            account_index: req_u256("account_index", &req.account_index)?,
            authenticator_address: req_address(
                "authenticator_address",
                &req.authenticator_address,
            )?,
            old_commit: req_u256(
                "old_offchain_signer_commitment",
                &req.old_offchain_signer_commitment,
            )?,
            new_commit: req_u256(
                "new_offchain_signer_commitment",
                &req.new_offchain_signer_commitment,
            )?,
            sibling_nodes: req_u256_vec("sibling_nodes", &req.sibling_nodes)?,
            signature: req_bytes("signature", &req.signature)?,
            nonce: req_u256("nonce", &req.nonce)?,
            pubkey_id: req
                .pubkey_id
                .as_deref()
                .map(|s| req_u256("pubkey_id", s))
                .transpose()?
                .unwrap_or(U256::from(0u64)),
        },
        resp: tx,
    };
    state
        .ops_batcher
        .tx
        .send(env)
        .await
        .map_err(|_| ApiError::Internal("ops batcher unavailable".into()))?;
    let res = tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .map_err(|_| ApiError::Internal("ops batch timeout".into()))?;
    let inner = res.map_err(|_| ApiError::Internal("ops batch canceled".into()))?;
    let hash = inner.map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok((StatusCode::OK, Json(TxResponse { tx_hash: hash })))
}

async fn recover_account(
    State(state): State<AppState>,
    Json(req): Json<RecoverAccountRequest>,
) -> ApiResult<impl IntoResponse> {
    let (tx, rx) = oneshot::channel();
    let env = OpEnvelope {
        kind: OpKind::Recover {
            account_index: req_u256("account_index", &req.account_index)?,
            new_authenticator_address: req_address(
                "new_authenticator_address",
                &req.new_authenticator_address,
            )?,
            old_commit: req_u256(
                "old_offchain_signer_commitment",
                &req.old_offchain_signer_commitment,
            )?,
            new_commit: req_u256(
                "new_offchain_signer_commitment",
                &req.new_offchain_signer_commitment,
            )?,
            sibling_nodes: req_u256_vec("sibling_nodes", &req.sibling_nodes)?,
            signature: req_bytes("signature", &req.signature)?,
            nonce: req_u256("nonce", &req.nonce)?,
        },
        resp: tx,
    };
    state
        .ops_batcher
        .tx
        .send(env)
        .await
        .map_err(|_| ApiError::Internal("ops batcher unavailable".into()))?;
    let res = tokio::time::timeout(Duration::from_secs(30), rx)
        .await
        .map_err(|_| ApiError::Internal("ops batch timeout".into()))?;
    let inner = res.map_err(|_| ApiError::Internal("ops batch canceled".into()))?;
    let hash = inner.map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok((StatusCode::OK, Json(TxResponse { tx_hash: hash })))
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
