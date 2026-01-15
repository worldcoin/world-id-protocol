use std::{sync::Arc, time::Duration};

use crate::{
    create_batcher::{CreateBatcherHandle, CreateBatcherRunner},
    error::ErrorBody,
    ops_batcher::{OpsBatcherHandle, OpsBatcherRunner},
    provider::{build_provider, build_wallet},
    request_tracker::{RequestKind, RequestState, RequestTracker},
    routes::{
        create_account::create_account,
        health::{health, HealthResponse, __path_health},
        insert_authenticator::insert_authenticator,
        is_valid_root::{is_valid_root, IsValidRootQuery, IsValidRootResponse},
        recover_account::recover_account,
        remove_authenticator::remove_authenticator,
        request_status::request_status,
        update_authenticator::update_authenticator,
    },
    AppState, RequestStatusResponse, SignerConfig,
};
use alloy::{primitives::Address, providers::DynProvider};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use tokio::sync::mpsc;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use world_id_core::types::{
    CreateAccountRequest, GatewayErrorCode as ErrorCode, InsertAuthenticatorRequest,
    RecoverAccountRequest, RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
};

mod create_account;
mod health;
mod insert_authenticator;
mod is_valid_root;
mod recover_account;
mod remove_authenticator;
mod request_status;
mod update_authenticator;
mod validation;

pub(crate) async fn build_app(
    provider: Arc<DynProvider>,
    registry: Arc<WorldIDRegistryInstance<DynProvider>>,
    batch_ms: u64,
    max_create_batch_size: usize,
    max_ops_batch_size: usize,
    redis_url: Option<String>,
) -> anyhow::Result<Router> {

    let tracker = RequestTracker::new(redis_url).await;
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
        .route("/openapi.json", get(openapi))
        .with_state(state)
        .layer(axum::Extension(tracker))
        .layer(TraceLayer::new_for_http())
        .layer(tower_http::timeout::TimeoutLayer::new(Duration::from_secs(
            30,
        ))))
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
        ErrorCode,
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

async fn openapi() -> impl IntoResponse {
    Json(ApiDoc::openapi())
}
