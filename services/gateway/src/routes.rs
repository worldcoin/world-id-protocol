use std::{sync::Arc, time::Duration};

use crate::{
    AppState,
    batch_policy::{BaseFeeCache, spawn_base_fee_sampler},
    batcher::BatcherHandle,
    config::{BatchPolicyConfig, BatcherConfig, OrphanSweeperConfig, RateLimitConfig},
    create_batcher::{CreateBatcherHandle, CreateBatcherRunner},
    error::{GatewayErrorBody, GatewayResult},
    ops_batcher::{OpsBatcherHandle, OpsBatcherRunner},
    orphan_sweeper::run_orphan_sweeper,
    request::GatewayContext,
    request_tracker::RequestTracker,
    routes::{
        create_account::create_account,
        health::{__path_health, health},
        insert_authenticator::insert_authenticator,
        is_valid_root::is_valid_root,
        recover_account::recover_account,
        remove_authenticator::remove_authenticator,
        request_status::request_status,
        update_authenticator::update_authenticator,
    },
    types::RootExpiry,
};
use alloy::providers::DynProvider;
use axum::{
    Json, Router,
    extract::{Path, State},
    middleware::from_fn,
    response::IntoResponse,
    routing::{get, post},
};
use moka::future::Cache;
use tokio::sync::mpsc;
use utoipa::OpenApi;
use world_id_core::{
    api_types::{
        CreateAccountRequest, GatewayErrorCode, GatewayRequestKind, GatewayRequestState,
        GatewayStatusResponse, HealthResponse, InsertAuthenticatorRequest, IsValidRootQuery,
        IsValidRootResponse, RecoverAccountRequest, RemoveAuthenticatorRequest,
        UpdateAuthenticatorRequest,
    },
    world_id_registry::WorldIdRegistry::WorldIdRegistryInstance,
};

mod create_account;
mod health;
mod insert_authenticator;
mod is_valid_root;
pub(crate) mod middleware;
mod recover_account;
mod remove_authenticator;
mod request_status;
mod update_authenticator;
pub(crate) mod validation;

const ROOT_CACHE_SIZE: u64 = 1024;
const CREATE_BATCHER_CHANNEL_CAPACITY: usize = 1024;
const OPS_BATCHER_CHANNEL_CAPACITY: usize = 2048;

pub(crate) async fn build_app(
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    batcher_config: BatcherConfig,
    redis_url: String,
    rate_limit: Option<RateLimitConfig>,
    request_timeout_secs: u64,
    orphan_sweeper_config: OrphanSweeperConfig,
    batch_policy_config: BatchPolicyConfig,
) -> GatewayResult<Router> {
    let tracker = RequestTracker::new(redis_url, rate_limit).await;
    let base_fee_cache = BaseFeeCache::default();

    spawn_base_fee_sampler(
        registry.provider().clone(),
        Duration::from_millis(batch_policy_config.reeval_ms),
        base_fee_cache.clone(),
    );

    let (tx, rx) = mpsc::channel(CREATE_BATCHER_CHANNEL_CAPACITY);
    let batcher = CreateBatcherHandle { tx };
    let runner = CreateBatcherRunner::new(
        registry.clone(),
        batcher_config.max_create_batch_size,
        CREATE_BATCHER_CHANNEL_CAPACITY,
        rx,
        tracker.clone(),
        batch_policy_config.clone(),
        base_fee_cache.clone(),
    );
    tokio::spawn(runner.run());

    // ops batcher (insert/remove/recover/update)
    let (otx, orx) = mpsc::channel(OPS_BATCHER_CHANNEL_CAPACITY);
    let ops_batcher = OpsBatcherHandle { tx: otx };
    let ops_runner = OpsBatcherRunner::new(
        registry.clone(),
        batcher_config.max_ops_batch_size,
        OPS_BATCHER_CHANNEL_CAPACITY,
        orx,
        tracker.clone(),
        batch_policy_config,
        base_fee_cache,
    );
    tokio::spawn(ops_runner.run());

    tracing::info!("Ops batcher initialized");

    let sweeper_tracker = tracker.clone();
    let sweeper_provider = registry.provider().clone();
    tokio::spawn(run_orphan_sweeper(
        sweeper_tracker,
        sweeper_provider,
        orphan_sweeper_config,
    ));
    tracing::info!("Orphan sweeper initialized");

    let root_cache = Cache::builder()
        .max_capacity(ROOT_CACHE_SIZE)
        .expire_after(RootExpiry)
        .build();

    let batcher_handle = BatcherHandle {
        create: batcher,
        ops: ops_batcher,
    };
    let ctx = GatewayContext {
        registry: registry.clone(),
        tracker,
        batcher: batcher_handle,
        root_cache,
    };
    let state = AppState { ctx };

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
        .layer(from_fn(middleware::request_id_middleware))
        .layer(world_id_services_common::timeout_layer(
            request_timeout_secs,
        ))
        .layer(world_id_services_common::trace_layer()))
}

#[utoipa::path(
    post,
    path = "/create-account",
    request_body = CreateAccountRequest,
    responses(
        (status = 202, description = "TODO", body = GatewayStatusResponse),
        (status = 500, description = "TODO", body = GatewayErrorBody)
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
        (status = 200, description = "TODO", body = GatewayStatusResponse),
        (status = 404, description = "TODO", body = GatewayErrorBody)
    ),
    tag = "Gateway"
)]
async fn _doc_request_status(_: State<AppState>, _: Path<String>) {}

#[utoipa::path(
    post,
    path = "/update-authenticator",
    request_body = UpdateAuthenticatorRequest,
    responses(
        (status = 202, description = "TODO", body = GatewayStatusResponse),
        (status = 500, description = "TODO", body = GatewayErrorBody)
    ),
    tag = "Gateway"
)]
async fn _doc_update_authenticator(_: State<AppState>, _: Json<UpdateAuthenticatorRequest>) {}

#[utoipa::path(
    post,
    path = "/insert-authenticator",
    request_body = InsertAuthenticatorRequest,
    responses(
        (status = 202, description = "TODO", body = GatewayStatusResponse),
        (status = 500, description = "TODO", body = GatewayErrorBody)
    ),
    tag = "Gateway"
)]
async fn _doc_insert_authenticator(_: State<AppState>, _: Json<InsertAuthenticatorRequest>) {}

#[utoipa::path(
    post,
    path = "/remove-authenticator",
    request_body = RemoveAuthenticatorRequest,
    responses(
        (status = 202, description = "TODO", body = GatewayStatusResponse),
        (status = 500, description = "TODO", body = GatewayErrorBody)
    ),
    tag = "Gateway"
)]
async fn _doc_remove_authenticator(_: State<AppState>, _: Json<RemoveAuthenticatorRequest>) {}

#[utoipa::path(
    post,
    path = "/recover-account",
    request_body = RecoverAccountRequest,
    responses(
        (status = 202, description = "TODO", body = GatewayStatusResponse),
        (status = 500, description = "TODO", body = GatewayErrorBody)
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
        (status = 400, description = "TODO", body = GatewayErrorBody)
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
        GatewayErrorCode,
        GatewayErrorBody,
        GatewayRequestKind,
        GatewayRequestState,
        GatewayStatusResponse,
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
