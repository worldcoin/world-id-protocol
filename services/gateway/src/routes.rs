use std::{sync::Arc, time::Duration};

use crate::{
    AppState,
    batch_policy::{BaseFeeCache, spawn_base_fee_sampler},
    batcher::{
        BatcherHandle, CreateBatcherHandle, CreateBatcherRunner, OpsBatcherHandle, OpsBatcherRunner,
    },
    config::{BatchPolicyConfig, BatcherConfig, OrphanSweeperConfig, RateLimitConfig},
    error::{GatewayErrorBody, GatewayErrorResponse, GatewayResult},
    orphan_sweeper::run_orphan_sweeper,
    request::GatewayContext,
    request_tracker::RequestTracker,
    routes::{
        cancel_recovery_agent_update::cancel_recovery_agent_update,
        create_account::create_account,
        execute_recovery_agent_update::execute_recovery_agent_update,
        health::{__path_health, health},
        initiate_recovery_agent_update::initiate_recovery_agent_update,
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
        CancelRecoveryAgentUpdateRequest, CreateAccountRequest, ExecuteRecoveryAgentUpdateRequest,
        GatewayErrorCode, GatewayRequestKind, GatewayRequestState, GatewayStatusResponse,
        HealthResponse, InsertAuthenticatorRequest, IsValidRootQuery, IsValidRootResponse,
        RecoverAccountRequest, RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
        UpdateRecoveryAgentRequest,
    },
    world_id_registry::WorldIdRegistry::WorldIdRegistryInstance,
};

// Health and status routes
mod health;
mod request_status;

// Account routes
mod create_account;
mod recover_account;

// Authenticator routes
mod insert_authenticator;
mod remove_authenticator;
mod update_authenticator;

// Recovery agent routes
mod cancel_recovery_agent_update;
mod execute_recovery_agent_update;
mod initiate_recovery_agent_update;

// Admin / utility routes
mod is_valid_root;

// Shared route internals
pub(crate) mod middleware;
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
    let tracker = RequestTracker::new(
        redis_url,
        rate_limit,
        // Timeout for receirpt polling tasks. Same as sweeper timeout for submitted transactions.
        orphan_sweeper_config.stale_submitted_threshold_secs,
    )
    .await;
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
        // recovery agent management
        .route(
            "/initiate-recovery-agent-update",
            post(initiate_recovery_agent_update),
        )
        .route(
            "/cancel-recovery-agent-update",
            post(cancel_recovery_agent_update),
        )
        .route(
            "/execute-recovery-agent-update",
            post(execute_recovery_agent_update),
        )
        // admin / utility
        .route("/is-valid-root", get(is_valid_root))
        .route("/openapi.json", get(openapi))
        .with_state(state)
        .layer(from_fn(middleware::request_id_middleware))
        .layer(world_id_services_common::timeout_layer(
            request_timeout_secs,
            GatewayErrorResponse::request_timeout(request_timeout_secs),
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
    post,
    path = "/initiate-recovery-agent-update",
    request_body = UpdateRecoveryAgentRequest,
    responses(
        (status = 200, description = "Request accepted", body = GatewayStatusResponse),
        (status = 400, description = "Bad request", body = GatewayErrorBody),
        (status = 429, description = "Rate limit exceeded", body = GatewayErrorBody),
        (status = 500, description = "Internal server error", body = GatewayErrorBody)
    ),
    tag = "Gateway"
)]
async fn _doc_initiate_recovery_agent_update(
    _: State<AppState>,
    _: Json<UpdateRecoveryAgentRequest>,
) {
}

#[utoipa::path(
    post,
    path = "/cancel-recovery-agent-update",
    request_body = CancelRecoveryAgentUpdateRequest,
    responses(
        (status = 200, description = "Request accepted", body = GatewayStatusResponse),
        (status = 400, description = "Bad request", body = GatewayErrorBody),
        (status = 429, description = "Rate limit exceeded", body = GatewayErrorBody),
        (status = 500, description = "Internal server error", body = GatewayErrorBody)
    ),
    tag = "Gateway"
)]
async fn _doc_cancel_recovery_agent_update(
    _: State<AppState>,
    _: Json<CancelRecoveryAgentUpdateRequest>,
) {
}

#[utoipa::path(
    post,
    path = "/execute-recovery-agent-update",
    request_body = ExecuteRecoveryAgentUpdateRequest,
    responses(
        (status = 200, description = "Request accepted", body = GatewayStatusResponse),
        (status = 400, description = "Bad request (leaf_index zero or no pending update)", body = GatewayErrorBody),
        (status = 429, description = "Rate limit exceeded", body = GatewayErrorBody),
        (status = 500, description = "Internal server error", body = GatewayErrorBody)
    ),
    tag = "Gateway"
)]
async fn _doc_execute_recovery_agent_update(
    _: State<AppState>,
    _: Json<ExecuteRecoveryAgentUpdateRequest>,
) {
}

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
        _doc_initiate_recovery_agent_update,
        _doc_cancel_recovery_agent_update,
        _doc_execute_recovery_agent_update,
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
        UpdateRecoveryAgentRequest,
        CancelRecoveryAgentUpdateRequest,
        ExecuteRecoveryAgentUpdateRequest,
        RecoverAccountRequest
    )),
    tags((name = "Gateway", description = "TODO"))
)]
struct ApiDoc;

async fn openapi() -> impl IntoResponse {
    Json(ApiDoc::openapi())
}
