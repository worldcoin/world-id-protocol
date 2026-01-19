use std::{sync::Arc, time::Duration};

use crate::{
    batcher::{
        EventsMultiplexerBuilder, LoggingHandler, MetricsHandler, OpAcceptedHandler, OpsBatcher,
        OpsBatcherConfig, StatusSyncHandler, Waiters,
    },
    create_batcher::{CreateBatcherHandle, CreateBatcherRunner},
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
    types::{AppState, RootExpiry},
};
use alloy::providers::DynProvider;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use moka::future::Cache;
use tokio::sync::mpsc;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use world_id_core::{
    types::{
        CreateAccountRequest, GatewayErrorBody, GatewayErrorCode, GatewayRequestKind,
        GatewayRequestState, GatewayStatusResponse, HealthResponse, InsertAuthenticatorRequest,
        IsValidRootQuery, IsValidRootResponse, RecoverAccountRequest, RemoveAuthenticatorRequest,
        UpdateAuthenticatorRequest,
    },
    world_id_registry::WorldIdRegistry::WorldIdRegistryInstance,
};

mod create_account;
mod health;
mod insert_authenticator;
mod is_valid_root;
mod middleware;
mod recover_account;
mod remove_authenticator;
mod request_status;
mod update_authenticator;
mod validation;

const ROOT_CACHE_SIZE: u64 = 1024;

/// Build the application router with all routes and middleware.
///
/// Uses type-erased `DynProvider` for flexibility with different RPC configurations.
pub(crate) async fn build_app(
    provider: Arc<DynProvider>,
    registry: Arc<WorldIdRegistryInstance<Arc<DynProvider>>>,
    batch_ms: u64,
    max_create_batch_size: usize,
    redis_url: Option<String>,
    metrics_enabled: bool,
) -> anyhow::Result<Router> {
    let tracker = RequestTracker::new(redis_url).await;
    let (tx, rx) = mpsc::channel(1024);
    let batcher = CreateBatcherHandle { tx };
    let runner = CreateBatcherRunner::new(
        registry.clone(),
        Duration::from_millis(batch_ms),
        max_create_batch_size,
        rx,
        tracker.clone(),
    );
    tokio::spawn(runner.run());

    // Create OpsBatcher for insert/remove/recover/update operations
    let mut ops_config = OpsBatcherConfig::new(registry.clone());
    ops_config.batch_window = Duration::from_millis(batch_ms);

    // Create event bus
    let tracker_arc = Arc::new(tracker.clone());
    let waiters = Arc::new(Waiters::new());

    let mut builder = EventsMultiplexerBuilder::new()
        .event_capacity(10_000)
        .waiters(waiters.clone())
        .subscribe_all(LoggingHandler)
        .subscribe_many(
            &[
                crate::batcher::EventType::OpFinalized,
                crate::batcher::EventType::OpFailed,
                crate::batcher::EventType::OpSubmitted,
                crate::batcher::EventType::OpBatched,
            ],
            StatusSyncHandler::new(tracker_arc.clone()),
        )
        .subscribe(
            crate::batcher::EventType::OpAccepted,
            OpAcceptedHandler::new(tracker_arc, waiters),
        );

    if metrics_enabled {
        builder = builder.subscribe_all(MetricsHandler);
    }

    let (event_bus, events, cmd_rx) = builder.build().expect("failed to build event bus");

    tokio::task::spawn_blocking({
        let scope = tracing::span!(tracing::Level::INFO, "event-processor");
        move || {
            let _enter = scope.enter();
            events.run()
        }
    });

    let event_bus = Arc::new(event_bus);
    let ops_batcher = OpsBatcher::new(provider, ops_config, event_bus.clone(), cmd_rx);

    // Spawn the OpsBatcher task
    tokio::spawn(ops_batcher.run());

    let root_cache = Cache::builder()
        .max_capacity(ROOT_CACHE_SIZE)
        .expire_after(RootExpiry)
        .build();

    let state = AppState {
        regsitry: registry.clone(),
        batcher,
        root_cache,
        event_bus,
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
