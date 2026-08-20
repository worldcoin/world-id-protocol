use crate::{
    error::{GatewayErrorBody, GatewayErrorResponse},
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
        revert_recovery_agent_update::revert_recovery_agent_update,
        update_authenticator::update_authenticator,
        update_recovery_agent::update_recovery_agent,
    },
    types::AppState,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    middleware::from_fn,
    response::IntoResponse,
    routing::{get, post},
};
use utoipa::OpenApi;
use world_id_primitives::api_types::{
    CancelRecoveryAgentUpdateRequest, CreateAccountRequest, ExecuteRecoveryAgentUpdateRequest,
    GatewayErrorCode, GatewayRequestKind, GatewayRequestState, GatewayStatusResponse,
    HealthResponse, InsertAuthenticatorRequest, IsValidRootQuery, IsValidRootResponse,
    RecoverAccountRequest, RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
    UpdateRecoveryAgentRequest,
};
use world_id_services_common::V1RecoveryAgentMethodsDeprecationLayer;

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
mod revert_recovery_agent_update;
mod update_recovery_agent;

// Admin / utility routes
mod is_valid_root;

// Shared route internals
pub(crate) mod middleware;
pub(crate) mod validation;

pub(crate) fn router(state: AppState) -> Router {
    let request_timeout_secs = state.config.request_timeout_secs;
    Router::new()
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
            post(initiate_recovery_agent_update)
                .route_layer(V1RecoveryAgentMethodsDeprecationLayer::new()),
        )
        .route(
            "/cancel-recovery-agent-update",
            post(cancel_recovery_agent_update)
                .route_layer(V1RecoveryAgentMethodsDeprecationLayer::new()),
        )
        .route(
            "/execute-recovery-agent-update",
            post(execute_recovery_agent_update)
                .route_layer(V1RecoveryAgentMethodsDeprecationLayer::new()),
        )
        // WIP-102 optimistic recovery agent update (gated on V2 contract)
        .route("/update-recovery-agent", post(update_recovery_agent))
        .route(
            "/revert-recovery-agent-update",
            post(revert_recovery_agent_update),
        )
        // admin / utility
        .route("/is-valid-root", get(is_valid_root))
        .route("/openapi.json", get(openapi))
        .with_state(state)
        .layer(from_fn(middleware::request_id_middleware))
        .layer(from_fn(
            world_id_services_common::request_latency_middleware,
        ))
        .layer(world_id_services_common::timeout_layer(
            request_timeout_secs,
            GatewayErrorResponse::request_timeout(request_timeout_secs),
        ))
        .layer(world_id_services_common::trace_layer())
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
