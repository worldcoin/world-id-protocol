use std::sync::Arc;

use crate::{
    batcher::{
        BatcherHandle, Command,
        defaults::{
            DEFAULT_CREATE_ACCOUNT_GAS, DEFAULT_INSERT_AUTHENTICATOR_GAS,
            DEFAULT_RECOVER_ACCOUNT_GAS, DEFAULT_REMOVE_AUTHENTICATOR_GAS,
            DEFAULT_UPDATE_AUTHENTICATOR_GAS,
        },
    },
    error::GatewayErrorResponse,
    request_tracker::RequestTracker,
    routes::validation::RequestValidation,
};
use alloy::{
    primitives::{Bytes, U256},
    providers::DynProvider,
};
use moka::future::Cache;
use uuid::Uuid;
use world_id_core::{
    api_types::{
        CreateAccountRequest, GatewayErrorCode, GatewayRequestKind, GatewayRequestState,
        GatewayStatusResponse, InsertAuthenticatorRequest, RecoverAccountRequest,
        RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
    },
    world_id_registry::WorldIdRegistry::WorldIdRegistryInstance,
};

/// Type alias for the registry instance.
pub type Registry = WorldIdRegistryInstance<Arc<DynProvider>>;

/// Context required for request validation and submission.
#[derive(Clone)]
pub struct GatewayContext {
    pub registry: Arc<Registry>,
    pub tracker: RequestTracker,
    pub batcher: BatcherHandle,
    pub root_cache: Cache<U256, U256>,
}

/// A request that has been validated and is ready for submission.
pub struct Request<T> {
    id: Uuid,
    kind: GatewayRequestKind,
    payload: T,
    /// Pre-computed calldata for the contract call.
    calldata: Bytes,
}

/// Response type after successful submission.
pub struct SubmittedRequest {
    id: Uuid,
    kind: GatewayRequestKind,
}

impl SubmittedRequest {
    /// Convert to the gateway status response.
    pub fn into_response(self) -> GatewayStatusResponse {
        GatewayStatusResponse {
            request_id: self.id.to_string(),
            kind: self.kind,
            status: GatewayRequestState::Queued,
        }
    }
}

/// Trait for requests that have a leaf_index field (for rate limiting).
pub trait HasLeafIndex {
    /// Get the leaf_index for this request.
    fn leaf_index(&self) -> u64;
}

/// Trait for converting API payloads into tracked Requests.
///
/// Validation is performed asynchronously, including contract simulation.
pub trait IntoRequest: RequestValidation + Sized {
    /// The kind of request this payload represents.
    const KIND: GatewayRequestKind;

    /// Validate and convert into a Request.
    ///
    /// This performs both pre-flight validation and contract simulation,
    /// then pre-computes the calldata for submission.
    async fn into_request(
        self,
        id: Uuid,
        ctx: &GatewayContext,
    ) -> Result<Request<Self>, GatewayErrorResponse> {
        let calldata = self.validate_and_calldata(&ctx.registry).await?;

        Ok(Request {
            id,
            kind: Self::KIND,
            payload: self,
            calldata,
        })
    }
}

/// Extended trait for requests with leaf_index that need rate limiting.
#[allow(async_fn_in_trait)]
pub trait IntoRequestWithRateLimit: IntoRequest + HasLeafIndex {
    /// Validate, rate-limit, and convert into a Request.
    async fn into_request_with_rate_limit(
        self,
        id: Uuid,
        ctx: &GatewayContext,
    ) -> Result<Request<Self>, GatewayErrorResponse> {
        // Check rate limit first (before validation to save resources)
        // We do also count rate limitted requests.
        ctx.tracker
            .check_rate_limit(self.leaf_index(), &id.to_string())
            .await?;

        self.into_request(id, ctx).await
    }
}

// =============================================================================
// CreateAccountRequest
// =============================================================================

impl IntoRequest for CreateAccountRequest {
    const KIND: GatewayRequestKind = GatewayRequestKind::CreateAccount;
}

impl Request<CreateAccountRequest> {
    /// Submit the request for processing.
    pub async fn submit(
        self,
        ctx: &GatewayContext,
    ) -> Result<SubmittedRequest, GatewayErrorResponse> {
        let Request {
            id, kind, payload, ..
        } = self;
        let request_id = id.to_string();

        // Atomically check and insert all authenticator addresses to prevent duplicates
        let auth_addresses = payload.authenticator_addresses.clone();

        ctx.tracker.try_insert_inflight(&auth_addresses).await?;

        // Register in tracker
        if let Err(err) = ctx
            .tracker
            .new_request_with_id(request_id.clone(), kind)
            .await
        {
            // Remove from inflight tracker if an error appears
            ctx.tracker.remove_inflight(&auth_addresses).await;
            return Err(err);
        };

        // Queue to batcher with typed request for createManyAccounts batching
        let cmd = Command::create_account(id, payload, DEFAULT_CREATE_ACCOUNT_GAS);

        if !ctx.batcher.submit(cmd).await {
            // Remove from inflight tracker if batcher submission fails
            ctx.tracker.remove_inflight(&auth_addresses).await;
            ctx.tracker
                .set_status(
                    &request_id,
                    GatewayRequestState::failed_from_code(GatewayErrorCode::BatcherUnavailable),
                )
                .await;
            return Err(GatewayErrorResponse::batcher_unavailable());
        }

        Ok(SubmittedRequest { id, kind })
    }
}

// =============================================================================
// InsertAuthenticatorRequest
// =============================================================================

impl HasLeafIndex for InsertAuthenticatorRequest {
    fn leaf_index(&self) -> u64 {
        self.leaf_index
    }
}

impl IntoRequest for InsertAuthenticatorRequest {
    const KIND: GatewayRequestKind = GatewayRequestKind::InsertAuthenticator;
}

impl IntoRequestWithRateLimit for InsertAuthenticatorRequest {}

impl Request<InsertAuthenticatorRequest> {
    /// Submit the request for processing.
    pub async fn submit(
        self,
        ctx: &GatewayContext,
    ) -> Result<SubmittedRequest, GatewayErrorResponse> {
        submit_operation_request(self, ctx, DEFAULT_INSERT_AUTHENTICATOR_GAS).await
    }
}

// =============================================================================
// UpdateAuthenticatorRequest
// =============================================================================

impl HasLeafIndex for UpdateAuthenticatorRequest {
    fn leaf_index(&self) -> u64 {
        self.leaf_index
    }
}

impl IntoRequest for UpdateAuthenticatorRequest {
    const KIND: GatewayRequestKind = GatewayRequestKind::UpdateAuthenticator;
}

impl IntoRequestWithRateLimit for UpdateAuthenticatorRequest {}

impl Request<UpdateAuthenticatorRequest> {
    /// Submit the request for processing.
    pub async fn submit(
        self,
        ctx: &GatewayContext,
    ) -> Result<SubmittedRequest, GatewayErrorResponse> {
        submit_operation_request(self, ctx, DEFAULT_UPDATE_AUTHENTICATOR_GAS).await
    }
}

// =============================================================================
// RemoveAuthenticatorRequest
// =============================================================================

impl HasLeafIndex for RemoveAuthenticatorRequest {
    fn leaf_index(&self) -> u64 {
        self.leaf_index
    }
}

impl IntoRequest for RemoveAuthenticatorRequest {
    const KIND: GatewayRequestKind = GatewayRequestKind::RemoveAuthenticator;
}

impl IntoRequestWithRateLimit for RemoveAuthenticatorRequest {}

impl Request<RemoveAuthenticatorRequest> {
    /// Submit the request for processing.
    pub async fn submit(
        self,
        ctx: &GatewayContext,
    ) -> Result<SubmittedRequest, GatewayErrorResponse> {
        submit_operation_request(self, ctx, DEFAULT_REMOVE_AUTHENTICATOR_GAS).await
    }
}

// =============================================================================
// RecoverAccountRequest
// =============================================================================

impl HasLeafIndex for RecoverAccountRequest {
    fn leaf_index(&self) -> u64 {
        self.leaf_index
    }
}

impl IntoRequest for RecoverAccountRequest {
    const KIND: GatewayRequestKind = GatewayRequestKind::RecoverAccount;
}

impl IntoRequestWithRateLimit for RecoverAccountRequest {}

impl Request<RecoverAccountRequest> {
    /// Submit the request for processing.
    pub async fn submit(
        self,
        ctx: &GatewayContext,
    ) -> Result<SubmittedRequest, GatewayErrorResponse> {
        submit_operation_request(self, ctx, DEFAULT_RECOVER_ACCOUNT_GAS).await
    }
}

async fn submit_operation_request<T>(
    request: Request<T>,
    ctx: &GatewayContext,
    gas: u64,
) -> Result<SubmittedRequest, GatewayErrorResponse> {
    let Request {
        id, kind, calldata, ..
    } = request;
    let request_id = id.to_string();

    // Register in tracker
    ctx.tracker
        .new_request_with_id(request_id.clone(), kind)
        .await?;

    // Build command with pre-computed calldata
    let cmd = Command::operation(id, calldata, gas);

    if !ctx.batcher.submit(cmd).await {
        ctx.tracker
            .set_status(
                &request_id,
                GatewayRequestState::failed_from_code(GatewayErrorCode::BatcherUnavailable),
            )
            .await;
        return Err(GatewayErrorResponse::batcher_unavailable());
    }

    Ok(SubmittedRequest { id, kind })
}
