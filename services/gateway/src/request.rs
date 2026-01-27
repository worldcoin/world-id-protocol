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
    request_tracker::RequestTracker,
    routes::validation::RequestValidation,
};
use alloy::{
    primitives::{Address, Bytes, U256},
    providers::DynProvider,
};
use moka::{
    future::Cache,
    ops::compute::{CompResult, Op},
};
use uuid::Uuid;
use world_id_core::{
    types::{
        CreateAccountRequest, GatewayErrorCode, GatewayErrorResponse, GatewayRequestKind,
        GatewayRequestState, GatewayStatusResponse, InsertAuthenticatorRequest,
        RecoverAccountRequest, RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
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
    pub inflight_authenticators: Cache<Address, ()>,
}

/// A request that has been validated and is ready for submission.
pub struct Request<T> {
    id: Uuid,
    kind: GatewayRequestKind,
    payload: T,
    /// Pre-computed calldata for the contract call.
    calldata: Bytes,
}

impl<T> Request<T> {
    /// Get the request ID.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Get the request kind.
    pub fn kind(&self) -> GatewayRequestKind {
        self.kind.clone()
    }

    /// Calldata for the contract call.
    pub fn calldata(&self) -> Bytes {
        self.calldata.clone()
    }
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
        self.validate(&ctx.registry).await?;
        let calldata = self.calldata(&ctx.registry);

        Ok(Request {
            id,
            kind: Self::KIND,
            payload: self,
            calldata,
        })
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
        // Atomically check and insert all authenticator addresses to prevent TOCTOU races
        let auth_addresses = self.payload.authenticator_addresses.clone();
        let mut inserted_addresses: Vec<Address> = Vec::new();

        for addr in &auth_addresses {
            let result = ctx
                .inflight_authenticators
                .entry_by_ref(addr)
                .and_compute_with(|entry| async move {
                    if entry.is_some() {
                        // Already exists, don't modify
                        Op::Nop
                    } else {
                        // Doesn't exist, insert
                        Op::Put(())
                    }
                })
                .await;

            match result {
                CompResult::Inserted(_) => {
                    // Successfully inserted this address
                    inserted_addresses.push(*addr);
                }
                CompResult::Unchanged(_) => {
                    // Entry already existed - rollback and return error
                    for inserted_addr in &inserted_addresses {
                        ctx.inflight_authenticators.invalidate(inserted_addr).await;
                    }
                    return Err(GatewayErrorResponse::bad_request(
                        GatewayErrorCode::DuplicateRequestInFlight,
                    ));
                }
                // These cases shouldn't happen with our Op::Put/Op::Nop logic
                _ => unreachable!("Unexpected CompResult variant"),
            }
        }

        // Register in tracker
        if let Err(err) = ctx
            .tracker
            .new_request_with_id(self.id().to_string(), self.kind().clone())
            .await
        {
            // Remove from cache if an error appears
            for addr in &auth_addresses {
                ctx.inflight_authenticators.invalidate(addr).await;
            }
            return Err(err);
        };

        // Queue to batcher with typed request for createManyAccounts batching
        let cmd = Command::create_account(self.id, self.payload, DEFAULT_CREATE_ACCOUNT_GAS);

        if !ctx.batcher.submit(cmd).await {
            // Remove from cache if batcher submission fails
            for addr in &auth_addresses {
                ctx.inflight_authenticators.invalidate(addr).await;
            }
            ctx.tracker
                .set_status(
                    &self.id.to_string(),
                    GatewayRequestState::failed_from_code(GatewayErrorCode::BatcherUnavailable),
                )
                .await;
            return Err(GatewayErrorResponse::batcher_unavailable());
        }

        Ok(SubmittedRequest {
            id: self.id,
            kind: self.kind,
        })
    }
}

// =============================================================================
// InsertAuthenticatorRequest
// =============================================================================

impl IntoRequest for InsertAuthenticatorRequest {
    const KIND: GatewayRequestKind = GatewayRequestKind::InsertAuthenticator;
}

impl Request<InsertAuthenticatorRequest> {
    /// Submit the request for processing.
    pub async fn submit(
        self,
        ctx: &GatewayContext,
    ) -> Result<SubmittedRequest, GatewayErrorResponse> {
        // Register in tracker
        ctx.tracker
            .new_request_with_id(self.id.to_string(), self.kind.clone())
            .await?;

        // Build command with pre-computed calldata
        let cmd = Command::operation(self.id(), self.calldata(), DEFAULT_INSERT_AUTHENTICATOR_GAS);

        if !ctx.batcher.submit(cmd).await {
            ctx.tracker
                .set_status(
                    &self.id().to_string(),
                    GatewayRequestState::failed_from_code(GatewayErrorCode::BatcherUnavailable),
                )
                .await;
            return Err(GatewayErrorResponse::batcher_unavailable());
        }

        Ok(SubmittedRequest {
            id: self.id(),
            kind: self.kind(),
        })
    }
}

// =============================================================================
// UpdateAuthenticatorRequest
// =============================================================================

impl IntoRequest for UpdateAuthenticatorRequest {
    const KIND: GatewayRequestKind = GatewayRequestKind::UpdateAuthenticator;
}

impl Request<UpdateAuthenticatorRequest> {
    /// Submit the request for processing.
    pub async fn submit(
        self,
        ctx: &GatewayContext,
    ) -> Result<SubmittedRequest, GatewayErrorResponse> {
        // Register in tracker
        ctx.tracker
            .new_request_with_id(self.id().to_string(), self.kind())
            .await?;

        // Build command with pre-computed calldata
        let cmd = Command::operation(self.id(), self.calldata(), DEFAULT_UPDATE_AUTHENTICATOR_GAS);

        if !ctx.batcher.submit(cmd).await {
            ctx.tracker
                .set_status(
                    &self.id().to_string(),
                    GatewayRequestState::failed_from_code(GatewayErrorCode::BatcherUnavailable),
                )
                .await;
            return Err(GatewayErrorResponse::batcher_unavailable());
        }

        Ok(SubmittedRequest {
            id: self.id(),
            kind: self.kind(),
        })
    }
}

// =============================================================================
// RemoveAuthenticatorRequest
// =============================================================================

impl IntoRequest for RemoveAuthenticatorRequest {
    const KIND: GatewayRequestKind = GatewayRequestKind::RemoveAuthenticator;
}

impl Request<RemoveAuthenticatorRequest> {
    /// Submit the request for processing.
    pub async fn submit(
        self,
        ctx: &GatewayContext,
    ) -> Result<SubmittedRequest, GatewayErrorResponse> {
        // Register in tracker
        ctx.tracker
            .new_request_with_id(self.id().to_string(), self.kind())
            .await?;

        // Build command with pre-computed calldata
        let cmd = Command::operation(self.id(), self.calldata(), DEFAULT_REMOVE_AUTHENTICATOR_GAS);
        if !ctx.batcher.submit(cmd).await {
            ctx.tracker
                .set_status(
                    &self.id().to_string(),
                    GatewayRequestState::failed_from_code(GatewayErrorCode::BatcherUnavailable),
                )
                .await;
            return Err(GatewayErrorResponse::batcher_unavailable());
        }

        Ok(SubmittedRequest {
            id: self.id(),
            kind: self.kind(),
        })
    }
}

// =============================================================================
// RecoverAccountRequest
// =============================================================================

impl IntoRequest for RecoverAccountRequest {
    const KIND: GatewayRequestKind = GatewayRequestKind::RecoverAccount;
}

impl Request<RecoverAccountRequest> {
    /// Submit the request for processing.
    pub async fn submit(
        self,
        ctx: &GatewayContext,
    ) -> Result<SubmittedRequest, GatewayErrorResponse> {
        // Register in tracker
        ctx.tracker
            .new_request_with_id(self.id().to_string(), self.kind().clone())
            .await?;

        // Build command with pre-computed calldata
        let cmd = Command::operation(self.id(), self.calldata(), DEFAULT_RECOVER_ACCOUNT_GAS);
        if !ctx.batcher.submit(cmd).await {
            ctx.tracker
                .set_status(
                    &self.id().to_string(),
                    GatewayRequestState::failed_from_code(GatewayErrorCode::BatcherUnavailable),
                )
                .await;
            return Err(GatewayErrorResponse::batcher_unavailable());
        }

        Ok(SubmittedRequest {
            id: self.id(),
            kind: self.kind(),
        })
    }
}
