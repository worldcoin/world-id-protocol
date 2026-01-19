//! Validation and simulation middleware for gateway routes.
//!
//! Provides extractors for request validation, simulation, and request ID generation.

use crate::types::AppState;
use alloy::primitives::{Bytes, U256};
use alloy::providers::DynProvider;
use axum::{
    extract::{FromRef, FromRequest, Request},
    Json,
};
use serde::de::DeserializeOwned;
use std::sync::Arc;
use world_id_core::{
    types::{
        GatewayErrorResponse, InsertAuthenticatorRequest, RecoverAccountRequest,
        RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
    },
    world_id_registry::WorldIdRegistry::WorldIdRegistryInstance,
};

use super::validation::ValidateRequest;

// ============================================================================
// Simulate Trait
// ============================================================================

/// Trait for requests that can be simulated against the contract.
pub trait SimulateRequest: ValidateRequest + Send {
    /// Simulate the request against the contract.
    fn simulate(
        &self,
        registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
    ) -> impl std::future::Future<Output = Result<(), GatewayErrorResponse>> + Send;
}

impl SimulateRequest for InsertAuthenticatorRequest {
    async fn simulate(
        &self,
        registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
    ) -> Result<(), GatewayErrorResponse> {
        registry
            .insertAuthenticator(
                self.leaf_index,
                self.new_authenticator_address,
                self.pubkey_id,
                self.new_authenticator_pubkey,
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .call()
            .await
            .map_err(GatewayErrorResponse::from_simulation_error)?;
        Ok(())
    }
}

impl SimulateRequest for UpdateAuthenticatorRequest {
    async fn simulate(
        &self,
        registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
    ) -> Result<(), GatewayErrorResponse> {
        registry
            .updateAuthenticator(
                self.leaf_index,
                self.old_authenticator_address,
                self.new_authenticator_address,
                self.pubkey_id,
                self.new_authenticator_pubkey,
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .call()
            .await
            .map_err(GatewayErrorResponse::from_simulation_error)?;
        Ok(())
    }
}

impl SimulateRequest for RemoveAuthenticatorRequest {
    async fn simulate(
        &self,
        registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
    ) -> Result<(), GatewayErrorResponse> {
        registry
            .removeAuthenticator(
                self.leaf_index,
                self.authenticator_address,
                self.pubkey_id.unwrap_or(0),
                self.authenticator_pubkey.unwrap_or(U256::ZERO),
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .call()
            .await
            .map_err(GatewayErrorResponse::from_simulation_error)?;
        Ok(())
    }
}

impl SimulateRequest for RecoverAccountRequest {
    async fn simulate(
        &self,
        registry: &WorldIdRegistryInstance<Arc<DynProvider>>,
    ) -> Result<(), GatewayErrorResponse> {
        registry
            .recoverAccount(
                self.leaf_index,
                self.new_authenticator_address,
                self.new_authenticator_pubkey.unwrap_or(U256::ZERO),
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .call()
            .await
            .map_err(GatewayErrorResponse::from_simulation_error)?;
        Ok(())
    }
}

// ============================================================================
// Validated Extractor
// ============================================================================

/// A wrapper that indicates the request has been validated and simulated.
///
/// Use this as an extractor in route handlers:
/// ```ignore
/// async fn insert_authenticator(
///     State(state): State<AppState>,
///     Validated(req): Validated<InsertAuthenticatorRequest>,
/// ) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
///     // req is guaranteed to be valid and simulation passed
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Validated<T>(pub T);

impl<S, T> FromRequest<S> for Validated<T>
where
    S: Send + Sync,
    T: DeserializeOwned + SimulateRequest + 'static,
    AppState: FromRef<S>,
{
    type Rejection = GatewayErrorResponse;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // Extract JSON body
        let Json(body): Json<T> = Json::from_request(req, state)
            .await
            .map_err(|e| GatewayErrorResponse::bad_request_message(e.to_string()))?;

        // Validate
        body.validate()?;

        // Get registry from state and simulate
        let app_state = AppState::from_ref(state);
        body.simulate(&app_state.regsitry).await?;

        Ok(Validated(body))
    }
}
