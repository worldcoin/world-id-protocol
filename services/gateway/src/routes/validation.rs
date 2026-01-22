use std::sync::Arc;

use alloy::{
    primitives::{Bytes, U256},
    providers::DynProvider,
};
use world_id_core::{
    types::{
        CreateAccountRequest, GatewayErrorResponse, InsertAuthenticatorRequest,
        RecoverAccountRequest, RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
    },
    world_id_registry::WorldIdRegistry::WorldIdRegistryInstance,
};

use crate::types::MAX_AUTHENTICATORS;

/// Type alias for the registry instance used in validation.
pub(crate) type Registry = WorldIdRegistryInstance<Arc<DynProvider>>;

/// Standard ECDSA signature length.
const ECDSA_SIGNATURE_LEN: usize = 65;

/// Trait for validating gateway requests before processing.
///
/// Validation consists of two phases:
/// 1. **Pre-flight**: Synchronous checks for basic field validation
/// 2. **Simulation**: Async contract call to verify the transaction would succeed
pub(crate) trait RequestValidation: Sized + Sync {
    /// Synchronous pre-flight validation.
    ///
    /// Checks basic constraints like field lengths, zero values, etc.
    fn pre_flight(&self) -> Result<(), GatewayErrorResponse>;

    /// Get the encoded calldata for this request.
    ///
    /// This produces the ABI-encoded calldata that can be used for both
    /// simulation and actual transaction submission.
    fn calldata(&self, registry: &Registry) -> Bytes;

    /// Simulate the request against the contract.
    ///
    /// Calls the contract with `.call()` to check if the transaction would revert
    /// without actually spending gas.
    fn simulate(
        &self,
        registry: &Registry,
    ) -> impl std::future::Future<Output = Result<(), GatewayErrorResponse>> + Send;

    /// Full validation: pre-flight checks followed by contract simulation.
    fn validate(
        &self,
        registry: &Registry,
    ) -> impl std::future::Future<Output = Result<(), GatewayErrorResponse>> + Send {
        async move {
            self.pre_flight()?;
            self.simulate(registry).await
        }
    }
}

/// Basic ECDSA signature validation.
///
/// Note that it does **NOT** compute a signature verification algorithm.
fn validate_ecdsa_signature(signature: &[u8]) -> Result<(), GatewayErrorResponse> {
    if signature.len() != ECDSA_SIGNATURE_LEN {
        return Err(GatewayErrorResponse::bad_request_message(
            "ECDSA signature must be exactly 65 bytes long".to_string(),
        ));
    }
    if signature.iter().all(|&byte| byte == 0) {
        return Err(GatewayErrorResponse::bad_request_message(
            "ECDSA signature cannot be all zeros".to_string(),
        ));
    }
    Ok(())
}

// =============================================================================
// CreateAccountRequest
// =============================================================================

impl RequestValidation for CreateAccountRequest {
    fn pre_flight(&self) -> Result<(), GatewayErrorResponse> {
        if self.authenticator_addresses.len() > MAX_AUTHENTICATORS as usize {
            return Err(GatewayErrorResponse::bad_request_message(format!(
                "authenticators cannot be more than {MAX_AUTHENTICATORS}"
            )));
        }
        if self.authenticator_addresses.is_empty() {
            return Err(GatewayErrorResponse::bad_request_message(
                "authenticators cannot be empty".to_string(),
            ));
        }
        if self.authenticator_addresses.len() != self.authenticator_pubkeys.len() {
            return Err(GatewayErrorResponse::bad_request_message(
                "authenticators addresses must be equal to authenticators pubkeys".to_string(),
            ));
        }
        if self.authenticator_addresses.iter().any(|a| a.is_zero()) {
            return Err(GatewayErrorResponse::bad_request_message(
                "authenticator address cannot be zero".to_string(),
            ));
        }
        if self.offchain_signer_commitment.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "offchain signer commitment cannot be zero".to_string(),
            ));
        }
        Ok(())
    }

    fn calldata(&self, registry: &Registry) -> Bytes {
        registry
            .createAccount(
                self.recovery_address.unwrap_or_default(),
                self.authenticator_addresses.clone(),
                self.authenticator_pubkeys.clone(),
                self.offchain_signer_commitment,
            )
            .calldata()
            .clone()
    }

    async fn simulate(&self, registry: &Registry) -> Result<(), GatewayErrorResponse> {
        registry
            .createAccount(
                self.recovery_address.unwrap_or_default(),
                self.authenticator_addresses.clone(),
                self.authenticator_pubkeys.clone(),
                self.offchain_signer_commitment,
            )
            .call()
            .await
            .map_err(GatewayErrorResponse::from_simulation_error)?;
        Ok(())
    }
}

// =============================================================================
// InsertAuthenticatorRequest
// =============================================================================

impl RequestValidation for InsertAuthenticatorRequest {
    fn pre_flight(&self) -> Result<(), GatewayErrorResponse> {
        if self.new_authenticator_address.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "new_authenticator_address cannot be zero".to_string(),
            ));
        }
        if self.pubkey_id >= MAX_AUTHENTICATORS {
            return Err(GatewayErrorResponse::bad_request_message(format!(
                "pubkey_id must be less than {MAX_AUTHENTICATORS}"
            )));
        }
        if self.leaf_index.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "leaf_index cannot be zero".to_string(),
            ));
        }
        if self.old_offchain_signer_commitment.is_zero()
            || self.new_offchain_signer_commitment.is_zero()
        {
            return Err(GatewayErrorResponse::bad_request_message(
                "offchain signer commitment cannot be zero".to_string(),
            ));
        }
        validate_ecdsa_signature(&self.signature)?;
        Ok(())
    }

    fn calldata(&self, registry: &Registry) -> Bytes {
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
            .calldata()
            .clone()
    }

    async fn simulate(&self, registry: &Registry) -> Result<(), GatewayErrorResponse> {
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

// =============================================================================
// UpdateAuthenticatorRequest
// =============================================================================

impl RequestValidation for UpdateAuthenticatorRequest {
    fn pre_flight(&self) -> Result<(), GatewayErrorResponse> {
        if self.leaf_index.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "leaf_index cannot be zero".to_string(),
            ));
        }
        if self.pubkey_id >= MAX_AUTHENTICATORS {
            return Err(GatewayErrorResponse::bad_request_message(format!(
                "pubkey_id must be less than {MAX_AUTHENTICATORS}"
            )));
        }
        if self.new_authenticator_address.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "new_authenticator_address cannot be zero".to_string(),
            ));
        }
        if self.old_offchain_signer_commitment.is_zero()
            || self.new_offchain_signer_commitment.is_zero()
        {
            return Err(GatewayErrorResponse::bad_request_message(
                "offchain signer commitment cannot be zero".to_string(),
            ));
        }
        validate_ecdsa_signature(&self.signature)?;
        Ok(())
    }

    fn calldata(&self, registry: &Registry) -> Bytes {
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
            .calldata()
            .clone()
    }

    async fn simulate(&self, registry: &Registry) -> Result<(), GatewayErrorResponse> {
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

// =============================================================================
// RemoveAuthenticatorRequest
// =============================================================================

impl RequestValidation for RemoveAuthenticatorRequest {
    fn pre_flight(&self) -> Result<(), GatewayErrorResponse> {
        let pubkey_id = self.pubkey_id.unwrap_or(0);

        if self.leaf_index.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "leaf_index cannot be zero".to_string(),
            ));
        }
        if pubkey_id >= MAX_AUTHENTICATORS {
            return Err(GatewayErrorResponse::bad_request_message(format!(
                "pubkey_id must be less than {MAX_AUTHENTICATORS}"
            )));
        }
        if self.authenticator_address.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "authenticator_address cannot be zero".to_string(),
            ));
        }
        if self.old_offchain_signer_commitment.is_zero()
            || self.new_offchain_signer_commitment.is_zero()
        {
            return Err(GatewayErrorResponse::bad_request_message(
                "offchain signer commitment cannot be zero".to_string(),
            ));
        }
        validate_ecdsa_signature(&self.signature)?;
        Ok(())
    }

    fn calldata(&self, registry: &Registry) -> Bytes {
        let pubkey_id = self.pubkey_id.unwrap_or(0);
        let authenticator_pubkey = self.authenticator_pubkey.unwrap_or(U256::ZERO);

        registry
            .removeAuthenticator(
                self.leaf_index,
                self.authenticator_address,
                pubkey_id,
                authenticator_pubkey,
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .calldata()
            .clone()
    }

    async fn simulate(&self, registry: &Registry) -> Result<(), GatewayErrorResponse> {
        let pubkey_id = self.pubkey_id.unwrap_or(0);
        let authenticator_pubkey = self.authenticator_pubkey.unwrap_or(U256::ZERO);

        registry
            .removeAuthenticator(
                self.leaf_index,
                self.authenticator_address,
                pubkey_id,
                authenticator_pubkey,
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .call()
            .await
            .map(|_| ())
            .map_err(GatewayErrorResponse::from_simulation_error)
    }
}

// =============================================================================
// RecoverAccountRequest
// =============================================================================

impl RequestValidation for RecoverAccountRequest {
    fn pre_flight(&self) -> Result<(), GatewayErrorResponse> {
        if self.leaf_index.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "leaf_index cannot be zero".to_string(),
            ));
        }
        if self.new_authenticator_address.is_zero() {
            return Err(GatewayErrorResponse::bad_request_message(
                "new_authenticator_address cannot be zero".to_string(),
            ));
        }
        if self.old_offchain_signer_commitment.is_zero()
            || self.new_offchain_signer_commitment.is_zero()
        {
            return Err(GatewayErrorResponse::bad_request_message(
                "offchain signer commitment cannot be zero".to_string(),
            ));
        }
        validate_ecdsa_signature(&self.signature)?;
        Ok(())
    }

    fn calldata(&self, registry: &Registry) -> Bytes {
        let new_pubkey = self.new_authenticator_pubkey.unwrap_or(U256::ZERO);

        registry
            .recoverAccount(
                self.leaf_index,
                self.new_authenticator_address,
                new_pubkey,
                self.old_offchain_signer_commitment,
                self.new_offchain_signer_commitment,
                Bytes::from(self.signature.clone()),
                self.sibling_nodes.clone(),
                self.nonce,
            )
            .calldata()
            .clone()
    }

    async fn simulate(&self, registry: &Registry) -> Result<(), GatewayErrorResponse> {
        let new_pubkey = self.new_authenticator_pubkey.unwrap_or(U256::ZERO);

        registry
            .recoverAccount(
                self.leaf_index,
                self.new_authenticator_address,
                new_pubkey,
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
