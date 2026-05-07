use alloy::{primitives::Address, signers::Signature};
use ruint::aliases::U256;

use crate::{
    api_types::{
        CancelRecoveryAgentUpdateRequest, ExecuteRecoveryAgentUpdateRequest, GatewayRequestId,
        GatewayStatusResponse, UpdateRecoveryAgentRequest,
    },
    authenticator::Authenticator,
    error::AuthenticatorError,
};
use world_id_registries::world_id::{
    domain, sign_cancel_recovery_agent_update, sign_initiate_recovery_agent_update,
};

impl Authenticator {
    /// Initiates a recovery agent update for the holder's World ID.
    ///
    /// This begins a time-locked process to change the recovery agent. The update must be
    /// executed after a cooldown period using [`execute_recovery_agent_update`](Self::execute_recovery_agent_update),
    /// or it can be cancelled using [`cancel_recovery_agent_update`](Self::cancel_recovery_agent_update).
    ///
    /// # Errors
    /// Returns an error if the gateway rejects the request or a network error occurs.
    pub async fn initiate_recovery_agent_update(
        &self,
        new_recovery_agent: Address,
    ) -> Result<GatewayRequestId, AuthenticatorError> {
        let leaf_index = self.leaf_index();
        let (sig, nonce) = self
            .danger_sign_initiate_recovery_agent_update(new_recovery_agent)
            .await?;

        let req = UpdateRecoveryAgentRequest {
            leaf_index,
            new_recovery_agent,
            signature: sig,
            nonce,
        };

        let gateway_resp: GatewayStatusResponse = self
            .gateway_client
            .post_json(
                self.config.gateway_url(),
                "/initiate-recovery-agent-update",
                &req,
            )
            .await?;
        Ok(gateway_resp.request_id)
    }

    /// Signs the EIP-712 `InitiateRecoveryAgentUpdate` payload and returns the
    /// signature without submitting anything to the gateway.
    ///
    /// This is the signing-only counterpart of [`Self::initiate_recovery_agent_update`].
    /// Callers can use the returned signature to build and submit the gateway
    /// request themselves.
    ///
    /// # Warning
    /// This method uses the `onchain_signer` (secp256k1 ECDSA) and produces a
    /// recoverable signature. Any holder of the signature together with the
    /// EIP-712 parameters can call `ecrecover` to obtain the `onchain_address`,
    /// which can then be looked up in the registry to derive the user's
    /// `leaf_index`. Only expose the output to trusted parties (e.g. a Recovery
    /// Agent).
    ///
    /// # Errors
    /// Returns an error if the nonce fetch or signing step fails.
    pub async fn danger_sign_initiate_recovery_agent_update(
        &self,
        new_recovery_agent: Address,
    ) -> Result<(Signature, U256), AuthenticatorError> {
        let leaf_index = self.leaf_index();
        let nonce = self.signing_nonce().await?;
        let eip712_domain = domain(self.config.chain_id(), *self.config.registry_address());

        let signature = sign_initiate_recovery_agent_update(
            &self.signer.onchain_signer(),
            leaf_index,
            new_recovery_agent,
            nonce,
            &eip712_domain,
        )
        .map_err(|e| {
            AuthenticatorError::Generic(format!(
                "Failed to sign initiate recovery agent update: {e}"
            ))
        })?;

        Ok((signature, nonce))
    }

    /// Executes a pending recovery agent update for the holder's World ID.
    ///
    /// This is a permissionless operation that can be called by anyone after the cooldown
    /// period has elapsed. No signature is required.
    ///
    /// # Errors
    /// Returns an error if the gateway rejects the request or a network error occurs.
    pub async fn execute_recovery_agent_update(
        &self,
    ) -> Result<GatewayRequestId, AuthenticatorError> {
        let req = ExecuteRecoveryAgentUpdateRequest {
            leaf_index: self.leaf_index(),
        };

        let gateway_resp: GatewayStatusResponse = self
            .gateway_client
            .post_json(
                self.config.gateway_url(),
                "/execute-recovery-agent-update",
                &req,
            )
            .await?;
        Ok(gateway_resp.request_id)
    }

    /// Cancels a pending recovery agent update for the holder's World ID.
    ///
    /// # Errors
    /// Returns an error if the gateway rejects the request or a network error occurs.
    pub async fn cancel_recovery_agent_update(
        &self,
    ) -> Result<GatewayRequestId, AuthenticatorError> {
        let leaf_index = self.leaf_index();
        let nonce = self.signing_nonce().await?;
        let eip712_domain = domain(self.config.chain_id(), *self.config.registry_address());

        let sig = sign_cancel_recovery_agent_update(
            &self.signer.onchain_signer(),
            leaf_index,
            nonce,
            &eip712_domain,
        )
        .map_err(|e| {
            AuthenticatorError::Generic(format!("Failed to sign cancel recovery agent update: {e}"))
        })?;

        let req = CancelRecoveryAgentUpdateRequest {
            leaf_index,
            signature: sig,
            nonce,
        };

        let gateway_resp: GatewayStatusResponse = self
            .gateway_client
            .post_json(
                self.config.gateway_url(),
                "/cancel-recovery-agent-update",
                &req,
            )
            .await?;
        Ok(gateway_resp.request_id)
    }
}
