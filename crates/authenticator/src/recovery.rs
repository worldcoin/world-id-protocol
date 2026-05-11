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
    #[deprecated(
        note = "WIP-102: use `update_recovery_agent`. The legacy URL still works against a V2-upgraded gateway, but the V2 contract changes the agent immediately (with a revert window) instead of starting a cooldown."
    )]
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

    /// Updates the holder's recovery agent (WIP-102).
    ///
    /// On a V2 registry the new agent becomes effective immediately, but for a
    /// revert window (`getRecoveryAgentUpdateCooldown` seconds) any
    /// authenticator can call [`Self::revert_recovery_agent_update`] to roll
    /// back. During that window the *previous* agent remains the only valid
    /// signer for `recoverAccount`, which mitigates a compromised authenticator
    /// silently swapping in an attacker-controlled recovery address.
    ///
    /// # Errors
    /// Returns an error if the gateway rejects the request or a network error occurs.
    pub async fn update_recovery_agent(
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
            .post_json(self.config.gateway_url(), "/update-recovery-agent", &req)
            .await?;
        Ok(gateway_resp.request_id)
    }

    /// Executes a pending recovery agent update for the holder's World ID.
    ///
    /// This is a permissionless operation that can be called by anyone after the cooldown
    /// period has elapsed. No signature is required.
    ///
    /// # Errors
    /// Returns an error if the gateway rejects the request or a network error occurs.
    #[deprecated(
        note = "WIP-102: this operation no longer exists. On a V2-upgraded gateway the call is a no-op (returns Finalized without touching chain). Remove the call from your flow."
    )]
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
    #[deprecated(
        note = "WIP-102: use `revert_recovery_agent_update`. The legacy URL still works against a V2-upgraded gateway, but the new method name reflects WIP-102 semantics: the operation can only succeed within the revert window after `update_recovery_agent`."
    )]
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

    /// Reverts an in-flight recovery agent update during the revert window (WIP-102).
    ///
    /// # Errors
    /// Returns an error if the gateway rejects the request or a network error occurs.
    pub async fn revert_recovery_agent_update(
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
            AuthenticatorError::Generic(format!("Failed to sign revert recovery agent update: {e}"))
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
                "/revert-recovery-agent-update",
                &req,
            )
            .await?;
        Ok(gateway_resp.request_id)
    }
}
