use alloy::primitives::Address;
use ark_serialize::CanonicalSerialize;
use ruint::aliases::U256;
use world_id_primitives::{PrimitiveError, Signer, authenticator::AuthenticatorPublicKeySet};

use crate::authenticator::{fetch_gateway_status, response_body_or_fallback};
use crate::error::AuthenticatorError;
use crate::api_types::{
    CreateAccountRequest, GatewayRequestId, GatewayRequestState, GatewayStatusResponse,
};

pub use world_id_primitives::Config;

/// Represents an account in the process of being initialized,
/// i.e. it is not yet registered in the `WorldIDRegistry` contract.
pub struct InitializingAuthenticator {
    request_id: GatewayRequestId,
    http_client: reqwest::Client,
    config: Config,
}

impl InitializingAuthenticator {
    /// Returns the gateway request ID for this pending account creation.
    #[must_use]
    pub fn request_id(&self) -> &GatewayRequestId {
        &self.request_id
    }

    /// Creates a new World ID account by adding it to the registry using the gateway.
    ///
    /// # Errors
    /// - See `Signer::from_seed_bytes` for additional error details.
    /// - Will error if the gateway rejects the request or a network error occurs.
    pub(crate) async fn new(
        seed: &[u8],
        config: Config,
        recovery_address: Option<Address>,
        http_client: reqwest::Client,
    ) -> Result<Self, AuthenticatorError> {
        let signer = Signer::from_seed_bytes(seed)?;

        let mut key_set = AuthenticatorPublicKeySet::default();
        key_set.try_push(signer.offchain_signer_pubkey())?;
        let leaf_hash = key_set.leaf_hash();

        let offchain_pubkey_compressed = {
            let pk = signer.offchain_signer_pubkey().pk;
            let mut compressed_bytes = Vec::new();
            pk.serialize_compressed(&mut compressed_bytes)
                .map_err(|e| PrimitiveError::Serialization(e.to_string()))?;
            U256::from_le_slice(&compressed_bytes)
        };

        let req = CreateAccountRequest {
            recovery_address,
            authenticator_addresses: vec![signer.onchain_signer_address()],
            authenticator_pubkeys: vec![offchain_pubkey_compressed],
            offchain_signer_commitment: leaf_hash.into(),
        };

        let resp = http_client
            .post(format!("{}/create-account", config.gateway_url()))
            .json(&req)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            let body: GatewayStatusResponse = resp.json().await?;
            Ok(Self {
                request_id: body.request_id,
                http_client,
                config,
            })
        } else {
            let body_text = response_body_or_fallback(resp).await;
            Err(AuthenticatorError::GatewayError {
                status,
                body: body_text,
            })
        }
    }

    /// Poll the status of the World ID creation request.
    ///
    /// # Errors
    /// - Will error if the network request fails.
    /// - Will error if the gateway returns an error response.
    pub async fn poll_status(&self) -> Result<GatewayRequestState, AuthenticatorError> {
        fetch_gateway_status(
            &self.http_client,
            self.config.gateway_url(),
            &self.request_id,
        )
        .await
    }
}
