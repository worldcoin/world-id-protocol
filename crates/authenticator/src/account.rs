//! This module contains account management operations for the user's World ID. It lets
//! the user add, update, remove authenticators.
use alloy::primitives::Address;
use eddsa_babyjubjub::EdDSAPublicKey;
use ruint::aliases::U256;

use crate::{
    api_types::{
        GatewayRequestId, GatewayRequestState, GatewayStatusResponse, InsertAuthenticatorRequest,
        RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
    },
    authenticator::Authenticator,
    error::AuthenticatorError,
    registry::{
        domain, sign_insert_authenticator, sign_remove_authenticator, sign_update_authenticator,
    },
    traits::OnchainKeyRepresentable,
};

impl Authenticator {
    /// Inserts a new authenticator to the account.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are HTTP call failures.
    ///
    /// # Note
    /// TODO: After successfully inserting an authenticator, the `packed_account_data` should be
    /// refreshed from the registry to reflect the new `pubkey_id` commitment.
    pub async fn insert_authenticator(
        &self,
        new_authenticator_pubkey: EdDSAPublicKey,
        new_authenticator_address: Address,
    ) -> Result<GatewayRequestId, AuthenticatorError> {
        let leaf_index = self.leaf_index();
        let nonce = self.signing_nonce().await?;
        let mut key_set = self.fetch_authenticator_pubkeys().await?;
        let old_offchain_signer_commitment = key_set.leaf_hash();
        let encoded_offchain_pubkey = new_authenticator_pubkey.to_ethereum_representation()?;
        let index =
            Self::insert_or_reuse_authenticator_key(&mut key_set, new_authenticator_pubkey)?;
        let new_offchain_signer_commitment = key_set.leaf_hash();

        let eip712_domain = domain(self.config.chain_id(), *self.config.registry_address());

        #[allow(clippy::cast_possible_truncation)]
        // truncating is intentional, and index will always fit in 32 bits
        let signature = sign_insert_authenticator(
            &self.signer.onchain_signer(),
            leaf_index,
            new_authenticator_address,
            index as u32,
            encoded_offchain_pubkey,
            new_offchain_signer_commitment.into(),
            nonce,
            &eip712_domain,
        )
        .map_err(|e| {
            AuthenticatorError::Generic(format!("Failed to sign insert authenticator: {e}"))
        })?;

        #[allow(clippy::cast_possible_truncation)]
        // truncating is intentional, and index will always fit in 32 bits
        let req = InsertAuthenticatorRequest {
            leaf_index,
            new_authenticator_address,
            pubkey_id: index as u32,
            new_authenticator_pubkey: encoded_offchain_pubkey,
            old_offchain_signer_commitment: old_offchain_signer_commitment.into(),
            new_offchain_signer_commitment: new_offchain_signer_commitment.into(),
            signature,
            nonce,
        };

        let body: GatewayStatusResponse = self
            .gateway_client
            .post_json(self.config.gateway_url(), "/insert-authenticator", &req)
            .await?;
        Ok(body.request_id)
    }

    /// Updates an existing authenticator slot with a new authenticator.
    ///
    /// # Errors
    /// Returns an error if the gateway rejects the request or a network error occurs.
    ///
    /// # Note
    /// TODO: After successfully updating an authenticator, the `packed_account_data` should be
    /// refreshed from the registry to reflect the new `pubkey_id` commitment.
    pub async fn update_authenticator(
        &self,
        old_authenticator_address: Address,
        new_authenticator_address: Address,
        new_authenticator_pubkey: EdDSAPublicKey,
        index: u32,
    ) -> Result<GatewayRequestId, AuthenticatorError> {
        let leaf_index = self.leaf_index();
        let nonce = self.signing_nonce().await?;
        let mut key_set = self.fetch_authenticator_pubkeys().await?;
        let old_commitment: U256 = key_set.leaf_hash().into();
        let encoded_offchain_pubkey = new_authenticator_pubkey.to_ethereum_representation()?;
        key_set.try_set_at_index(index as usize, new_authenticator_pubkey)?;
        let new_commitment: U256 = key_set.leaf_hash().into();

        let eip712_domain = domain(self.config.chain_id(), *self.config.registry_address());

        let signature = sign_update_authenticator(
            &self.signer.onchain_signer(),
            leaf_index,
            old_authenticator_address,
            new_authenticator_address,
            index,
            encoded_offchain_pubkey,
            new_commitment,
            nonce,
            &eip712_domain,
        )
        .map_err(|e| {
            AuthenticatorError::Generic(format!("Failed to sign update authenticator: {e}"))
        })?;

        let req = UpdateAuthenticatorRequest {
            leaf_index,
            old_authenticator_address,
            new_authenticator_address,
            old_offchain_signer_commitment: old_commitment,
            new_offchain_signer_commitment: new_commitment,
            signature,
            nonce,
            pubkey_id: index,
            new_authenticator_pubkey: encoded_offchain_pubkey,
        };

        let gateway_resp: GatewayStatusResponse = self
            .gateway_client
            .post_json(self.config.gateway_url(), "/update-authenticator", &req)
            .await?;
        Ok(gateway_resp.request_id)
    }

    /// Removes an authenticator from the account.
    ///
    /// # Errors
    /// Returns an error if the gateway rejects the request or a network error occurs.
    ///
    /// # Note
    /// TODO: After successfully removing an authenticator, the `packed_account_data` should be
    /// refreshed from the registry to reflect the new `pubkey_id` commitment.
    pub async fn remove_authenticator(
        &self,
        authenticator_address: Address,
        index: u32,
    ) -> Result<GatewayRequestId, AuthenticatorError> {
        let leaf_index = self.leaf_index();
        let nonce = self.signing_nonce().await?;
        let mut key_set = self.fetch_authenticator_pubkeys().await?;
        let old_commitment: U256 = key_set.leaf_hash().into();
        let existing_pubkey = key_set
            .get(index as usize)
            .ok_or(AuthenticatorError::PublicKeyNotFound)?;

        let encoded_old_offchain_pubkey = existing_pubkey.to_ethereum_representation()?;

        key_set.try_clear_at_index(index as usize)?;
        let new_commitment: U256 = key_set.leaf_hash().into();

        let eip712_domain = domain(self.config.chain_id(), *self.config.registry_address());

        let signature = sign_remove_authenticator(
            &self.signer.onchain_signer(),
            leaf_index,
            authenticator_address,
            index,
            encoded_old_offchain_pubkey,
            new_commitment,
            nonce,
            &eip712_domain,
        )
        .map_err(|e| {
            AuthenticatorError::Generic(format!("Failed to sign remove authenticator: {e}"))
        })?;

        let req = RemoveAuthenticatorRequest {
            leaf_index,
            authenticator_address,
            old_offchain_signer_commitment: old_commitment,
            new_offchain_signer_commitment: new_commitment,
            signature,
            nonce,
            pubkey_id: Some(index),
            authenticator_pubkey: Some(encoded_old_offchain_pubkey),
        };

        let gateway_resp: GatewayStatusResponse = self
            .gateway_client
            .post_json(self.config.gateway_url(), "/remove-authenticator", &req)
            .await?;
        Ok(gateway_resp.request_id)
    }

    /// Polls the gateway for the current status of a previously submitted request.
    ///
    /// Use the [`GatewayRequestId`] returned by [`insert_authenticator`](Self::insert_authenticator),
    /// [`update_authenticator`](Self::update_authenticator), or
    /// [`remove_authenticator`](Self::remove_authenticator) to track the operation.
    ///
    /// # Errors
    /// - Will error if the network request fails.
    /// - Will error if the gateway returns an error response (e.g. request not found).
    pub async fn poll_status(
        &self,
        request_id: &GatewayRequestId,
    ) -> Result<GatewayRequestState, AuthenticatorError> {
        let path = format!("/status/{request_id}");
        let body: GatewayStatusResponse = self
            .gateway_client
            .get_json(self.config.gateway_url(), &path)
            .await?;
        Ok(body.status)
    }
}
