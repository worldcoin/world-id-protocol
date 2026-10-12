//! Account state and account management operations for the user's World ID: reading the
//! account's registered authenticators, and adding, updating and removing authenticators.
use alloy::primitives::Address;
use eddsa_babyjubjub::EdDSAPublicKey;
use ruint::aliases::U256;

use world_id_primitives::{AuthenticatorPublicKeySet, MAX_AUTHENTICATOR_KEYS};

use crate::{
    api_types::{
        GatewayRequestId, GatewayRequestState, GatewayStatusResponse, InsertAuthenticatorRequest,
        RemoveAuthenticatorRequest, UpdateAuthenticatorRequest,
    },
    authenticator::Authenticator,
    error::AuthenticatorError,
    traits::OnchainKeyRepresentable,
};

use world_id_registries::world_id::{
    domain, sign_insert_authenticator, sign_remove_authenticator, sign_update_authenticator,
};

/// The registered authenticators of an account, read from one indexed account state.
#[derive(Clone, Debug)]
pub struct AccountAuthenticators {
    /// The public keys, by `pubkey_id`.
    pub key_set: AuthenticatorPublicKeySet,
    /// The on-chain addresses, by `pubkey_id`. A removed slot is `None`, as in `key_set`. An
    /// Admin Authenticator (WIP-104) has its management key's address, and a Proving
    /// Authenticator has the zero address.
    pub addresses: Vec<Option<Address>>,
    /// The commitment to `key_set` stored in the `WorldIDRegistry`.
    pub offchain_signer_commitment: U256,
    /// The number of recoveries of the account.
    pub recovery_counter: u64,
}

impl AccountAuthenticators {
    /// Returns the slot and on-chain address of `pubkey`, if it is registered. The address is
    /// zero for a Proving Authenticator.
    #[must_use]
    pub fn find(&self, pubkey: &EdDSAPublicKey) -> Option<(u32, Address)> {
        let slot = self
            .key_set
            .iter()
            .position(|key| key.as_ref().is_some_and(|key| key.pk == pubkey.pk))?;
        let address = self.addresses.get(slot).copied().flatten()?;
        Some((
            u32::try_from(slot).expect("a slot below MAX_AUTHENTICATOR_KEYS fits in u32"),
            address,
        ))
    }

    /// Returns the registry's packed account data for `pubkey` on `leaf_index`: the recovery
    /// counter, the slot and the leaf index. `None` if `pubkey` is not registered.
    #[must_use]
    pub(crate) fn packed_account_data(
        &self,
        leaf_index: u64,
        pubkey: &EdDSAPublicKey,
    ) -> Option<U256> {
        let (pubkey_id, _) = self.find(pubkey)?;
        Some(
            (U256::from(self.recovery_counter) << 224)
                | (U256::from(pubkey_id) << 192)
                | U256::from(leaf_index),
        )
    }
}

/// A view of an account to sign an account operation from. See
/// [`Authenticator::fetch_account_snapshot`].
#[derive(Clone, Debug)]
pub struct AccountSnapshot {
    /// The account the snapshot belongs to.
    pub leaf_index: u64,
    /// The account's signature nonce.
    pub signature_nonce: U256,
    /// The account's registered authenticators.
    pub authenticators: AccountAuthenticators,
    /// The registry's `getMaxAuthenticators()`, or `None` when no RPC is configured.
    pub max_authenticators: Option<usize>,
}

impl AccountSnapshot {
    /// Returns the lowest slot a new authenticator would be inserted at, or `None` if every slot
    /// below the registry's `getMaxAuthenticators()` is taken.
    ///
    /// Slots are also bounded by [`MAX_AUTHENTICATOR_KEYS`], the size of the key set. Without
    /// [`max_authenticators`](Self::max_authenticators), that is the only bound, and the registry
    /// rejects a slot above its limit.
    #[must_use]
    pub fn lowest_free_pubkey_id(&self) -> Option<u32> {
        let key_set = &self.authenticators.key_set;
        let slot = key_set
            .iter()
            .position(Option::is_none)
            .unwrap_or(key_set.len());
        let limit = self
            .max_authenticators
            .map_or(MAX_AUTHENTICATOR_KEYS, |max| {
                max.min(MAX_AUTHENTICATOR_KEYS)
            });
        (slot < limit)
            .then(|| u32::try_from(slot).expect("a slot below MAX_AUTHENTICATOR_KEYS fits in u32"))
    }
}

/// An `InsertAuthenticator` operation accepted by the gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingInsertion {
    /// The gateway request to track the operation with.
    pub request_id: GatewayRequestId,
    /// The slot the authenticator is inserted at once the operation finalizes.
    pub pubkey_id: u32,
}

impl Authenticator {
    /// Inserts a new authenticator to the account.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are HTTP call failures.
    ///
    /// # Note
    /// Inserting another authenticator changes the account's off-chain signer commitment, but does
    /// not change this authenticator's own `packed_account_data`. Indexer-backed account views may
    /// remain stale until the gateway request finalizes and the indexer catches up.
    pub async fn insert_authenticator(
        &self,
        new_authenticator_pubkey: EdDSAPublicKey,
        new_authenticator_address: Address,
    ) -> Result<GatewayRequestId, AuthenticatorError> {
        let nonce = self.signing_nonce().await?;
        let key_set = self.fetch_authenticator_pubkeys().await?;
        let old_offchain_signer_commitment = key_set.leaf_hash().into();
        let insertion = self
            .submit_insert_authenticator(
                nonce,
                old_offchain_signer_commitment,
                key_set,
                new_authenticator_pubkey,
                new_authenticator_address,
            )
            .await?;
        Ok(insertion.request_id)
    }

    /// Fetches the account state needed to sign an account operation.
    ///
    /// The authenticator slots, the off-chain signer commitment and the recovery counter come
    /// from the same indexed account state (the indexer's `/authenticators` endpoint). The
    /// signature nonce is read separately, from the registry when an RPC URL is configured and
    /// from the indexer otherwise. The registry's `getMaxAuthenticators()` is read only when an
    /// RPC URL is configured.
    ///
    /// An operation signed from a stale snapshot cannot land: the registry checks both the nonce
    /// and the old commitment, so it reverts instead.
    ///
    /// # Errors
    /// Returns an error if a network call fails, or if the indexer returns malformed or
    /// inconsistent slots.
    pub async fn fetch_account_snapshot(&self) -> Result<AccountSnapshot, AuthenticatorError> {
        let signature_nonce = self.signing_nonce().await?;
        let authenticators =
            Self::fetch_authenticators_for(self.leaf_index(), &self.config, &self.indexer_client)
                .await?;
        let max_authenticators = match self.registry() {
            Some(registry) => Some(
                registry
                    .getMaxAuthenticators()
                    .call()
                    .await?
                    .saturating_to::<usize>(),
            ),
            None => None,
        };
        Ok(AccountSnapshot {
            leaf_index: self.leaf_index(),
            signature_nonce,
            authenticators,
            max_authenticators,
        })
    }

    /// Inserts a new authenticator into the lowest free slot of `snapshot`, signing the operation
    /// with the snapshot's nonce and off-chain signer commitment.
    ///
    /// `new_authenticator_address` is the new authenticator's management key for an Admin
    /// Authenticator, or the zero address for a Proving Authenticator (WIP-104).
    ///
    /// Returns the gateway request to track and the slot the authenticator is inserted at once
    /// the request finalizes.
    ///
    /// # Errors
    /// - [`AuthenticatorError::InvalidAccountSnapshot`] if the snapshot belongs to another account
    ///   or its commitment does not match its public keys.
    /// - [`AuthenticatorError::MaxAuthenticatorsReached`] if the snapshot has no free slot below
    ///   the registry's limit.
    /// - [`AuthenticatorError::GatewayError`] if the gateway rejects the operation, e.g. because
    ///   the snapshot is stale or the address is already registered.
    /// - Other errors if signing or a network call fails.
    pub async fn insert_authenticator_from_snapshot(
        &self,
        snapshot: &AccountSnapshot,
        new_authenticator_pubkey: EdDSAPublicKey,
        new_authenticator_address: Address,
    ) -> Result<PendingInsertion, AuthenticatorError> {
        if snapshot.leaf_index != self.leaf_index() {
            return Err(AuthenticatorError::InvalidAccountSnapshot(
                "snapshot belongs to a different account",
            ));
        }
        let commitment: U256 = snapshot.authenticators.key_set.leaf_hash().into();
        if snapshot.authenticators.offchain_signer_commitment != commitment {
            return Err(AuthenticatorError::InvalidAccountSnapshot(
                "off-chain signer commitment does not match the public key set",
            ));
        }
        snapshot
            .lowest_free_pubkey_id()
            .ok_or(AuthenticatorError::MaxAuthenticatorsReached)?;
        self.submit_insert_authenticator(
            snapshot.signature_nonce,
            snapshot.authenticators.offchain_signer_commitment,
            snapshot.authenticators.key_set.clone(),
            new_authenticator_pubkey,
            new_authenticator_address,
        )
        .await
    }

    /// Updates an existing authenticator slot with a new authenticator.
    ///
    /// # Errors
    /// Returns an error if the gateway rejects the request or a network error occurs.
    ///
    /// # Note
    /// After this request finalizes on-chain, the current `Authenticator` may become unusable if it
    /// corresponds to the authenticator being updated. Consumers should poll the gateway request and
    /// re-initialize the appropriate authenticator as needed.
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
    /// After this request finalizes on-chain, the current `Authenticator` may become unusable if it
    /// corresponds to the authenticator being removed. Consumers should poll the gateway request and
    /// re-initialize or discard this authenticator as needed.
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

    async fn submit_insert_authenticator(
        &self,
        nonce: U256,
        old_offchain_signer_commitment: U256,
        mut key_set: AuthenticatorPublicKeySet,
        new_authenticator_pubkey: EdDSAPublicKey,
        new_authenticator_address: Address,
    ) -> Result<PendingInsertion, AuthenticatorError> {
        let leaf_index = self.leaf_index();
        let encoded_offchain_pubkey = new_authenticator_pubkey.to_ethereum_representation()?;
        let pubkey_id = key_set
            .insert_or_reuse(new_authenticator_pubkey)
            .map_err(|_| AuthenticatorError::MaxAuthenticatorsReached)?;
        let pubkey_id =
            u32::try_from(pubkey_id).expect("a slot below MAX_AUTHENTICATOR_KEYS fits in u32");
        let new_offchain_signer_commitment = key_set.leaf_hash();

        let eip712_domain = domain(self.config.chain_id(), *self.config.registry_address());

        let signature = sign_insert_authenticator(
            &self.signer.onchain_signer(),
            leaf_index,
            new_authenticator_address,
            pubkey_id,
            encoded_offchain_pubkey,
            new_offchain_signer_commitment.into(),
            nonce,
            &eip712_domain,
        )
        .map_err(|e| {
            AuthenticatorError::Generic(format!("Failed to sign insert authenticator: {e}"))
        })?;

        let req = InsertAuthenticatorRequest {
            leaf_index,
            new_authenticator_address,
            pubkey_id,
            new_authenticator_pubkey: encoded_offchain_pubkey,
            old_offchain_signer_commitment,
            new_offchain_signer_commitment: new_offchain_signer_commitment.into(),
            signature,
            nonce,
        };

        let body: GatewayStatusResponse = self
            .gateway_client
            .post_json(self.config.gateway_url(), "/insert-authenticator", &req)
            .await?;
        Ok(PendingInsertion {
            request_id: body.request_id,
            pubkey_id,
        })
    }
}
