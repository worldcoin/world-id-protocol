//! Account state and account management operations for the user's World ID: reading the
//! account's registered authenticators, and adding, updating and removing authenticators.
use alloy::primitives::Address;
use eddsa_babyjubjub::EdDSAPublicKey;
use ruint::aliases::U256;

use world_id_primitives::{AuthenticatorPublicKeySet, MAX_AUTHENTICATOR_KEYS, PrimitiveError};

use crate::{
    api_types::{
        GatewayRequestId, GatewayRequestState, GatewayStatusResponse,
        IndexerAuthenticatorsResponse, InsertAuthenticatorRequest, RemoveAuthenticatorRequest,
        UpdateAuthenticatorRequest,
    },
    authenticator::{Authenticator, pack_account_data},
    error::AuthenticatorError,
    traits::OnchainKeyRepresentable,
};

use world_id_registries::world_id::{
    domain, sign_insert_authenticator, sign_remove_authenticator, sign_update_authenticator,
};

/// The `WorldIDRegistry`'s `MAX_AUTHENTICATORS_HARD_LIMIT`: no account has a slot at or above it.
const MAX_AUTHENTICATORS_HARD_LIMIT: usize = 96;

/// The registered authenticators of an account, read from one indexed account state.
///
/// Parsed from the indexer's `/authenticators` response with [`TryFrom`]: every slot has both a
/// public key and an address, or neither, the off-chain signer commitment is the commitment to the
/// public keys, and the recovery counter fits the registry's 32 bits. Removed slots after the last
/// registered one are dropped, so the addresses are as many as the public keys.
#[derive(Clone, Debug)]
pub struct AccountAuthenticators {
    key_set: AuthenticatorPublicKeySet,
    addresses: Vec<Option<Address>>,
    offchain_signer_commitment: U256,
    recovery_counter: u32,
}

impl AccountAuthenticators {
    /// Returns the public keys, by `pubkey_id`.
    #[must_use]
    pub const fn key_set(&self) -> &AuthenticatorPublicKeySet {
        &self.key_set
    }

    /// Returns the on-chain addresses, by `pubkey_id`. A removed slot is `None`, as in
    /// [`key_set`](Self::key_set). An Admin Authenticator (WIP-104) has its management key's
    /// address, and a Proving Authenticator has the zero address.
    #[must_use]
    pub fn addresses(&self) -> &[Option<Address>] {
        &self.addresses
    }

    /// Returns the off-chain signer commitment stored in the `WorldIDRegistry`: the commitment to
    /// [`key_set`](Self::key_set).
    #[must_use]
    pub const fn offchain_signer_commitment(&self) -> U256 {
        self.offchain_signer_commitment
    }

    /// Returns the number of recoveries of the account.
    #[must_use]
    pub const fn recovery_counter(&self) -> u32 {
        self.recovery_counter
    }

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

    /// Returns the lowest slot a new authenticator would take: a removed slot, or the slot after
    /// the last key. `None` if the key set is full.
    ///
    /// The registry may allow fewer slots than the key set holds;
    /// [`Authenticator::insert_authenticator_at`] checks that limit.
    #[must_use]
    pub fn lowest_free_pubkey_id(&self) -> Option<u32> {
        lowest_free_slot(&self.key_set)
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
        Some(pack_account_data(
            self.recovery_counter,
            pubkey_id,
            leaf_index,
        ))
    }
}

impl TryFrom<IndexerAuthenticatorsResponse> for AccountAuthenticators {
    type Error = AuthenticatorError;

    /// Parses the indexer's `/authenticators` response.
    ///
    /// # Errors
    /// - [`AuthenticatorError::PrimitiveError`] if the response has different numbers of
    ///   addresses and public keys, more slots than the registry allows, a slot with only an
    ///   address or only a public key, a recovery counter above 32 bits, an invalid public key,
    ///   or a commitment that does not match the public keys. Such an account state cannot be
    ///   signed from or proven with.
    /// - [`AuthenticatorError::InvalidIndexerPubkeySlot`] if a public key is registered at a
    ///   slot beyond [`MAX_AUTHENTICATOR_KEYS`].
    fn try_from(response: IndexerAuthenticatorsResponse) -> Result<Self, Self::Error> {
        let IndexerAuthenticatorsResponse {
            authenticator_pubkeys,
            authenticator_addresses,
            offchain_signer_commitment,
            recovery_counter,
        } = response;
        if authenticator_addresses.len() != authenticator_pubkeys.len() {
            return Err(invalid_response(
                "different numbers of authenticator addresses and pubkeys",
            ));
        }
        if authenticator_pubkeys.len() > MAX_AUTHENTICATORS_HARD_LIMIT {
            return Err(invalid_response(
                "more authenticator slots than the registry allows",
            ));
        }
        if authenticator_addresses
            .iter()
            .zip(&authenticator_pubkeys)
            .any(|(address, pubkey)| address.is_some() != pubkey.is_some())
        {
            return Err(invalid_response(
                "an authenticator slot with only an address or a pubkey",
            ));
        }
        let recovery_counter = u32::try_from(recovery_counter)
            .map_err(|_| invalid_response("a recovery counter above 32 bits"))?;
        let key_set = Authenticator::decode_indexer_pubkeys(authenticator_pubkeys)?;
        let commitment: U256 = key_set.leaf_hash().into();
        if offchain_signer_commitment != commitment {
            return Err(invalid_response(
                "an off-chain signer commitment that does not match the pubkeys",
            ));
        }
        let mut addresses = authenticator_addresses;
        addresses.truncate(key_set.len());
        Ok(Self {
            key_set,
            addresses,
            offchain_signer_commitment,
            recovery_counter,
        })
    }
}

impl Authenticator {
    /// Inserts a new authenticator to the account, at the lowest free slot of its current key set.
    ///
    /// # Errors
    /// - [`AuthenticatorError::MaxAuthenticatorsReached`] if the key set has no free slot.
    /// - Other errors if the provided RPC URL is not valid or if there are HTTP call failures.
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
        let key_set = self.fetch_authenticator_pubkeys().await?;
        let pubkey_id =
            lowest_free_slot(&key_set).ok_or(AuthenticatorError::MaxAuthenticatorsReached)?;
        self.insert_authenticator_at(
            &key_set,
            pubkey_id,
            new_authenticator_pubkey,
            new_authenticator_address,
        )
        .await
    }

    /// Inserts a new authenticator at `pubkey_id`, signing the change from `key_set`, the
    /// account's current key set.
    ///
    /// Use it to insert into a key set the caller has already checked, e.g. one from
    /// [`Authenticator::fetch_authenticators`]. If `key_set` is stale, the registry rejects the
    /// operation, because it checks the old off-chain signer commitment.
    ///
    /// `pubkey_id` must be free in `key_set`: a removed slot, or the slot after the last key.
    /// `new_authenticator_address` is the new authenticator's management key for an Admin
    /// Authenticator, or the zero address for a Proving Authenticator (WIP-104).
    ///
    /// Returns the gateway request to track the operation with.
    ///
    /// # Errors
    /// - [`AuthenticatorError::MaxAuthenticatorsReached`] if `pubkey_id` is not below the
    ///   registry's `getMaxAuthenticators()`. The limit is read only when an RPC URL is
    ///   configured.
    /// - [`AuthenticatorError::PrimitiveError`] if `pubkey_id` is taken or past the slot after
    ///   the last key.
    /// - [`AuthenticatorError::GatewayError`] if the gateway rejects the operation, e.g. because
    ///   `key_set` is stale or the address is already registered.
    /// - Other errors if signing or a network call fails.
    pub async fn insert_authenticator_at(
        &self,
        key_set: &AuthenticatorPublicKeySet,
        pubkey_id: u32,
        new_authenticator_pubkey: EdDSAPublicKey,
        new_authenticator_address: Address,
    ) -> Result<GatewayRequestId, AuthenticatorError> {
        let slot = pubkey_id as usize;
        if key_set.get(slot).is_some() {
            return Err(PrimitiveError::InvalidInput {
                attribute: "pubkey_id".to_string(),
                reason: format!("slot {pubkey_id} is taken"),
            }
            .into());
        }
        let encoded_offchain_pubkey = new_authenticator_pubkey.to_ethereum_representation()?;
        let old_offchain_signer_commitment = key_set.leaf_hash();
        let mut new_key_set = key_set.clone();
        if slot == new_key_set.len() {
            new_key_set.try_push(new_authenticator_pubkey)?;
        } else {
            new_key_set.try_set_at_index(slot, new_authenticator_pubkey)?;
        }
        let new_offchain_signer_commitment = new_key_set.leaf_hash();

        if let Some(registry) = self.registry() {
            let max_authenticators = registry.getMaxAuthenticators().call().await?;
            if U256::from(pubkey_id) >= max_authenticators {
                return Err(AuthenticatorError::MaxAuthenticatorsReached);
            }
        }
        let leaf_index = self.leaf_index();
        let nonce = self.signing_nonce().await?;

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
}

/// Returns the lowest slot of `key_set` a new key would take, a removed slot or the slot after
/// the last key, or `None` if the key set is full.
fn lowest_free_slot(key_set: &AuthenticatorPublicKeySet) -> Option<u32> {
    let slot = key_set
        .iter()
        .position(Option::is_none)
        .unwrap_or(key_set.len());
    (slot < MAX_AUTHENTICATOR_KEYS)
        .then(|| u32::try_from(slot).expect("a slot below MAX_AUTHENTICATOR_KEYS fits in u32"))
}

/// An error for an `/authenticators` response that does not describe a valid account state.
fn invalid_response(reason: &str) -> AuthenticatorError {
    PrimitiveError::Deserialization(format!("indexer returned {reason}")).into()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy::primitives::address;
    use taceo_oprf::client::Connector;
    use test_case::test_case;
    use world_id_primitives::{Config, ServiceEndpoint, Signer};

    use super::*;
    use crate::service_client::{ServiceClient, ServiceKind};

    const ADMIN: Address = address!("0x0000000000000000000000000000000000000011");
    const LEAF_INDEX: u64 = 42;

    fn pubkey(seed: u8) -> EdDSAPublicKey {
        Signer::from_seed_bytes(&[seed; 32])
            .unwrap()
            .offchain_signer_pubkey()
    }

    fn encoded_pubkey(seed: u8) -> U256 {
        pubkey(seed).to_ethereum_representation().unwrap()
    }

    /// An `/authenticators` response with the key derived from each slot's seed, the slot's
    /// address, and the commitment to those keys.
    fn response(slots: &[Option<(u8, Address)>]) -> IndexerAuthenticatorsResponse {
        let pubkeys: Vec<_> = slots
            .iter()
            .map(|slot| slot.map(|(seed, _)| encoded_pubkey(seed)))
            .collect();
        let key_set =
            AuthenticatorPublicKeySet::from_sparse_encoded_pubkeys(pubkeys.clone()).unwrap();
        IndexerAuthenticatorsResponse {
            authenticator_pubkeys: pubkeys,
            authenticator_addresses: slots
                .iter()
                .map(|slot| slot.map(|(_, address)| address))
                .collect(),
            offchain_signer_commitment: key_set.leaf_hash().into(),
            recovery_counter: 3,
        }
    }

    fn authenticators(slots: &[Option<(u8, Address)>]) -> AccountAuthenticators {
        response(slots).try_into().unwrap()
    }

    #[test]
    fn parses_each_slot_with_its_address() {
        let authenticators = authenticators(&[Some((1, ADMIN)), None, Some((2, Address::ZERO))]);

        assert_eq!(
            authenticators.addresses(),
            [Some(ADMIN), None, Some(Address::ZERO)]
        );
        assert_eq!(authenticators.recovery_counter(), 3);
        assert_eq!(authenticators.find(&pubkey(1)), Some((0, ADMIN)));
        assert_eq!(authenticators.find(&pubkey(2)), Some((2, Address::ZERO)));
        assert_eq!(authenticators.find(&pubkey(3)), None);
    }

    #[test_case(vec![Some(ADMIN)], vec![Some(encoded_pubkey(1)), None]; "more pubkeys than addresses")]
    #[test_case(vec![None], vec![Some(encoded_pubkey(1))]; "a pubkey without an address")]
    #[test_case(vec![Some(ADMIN)], vec![None]; "an address without a pubkey")]
    fn rejects_unpaired_slots(addresses: Vec<Option<Address>>, pubkeys: Vec<Option<U256>>) {
        let response = IndexerAuthenticatorsResponse {
            authenticator_addresses: addresses,
            authenticator_pubkeys: pubkeys,
            ..response(&[])
        };

        assert!(matches!(
            AccountAuthenticators::try_from(response),
            Err(AuthenticatorError::PrimitiveError(
                PrimitiveError::Deserialization(_)
            ))
        ));
    }

    #[test_case(u64::from(u32::MAX) => true; "the largest 32-bit counter")]
    #[test_case(u64::from(u32::MAX) + 1 => false; "a counter above 32 bits")]
    fn accepts_only_32_bit_recovery_counters(recovery_counter: u64) -> bool {
        let response = IndexerAuthenticatorsResponse {
            recovery_counter,
            ..response(&[Some((1, ADMIN))])
        };

        AccountAuthenticators::try_from(response).is_ok()
    }

    #[test]
    fn drops_removed_slots_after_the_last_key() {
        let authenticators = authenticators(&[Some((1, ADMIN)), None, None]);

        assert_eq!(authenticators.key_set().len(), 1);
        assert_eq!(authenticators.addresses(), [Some(ADMIN)]);
    }

    #[test_case(MAX_AUTHENTICATORS_HARD_LIMIT => true; "as many slots as the registry allows")]
    #[test_case(MAX_AUTHENTICATORS_HARD_LIMIT + 1 => false; "more slots than the registry allows")]
    fn accepts_at_most_the_registrys_slots(slots: usize) -> bool {
        let mut response = response(&[Some((1, ADMIN))]);
        response.authenticator_pubkeys.resize(slots, None);
        response.authenticator_addresses.resize(slots, None);

        AccountAuthenticators::try_from(response).is_ok()
    }

    #[test]
    fn rejects_a_commitment_that_does_not_match_the_pubkeys() {
        let consistent = response(&[Some((1, ADMIN))]);
        let response = IndexerAuthenticatorsResponse {
            offchain_signer_commitment: consistent.offchain_signer_commitment ^ U256::from(1),
            ..consistent
        };

        assert!(matches!(
            AccountAuthenticators::try_from(response),
            Err(AuthenticatorError::PrimitiveError(
                PrimitiveError::Deserialization(_)
            ))
        ));
    }

    #[test_case(&[] => Some(0); "an empty account")]
    #[test_case(&[Some(1)] => Some(1); "the slot after the last key")]
    #[test_case(&[Some(1), None, Some(2)] => Some(1); "a removed slot")]
    #[test_case(&[Some(1), Some(2), Some(3), Some(4), Some(5), Some(6), Some(7)] => None; "a full key set")]
    fn lowest_free_pubkey_id(key_seeds: &[Option<u8>]) -> Option<u32> {
        let slots: Vec<_> = key_seeds
            .iter()
            .map(|seed| seed.map(|seed| (seed, Address::ZERO)))
            .collect();
        authenticators(&slots).lowest_free_pubkey_id()
    }

    /// An Admin Authenticator of the account at `leaf_index` whose gateway is `server`.
    fn admin_authenticator(server: &mockito::ServerGuard, leaf_index: u64) -> Authenticator {
        let config = Config::new(
            None,
            1,
            address!("0x0000000000000000000000000000000000000001"),
            ServiceEndpoint::direct(server.url()),
            ServiceEndpoint::direct(server.url()),
            Vec::new(),
            2,
        )
        .unwrap();
        let http_client = reqwest::Client::new();
        Authenticator {
            indexer_client: ServiceClient::new(
                http_client.clone(),
                ServiceKind::Indexer,
                config.indexer(),
            )
            .unwrap(),
            gateway_client: ServiceClient::new(http_client, ServiceKind::Gateway, config.gateway())
                .unwrap(),
            config,
            packed_account_data: U256::from(leaf_index),
            signer: Signer::from_seed_bytes(&[1; 32]).unwrap(),
            registry: None,
            ws_connector: Connector::Plain,
            zk_artifact_source: Arc::new(world_id_proof::artifacts::dummy::DummyZkArtifactSource),
        }
    }

    /// Answers the indexer's `/signature-nonce` with 7.
    async fn mock_signature_nonce(server: &mut mockito::ServerGuard) -> mockito::Mock {
        server
            .mock("POST", "/signature-nonce")
            .with_header("content-type", "application/json")
            .with_body(serde_json::json!({ "signature_nonce": "0x7" }).to_string())
            .create_async()
            .await
    }

    #[test_case(&[Some(1)], 1, &[Some(1), Some(2)]; "after the last key")]
    #[test_case(&[Some(1), None, Some(3)], 1, &[Some(1), Some(2), Some(3)]; "into a removed slot")]
    #[tokio::test]
    async fn insertion_signs_the_new_key_set_with_the_old_commitment(
        key_seeds: &[Option<u8>],
        pubkey_id: u32,
        new_key_seeds: &[Option<u8>],
    ) {
        let mut server = mockito::Server::new_async().await;
        let authenticator = admin_authenticator(&server, LEAF_INDEX);
        let slots: Vec<_> = key_seeds
            .iter()
            .map(|seed| seed.map(|seed| (seed, ADMIN)))
            .collect();
        let authenticators = authenticators(&slots);
        let new_commitment: U256 = AuthenticatorPublicKeySet::from_sparse_encoded_pubkeys(
            new_key_seeds
                .iter()
                .map(|seed| seed.map(encoded_pubkey))
                .collect(),
        )
        .unwrap()
        .leaf_hash()
        .into();
        let _nonce = mock_signature_nonce(&mut server).await;
        let submission = server
            .mock("POST", "/insert-authenticator")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "leaf_index": "0x2a",
                "pubkey_id": format!("{pubkey_id:#x}"),
                "new_authenticator_address": Address::ZERO,
                "new_authenticator_pubkey": format!("{:#x}", encoded_pubkey(2)),
                "old_offchain_signer_commitment":
                    format!("{:#x}", authenticators.offchain_signer_commitment()),
                "new_offchain_signer_commitment": format!("{new_commitment:#x}"),
                "nonce": "0x7",
            })))
            .with_status(202)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "request_id": "insert-at",
                    "kind": "insert_authenticator",
                    "status": { "state": "queued" },
                })
                .to_string(),
            )
            .create_async()
            .await;

        let request_id = authenticator
            .insert_authenticator_at(
                authenticators.key_set(),
                pubkey_id,
                pubkey(2),
                Address::ZERO,
            )
            .await
            .unwrap();

        assert_eq!(request_id.as_str(), "insert-at");
        submission.assert_async().await;
    }

    #[test_case(0; "a taken slot")]
    #[test_case(2; "a slot past the one after the last key")]
    #[tokio::test]
    async fn insertion_refuses_a_slot_that_is_not_free_without_submitting(pubkey_id: u32) {
        let mut server = mockito::Server::new_async().await;
        let authenticator = admin_authenticator(&server, LEAF_INDEX);
        let no_submission = server
            .mock("POST", "/insert-authenticator")
            .expect(0)
            .create_async()
            .await;

        let result = authenticator
            .insert_authenticator_at(
                authenticators(&[Some((1, ADMIN))]).key_set(),
                pubkey_id,
                pubkey(2),
                Address::ZERO,
            )
            .await;

        assert!(matches!(result, Err(AuthenticatorError::PrimitiveError(_))));
        no_submission.assert_async().await;
    }
}
