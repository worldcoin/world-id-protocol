//! This module contains all the base functionality to support Authenticators in World ID.
//!
//! An Authenticator is the application layer with which a user interacts with the Protocol.
use std::sync::Arc;
use std::time::Duration;

use crate::account_registry::AccountRegistry::{self, AccountRegistryInstance};
use crate::account_registry::{
    domain, sign_insert_authenticator, sign_remove_authenticator, sign_update_authenticator,
};
use crate::types::{
    AccountInclusionProof, CreateAccountRequest, GatewayRequestState, GatewayStatusResponse,
    InsertAuthenticatorRequest, RemoveAuthenticatorRequest, RpRequest, UpdateAuthenticatorRequest,
};
use crate::{Credential, FieldElement, Signer};
use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::uint;
use ark_babyjubjub::EdwardsAffine;
use ark_ff::AdditiveGroup;
use ark_serialize::CanonicalSerialize;
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use oprf_types::ShareEpoch;
use oprf_zk::{groth16_serde::Groth16Proof, Groth16Material};
use poseidon2::Poseidon2;
use secrecy::ExposeSecret;
use std::str::FromStr;
use world_id_primitives::authenticator::AuthenticatorPublicKeySet;
use world_id_primitives::merkle::MerkleInclusionProof;
use world_id_primitives::proof::SingleProofInput;
use world_id_primitives::PrimitiveError;
pub use world_id_primitives::{authenticator::ProtocolSigner, Config, TREE_DEPTH};

static MASK_RECOVERY_COUNTER: U256 =
    uint!(0xFFFFFFFF00000000000000000000000000000000000000000000000000000000_U256);
static MASK_PUBKEY_ID: U256 =
    uint!(0x00000000FFFFFFFF000000000000000000000000000000000000000000000000_U256);
static MASK_ACCOUNT_INDEX: U256 =
    uint!(0x0000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_U256);

static QUERY_ZKEY_PATH: &str = "circom/query.zkey";
static QUERY_GRAPH_PATH: &str = "circom/query_graph.bin";
static NULLIFIER_ZKEY_PATH: &str = "circom/nullifier.zkey";
static NULLIFIER_GRAPH_PATH: &str = "circom/nullifier_graph.bin";

/// Maximum timeout for polling account creation status (30 seconds)
const MAX_POLL_TIMEOUT_SECS: u64 = 30;

type UniquenessProof = (Groth16Proof, FieldElement);

/// An Authenticator is the base layer with which a user interacts with the Protocol.
#[derive(Debug)]
pub struct Authenticator {
    /// General configuration for the Authenticator.
    pub config: Config,
    /// The packed account index for the holder's World ID is a `uint256` defined in the `AccountRegistry` contract as:
    /// `recovery_counter` (32 bits) | `pubkey_id` (commitment to all off-chain public keys) (32 bits) | `account_index` (192 bits)
    pub packed_account_index: U256,
    signer: Signer,
    registry: Arc<AccountRegistryInstance<DynProvider>>,
    provider: DynProvider,
}

impl Authenticator {
    /// Initialize an Authenticator from a seed and config.
    ///
    /// This method will error if the World ID account does not exist on the registry.
    ///
    /// # Errors
    /// - Will error if the provided seed is invalid (not 32 bytes).
    /// - Will error if the RPC URL is invalid.
    /// - Will error if there are contract call failures.
    /// - Will error if the account does not exist (`AccountDoesNotExist`).
    pub async fn init(seed: &[u8], config: Config) -> Result<Self, AuthenticatorError> {
        let signer = Signer::from_seed_bytes(seed)?;
        let provider =
            ProviderBuilder::new().connect_http(config.rpc_url().parse().map_err(|e| {
                PrimitiveError::InvalidInput {
                    attribute: "RPC URL".to_string(),
                    reason: format!("invalid URL: {e}"),
                }
            })?);

        let registry = AccountRegistry::new(*config.registry_address(), provider.clone().erased());
        let packed_account_index =
            Self::get_packed_account_index(signer.onchain_signer_address(), &registry).await?;

        Ok(Self {
            packed_account_index,
            signer,
            config,
            registry: Arc::new(registry),
            provider: provider.erased(),
        })
    }

    /// Initialize an Authenticator from a seed and config, creating the account if it doesn't exist.
    ///
    /// If the account does not exist, it will automatically create it. Since account creation
    /// is asynchronous (requires on-chain transaction confirmation), this method will return `None`
    /// and you should poll.
    ///
    /// # Errors
    /// - See `init` for additional error details.
    pub async fn init_or_create(
        seed: &[u8],
        config: Config,
        recovery_address: Option<Address>,
    ) -> Result<Option<Self>, AuthenticatorError> {
        // First try to initialize normally
        match Self::init(seed, config.clone()).await {
            Ok(authenticator) => Ok(Some(authenticator)),
            Err(AuthenticatorError::AccountDoesNotExist) => {
                Self::create_account(seed, &config, recovery_address).await?;
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Initialize an Authenticator from a seed and config, creating the account if it doesn't exist
    /// and blocking until the account is confirmed on-chain.
    ///
    /// # Errors
    /// - Will error with `Timeout` if account creation takes longer than 30 seconds.
    /// - Will error if the gateway reports the account creation as failed.
    /// - See `init` for additional error details.
    pub async fn init_or_create_blocking(
        seed: &[u8],
        config: Config,
        recovery_address: Option<Address>,
    ) -> Result<Self, AuthenticatorError> {
        match Self::init(seed, config.clone()).await {
            Ok(authenticator) => return Ok(authenticator),
            Err(AuthenticatorError::AccountDoesNotExist) => {
                // Account doesn't exist, create it and poll for confirmation
            }
            Err(e) => return Err(e),
        }

        // Create the account and get the request ID
        let request_id = Self::create_account(seed, &config, recovery_address).await?;

        // Poll for confirmation with exponential backoff
        let start = std::time::Instant::now();
        let mut delay_ms = 100u64; // Start with 100ms

        loop {
            // Check if we've exceeded the timeout
            if start.elapsed().as_secs() >= MAX_POLL_TIMEOUT_SECS {
                return Err(AuthenticatorError::Timeout(MAX_POLL_TIMEOUT_SECS));
            }

            // Wait before polling
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;

            // Poll the gateway status
            match Self::poll_gateway_status(&config, &request_id).await {
                Ok(GatewayRequestState::Finalized { .. }) => {
                    return Self::init(seed, config).await;
                }
                Ok(GatewayRequestState::Failed { error }) => {
                    return Err(AuthenticatorError::Generic(format!(
                        "Account creation failed: {error}"
                    )));
                }
                Ok(_) => {
                    // Still pending, continue polling with exponential backoff
                    delay_ms = (delay_ms * 2).min(5000); // Cap at 5 seconds
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Poll the gateway for the status of a request.
    ///
    /// # Errors
    /// - Will error if the network request fails.
    /// - Will error if the gateway returns an error response.
    async fn poll_gateway_status(
        config: &Config,
        request_id: &str,
    ) -> Result<GatewayRequestState, AuthenticatorError> {
        let resp = reqwest::Client::new()
            .get(format!("{}/status/{}", config.gateway_url(), request_id))
            .send()
            .await?;

        let status = resp.status();

        if status.is_success() {
            let body: GatewayStatusResponse = resp.json().await?;
            Ok(body.status)
        } else {
            let body_text = resp.text().await.unwrap_or_else(|_| String::new());
            Err(AuthenticatorError::GatewayError {
                status: status.as_u16(),
                body: body_text,
            })
        }
    }

    /// Returns the packed account index for the holder's World ID.
    ///
    /// The packed account index is a 256 bit integer which includes the user's account index, their recovery counter,
    /// and their pubkey id/commitment.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are RPC call failures.
    pub async fn get_packed_account_index(
        onchain_signer_address: Address,
        registry: &AccountRegistryInstance<DynProvider>,
    ) -> Result<U256, AuthenticatorError> {
        let raw_index = registry
            .authenticatorAddressToPackedAccountIndex(onchain_signer_address)
            .call()
            .await?;

        if raw_index == U256::ZERO {
            return Err(AuthenticatorError::AccountDoesNotExist);
        }

        Ok(raw_index)
    }

    /// Returns the k256 public key of the Authenticator signer which is used to verify on-chain operations,
    /// chiefly with the `AccountRegistry` contract.
    #[must_use]
    pub const fn onchain_address(&self) -> Address {
        self.signer.onchain_signer_address()
    }

    /// Returns the `EdDSA` public key of the Authenticator signer which is used to verify off-chain operations. For example,
    /// the Nullifier Oracle uses it to verify requests for nullifiers.
    #[must_use]
    pub fn offchain_pubkey(&self) -> EdDSAPublicKey {
        self.signer.offchain_signer_pubkey()
    }

    /// Returns the compressed `EdDSA` public key of the Authenticator signer which is used to verify off-chain operations.
    /// For example, the Nullifier Oracle uses it to verify requests for nullifiers.
    /// # Errors
    /// Will error if the public key cannot be serialized.
    pub fn offchain_pubkey_compressed(&self) -> Result<U256, AuthenticatorError> {
        let pk = self.signer.offchain_signer_pubkey().pk;
        let mut compressed_bytes = Vec::new();
        pk.serialize_compressed(&mut compressed_bytes)
            .map_err(|e| PrimitiveError::Serialization(e.to_string()))?;
        Ok(U256::from_le_slice(&compressed_bytes))
    }

    /// Returns a reference to the `AccountRegistry` contract instance.
    #[must_use]
    pub fn registry(&self) -> Arc<AccountRegistryInstance<DynProvider>> {
        Arc::clone(&self.registry)
    }

    /// Returns a reference to the Ethereum provider.
    #[must_use]
    pub fn provider(&self) -> DynProvider {
        self.provider.clone()
    }

    /// Returns the account index for the holder's World ID.
    ///
    /// This is the index at the tree where the holder's World ID account is registered (1-indexed).
    #[must_use]
    pub fn account_id(&self) -> U256 {
        self.packed_account_index & MASK_ACCOUNT_INDEX
    }

    /// Returns the raw index at the tree where the holder's World ID account is registered.
    #[must_use]
    pub fn raw_tree_index(&self) -> U256 {
        self.account_id() - U256::from(1)
    }

    /// Returns the recovery counter for the holder's World ID.
    ///
    /// The recovery counter is used to efficiently invalidate all the old keys when an account is recovered.
    #[must_use]
    pub fn recovery_counter(&self) -> U256 {
        let recovery_counter = self.packed_account_index & MASK_RECOVERY_COUNTER;
        recovery_counter >> 224
    }

    /// Returns the pubkey id (or commitment) for the holder's World ID.
    ///
    /// This is a commitment to all the off-chain public keys that are authorized to act on behalf of the holder.
    #[must_use]
    pub fn pubkey_id(&self) -> U256 {
        let pubkey_id = self.packed_account_index & MASK_PUBKEY_ID;
        pubkey_id >> 192
    }

    /// Fetches a Merkle inclusion proof for the holder's World ID given their account index.
    ///
    /// # Errors
    /// - Will error if the provided indexer URL is not valid or if there are HTTP call failures.
    /// - Will error if the user is not registered on the registry.
    pub async fn fetch_inclusion_proof(
        &self,
    ) -> Result<(MerkleInclusionProof<TREE_DEPTH>, AuthenticatorPublicKeySet), AuthenticatorError>
    {
        let url = format!("{}/proof/{}", self.config.indexer_url(), self.account_id());
        let response = reqwest::get(url).await?;
        let response = response.json::<AccountInclusionProof<TREE_DEPTH>>().await?;

        Ok((response.proof, response.authenticator_pubkeys))
    }

    /// Returns the signing nonce for the holder's World ID.
    ///
    /// # Errors
    /// Will return an error if the registry contract call fails.
    pub async fn signing_nonce(&self) -> Result<U256, AuthenticatorError> {
        let registry = self.registry();
        let nonce = registry.signatureNonces(self.account_id()).call().await?;
        Ok(nonce)
    }

    /// Generates a World ID Uniqueness Proof given a provided context.
    ///
    /// # Errors
    /// - Will error if the any of the provided parameters are not valid.
    /// - Will error if any of the required network requests fail.
    /// - Will error if the user does not have a registered World ID.
    #[allow(clippy::future_not_send)]
    pub async fn generate_proof(
        &self,
        message_hash: FieldElement,
        rp_request: RpRequest,
        credential: Credential,
    ) -> Result<UniquenessProof, AuthenticatorError> {
        let (inclusion_proof, key_set) = self.fetch_inclusion_proof().await?;
        let key_index = key_set
            .iter()
            .position(|pk| pk.pk == self.offchain_pubkey().pk)
            .ok_or(AuthenticatorError::PublicKeyNotFound)? as u64;

        // TODO: load once and from bytes
        let query_material = Groth16Material::new(QUERY_ZKEY_PATH, None, QUERY_GRAPH_PATH)
            .map_err(|e| {
                AuthenticatorError::Generic(format!("Failed to load query material: {e}"))
            })?;
        let nullifier_material =
            Groth16Material::new(NULLIFIER_ZKEY_PATH, None, NULLIFIER_GRAPH_PATH).map_err(|e| {
                AuthenticatorError::Generic(format!("Failed to load nullifier material: {e}"))
            })?;

        // TODO: convert rp_request to primitives types
        let primitives_rp_id =
            world_id_primitives::rp::RpId::new(rp_request.rp_id.parse::<u128>().map_err(|e| {
                PrimitiveError::InvalidInput {
                    attribute: "RP ID".to_string(),
                    reason: format!("invalid RP ID: {e}"),
                }
            })?);
        let primitives_rp_nullifier_key =
            world_id_primitives::rp::RpNullifierKey::new(rp_request.rp_nullifier_key.inner());

        let args = SingleProofInput::<TREE_DEPTH> {
            credential,
            inclusion_proof,
            key_set,
            key_index,
            rp_session_id_r_seed: FieldElement::ZERO, // FIXME: expose properly (was id_commitment_r)
            rp_id: primitives_rp_id,
            share_epoch: ShareEpoch::default().into_inner(), // TODO
            action: rp_request.action_id,
            nonce: rp_request.nonce,
            current_timestamp: rp_request.current_time_stamp, // TODO
            rp_signature: rp_request.signature,
            rp_nullifier_key: primitives_rp_nullifier_key,
            signal_hash: message_hash,
        };

        let private_key = self.signer.offchain_signer_private_key().expose_secret();

        let mut rng = rand::thread_rng();
        let (proof, _public, nullifier, _id_commitment) = oprf_client::nullifier(
            self.config.nullifier_oracle_urls(),
            2,
            &query_material,
            &nullifier_material,
            args,
            private_key,
            &mut rng,
        )
        .await
        .map_err(|e| AuthenticatorError::Generic(format!("Failed to generate nullifier: {e}")))?;

        Ok((proof, nullifier.into()))
    }

    /// Inserts a new authenticator to the account.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are HTTP call failures.
    ///
    /// # Note
    /// TODO: After successfully inserting an authenticator, the `packed_account_index` should be
    /// refreshed from the registry to reflect the new `pubkey_id` commitment.
    pub async fn insert_authenticator(
        &mut self,
        new_authenticator_pubkey: EdDSAPublicKey,
        new_authenticator_address: Address,
    ) -> Result<String, AuthenticatorError> {
        let account_id = self.account_id();
        let nonce = self.signing_nonce().await?;
        let (inclusion_proof, mut key_set) = self.fetch_inclusion_proof().await?;
        let old_offchain_signer_commitment = Self::leaf_hash(&key_set);
        key_set.try_push(new_authenticator_pubkey.clone())?;
        let index = key_set.len() - 1;
        let new_offchain_signer_commitment = Self::leaf_hash(&key_set);

        let encoded_offchain_pubkey = new_authenticator_pubkey.to_ethereum_representation()?;

        let eip712_domain = domain(
            self.provider()
                .get_chain_id()
                .await
                .map_err(|e| AuthenticatorError::Generic(format!("Failed to get chain ID: {e}")))?,
            *self.config.registry_address(),
        );

        let signature = sign_insert_authenticator(
            &self.signer.onchain_signer(),
            account_id,
            new_authenticator_address,
            U256::from(index),
            encoded_offchain_pubkey,
            new_offchain_signer_commitment.into(),
            nonce,
            &eip712_domain,
        )
        .await
        .map_err(|e| {
            AuthenticatorError::Generic(format!("Failed to sign insert authenticator: {e}"))
        })?;

        let req = InsertAuthenticatorRequest {
            account_index: account_id,
            new_authenticator_address,
            pubkey_id: U256::from(index),
            new_authenticator_pubkey: encoded_offchain_pubkey,
            old_offchain_signer_commitment: old_offchain_signer_commitment.into(),
            new_offchain_signer_commitment: new_offchain_signer_commitment.into(),
            sibling_nodes: inclusion_proof
                .siblings
                .iter()
                .map(|s| (*s).into())
                .collect(),
            signature: signature.as_bytes().to_vec(),
            nonce,
        };

        let resp = reqwest::Client::new()
            .post(format!(
                "{}/insert-authenticator",
                self.config.gateway_url()
            ))
            .json(&req)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            let body: GatewayStatusResponse = resp.json().await?;
            Ok(body.request_id)
        } else {
            let body_text = resp.text().await.unwrap_or_else(|_| String::new());
            Err(AuthenticatorError::GatewayError {
                status: status.as_u16(),
                body: body_text,
            })
        }
    }

    /// Updates an existing authenticator slot with a new authenticator.
    ///
    /// # Errors
    /// Returns an error if the gateway rejects the request or a network error occurs.
    ///
    /// # Note
    /// TODO: After successfully updating an authenticator, the `packed_account_index` should be
    /// refreshed from the registry to reflect the new `pubkey_id` commitment.
    pub async fn update_authenticator(
        &mut self,
        old_authenticator_address: Address,
        new_authenticator_address: Address,
        new_authenticator_pubkey: EdDSAPublicKey,
        index: u32,
    ) -> Result<String, AuthenticatorError> {
        let account_id = self.account_id();
        let nonce = self.signing_nonce().await?;
        let (inclusion_proof, mut key_set) = self.fetch_inclusion_proof().await?;
        let old_commitment: U256 = Self::leaf_hash(&key_set).into();
        key_set.try_set_at_index(index as usize, new_authenticator_pubkey.clone())?;
        let new_commitment: U256 = Self::leaf_hash(&key_set).into();

        let encoded_offchain_pubkey = new_authenticator_pubkey.to_ethereum_representation()?;

        let eip712_domain = domain(
            self.provider()
                .get_chain_id()
                .await
                .map_err(|e| AuthenticatorError::Generic(format!("Failed to get chain ID: {e}")))?,
            *self.config.registry_address(),
        );

        let signature = sign_update_authenticator(
            &self.signer.onchain_signer(),
            account_id,
            old_authenticator_address,
            new_authenticator_address,
            U256::from(index),
            encoded_offchain_pubkey,
            new_commitment,
            nonce,
            &eip712_domain,
        )
        .await
        .map_err(|e| {
            AuthenticatorError::Generic(format!("Failed to sign update authenticator: {e}"))
        })?;

        let sibling_nodes: Vec<U256> = inclusion_proof
            .siblings
            .iter()
            .map(|s| (*s).into())
            .collect();

        let req = UpdateAuthenticatorRequest {
            account_index: account_id,
            old_authenticator_address,
            new_authenticator_address,
            old_offchain_signer_commitment: old_commitment,
            new_offchain_signer_commitment: new_commitment,
            sibling_nodes,
            signature: signature.as_bytes().to_vec(),
            nonce,
            pubkey_id: Some(U256::from(index)),
            new_authenticator_pubkey: Some(encoded_offchain_pubkey),
        };

        let resp = reqwest::Client::new()
            .post(format!(
                "{}/update-authenticator",
                self.config.gateway_url()
            ))
            .json(&req)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            let gateway_resp: GatewayStatusResponse = resp.json().await?;
            Ok(gateway_resp.request_id)
        } else {
            let body_text = resp.text().await.unwrap_or_else(|_| String::new());
            Err(AuthenticatorError::GatewayError {
                status: status.as_u16(),
                body: body_text,
            })
        }
    }

    /// Removes an authenticator from the account.
    ///
    /// # Errors
    /// Returns an error if the gateway rejects the request or a network error occurs.
    ///
    /// # Note
    /// TODO: After successfully removing an authenticator, the `packed_account_index` should be
    /// refreshed from the registry to reflect the new `pubkey_id` commitment.
    pub async fn remove_authenticator(
        &mut self,
        authenticator_address: Address,
        index: u32,
    ) -> Result<String, AuthenticatorError> {
        let account_id = self.account_id();
        let nonce = self.signing_nonce().await?;
        let (inclusion_proof, mut key_set) = self.fetch_inclusion_proof().await?;
        let old_commitment: U256 = Self::leaf_hash(&key_set).into();
        let existing_pubkey = key_set
            .get(index as usize)
            .ok_or(AuthenticatorError::PublicKeyNotFound)?;

        let encoded_old_offchain_pubkey = existing_pubkey.to_ethereum_representation()?;

        key_set[index as usize] = EdDSAPublicKey {
            pk: EdwardsAffine::default(),
        };
        let new_commitment: U256 = Self::leaf_hash(&key_set).into();

        let eip712_domain = domain(
            self.provider()
                .get_chain_id()
                .await
                .map_err(|e| AuthenticatorError::Generic(format!("Failed to get chain ID: {e}")))?,
            *self.config.registry_address(),
        );

        let signature = sign_remove_authenticator(
            &self.signer.onchain_signer(),
            account_id,
            authenticator_address,
            U256::from(index),
            encoded_old_offchain_pubkey,
            new_commitment,
            nonce,
            &eip712_domain,
        )
        .await
        .map_err(|e| {
            AuthenticatorError::Generic(format!("Failed to sign remove authenticator: {e}"))
        })?;

        let sibling_nodes: Vec<U256> = inclusion_proof
            .siblings
            .iter()
            .map(|s| (*s).into())
            .collect();

        let req = RemoveAuthenticatorRequest {
            account_index: account_id,
            authenticator_address,
            old_offchain_signer_commitment: old_commitment,
            new_offchain_signer_commitment: new_commitment,
            sibling_nodes,
            signature: signature.as_bytes().to_vec(),
            nonce,
            pubkey_id: Some(U256::from(index)),
            authenticator_pubkey: Some(encoded_old_offchain_pubkey),
        };

        let resp = reqwest::Client::new()
            .post(format!(
                "{}/remove-authenticator",
                self.config.gateway_url()
            ))
            .json(&req)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            let gateway_resp: GatewayStatusResponse = resp.json().await?;
            Ok(gateway_resp.request_id)
        } else {
            let body_text = resp.text().await.unwrap_or_else(|_| String::new());
            Err(AuthenticatorError::GatewayError {
                status: status.as_u16(),
                body: body_text,
            })
        }
    }

    /// Computes the Merkle leaf (i.e. the commitment to the public key set) for a given public key set.
    ///
    /// TODO: move to primitives
    ///
    /// # Errors
    /// Will error if the provided public key set is not valid.
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn leaf_hash(key_set: &AuthenticatorPublicKeySet) -> ark_babyjubjub::Fq {
        let poseidon2_16: Poseidon2<ark_babyjubjub::Fq, 16, 5> = Poseidon2::default();
        let mut input = [ark_babyjubjub::Fq::ZERO; 16];
        #[allow(clippy::unwrap_used)]
        {
            input[0] = ark_babyjubjub::Fq::from_str("105702839725298824521994315").unwrap();
        }
        // The circuit expects all 7 public key slots to be hashed (with default points for unused slots)
        // Create a full array of 7 keys, padding with defaults
        let mut pk_array = [ark_babyjubjub::EdwardsAffine::default(); 7];
        for (i, pubkey) in key_set.iter().enumerate() {
            pk_array[i] = pubkey.pk;
        }
        // Hash all 7 slots to match circuit expectations
        for i in 0..7 {
            input[i * 2 + 1] = pk_array[i].x;
            input[i * 2 + 2] = pk_array[i].y;
        }
        poseidon2_16.permutation(&input)[1]
    }

    /// Creates a new World ID account by adding it to the registry using the gateway.
    ///
    /// # Errors
    /// - See `Signer::from_seed_bytes` for additional error details.
    /// - Will error if the gateway rejects the request or a network error occurs.
    async fn create_account(
        seed: &[u8],
        config: &Config,
        recovery_address: Option<Address>,
    ) -> Result<String, AuthenticatorError> {
        let signer = Signer::from_seed_bytes(seed)?;

        let mut key_set = AuthenticatorPublicKeySet::new(None)?;
        key_set.try_push(signer.offchain_signer_pubkey())?;
        let leaf_hash = Self::leaf_hash(&key_set);

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

        let resp = reqwest::Client::new()
            .post(format!("{}/create-account", config.gateway_url()))
            .json(&req)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            let body: GatewayStatusResponse = resp.json().await?;
            Ok(body.request_id)
        } else {
            let body_text = resp.text().await.unwrap_or_else(|_| String::new());
            Err(AuthenticatorError::GatewayError {
                status: status.as_u16(),
                body: body_text,
            })
        }
    }
}

impl ProtocolSigner for Authenticator {
    fn sign(&self, message: FieldElement) -> EdDSASignature {
        self.signer
            .offchain_signer_private_key()
            .expose_secret()
            .sign(*message)
    }
}

/// A trait for types that can be represented as a `U256` on-chain.
pub trait OnchainKeyRepresentable {
    /// Converts an off-chain public key into a `U256` representation for on-chain use in the `AccountRegistry` contract.
    ///
    /// The `U256` representation is a 32-byte little-endian encoding of the **compressed** (single point) public key.
    ///
    /// # Errors
    /// Will error if the public key unexpectedly fails to serialize.
    fn to_ethereum_representation(&self) -> Result<U256, PrimitiveError>;
}

impl OnchainKeyRepresentable for EdDSAPublicKey {
    // REVIEW: updating to BE
    fn to_ethereum_representation(&self) -> Result<U256, PrimitiveError> {
        let mut compressed_bytes = Vec::new();
        self.pk
            .serialize_compressed(&mut compressed_bytes)
            .map_err(|e| PrimitiveError::Serialization(e.to_string()))?;
        Ok(U256::from_le_slice(&compressed_bytes))
    }
}

/// Errors that can occur when interacting with the Authenticator.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticatorError {
    /// Primitive error
    #[error(transparent)]
    PrimitiveError(#[from] PrimitiveError),

    /// This operation requires a registered account and an account is not registered
    /// for this authenticator. Call `create_account` first to register it.
    #[error("Account is not registered for this authenticator.")]
    AccountDoesNotExist,

    /// The account already exists for this authenticator. Call `account_id` to get the account index.
    #[error("Account already exists for this authenticator.")]
    AccountAlreadyExists,

    /// An error occurred while interacting with the EVM contract.
    #[error("Error interacting with EVM contract: {0}")]
    ContractError(#[from] alloy::contract::Error),

    /// Network/HTTP request error.
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),

    /// Public key not found in the Authenticator public key set. Usually indicates the local state is out of sync with the registry.
    #[error("Public key not found.")]
    PublicKeyNotFound,

    /// Gateway returned an error response.
    #[error("Gateway error (status {status}): {body}")]
    GatewayError {
        /// HTTP status code
        status: u16,
        /// Response body
        body: String,
    },

    /// Account creation timed out while polling for confirmation.
    #[error("Account creation timed out after {0} seconds")]
    Timeout(u64),

    /// Generic error for other unexpected issues.
    #[error("{0}")]
    Generic(String),
}
