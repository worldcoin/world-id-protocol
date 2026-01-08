//! This module contains all the base functionality to support Authenticators in World ID.
//!
//! An Authenticator is the application layer with which a user interacts with the Protocol.

use std::sync::Arc;
use std::time::Duration;

use crate::requests::ProofRequest;
use crate::types::{
    AccountInclusionProof, CreateAccountRequest, GatewayRequestState, GatewayStatusResponse,
    IndexerErrorCode, IndexerPackedAccountRequest, IndexerPackedAccountResponse,
    IndexerQueryRequest, IndexerSignatureNonceResponse, InsertAuthenticatorRequest,
    RemoveAuthenticatorRequest, ServiceApiError, UpdateAuthenticatorRequest,
};
use crate::world_id_registry::WorldIdRegistry::{self, WorldIdRegistryInstance};
use crate::world_id_registry::{
    domain, sign_insert_authenticator, sign_remove_authenticator, sign_update_authenticator,
};
use crate::{Credential, FieldElement, Signer};
use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::uint;
use ark_babyjubjub::EdwardsAffine;
use ark_bn254::Bn254;
use ark_serialize::CanonicalSerialize;
use circom_types::groth16::Proof;
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use rustls::{ClientConfig, RootCertStore};
use secrecy::ExposeSecret;
use taceo_oprf_client::Connector;
use taceo_oprf_types::ShareEpoch;
use world_id_primitives::authenticator::AuthenticatorPublicKeySet;
use world_id_primitives::merkle::MerkleInclusionProof;
use world_id_primitives::proof::SingleProofInput;
use world_id_primitives::PrimitiveError;
pub use world_id_primitives::{authenticator::ProtocolSigner, Config, TREE_DEPTH};

static MASK_RECOVERY_COUNTER: U256 =
    uint!(0xFFFFFFFF00000000000000000000000000000000000000000000000000000000_U256);
static MASK_PUBKEY_ID: U256 =
    uint!(0x00000000FFFFFFFF000000000000000000000000000000000000000000000000_U256);
static MASK_LEAF_INDEX: U256 =
    uint!(0x0000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_U256);

/// Maximum timeout for polling account creation status (30 seconds)
const MAX_POLL_TIMEOUT_SECS: u64 = 30;

type UniquenessProof = (Proof<Bn254>, FieldElement);

/// An Authenticator is the base layer with which a user interacts with the Protocol.
pub struct Authenticator {
    /// General configuration for the Authenticator.
    pub config: Config,
    /// The packed account data for the holder's World ID is a `uint256` defined in the `WorldIDRegistry` contract as:
    /// `recovery_counter` (32 bits) | `pubkey_id` (commitment to all off-chain public keys) (32 bits) | `leaf_index` (192 bits)
    pub packed_account_data: U256,
    signer: Signer,
    registry: Option<Arc<WorldIdRegistryInstance<DynProvider>>>,
    http_client: reqwest::Client,
    ws_connector: Connector,
}

#[expect(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator")
            .field("config", &self.config)
            .field("packed_account_data", &self.packed_account_data)
            .field("signer", &self.signer)
            .finish()
    }
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

        let registry = config.rpc_url().map_or_else(
            || None,
            |rpc_url| {
                let provider = ProviderBuilder::new()
                    .with_chain_id(config.chain_id())
                    .connect_http(rpc_url.clone());
                Some(WorldIdRegistry::new(
                    *config.registry_address(),
                    provider.erased(),
                ))
            },
        );

        let http_client = reqwest::Client::new();

        let packed_account_data = Self::get_packed_account_data(
            signer.onchain_signer_address(),
            registry.as_ref(),
            &config,
            &http_client,
        )
        .await?;

        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let rustls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let ws_connector = Connector::Rustls(Arc::new(rustls_config));

        Ok(Self {
            packed_account_data,
            signer,
            config,
            registry: registry.map(Arc::new),
            http_client,
            ws_connector,
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
                let http_client = reqwest::Client::new();
                Self::create_account(seed, &config, recovery_address, &http_client).await?;
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

        // Create HTTP client for account creation and polling
        let http_client = reqwest::Client::new();

        // Create the account and get the request ID
        let request_id =
            Self::create_account(seed, &config, recovery_address, &http_client).await?;

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
            match Self::poll_gateway_status(&config, &request_id, &http_client).await {
                Ok(GatewayRequestState::Finalized { .. }) => {
                    let result = Self::init(seed, config.clone()).await;
                    match result {
                        Ok(authenticator) => return Ok(authenticator),
                        Err(e) => {
                            if matches!(e, AuthenticatorError::AccountDoesNotExist) {
                                // continue polling, as the indexer may take a while
                                delay_ms = (delay_ms * 2).min(5000); // Cap at 5 seconds
                                continue;
                            }
                            return Err(e);
                        }
                    }
                }
                Ok(GatewayRequestState::Failed { error, .. }) => {
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
        http_client: &reqwest::Client,
    ) -> Result<GatewayRequestState, AuthenticatorError> {
        let resp = http_client
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

    /// Returns the packed account data for the holder's World ID.
    ///
    /// The packed account data is a 256 bit integer which includes the World ID's leaf index, their recovery counter,
    /// and their pubkey id/commitment.
    ///
    /// # Errors
    /// Will error if the network call fails or if the account does not exist.
    pub async fn get_packed_account_data(
        onchain_signer_address: Address,
        registry: Option<&WorldIdRegistryInstance<DynProvider>>,
        config: &Config,
        http_client: &reqwest::Client,
    ) -> Result<U256, AuthenticatorError> {
        // If the registry is available through direct RPC calls, use it. Otherwise fallback to the indexer.
        let raw_index = if let Some(registry) = registry {
            registry
                .authenticatorAddressToPackedAccountData(onchain_signer_address)
                .call()
                .await?
        } else {
            let url = format!("{}/packed-account", config.indexer_url());
            let req = IndexerPackedAccountRequest {
                authenticator_address: onchain_signer_address,
            };
            let resp = http_client.post(&url).json(&req).send().await?;

            let status = resp.status();
            if !status.is_success() {
                // Try to parse the error response
                if let Ok(error_resp) = resp.json::<ServiceApiError<IndexerErrorCode>>().await {
                    return match error_resp.code {
                        IndexerErrorCode::AccountDoesNotExist => {
                            Err(AuthenticatorError::AccountDoesNotExist)
                        }
                        _ => Err(AuthenticatorError::IndexerError {
                            status: status.as_u16(),
                            body: error_resp.message,
                        }),
                    };
                }
                return Err(AuthenticatorError::IndexerError {
                    status: status.as_u16(),
                    body: "Failed to parse indexer error response".to_string(),
                });
            }

            let response: IndexerPackedAccountResponse = resp.json().await?;
            response.packed_account_data
        };

        if raw_index == U256::ZERO {
            return Err(AuthenticatorError::AccountDoesNotExist);
        }

        Ok(raw_index)
    }

    /// Returns the k256 public key of the Authenticator signer which is used to verify on-chain operations,
    /// chiefly with the `WorldIdRegistry` contract.
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

    /// Returns a reference to the `WorldIdRegistry` contract instance.
    #[must_use]
    pub fn registry(&self) -> Option<Arc<WorldIdRegistryInstance<DynProvider>>> {
        self.registry.clone()
    }

    /// Returns the account index for the holder's World ID.
    ///
    /// This is the index at the Merkle tree where the holder's World ID account is registered.
    #[must_use]
    pub fn leaf_index(&self) -> U256 {
        self.packed_account_data & MASK_LEAF_INDEX
    }

    /// Returns the recovery counter for the holder's World ID.
    ///
    /// The recovery counter is used to efficiently invalidate all the old keys when an account is recovered.
    #[must_use]
    pub fn recovery_counter(&self) -> U256 {
        let recovery_counter = self.packed_account_data & MASK_RECOVERY_COUNTER;
        recovery_counter >> 224
    }

    /// Returns the pubkey id (or commitment) for the holder's World ID.
    ///
    /// This is a commitment to all the off-chain public keys that are authorized to act on behalf of the holder.
    #[must_use]
    pub fn pubkey_id(&self) -> U256 {
        let pubkey_id = self.packed_account_data & MASK_PUBKEY_ID;
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
        let url = format!("{}/inclusion-proof", self.config.indexer_url());
        let req = IndexerQueryRequest {
            leaf_index: self.leaf_index(),
        };
        let response = self.http_client.post(&url).json(&req).send().await?;
        let response = response.json::<AccountInclusionProof<TREE_DEPTH>>().await?;

        Ok((response.inclusion_proof, response.authenticator_pubkeys))
    }

    /// Returns the signing nonce for the holder's World ID.
    ///
    /// # Errors
    /// Will return an error if the registry contract call fails.
    pub async fn signing_nonce(&self) -> Result<U256, AuthenticatorError> {
        let registry = self.registry();
        if let Some(registry) = registry {
            let nonce = registry
                .leafIndexToSignatureNonce(self.leaf_index())
                .call()
                .await?;
            Ok(nonce)
        } else {
            let url = format!("{}/signature-nonce", self.config.indexer_url());
            let req = IndexerQueryRequest {
                leaf_index: self.leaf_index(),
            };
            let resp = self.http_client.post(&url).json(&req).send().await?;

            let status = resp.status();
            if !status.is_success() {
                return Err(AuthenticatorError::IndexerError {
                    status: status.as_u16(),
                    body: resp
                        .json()
                        .await
                        .unwrap_or_else(|_| "Unable to parse response".to_string()),
                });
            }

            let response: IndexerSignatureNonceResponse = resp.json().await?;
            Ok(response.signature_nonce)
        }
    }

    /// Generates a single World ID Proof from a provided `[ProofRequest]` and `[Credential]`.
    ///
    /// This assumes the Authenticator has already parsed the `[ProofRequest]` and determined
    /// which `[Credential]` is appropriate for the request.
    ///
    /// # Errors
    /// - Will error if the any of the provided parameters are not valid.
    /// - Will error if any of the required network requests fail.
    /// - Will error if the user does not have a registered World ID.
    #[allow(clippy::future_not_send)]
    pub async fn generate_proof(
        &self,
        proof_request: ProofRequest,
        credential: Credential,
    ) -> Result<UniquenessProof, AuthenticatorError> {
        let (inclusion_proof, key_set) = self.fetch_inclusion_proof().await?;
        let key_index = key_set
            .iter()
            .position(|pk| pk.pk == self.offchain_pubkey().pk)
            .ok_or(AuthenticatorError::PublicKeyNotFound)? as u64;

        // TODO: load once and from bytes
        let query_material = crate::proof::load_embedded_query_material();
        let nullifier_material = crate::proof::load_embedded_nullifier_material();

        let request_item = proof_request
            .find_request_by_issuer_schema_id(credential.issuer_schema_id.into())
            .ok_or(AuthenticatorError::InvalidCredentialForProofRequest)?;

        let args = SingleProofInput::<TREE_DEPTH> {
            credential,
            inclusion_proof,
            key_set,
            key_index,
            rp_session_id_r_seed: FieldElement::ZERO, // FIXME: expose properly (was id_commitment_r)
            rp_id: proof_request.rp_id,
            share_epoch: ShareEpoch::default().into_inner(),
            action: proof_request.action,
            nonce: proof_request.nonce,
            current_timestamp: proof_request.created_at,
            rp_signature: proof_request.signature,
            oprf_public_key: proof_request.oprf_public_key,
            signal_hash: request_item.signal_hash(),
        };

        let private_key = self.signer.offchain_signer_private_key().expose_secret();

        let services = self.config.nullifier_oracle_urls();
        if services.is_empty() {
            return Err(AuthenticatorError::Generic(
                "No nullifier oracle URLs configured".to_string(),
            ));
        }
        let requested_threshold = self.config.nullifier_oracle_threshold();
        if requested_threshold == 0 {
            return Err(AuthenticatorError::InvalidConfig {
                attribute: "nullifier_oracle_threshold",
                reason: "must be at least 1".to_string(),
            });
        }
        let threshold = requested_threshold.min(services.len());

        let mut rng = rand::thread_rng();
        let (proof, _public, nullifier, _id_commitment) = crate::proof::nullifier(
            services,
            threshold,
            &query_material,
            &nullifier_material,
            args,
            private_key,
            self.ws_connector.clone(),
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
    /// TODO: After successfully inserting an authenticator, the `packed_account_data` should be
    /// refreshed from the registry to reflect the new `pubkey_id` commitment.
    pub async fn insert_authenticator(
        &mut self,
        new_authenticator_pubkey: EdDSAPublicKey,
        new_authenticator_address: Address,
    ) -> Result<String, AuthenticatorError> {
        let leaf_index = self.leaf_index();
        let nonce = self.signing_nonce().await?;
        let (inclusion_proof, mut key_set) = self.fetch_inclusion_proof().await?;
        let old_offchain_signer_commitment = Self::leaf_hash(&key_set);
        key_set.try_push(new_authenticator_pubkey.clone())?;
        let index = key_set.len() - 1;
        let new_offchain_signer_commitment = Self::leaf_hash(&key_set);

        let encoded_offchain_pubkey = new_authenticator_pubkey.to_ethereum_representation()?;

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
        .await
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
            sibling_nodes: inclusion_proof
                .siblings
                .iter()
                .map(|s| (*s).into())
                .collect(),
            signature: signature.as_bytes().to_vec(),
            nonce,
        };

        let resp = self
            .http_client
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
    /// TODO: After successfully updating an authenticator, the `packed_account_data` should be
    /// refreshed from the registry to reflect the new `pubkey_id` commitment.
    pub async fn update_authenticator(
        &mut self,
        old_authenticator_address: Address,
        new_authenticator_address: Address,
        new_authenticator_pubkey: EdDSAPublicKey,
        index: u32,
    ) -> Result<String, AuthenticatorError> {
        let leaf_index = self.leaf_index();
        let nonce = self.signing_nonce().await?;
        let (inclusion_proof, mut key_set) = self.fetch_inclusion_proof().await?;
        let old_commitment: U256 = Self::leaf_hash(&key_set).into();
        key_set.try_set_at_index(index as usize, new_authenticator_pubkey.clone())?;
        let new_commitment: U256 = Self::leaf_hash(&key_set).into();

        let encoded_offchain_pubkey = new_authenticator_pubkey.to_ethereum_representation()?;

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
            leaf_index,
            old_authenticator_address,
            new_authenticator_address,
            old_offchain_signer_commitment: old_commitment,
            new_offchain_signer_commitment: new_commitment,
            sibling_nodes,
            signature: signature.as_bytes().to_vec(),
            nonce,
            pubkey_id: index,
            new_authenticator_pubkey: encoded_offchain_pubkey,
        };

        let resp = self
            .http_client
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
    /// TODO: After successfully removing an authenticator, the `packed_account_data` should be
    /// refreshed from the registry to reflect the new `pubkey_id` commitment.
    pub async fn remove_authenticator(
        &mut self,
        authenticator_address: Address,
        index: u32,
    ) -> Result<String, AuthenticatorError> {
        let leaf_index = self.leaf_index();
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
            leaf_index,
            authenticator_address,
            old_offchain_signer_commitment: old_commitment,
            new_offchain_signer_commitment: new_commitment,
            sibling_nodes,
            signature: signature.as_bytes().to_vec(),
            nonce,
            pubkey_id: Some(index),
            authenticator_pubkey: Some(encoded_old_offchain_pubkey),
        };

        let resp = self
            .http_client
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
        key_set.leaf_hash()
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
        http_client: &reqwest::Client,
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

        let resp = http_client
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
    /// Converts an off-chain public key into a `U256` representation for on-chain use in the `WorldIDRegistry` contract.
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

    /// The account already exists for this authenticator. Call `leaf_index` to get the leaf index.
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

    /// Indexer returned an error response.
    #[error("Indexer error (status {status}): {body}")]
    IndexerError {
        /// HTTP status code
        status: u16,
        /// Response body
        body: String,
    },

    /// Account creation timed out while polling for confirmation.
    #[error("Account creation timed out after {0} seconds")]
    Timeout(u64),

    /// Configuration is invalid or missing required values.
    #[error("Invalid configuration for {attribute}: {reason}")]
    InvalidConfig {
        /// The config attribute that is invalid.
        attribute: &'static str,
        /// Description of why it is invalid.
        reason: String,
    },

    /// The provided credential is not valid for the provided proof request.
    #[error("The provided credential is not valid for the provided proof request")]
    InvalidCredentialForProofRequest,

    /// Generic error for other unexpected issues.
    #[error("{0}")]
    Generic(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, U256};

    /// Tests that `get_packed_account_data` correctly fetches the packed account data from the indexer
    /// when no RPC is configured.
    #[tokio::test]
    async fn test_get_packed_account_data_from_indexer() {
        let mut server = mockito::Server::new_async().await;
        let indexer_url = server.url();

        let test_address = address!("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0");
        let expected_packed_index = U256::from(42);

        let mock = server
            .mock("POST", "/packed-account")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::JsonString(
                serde_json::json!({
                    "authenticator_address": test_address
                })
                .to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "packed_account_data": format!("{:#x}", expected_packed_index)
                })
                .to_string(),
            )
            .create_async()
            .await;

        let config = Config::new(
            None,
            1,
            address!("0x0000000000000000000000000000000000000001"),
            indexer_url,
            "http://gateway.example.com".to_string(),
            Vec::new(),
            2,
        )
        .unwrap();

        let http_client = reqwest::Client::new();

        let result = Authenticator::get_packed_account_data(
            test_address,
            None, // No registry, force indexer usage
            &config,
            &http_client,
        )
        .await
        .unwrap();

        assert_eq!(result, expected_packed_index);
        mock.assert_async().await;
        drop(server);
    }

    #[tokio::test]
    async fn test_get_packed_account_data_from_indexer_error() {
        let mut server = mockito::Server::new_async().await;
        let indexer_url = server.url();

        let test_address = address!("0x0000000000000000000000000000000000000099");

        let mock = server
            .mock("POST", "/packed-account")
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "code": "account_does_not_exist",
                    "message": "There is no account for this authenticator address"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let config = Config::new(
            None,
            1,
            address!("0x0000000000000000000000000000000000000001"),
            indexer_url,
            "http://gateway.example.com".to_string(),
            Vec::new(),
            2,
        )
        .unwrap();

        let http_client = reqwest::Client::new();

        let result =
            Authenticator::get_packed_account_data(test_address, None, &config, &http_client).await;

        assert!(matches!(
            result,
            Err(AuthenticatorError::AccountDoesNotExist)
        ));
        mock.assert_async().await;
        drop(server);
    }

    #[tokio::test]
    async fn test_signing_nonce_from_indexer() {
        let mut server = mockito::Server::new_async().await;
        let indexer_url = server.url();

        let leaf_index = U256::from(1);
        let expected_nonce = U256::from(5);

        let mock = server
            .mock("POST", "/signature-nonce")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::JsonString(
                serde_json::json!({
                    "leaf_index": format!("{:#x}", leaf_index)
                })
                .to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "signature_nonce": format!("{:#x}", expected_nonce)
                })
                .to_string(),
            )
            .create_async()
            .await;

        let config = Config::new(
            None,
            1,
            address!("0x0000000000000000000000000000000000000001"),
            indexer_url,
            "http://gateway.example.com".to_string(),
            Vec::new(),
            2,
        )
        .unwrap();

        let authenticator = Authenticator {
            config,
            packed_account_data: leaf_index, // This sets leaf_index() to 1
            signer: Signer::from_seed_bytes(&[1u8; 32]).unwrap(),
            registry: None, // No registry - forces indexer usage
            http_client: reqwest::Client::new(),
            ws_connector: Connector::Plain,
        };

        let nonce = authenticator.signing_nonce().await.unwrap();

        assert_eq!(nonce, expected_nonce);
        mock.assert_async().await;
        drop(server);
    }

    #[tokio::test]
    async fn test_signing_nonce_from_indexer_error() {
        let mut server = mockito::Server::new_async().await;
        let indexer_url = server.url();

        let mock = server
            .mock("POST", "/signature-nonce")
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "code": "invalid_leaf_index",
                    "message": "Account index cannot be zero"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let config = Config::new(
            None,
            1,
            address!("0x0000000000000000000000000000000000000001"),
            indexer_url,
            "http://gateway.example.com".to_string(),
            Vec::new(),
            2,
        )
        .unwrap();

        let authenticator = Authenticator {
            config,
            packed_account_data: U256::ZERO,
            signer: Signer::from_seed_bytes(&[1u8; 32]).unwrap(),
            registry: None,
            http_client: reqwest::Client::new(),
            ws_connector: Connector::Plain,
        };

        let result = authenticator.signing_nonce().await;

        assert!(matches!(
            result,
            Err(AuthenticatorError::IndexerError { .. })
        ));
        mock.assert_async().await;
        drop(server);
    }
}
