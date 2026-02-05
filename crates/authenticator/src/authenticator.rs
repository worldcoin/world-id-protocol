//! This module contains all the base functionality to support Authenticators in World ID.
//!
//! An Authenticator is the application layer with which a user interacts with the Protocol.

use std::sync::Arc;

use world_id_primitives::{Credential, FieldElement, SessionNullifier};
use world_id_signer::Signer;
use world_id_types::{
    AccountInclusionProof, CreateAccountRequest, GatewayRequestState, GatewayStatusResponse,
    IndexerErrorCode, IndexerPackedAccountRequest, IndexerPackedAccountResponse,
    IndexerQueryRequest, IndexerSignatureNonceResponse, InsertAuthenticatorRequest,
    RemoveAuthenticatorRequest, ServiceApiError, UpdateAuthenticatorRequest,
};

use world_id_proof::{
    AuthenticatorProofInput,
    credential_blinding_factor::OprfCredentialBlindingFactor,
    nullifier::OprfNullifier,
    proof::{ProofError, generate_nullifier_proof},
};
use world_id_request::{ProofRequest, RequestItem, ResponseItem};

use alloy::{
    primitives::{Address, U256},
    providers::DynProvider,
    uint,
};
use ark_babyjubjub::EdwardsAffine;
use ark_serialize::CanonicalSerialize;
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use groth16_material::circom::CircomGroth16Material;
use reqwest::StatusCode;
use secrecy::ExposeSecret;
use taceo_oprf::client::Connector;
pub use world_id_primitives::{Config, TREE_DEPTH, authenticator::ProtocolSigner};
use world_id_primitives::{
    PrimitiveError, ZeroKnowledgeProof, authenticator::AuthenticatorPublicKeySet,
    merkle::MerkleInclusionProof,
};
use world_id_registry::{
    WorldIdRegistry::WorldIdRegistryInstance, domain, sign_insert_authenticator,
    sign_remove_authenticator, sign_update_authenticator,
};

static MASK_RECOVERY_COUNTER: U256 =
    uint!(0xFFFFFFFF00000000000000000000000000000000000000000000000000000000_U256);
static MASK_PUBKEY_ID: U256 =
    uint!(0x00000000FFFFFFFF000000000000000000000000000000000000000000000000_U256);
static MASK_LEAF_INDEX: U256 =
    uint!(0x0000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_U256);

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
    query_material: Arc<CircomGroth16Material>,
    nullifier_material: Arc<CircomGroth16Material>,
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
    #[cfg(feature = "embed-zkeys")]
    pub async fn init(seed: &[u8], config: Config) -> Result<Self, AuthenticatorError> {
        let signer = Signer::from_seed_bytes(seed)?;

        let registry = config.rpc_url().map_or_else(
            || None,
            |rpc_url| {
                let provider = alloy::providers::ProviderBuilder::new()
                    .with_chain_id(config.chain_id())
                    .connect_http(rpc_url.clone());
                Some(world_id_registry::WorldIdRegistry::new(
                    *config.registry_address(),
                    alloy::providers::Provider::erased(provider),
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

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let rustls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let ws_connector = Connector::Rustls(Arc::new(rustls_config));

        let cache_dir = config.zkey_cache_dir();
        let query_material = Arc::new(
            world_id_proof::proof::load_embedded_query_material(cache_dir).map_err(|e| {
                AuthenticatorError::Generic(format!("Failed to load cached query material: {e}"))
            })?,
        );
        let nullifier_material = Arc::new(
            world_id_proof::proof::load_embedded_nullifier_material(cache_dir).map_err(|e| {
                AuthenticatorError::Generic(format!(
                    "Failed to load cached nullifier material: {e}"
                ))
            })?,
        );

        Ok(Self {
            packed_account_data,
            signer,
            config,
            registry: registry.map(Arc::new),
            http_client,
            ws_connector,
            query_material,
            nullifier_material,
        })
    }

    /// Registers a new World ID in the `WorldIDRegistry`.
    ///
    /// Given the registration process is asynchronous, this method will return a `InitializingAuthenticator`
    /// object.
    ///
    /// # Errors
    /// - See `init` for additional error details.
    pub async fn register(
        seed: &[u8],
        config: Config,
        recovery_address: Option<Address>,
    ) -> Result<InitializingAuthenticator, AuthenticatorError> {
        let http_client = reqwest::Client::new();
        InitializingAuthenticator::new(seed, config, recovery_address, http_client).await
    }

    /// Initializes (if the World ID already exists in the registry) or registers a new World ID.
    ///
    /// The registration process is asynchronous and may take some time. This method will block
    /// the thread until the registration is in a final state (success or terminal error). For better
    /// user experience in end authenticator clients, it is recommended to implement custom polling logic.
    ///
    /// Explicit `init` or `register` calls are also recommended as the authenticator should know
    /// if a new World ID should be truly created. For example, an authenticator may have been revoked
    /// access to an existing World ID.
    ///
    /// # Errors
    /// - See `init` for additional error details.
    #[cfg(feature = "embed-zkeys")]
    pub async fn init_or_register(
        seed: &[u8],
        config: Config,
        recovery_address: Option<Address>,
    ) -> Result<Self, AuthenticatorError> {
        match Self::init(seed, config.clone()).await {
            Ok(authenticator) => Ok(authenticator),
            Err(AuthenticatorError::AccountDoesNotExist) => {
                // Authenticator is not registered, create it.
                let http_client = reqwest::Client::new();
                let initializing_authenticator = InitializingAuthenticator::new(
                    seed,
                    config.clone(),
                    recovery_address,
                    http_client,
                )
                .await?;

                let backoff = backon::ExponentialBuilder::default()
                    .with_min_delay(std::time::Duration::from_millis(800))
                    .with_factor(1.5)
                    .without_max_times()
                    .with_total_delay(Some(std::time::Duration::from_secs(120)));

                let poller = || async {
                    let poll_status = initializing_authenticator.poll_status().await;
                    let result = match poll_status {
                        Ok(GatewayRequestState::Finalized { .. }) => Ok(()),
                        Ok(GatewayRequestState::Failed { error_code, error }) => Err(
                            PollResult::TerminalError(AuthenticatorError::RegistrationError {
                                error_code: error_code.map(|v| v.to_string()).unwrap_or_default(),
                                error_message: error,
                            }),
                        ),
                        Err(AuthenticatorError::GatewayError { status, body }) => {
                            if status.is_client_error() {
                                Err(PollResult::TerminalError(
                                    AuthenticatorError::GatewayError { status, body },
                                ))
                            } else {
                                Err(PollResult::Retryable)
                            }
                        }
                        _ => Err(PollResult::Retryable),
                    };

                    match result {
                        Ok(()) => match Self::init(seed, config.clone()).await {
                            Ok(auth) => Ok(auth),
                            Err(AuthenticatorError::AccountDoesNotExist) => {
                                Err(PollResult::Retryable)
                            }
                            Err(e) => Err(PollResult::TerminalError(e)),
                        },
                        Err(e) => Err(e),
                    }
                };

                let result = backon::Retryable::retry(poller, backoff)
                    .when(|e| matches!(e, PollResult::Retryable))
                    .await;

                match result {
                    Ok(authenticator) => Ok(authenticator),
                    Err(PollResult::TerminalError(e)) => Err(e),
                    Err(PollResult::Retryable) => Err(AuthenticatorError::Timeout),
                }
            }
            Err(e) => Err(e),
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
            // TODO: Better error handling to expose the specific failure
            registry
                .getPackedAccountData(onchain_signer_address)
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
                            status,
                            body: error_resp.message,
                        }),
                    };
                }
                return Err(AuthenticatorError::IndexerError {
                    status,
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
    /// - Will error if the user is not registered on the `WorldIDRegistry`.
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
            let nonce = registry.getSignatureNonce(self.leaf_index()).call().await?;
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
                    status,
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

    /// Checks that the OPRF Nodes configuration is valid and returns the list of URLs and the threshold to use.
    ///
    /// # Errors
    /// Will return an error if there are no OPRF Nodes configured or if the threshold is invalid.
    fn check_oprf_config(&self) -> Result<(&[String], usize), AuthenticatorError> {
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
        Ok((services, threshold))
    }

    /// Generates a nullifier for a World ID Proof (through OPRF Nodes).
    ///
    /// A nullifier is a unique, one-time use, anonymous identifier for a World ID
    /// on a specific RP context. It is used to ensure that a single World ID can only
    /// perform an action once.
    ///
    /// # Errors
    ///
    /// - Will raise a [`ProofError`] if there is any issue generating the nullifier. For example,
    ///   network issues, unexpected incorrect responses from OPRF Nodes.
    /// - Raises an error if the OPRF Nodes configuration is not correctly set.
    pub async fn generate_nullifier(
        &self,
        proof_request: &ProofRequest,
    ) -> Result<OprfNullifier, AuthenticatorError> {
        let (services, threshold) = self.check_oprf_config()?;

        let (inclusion_proof, key_set) = self.fetch_inclusion_proof().await?;
        let key_index = key_set
            .iter()
            .position(|pk| pk.pk == self.offchain_pubkey().pk)
            .ok_or(AuthenticatorError::PublicKeyNotFound)? as u64;

        let authenticator_input = AuthenticatorProofInput::new(
            key_set,
            inclusion_proof,
            self.signer
                .offchain_signer_private_key()
                .expose_secret()
                .clone(),
            key_index,
        );

        Ok(OprfNullifier::generate(
            services,
            threshold,
            &self.query_material,
            authenticator_input,
            proof_request,
            self.ws_connector.clone(),
        )
        .await?)
    }

    // TODO add more docs
    /// Generates a blinding factor for a Credential sub (through OPRF Nodes).
    ///
    /// # Errors
    ///
    /// - Will raise a [`ProofError`] if there is any issue generating the blinding factor.
    ///   For example, network issues, unexpected incorrect responses from OPRF Nodes.
    /// - Raises an error if the OPRF Nodes configuration is not correctly set.
    pub async fn generate_credential_blinding_factor(
        &self,
        issuer_schema_id: u64,
    ) -> Result<FieldElement, AuthenticatorError> {
        let (services, threshold) = self.check_oprf_config()?;

        let (inclusion_proof, key_set) = self.fetch_inclusion_proof().await?;
        let key_index = key_set
            .iter()
            .position(|pk| pk.pk == self.offchain_pubkey().pk)
            .ok_or(AuthenticatorError::PublicKeyNotFound)? as u64;

        let authenticator_input = AuthenticatorProofInput::new(
            key_set,
            inclusion_proof,
            self.signer
                .offchain_signer_private_key()
                .expose_secret()
                .clone(),
            key_index,
        );

        let blinding_factor = OprfCredentialBlindingFactor::generate(
            services,
            threshold,
            &self.query_material,
            authenticator_input,
            issuer_schema_id,
            FieldElement::ZERO, // for now action is always zero, might change in future
            self.ws_connector.clone(),
        )
        .await?;

        Ok(blinding_factor.verifiable_oprf_output.output.into())
    }

    /// Generates a single World ID Proof from a provided `[ProofRequest]` and `[Credential]`. This
    /// method generates the raw proof to be translated into a Uniqueness Proof or a Session Proof for the RP.
    ///
    /// This assumes the RP's `[ProofRequest]` has already been parsed to determine
    /// which `[Credential]` is appropriate for the request. This method responds to a
    /// specific `[RequestItem]` (a `[ProofRequest]` may contain multiple items).
    ///
    /// # Arguments
    /// - `oprf_nullifier`: The `[OprfNullifier]` output generated from the `generate_nullifier` function.
    /// - `request_item`: The specific `RequestItem` that is being resolved from the RP's `ProofRequest`.
    /// - `credential`: The Credential to be used for the proof that fulfills the `RequestItem`.
    /// - `credential_sub_blinding_factor`: The blinding factor for the Credential's sub.
    /// - `session_id_r_seed`: The session ID random seed. Obtained from the RP's [`ProofRequest`].
    /// - `session_id`: The expected session ID provided by the RP. Only needed for Session Proofs. Obtained from the RP's [`ProofRequest`].
    /// - `request_timestamp`: The timestamp of the request. Obtained from the RP's [`ProofRequest`].
    ///
    /// # Errors
    /// - Will error if the any of the provided parameters are not valid.
    /// - Will error if any of the required network requests fail.
    /// - Will error if the user does not have a registered World ID.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_single_proof(
        &self,
        oprf_nullifier: OprfNullifier,
        request_item: &RequestItem,
        credential: &Credential,
        credential_sub_blinding_factor: FieldElement,
        session_id_r_seed: FieldElement,
        session_id: Option<FieldElement>,
        request_timestamp: u64,
    ) -> Result<ResponseItem, AuthenticatorError> {
        let mut rng = rand::rngs::OsRng;

        let merkle_root: FieldElement = oprf_nullifier.query_proof_input.merkle_root.into();

        let expires_at_min = request_item.effective_expires_at_min(request_timestamp);

        let (proof, public_inputs, nullifier) = generate_nullifier_proof(
            &self.nullifier_material,
            &mut rng,
            credential,
            credential_sub_blinding_factor,
            oprf_nullifier,
            request_item,
            session_id,
            session_id_r_seed,
            expires_at_min,
        )?;

        let proof = ZeroKnowledgeProof::from_groth16_proof(&proof, merkle_root);

        // Construct the appropriate response item based on proof type
        let nullifier_fe: FieldElement = nullifier.into();
        let response_item = if session_id.is_some() {
            // Session proof: extract action from public_inputs[9]
            let action: FieldElement = public_inputs[9].into();
            let session_nullifier = SessionNullifier::new(nullifier_fe, action);
            ResponseItem::new_session(
                request_item.identifier.clone(),
                request_item.issuer_schema_id,
                proof,
                session_nullifier,
                expires_at_min,
            )
        } else {
            ResponseItem::new_uniqueness(
                request_item.identifier.clone(),
                request_item.issuer_schema_id,
                proof,
                nullifier_fe,
                expires_at_min,
            )
        };

        Ok(response_item)
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
        let old_offchain_signer_commitment = key_set.leaf_hash();
        let encoded_offchain_pubkey = new_authenticator_pubkey.to_ethereum_representation()?;
        key_set.try_push(new_authenticator_pubkey)?;
        let index = key_set.len() - 1;
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
                status,
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
                status,
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
        let old_commitment: U256 = key_set.leaf_hash().into();
        let existing_pubkey = key_set
            .get(index as usize)
            .ok_or(AuthenticatorError::PublicKeyNotFound)?;

        let encoded_old_offchain_pubkey = existing_pubkey.to_ethereum_representation()?;

        key_set[index as usize] = EdDSAPublicKey {
            pk: EdwardsAffine::default(),
        };
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
                status,
                body: body_text,
            })
        }
    }
}

/// Represents an account in the process of being initialized,
/// i.e. it is not yet registered in the `WorldIDRegistry` contract.
pub struct InitializingAuthenticator {
    request_id: String,
    http_client: reqwest::Client,
    config: Config,
}

impl InitializingAuthenticator {
    /// Creates a new World ID account by adding it to the registry using the gateway.
    ///
    /// # Errors
    /// - See `Signer::from_seed_bytes` for additional error details.
    /// - Will error if the gateway rejects the request or a network error occurs.
    async fn new(
        seed: &[u8],
        config: Config,
        recovery_address: Option<Address>,
        http_client: reqwest::Client,
    ) -> Result<Self, AuthenticatorError> {
        let signer = Signer::from_seed_bytes(seed)?;

        let mut key_set = AuthenticatorPublicKeySet::new(None)?;
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
            let body_text = resp.text().await.unwrap_or_else(|_| String::new());
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
        let resp = self
            .http_client
            .get(format!(
                "{}/status/{}",
                self.config.gateway_url(),
                self.request_id
            ))
            .send()
            .await?;

        let status = resp.status();

        if status.is_success() {
            let body: GatewayStatusResponse = resp.json().await?;
            Ok(body.status)
        } else {
            let body_text = resp.text().await.unwrap_or_else(|_| String::new());
            Err(AuthenticatorError::GatewayError {
                status,
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
        status: StatusCode,
        /// Response body
        body: String,
    },

    /// Indexer returned an error response.
    #[error("Indexer error (status {status}): {body}")]
    IndexerError {
        /// HTTP status code
        status: StatusCode,
        /// Response body
        body: String,
    },

    /// Account creation timed out while polling for confirmation.
    #[error("Account creation timed out")]
    Timeout,

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

    /// Error during the World ID registration process.
    ///
    /// This usually occurs from an on-chain revert.
    #[error("Registration error ({error_code}): {error_message}")]
    RegistrationError {
        /// Error code from the registration process.
        error_code: String,
        /// Detailed error message.
        error_message: String,
    },

    /// Error on proof generation
    #[error(transparent)]
    ProofError(#[from] ProofError),

    /// Generic error for other unexpected issues.
    #[error("{0}")]
    Generic(String),
}

#[cfg(feature = "embed-zkeys")]
#[derive(Debug)]
enum PollResult {
    Retryable,
    TerminalError(AuthenticatorError),
}

#[cfg(all(test, feature = "embed-zkeys"))]
mod tests {
    use super::*;
    use alloy::primitives::{U256, address};
    use std::{path::PathBuf, sync::OnceLock};

    fn test_materials() -> (Arc<CircomGroth16Material>, Arc<CircomGroth16Material>) {
        static QUERY: OnceLock<Arc<CircomGroth16Material>> = OnceLock::new();
        static NULLIFIER: OnceLock<Arc<CircomGroth16Material>> = OnceLock::new();

        let query = QUERY.get_or_init(|| {
            Arc::new(
                world_id_proof::proof::load_embedded_query_material(Option::<PathBuf>::None)
                    .unwrap(),
            )
        });
        let nullifier = NULLIFIER.get_or_init(|| {
            Arc::new(
                world_id_proof::proof::load_embedded_nullifier_material(Option::<PathBuf>::None)
                    .unwrap(),
            )
        });

        (Arc::clone(query), Arc::clone(nullifier))
    }

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

        let (query_material, nullifier_material) = test_materials();
        let authenticator = Authenticator {
            config,
            packed_account_data: leaf_index, // This sets leaf_index() to 1
            signer: Signer::from_seed_bytes(&[1u8; 32]).unwrap(),
            registry: None, // No registry - forces indexer usage
            http_client: reqwest::Client::new(),
            ws_connector: Connector::Plain,
            query_material,
            nullifier_material,
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

        let (query_material, nullifier_material) = test_materials();
        let authenticator = Authenticator {
            config,
            packed_account_data: U256::ZERO,
            signer: Signer::from_seed_bytes(&[1u8; 32]).unwrap(),
            registry: None,
            http_client: reqwest::Client::new(),
            ws_connector: Connector::Plain,
            query_material,
            nullifier_material,
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
