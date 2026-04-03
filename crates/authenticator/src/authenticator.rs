//! This module contains all the base functionality to support Authenticators in World ID. See
//! [`Authenticator`] for a definition.

use std::sync::Arc;

use crate::api_types::{
    AccountInclusionProof, CancelRecoveryAgentUpdateRequest, CreateAccountRequest,
    ExecuteRecoveryAgentUpdateRequest, GatewayRequestId, GatewayRequestState,
    GatewayStatusResponse, IndexerAuthenticatorPubkeysResponse, IndexerErrorCode,
    IndexerPackedAccountRequest, IndexerPackedAccountResponse, IndexerQueryRequest,
    IndexerSignatureNonceResponse, InsertAuthenticatorRequest, RemoveAuthenticatorRequest,
    ServiceApiError, UpdateAuthenticatorRequest, UpdateRecoveryAgentRequest,
};
use world_id_primitives::{
    Credential, FieldElement, ProofRequest, ProofResponse, RequestItem, ResponseItem,
    SessionNullifier, Signer, ValidationError,
};

use crate::registry::{
    WorldIdRegistry::WorldIdRegistryInstance, domain, sign_cancel_recovery_agent_update,
    sign_initiate_recovery_agent_update, sign_insert_authenticator, sign_remove_authenticator,
    sign_update_authenticator,
};
use alloy::{
    primitives::Address,
    providers::DynProvider,
    signers::{Signature, SignerSync},
};
use ark_serialize::CanonicalSerialize;
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use groth16_material::circom::CircomGroth16Material;
use reqwest::StatusCode;
use ruint::{aliases::U256, uint};
use secrecy::ExposeSecret;
use taceo_oprf::client::Connector;
pub use world_id_primitives::{Config, TREE_DEPTH, authenticator::ProtocolSigner};
use world_id_primitives::{
    PrimitiveError, SessionId, ZeroKnowledgeProof,
    authenticator::{
        AuthenticatorPublicKeySet, SparseAuthenticatorPubkeysError,
        decode_sparse_authenticator_pubkeys,
    },
};
use world_id_proof::{
    AuthenticatorProofInput, FullOprfOutput, OprfEntrypoint,
    proof::{ProofError, generate_nullifier_proof},
};

#[expect(unused_imports, reason = "used for docs")]
use world_id_primitives::Nullifier;

/// Shared helper that polls `GET {gateway_url}/status/{request_id}` and
/// returns the current [`GatewayRequestState`].
async fn fetch_gateway_status(
    http_client: &reqwest::Client,
    gateway_url: &str,
    request_id: &GatewayRequestId,
) -> Result<GatewayRequestState, AuthenticatorError> {
    let resp = http_client
        .get(format!("{gateway_url}/status/{request_id}"))
        .send()
        .await?;

    let status = resp.status();

    if status.is_success() {
        let body: GatewayStatusResponse = resp.json().await?;
        Ok(body.status)
    } else {
        let body_text = resp
            .text()
            .await
            .unwrap_or_else(|e| format!("Unable to read response body: {e}"));
        Err(AuthenticatorError::GatewayError {
            status,
            body: body_text,
        })
    }
}

static MASK_RECOVERY_COUNTER: U256 =
    uint!(0xFFFFFFFF00000000000000000000000000000000000000000000000000000000_U256);
static MASK_PUBKEY_ID: U256 =
    uint!(0x00000000FFFFFFFF000000000000000000000000000000000000000000000000_U256);
static MASK_LEAF_INDEX: U256 =
    uint!(0x000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF_U256);

/// Input for a single credential proof within a proof request.
pub struct CredentialInput {
    /// The credential to prove.
    pub credential: Credential,
    /// The blinding factor for the credential's sub.
    pub blinding_factor: FieldElement,
}

/// Output from proof generation process.
///
/// The [`Authenticator`] herein deliberately does not handle caching or replay guards as
/// those are SDK concerns.
#[derive(Debug)]
pub struct ProofResult {
    /// The session_id_r_seed (`r`), if a session proof was generated.
    ///
    /// The SDK should cache this keyed by [`SessionId::oprf_seed`].
    pub session_id_r_seed: Option<FieldElement>,

    /// The response to deliver to an RP.
    pub proof_response: ProofResponse,
}

/// An Authenticator is the agent of a **user** interacting with the World ID Protocol.
///
/// # Definition
///
/// A software or hardware agent (e.g., app, device, web client, or service) that controls a
/// set of authorized keypairs for a World ID Account and is functionally capable of interacting
/// with the Protocol, and is therefore permitted to act on that account’s behalf. An Authenticator
/// is the agent of users/holders. Each Authenticator is registered in the `WorldIDRegistry`
/// through their authorized keypairs.
///
/// For example, an Authenticator can live in a mobile wallet or a web application.
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
    query_material: Option<Arc<CircomGroth16Material>>,
    nullifier_material: Option<Arc<CircomGroth16Material>>,
}

impl std::fmt::Debug for Authenticator {
    // avoiding logging other attributes to avoid accidental leak of leaf_index
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Authenticator {
    async fn response_body_or_fallback(response: reqwest::Response) -> String {
        response
            .text()
            .await
            .unwrap_or_else(|e| format!("Unable to read response body: {e}"))
    }

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

        let registry: Option<Arc<WorldIdRegistryInstance<DynProvider>>> =
            config.rpc_url().map(|rpc_url| {
                let provider = alloy::providers::ProviderBuilder::new()
                    .with_chain_id(config.chain_id())
                    .connect_http(rpc_url.clone());
                Arc::new(crate::registry::WorldIdRegistry::new(
                    *config.registry_address(),
                    alloy::providers::Provider::erased(provider),
                ))
            });

        let http_client = reqwest::Client::new();

        let packed_account_data = Self::get_packed_account_data(
            signer.onchain_signer_address(),
            registry.as_deref(),
            &config,
            &http_client,
        )
        .await?;

        #[cfg(not(target_arch = "wasm32"))]
        let ws_connector = {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let rustls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            Connector::Rustls(Arc::new(rustls_config))
        };

        #[cfg(target_arch = "wasm32")]
        let ws_connector = Connector;

        Ok(Self {
            packed_account_data,
            signer,
            config,
            registry,
            http_client,
            ws_connector,
            query_material: None,
            nullifier_material: None,
        })
    }

    /// Sets the proof materials for the Authenticator, returning a new instance.
    ///
    /// Proof materials are required for proof generation, blinding factors and starting
    /// sessions. Given the proof circuits are large, this may be loaded only when necessary.
    #[must_use]
    pub fn with_proof_materials(
        self,
        query_material: Arc<CircomGroth16Material>,
        nullifier_material: Arc<CircomGroth16Material>,
    ) -> Self {
        Self {
            query_material: Some(query_material),
            nullifier_material: Some(nullifier_material),
            ..self
        }
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
                let body = Self::response_body_or_fallback(resp).await;
                if let Ok(error_resp) =
                    serde_json::from_str::<ServiceApiError<IndexerErrorCode>>(&body)
                {
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
                return Err(AuthenticatorError::IndexerError { status, body });
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

    /// Returns the index for the holder's World ID.
    ///
    /// # Definition
    ///
    /// The `leaf_index` is the main (internal) identifier of a World ID. It is registered in
    /// the `WorldIDRegistry` and represents the index at the Merkle tree where the World ID
    /// resides.
    ///
    /// # Notes
    /// - The `leaf_index` is used as input in the nullifier generation, ensuring a nullifier
    ///   will always be the same for the same RP context and the same World ID (allowing for uniqueness).
    /// - The `leaf_index` is generally not exposed outside Authenticators. It is not a secret because
    ///   it's not exposed to RPs outside ZK-circuits, but the only acceptable exposure outside an Authenticator
    ///   is to fetch Merkle inclusion proofs from an indexer or it may create a pseudonymous identifier.
    /// - The `leaf_index` is stored as a `uint64` inside packed account data.
    #[must_use]
    pub fn leaf_index(&self) -> u64 {
        (self.packed_account_data & MASK_LEAF_INDEX).to::<u64>()
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
    ) -> Result<AccountInclusionProof<TREE_DEPTH>, AuthenticatorError> {
        let url = format!("{}/inclusion-proof", self.config.indexer_url());
        let req = IndexerQueryRequest {
            leaf_index: self.leaf_index(),
        };
        let response = self.http_client.post(&url).json(&req).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(AuthenticatorError::IndexerError {
                status,
                body: Self::response_body_or_fallback(response).await,
            });
        }
        let response = response.json::<AccountInclusionProof<TREE_DEPTH>>().await?;

        Ok(response)
    }

    /// Fetches the current authenticator public key set for the account.
    ///
    /// This is used by mutation operations to compute old/new offchain signer commitments
    /// without requiring Merkle proof generation.
    ///
    /// # Errors
    /// - Will error if the provided indexer URL is not valid or if there are HTTP call failures.
    /// - Will error if the user is not registered on the `WorldIDRegistry`.
    pub async fn fetch_authenticator_pubkeys(
        &self,
    ) -> Result<AuthenticatorPublicKeySet, AuthenticatorError> {
        let url = format!("{}/authenticator-pubkeys", self.config.indexer_url());
        let req = IndexerQueryRequest {
            leaf_index: self.leaf_index(),
        };
        let response = self.http_client.post(&url).json(&req).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(AuthenticatorError::IndexerError {
                status,
                body: Self::response_body_or_fallback(response).await,
            });
        }
        let response = response
            .json::<IndexerAuthenticatorPubkeysResponse>()
            .await?;
        Self::decode_indexer_pubkeys(response.authenticator_pubkeys)
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
                    body: Self::response_body_or_fallback(resp).await,
                });
            }

            let response: IndexerSignatureNonceResponse = resp.json().await?;
            Ok(response.signature_nonce)
        }
    }

    /// Signs an arbitrary challenge with the authenticator's on-chain key following
    /// [ERC-191](https://eips.ethereum.org/EIPS/eip-191).
    ///
    /// # Warning
    /// This is considered a dangerous operation because it leaks the user's on-chain key,
    /// hence its `leaf_index`. The only acceptable use is to prove the user's `leaf_index`
    /// to a Recovery Agent. The Recovery Agent is the only party beyond the user who needs
    /// to know the `leaf_index`.
    ///
    /// # Use
    /// - This method is used to prove ownership over a leaf index **only for Recovery Agents**.
    pub fn danger_sign_challenge(&self, challenge: &[u8]) -> Result<Signature, AuthenticatorError> {
        self.signer
            .onchain_signer()
            .sign_message_sync(challenge)
            .map_err(|e| AuthenticatorError::Generic(format!("signature error: {e}")))
    }

    /// Gets an object to request OPRF computations to OPRF Nodes.
    ///
    /// # Arguments
    /// - `account_inclusion_proof`: an optionally cached object can be passed to
    ///   avoid an additional network call. If not passed, it'll be fetched from the indexer.
    ///
    /// # Errors
    /// - Will return an error if there are no OPRF Nodes configured or if the threshold is invalid.
    /// - Will return an error if proof materials are not loaded.
    /// - Will return an error if there are issues fetching an inclusion proof.
    async fn get_oprf_entrypoint(
        &self,
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
    ) -> Result<OprfEntrypoint<'_>, AuthenticatorError> {
        // Check OPRF Config
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

        let query_material = self
            .query_material
            .as_ref()
            .ok_or(AuthenticatorError::ProofMaterialsNotLoaded)?;

        // Fetch inclusion_proof && authenticator key_set if not provided
        let account_inclusion_proof = if let Some(account_inclusion_proof) = account_inclusion_proof
        {
            account_inclusion_proof
        } else {
            self.fetch_inclusion_proof().await?
        };

        let key_index = account_inclusion_proof
            .authenticator_pubkeys
            .iter()
            .position(|pk| {
                pk.as_ref()
                    .is_some_and(|pk| pk.pk == self.offchain_pubkey().pk)
            })
            .ok_or(AuthenticatorError::PublicKeyNotFound)? as u64;

        let authenticator_input = AuthenticatorProofInput::new(
            account_inclusion_proof.authenticator_pubkeys,
            account_inclusion_proof.inclusion_proof,
            self.signer
                .offchain_signer_private_key()
                .expose_secret()
                .clone(),
            key_index,
        );

        Ok(OprfEntrypoint::new(
            services,
            threshold,
            query_material,
            authenticator_input,
            &self.ws_connector,
        ))
    }

    fn decode_indexer_pubkeys(
        pubkeys: Vec<Option<U256>>,
    ) -> Result<AuthenticatorPublicKeySet, AuthenticatorError> {
        decode_sparse_authenticator_pubkeys(pubkeys).map_err(|e| match e {
            SparseAuthenticatorPubkeysError::SlotOutOfBounds {
                slot_index,
                max_supported_slot,
            } => AuthenticatorError::InvalidIndexerPubkeySlot {
                slot_index,
                max_supported_slot,
            },
            SparseAuthenticatorPubkeysError::InvalidCompressedPubkey { slot_index, reason } => {
                PrimitiveError::Deserialization(format!(
                    "invalid authenticator public key returned by indexer at slot {slot_index}: {reason}"
                ))
                .into()
            }
        })
    }

    fn insert_or_reuse_authenticator_key(
        key_set: &mut AuthenticatorPublicKeySet,
        new_authenticator_pubkey: EdDSAPublicKey,
    ) -> Result<usize, AuthenticatorError> {
        if let Some(index) = key_set.iter().position(Option::is_none) {
            key_set.try_set_at_index(index, new_authenticator_pubkey)?;
            Ok(index)
        } else {
            key_set.try_push(new_authenticator_pubkey)?;
            Ok(key_set.len() - 1)
        }
    }

    /// Generates a nullifier for a World ID Proof (through OPRF Nodes).
    ///
    /// A [`Nullifier`] is a unique, one-time use, anonymous identifier for a World ID
    /// on a specific RP context. See [`Nullifier`] for more details.
    ///
    /// # Arguments
    /// - `proof_request`: the request received from the RP.
    /// - `account_inclusion_proof`: an optionally cached object can be passed to
    ///   avoid an additional network call. If not passed, it'll be fetched from the indexer.
    ///
    /// A Nullifier takes an `action` as input:
    /// - If `proof_request` is for a Session Proof, a random internal `action` is generated. This
    ///   is opaque to RPs, and verified internally in the verification contract.
    /// - If `proof_request` is for a Uniqueness Proof, the `action` is provided by the RP,
    ///   if not provided a default of [`FieldElement::ZERO`] is used.
    ///
    /// # Errors
    ///
    /// - Will raise a [`ProofError`] if there is any issue generating the nullifier. For example,
    ///   network issues, unexpected incorrect responses from OPRF Nodes.
    /// - Raises an error if the OPRF Nodes configuration is not correctly set.
    pub async fn generate_nullifier(
        &self,
        proof_request: &ProofRequest,
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
    ) -> Result<FullOprfOutput, AuthenticatorError> {
        let mut rng = rand::rngs::OsRng;

        let oprf_entrypoint = self.get_oprf_entrypoint(account_inclusion_proof).await?;

        Ok(oprf_entrypoint
            .gen_nullifier(&mut rng, proof_request)
            .await?)
    }

    /// Generates a blinding factor for a Credential sub (through OPRF Nodes). The credential
    /// blinding factor enables every credential to have a different subject identifier, see
    /// [`Credential::sub`] for more details.
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
        let mut rng = rand::rngs::OsRng;

        // This is called sporadic enough that fetching fresh is reasonable
        let oprf_entrypoint = self.get_oprf_entrypoint(None).await?;

        let (blinding_factor, _share_epoch) = oprf_entrypoint
            .gen_credential_blinding_factor(&mut rng, issuer_schema_id)
            .await?;

        Ok(blinding_factor)
    }

    /// Builds a [`SessionId`] object which can be used for Session Proofs. This has two uses:
    /// 1. Creating a new Sesssion, i.e. generating a [`SessionId`] for the first time.
    /// 2. Reconstructing a session for a Session Proof, particularly if the `session_id_r_seed` is not cached.
    ///
    /// Internally, this generates the session's random seed (`r`) using OPRF Nodes. This seed is used to
    /// compute the [`SessionId::commitment`] for Session Proofs.
    ///
    /// # Arguments
    /// - `proof_request`: the request received from the RP to initialize a session id.
    /// - `session_id_r_seed`: the seed (see below) if it was already generated previously and it's cached.
    /// - `account_inclusion_proof`: an optionally cached object can be passed to
    ///   avoid an additional network call. If not passed, it'll be fetched from the indexer.
    ///
    /// # Returns
    /// - `session_id`: The generated [`SessionId`] to be shared with the requesting RP.
    /// - `session_id_r_seed`: The `r` value used for this session so the Authenticator can cache it.
    ///
    /// # Seed (`session_id_r_seed`)
    /// - If a `session_id_r_seed` (`r`) is not provided, it'll be derived/re-derived with the OPRF nodes.
    /// - Even if `r` has been generated before, the same `r` will be computed again for the same
    ///   context (i.e. `rpId`, [`SessionId::oprf_seed`]). This means caching `r` is optional but RECOMMENDED.
    /// -  Caching behavior is the responsibility of the Authenticator (and/or its relevant SDKs), not this crate.
    /// - More information about the seed can be found in [`SessionId::from_r_seed`].
    pub async fn build_session_id(
        &self,
        proof_request: &ProofRequest,
        session_id_r_seed: Option<FieldElement>,
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
    ) -> Result<(SessionId, FieldElement), AuthenticatorError> {
        let mut rng = rand::rngs::OsRng;

        let oprf_seed = match proof_request.session_id {
            Some(session_id) => session_id.oprf_seed,
            None => SessionId::generate_oprf_seed(&mut rng),
        };

        let session_id_r_seed = match session_id_r_seed {
            Some(seed) => seed,
            None => {
                let entrypoint = self.get_oprf_entrypoint(account_inclusion_proof).await?;
                let oprf_output = entrypoint
                    .gen_session_id_r_seed(&mut rng, proof_request, oprf_seed)
                    .await?;
                oprf_output.verifiable_oprf_output.output.into()
            }
        };

        let session_id = SessionId::from_r_seed(self.leaf_index(), session_id_r_seed, oprf_seed)?;

        if let Some(request_session_id) = proof_request.session_id {
            if request_session_id != session_id {
                return Err(AuthenticatorError::SessionIdMismatch);
            }
        }

        Ok((session_id, session_id_r_seed))
    }

    /// Generates a complete [`ProofResponse`] for
    /// the given [`ProofRequest`] to respond to an RP request.
    ///
    /// This orchestrates session resolution, per-credential proof generation,
    /// response assembly, and self-validation.
    ///
    /// # Typical flow
    /// ```rust,ignore
    /// // <- check request can be fulfilled with available credentials
    /// let nullifier = authenticator.generate_nullifier(&request, None).await?;
    /// // <- check replay guard using nullifier.oprf_output()
    /// let (response, meta) = authenticator.generate_proof(&request, nullifier, &creds, ...).await?;
    /// // <- cache `session_id_r_seed` (to speed future proofs) and `nullifier` (to prevent replays)
    /// ```
    ///
    /// # Arguments
    /// - `proof_request` — the RP's full request.
    /// - `nullifier` — the OPRF nullifier output, obtained from
    ///   [`generate_nullifier`](Self::generate_nullifier). The caller MUST check
    ///   for replays before calling this method to avoid wasted computation.
    /// - `credentials` — one [`CredentialInput`] per credential to prove,
    ///   matched to request items by `issuer_schema_id`.
    /// - `account_inclusion_proof` — a cached inclusion proof if available (a fresh one will be fetched otherwise)
    /// - `session_id_r_seed` — a cached session `r` seed for Session Proofs. If not available, it will be
    ///   re-computed.
    ///
    /// # Caller Responsibilities
    /// 1. The caller must ensure the request can be fulfilled with the credentials which the user has available,
    ///    and provide such credentials.
    /// 2. The caller must ensure the nullifier has not been used before.
    ///
    /// # Errors
    /// - [`AuthenticatorError::CredentialMismatch`] if the provided credentials
    ///   cannot satisfy the request (including constraints).
    /// - Other `AuthenticatorError` variants on proof circuit or validation failures.
    pub async fn generate_proof(
        &self,
        proof_request: &ProofRequest,
        nullifier: FullOprfOutput,
        credentials: &[CredentialInput],
        account_inclusion_proof: Option<AccountInclusionProof<TREE_DEPTH>>,
        session_id_r_seed: Option<FieldElement>,
    ) -> Result<ProofResult, AuthenticatorError> {
        // 1. Determine request items to prove
        let available: std::collections::HashSet<u64> = credentials
            .iter()
            .map(|c| c.credential.issuer_schema_id)
            .collect();
        let items_to_prove = proof_request
            .credentials_to_prove(&available)
            .ok_or(AuthenticatorError::UnfullfilableRequest)?;

        // 2. Resolve session seed
        let resolved_session_seed = if proof_request.is_session_proof() {
            if let Some(seed) = session_id_r_seed {
                // Validate the cached seed produces the expected session ID
                let oprf_seed = proof_request
                    .session_id
                    .expect("session proof must have session_id")
                    .oprf_seed;
                let computed = SessionId::from_r_seed(self.leaf_index(), seed, oprf_seed)?;
                let expected = proof_request
                    .session_id
                    .expect("session proof must have session_id");
                if computed != expected {
                    return Err(AuthenticatorError::SessionIdMismatch);
                }
                Some(seed)
            } else {
                let (_session_id, seed) = self
                    .build_session_id(proof_request, None, account_inclusion_proof)
                    .await?;
                Some(seed)
            }
        } else {
            None
        };

        // 3. Generate per-credential proofs for the selected items
        let creds_by_schema: std::collections::HashMap<u64, &CredentialInput> = credentials
            .iter()
            .map(|c| (c.credential.issuer_schema_id, c))
            .collect();

        let mut responses = Vec::with_capacity(items_to_prove.len());
        for request_item in &items_to_prove {
            let cred_input = creds_by_schema[&request_item.issuer_schema_id];

            let response_item = self.generate_credential_proof(
                nullifier.clone(),
                request_item,
                &cred_input.credential,
                cred_input.blinding_factor,
                resolved_session_seed,
                proof_request.session_id,
                proof_request.created_at,
            )?;
            responses.push(response_item);
        }

        // 3. Assemble response
        let proof_response = ProofResponse {
            id: proof_request.id.clone(),
            version: proof_request.version,
            session_id: proof_request.session_id,
            responses,
            error: None,
        };

        // 4. Validate and return response
        proof_request.validate_response(&proof_response)?;
        Ok(ProofResult {
            session_id_r_seed: resolved_session_seed,
            proof_response,
        })
    }

    /// Generates a single World ID Proof from a provided `[ProofRequest]` and `[Credential]`. This
    /// method generates the raw proof to be translated into a Uniqueness Proof or a Session Proof for the RP.
    ///
    /// The correct entrypoint for an RP request is [`Self::generate_proof`].
    ///
    /// This assumes the RP's `[ProofRequest]` has already been parsed to determine
    /// which `[Credential]` is appropriate for the request. This method responds to a
    /// specific `[RequestItem]` (a `[ProofRequest]` may contain multiple items).
    ///
    /// # Arguments
    /// - `oprf_nullifier`: The output representing the nullifier, generated from the `generate_nullifier` function. All proofs
    ///   require this attribute.
    /// - `request_item`: The specific `RequestItem` that is being resolved from the RP's `ProofRequest`.
    /// - `credential`: The Credential to be used for the proof that fulfills the `RequestItem`.
    /// - `credential_sub_blinding_factor`: The blinding factor for the Credential's sub.
    /// - `session_id_r_seed`: The session ID random seed, obtained via [`build_session_id`](Self::build_session_id).
    ///   For Uniqueness Proofs (when `session_id` is `None`), this value is ignored by the circuit.
    /// - `session_id`: The expected session ID provided by the RP. Only needed for Session Proofs. Obtained from the RP's [`ProofRequest`].
    /// - `request_timestamp`: The timestamp of the request. Obtained from the RP's [`ProofRequest`].
    ///
    /// # Errors
    /// - Will error if the any of the provided parameters are not valid.
    /// - Will error if any of the required network requests fail.
    /// - Will error if the user does not have a registered World ID.
    #[expect(clippy::too_many_arguments)]
    fn generate_credential_proof(
        &self,
        oprf_nullifier: FullOprfOutput,
        request_item: &RequestItem,
        credential: &Credential,
        credential_sub_blinding_factor: FieldElement,
        session_id_r_seed: Option<FieldElement>,
        session_id: Option<SessionId>,
        request_timestamp: u64,
    ) -> Result<ResponseItem, AuthenticatorError> {
        let mut rng = rand::rngs::OsRng;

        let nullifier_material = self
            .nullifier_material
            .as_ref()
            .ok_or(AuthenticatorError::ProofMaterialsNotLoaded)?;

        let merkle_root: FieldElement = oprf_nullifier.query_proof_input.merkle_root.into();
        let action_from_query: FieldElement = oprf_nullifier.query_proof_input.action.into();

        let expires_at_min = request_item.effective_expires_at_min(request_timestamp);

        let (proof, _public_inputs, nullifier) = generate_nullifier_proof(
            nullifier_material,
            &mut rng,
            credential,
            credential_sub_blinding_factor,
            oprf_nullifier,
            request_item,
            session_id.map(|v| v.commitment),
            session_id_r_seed,
            expires_at_min,
        )?;

        let proof = ZeroKnowledgeProof::from_groth16_proof(&proof, merkle_root);

        // Construct the appropriate response item based on proof type
        let nullifier_fe: FieldElement = nullifier.into();
        let response_item = if session_id.is_some() {
            let session_nullifier = SessionNullifier::new(nullifier_fe, action_from_query)?;
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
                nullifier_fe.into(),
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
            let body_text = Self::response_body_or_fallback(resp).await;
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
            let body_text = Self::response_body_or_fallback(resp).await;
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
            let body_text = Self::response_body_or_fallback(resp).await;
            Err(AuthenticatorError::GatewayError {
                status,
                body: body_text,
            })
        }
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
        fetch_gateway_status(&self.http_client, self.config.gateway_url(), request_id).await
    }

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

        let resp = self
            .http_client
            .post(format!(
                "{}/initiate-recovery-agent-update",
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
            let body_text = Self::response_body_or_fallback(resp).await;
            Err(AuthenticatorError::GatewayError {
                status,
                body: body_text,
            })
        }
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

        let resp = self
            .http_client
            .post(format!(
                "{}/execute-recovery-agent-update",
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
            let body_text = Self::response_body_or_fallback(resp).await;
            Err(AuthenticatorError::GatewayError {
                status,
                body: body_text,
            })
        }
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

        let resp = self
            .http_client
            .post(format!(
                "{}/cancel-recovery-agent-update",
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
            let body_text = Self::response_body_or_fallback(resp).await;
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
    async fn new(
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
            let body_text = Authenticator::response_body_or_fallback(resp).await;
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

    /// The provided credentials do not satisfy the proof request.
    ///
    /// This usually means the authenticator made an incorrect selection of credentials.
    #[error("Proof request cannot be fulfilled with the provided credentials.")]
    UnfullfilableRequest,

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

    /// Indexer returned an authenticator key slot that exceeds supported key capacity.
    #[error(
        "Invalid indexer authenticator pubkey slot {slot_index}; max supported slot is {max_supported_slot}"
    )]
    InvalidIndexerPubkeySlot {
        /// Slot index returned by the indexer.
        slot_index: usize,
        /// Highest supported slot index.
        max_supported_slot: usize,
    },

    /// The assembled proof response failed self-validation against the request.
    #[error(transparent)]
    ResponseValidationError(#[from] ValidationError),

    /// Proof materials not loaded. Call `with_proof_materials` before generating proofs.
    #[error("Proof materials not loaded. Call `with_proof_materials` before generating proofs.")]
    ProofMaterialsNotLoaded,

    /// The session ID computed for this proof does not match the expected session ID from the proof request.
    ///
    /// This indicates the `session_id` provided by the RP is invalid or compromised, as
    /// the only other failure option is OPRFs not having performed correct computations.
    #[error("the expected session id and the generated session id do not match")]
    SessionIdMismatch,

    /// Generic error for other unexpected issues.
    #[error("{0}")]
    Generic(String),
}

#[derive(Debug)]
enum PollResult {
    Retryable,
    TerminalError(AuthenticatorError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{U256, address};
    use world_id_primitives::authenticator::MAX_AUTHENTICATOR_KEYS;

    fn test_pubkey(seed_byte: u8) -> EdDSAPublicKey {
        Signer::from_seed_bytes(&[seed_byte; 32])
            .unwrap()
            .offchain_signer_pubkey()
    }

    fn encoded_test_pubkey(seed_byte: u8) -> U256 {
        test_pubkey(seed_byte).to_ethereum_representation().unwrap()
    }

    #[test]
    fn test_insert_or_reuse_authenticator_key_reuses_empty_slot() {
        let mut key_set =
            AuthenticatorPublicKeySet::new(vec![test_pubkey(1), test_pubkey(2), test_pubkey(4)])
                .unwrap();
        key_set[1] = None;
        let new_key = test_pubkey(3);

        let index =
            Authenticator::insert_or_reuse_authenticator_key(&mut key_set, new_key).unwrap();

        assert_eq!(index, 1);
        assert_eq!(key_set.len(), 3);
        assert_eq!(key_set[1].as_ref().unwrap().pk, test_pubkey(3).pk);
    }

    #[test]
    fn test_insert_or_reuse_authenticator_key_appends_when_no_empty_slot() {
        let mut key_set = AuthenticatorPublicKeySet::new(vec![test_pubkey(1)]).unwrap();
        let new_key = test_pubkey(2);

        let index =
            Authenticator::insert_or_reuse_authenticator_key(&mut key_set, new_key).unwrap();

        assert_eq!(index, 1);
        assert_eq!(key_set.len(), 2);
        assert_eq!(key_set[1].as_ref().unwrap().pk, test_pubkey(2).pk);
    }

    #[test]
    fn test_decode_indexer_pubkeys_trims_trailing_empty_slots() {
        let mut encoded_pubkeys = vec![Some(encoded_test_pubkey(1)), Some(encoded_test_pubkey(2))];
        encoded_pubkeys.extend(vec![None; MAX_AUTHENTICATOR_KEYS + 5]);

        let key_set = Authenticator::decode_indexer_pubkeys(encoded_pubkeys).unwrap();

        assert_eq!(key_set.len(), 2);
        assert_eq!(key_set[0].as_ref().unwrap().pk, test_pubkey(1).pk);
        assert_eq!(key_set[1].as_ref().unwrap().pk, test_pubkey(2).pk);
    }

    #[test]
    fn test_decode_indexer_pubkeys_rejects_used_slot_beyond_max() {
        let mut encoded_pubkeys = vec![None; MAX_AUTHENTICATOR_KEYS + 1];
        encoded_pubkeys[MAX_AUTHENTICATOR_KEYS] = Some(encoded_test_pubkey(1));

        let error = Authenticator::decode_indexer_pubkeys(encoded_pubkeys).unwrap_err();
        assert!(matches!(
            error,
            AuthenticatorError::InvalidIndexerPubkeySlot {
                slot_index,
                max_supported_slot
            } if slot_index == MAX_AUTHENTICATOR_KEYS && max_supported_slot == MAX_AUTHENTICATOR_KEYS - 1
        ));
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
    #[cfg(not(target_arch = "wasm32"))]
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
            query_material: None,
            nullifier_material: None,
        };

        let nonce = authenticator.signing_nonce().await.unwrap();

        assert_eq!(nonce, expected_nonce);
        mock.assert_async().await;
        drop(server);
    }

    #[test]
    fn test_danger_sign_challenge_returns_valid_signature() {
        let authenticator = Authenticator {
            config: Config::new(
                None,
                1,
                address!("0x0000000000000000000000000000000000000001"),
                "http://indexer.example.com".to_string(),
                "http://gateway.example.com".to_string(),
                Vec::new(),
                2,
            )
            .unwrap(),
            packed_account_data: U256::from(1),
            signer: Signer::from_seed_bytes(&[1u8; 32]).unwrap(),
            registry: None,
            http_client: reqwest::Client::new(),
            ws_connector: Connector::Plain,
            query_material: None,
            nullifier_material: None,
        };

        let challenge = b"test challenge";
        let signature = authenticator.danger_sign_challenge(challenge).unwrap();

        let recovered = signature
            .recover_address_from_msg(challenge)
            .expect("should recover address");
        assert_eq!(recovered, authenticator.onchain_address());
    }

    #[test]
    fn test_danger_sign_challenge_different_challenges_different_signatures() {
        let authenticator = Authenticator {
            config: Config::new(
                None,
                1,
                address!("0x0000000000000000000000000000000000000001"),
                "http://indexer.example.com".to_string(),
                "http://gateway.example.com".to_string(),
                Vec::new(),
                2,
            )
            .unwrap(),
            packed_account_data: U256::from(1),
            signer: Signer::from_seed_bytes(&[1u8; 32]).unwrap(),
            registry: None,
            http_client: reqwest::Client::new(),
            ws_connector: Connector::Plain,
            query_material: None,
            nullifier_material: None,
        };

        let sig_a = authenticator.danger_sign_challenge(b"challenge A").unwrap();
        let sig_b = authenticator.danger_sign_challenge(b"challenge B").unwrap();
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn test_danger_sign_challenge_deterministic() {
        let authenticator = Authenticator {
            config: Config::new(
                None,
                1,
                address!("0x0000000000000000000000000000000000000001"),
                "http://indexer.example.com".to_string(),
                "http://gateway.example.com".to_string(),
                Vec::new(),
                2,
            )
            .unwrap(),
            packed_account_data: U256::from(1),
            signer: Signer::from_seed_bytes(&[1u8; 32]).unwrap(),
            registry: None,
            http_client: reqwest::Client::new(),
            ws_connector: Connector::Plain,
            query_material: None,
            nullifier_material: None,
        };

        let challenge = b"deterministic test";
        let sig1 = authenticator.danger_sign_challenge(challenge).unwrap();
        let sig2 = authenticator.danger_sign_challenge(challenge).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[tokio::test]
    #[cfg(not(target_arch = "wasm32"))]
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
            query_material: None,
            nullifier_material: None,
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
