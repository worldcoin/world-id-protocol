//! This module contains all the base functionality to support Authenticators in World ID. See
//! [`Authenticator`] for a definition.

use crate::{
    error::{AuthenticatorError, PollResult},
    init::InitializingAuthenticator,
};

use std::sync::Arc;

use crate::{
    account::AccountAuthenticators,
    api_types::{
        AccountInclusionProof, GatewayRequestState, IndexerAuthenticatorPubkeysResponse,
        IndexerAuthenticatorsResponse, IndexerErrorCode, IndexerPackedAccountRequest,
        IndexerPackedAccountResponse, IndexerQueryRequest, IndexerSignatureNonceResponse,
        ServiceApiError,
    },
    service_client::{ServiceClient, ServiceKind, default_http_client},
};
use world_id_primitives::{Credential, FieldElement, ProofResponse, Signer};

pub use crate::ohttp::OhttpClientConfig;
use alloy::{
    primitives::Address,
    providers::DynProvider,
    signers::{Signature, SignerSync},
};
use ark_serialize::CanonicalSerialize;
use eddsa_babyjubjub::EdDSAPublicKey;
use ruint::{aliases::U256, uint};
use taceo_oprf::client::Connector;
use world_id_primitives::{
    AuthenticatorPublicKeySet, PrimitiveError, SparseAuthenticatorPubkeysError,
};
pub use world_id_primitives::{Config, ServiceEndpoint, TREE_DEPTH, authenticator::ProtocolSigner};
use world_id_proof::artifacts::ZkArtifactSource;
use world_id_registries::world_id::WorldIdRegistry::WorldIdRegistryInstance;

#[expect(unused_imports, reason = "used for docs")]
use world_id_primitives::{Nullifier, SessionId};

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
    /// The session_id_r_seed (`r`), when a session was created or proven.
    ///
    /// Returned for session proofs and for uniqueness proofs that create a bound
    /// session. The SDK should cache this keyed by [`SessionId::oprf_seed`].
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
/// with the Protocol, and is therefore permitted to act on that account's behalf. An Authenticator
/// is the agent of users/holders. Each Authenticator is registered in the `WorldIDRegistry`
/// through their authorized keypairs.
///
/// For example, an Authenticator can live in a mobile wallet or a web application.
pub struct Authenticator {
    /// General configuration for the Authenticator.
    pub config: Config,
    /// The packed account data for the holder's World ID is a `uint256` defined in the `WorldIDRegistry` contract as:
    /// `recovery_counter` (32 bits) | `pubkey_id`, this authenticator's slot (32 bits) | reserved (128 bits) | `leaf_index` (64 bits)
    pub packed_account_data: U256,
    pub(crate) signer: Signer,
    pub(crate) registry: Option<Arc<WorldIdRegistryInstance<DynProvider>>>,
    pub(crate) indexer_client: ServiceClient,
    pub(crate) gateway_client: ServiceClient,
    pub(crate) ws_connector: Connector,
    pub(crate) zk_artifact_source: Arc<dyn ZkArtifactSource>,
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
    /// Initialize an Authenticator from a seed, config, and a source of ZK artifacts.
    ///
    /// The artifact source supplies the proving material for all proof generation. Use
    /// [`world_id_proof::artifacts::dummy::DummyZkArtifactSource`] in tests or code paths
    /// that never generate proofs.
    ///
    /// This method requires the authenticator address derived from `seed` to already be present
    /// on-chain in the `WorldIDRegistry`.
    ///
    /// If no account exists for that authenticator, it returns
    /// [`AuthenticatorError::AccountDoesNotExist`]. The same error can also occur transiently
    /// while a create-account or authenticator-management operation is still pending on-chain and
    /// the authenticator address has not been registered yet. Consumers that are coordinating such
    /// operations should poll the gateway request and retry initialization after finalization.
    ///
    /// Indexer DB catch-up is separate and does not block initialization, since packed account data
    /// is read from the registry (directly or via the indexer's chain-backed packed-account
    /// endpoint).
    ///
    /// # Errors
    /// - Will error if the provided seed is invalid (not 32 bytes).
    /// - Will error if the RPC URL is invalid.
    /// - Will error if there are contract call failures.
    /// - Will return [`AuthenticatorError::AccountDoesNotExist`] if the authenticator address
    ///   derived from `seed` is not currently registered on-chain, whether permanently or because a
    ///   relevant on-chain operation has not finalized yet.
    pub async fn init(
        seed: &[u8],
        config: Config,
        zk_artifact_source: Arc<dyn ZkArtifactSource>,
    ) -> Result<Self, AuthenticatorError> {
        let signer = Signer::from_seed_bytes(seed)?;
        let http_client = default_http_client()?;
        let registry = Self::registry_for(&config, http_client.clone());

        let indexer_client =
            ServiceClient::new(http_client.clone(), ServiceKind::Indexer, config.indexer())?;

        let gateway_client =
            ServiceClient::new(http_client, ServiceKind::Gateway, config.gateway())?;

        let packed_account_data = Self::fetch_packed_account_data_for(
            signer.onchain_signer_address(),
            registry.as_deref(),
            &config,
            &indexer_client,
        )
        .await?;

        Ok(Self {
            config,
            packed_account_data,
            signer,
            registry,
            indexer_client,
            gateway_client,
            ws_connector: ws_connector(),
            zk_artifact_source,
        })
    }

    /// Initializes an Authenticator for the account at `leaf_index` from a seed, without looking
    /// the account up by on-chain address.
    ///
    /// This is how a Proving Authenticator (WIP-104) is initialized: it has no management key
    /// registered on-chain, so [`Authenticator::init`] cannot find its account. It also works
    /// for an Admin Authenticator whose `leaf_index` is known, e.g. after a WIP-109 registration.
    ///
    /// The off-chain public key derived from `seed` must be registered on the account according
    /// to the indexer. Its slot becomes [`Authenticator::pubkey_id`] and the account's recovery
    /// counter becomes [`Authenticator::recovery_counter`].
    ///
    /// A Proving Authenticator can generate proofs, but it cannot perform account operations
    /// such as [`Authenticator::insert_authenticator`]: the registry rejects its signatures.
    ///
    /// # Errors
    /// - [`AuthenticatorError::AccountDoesNotExist`] if the indexer does not know the account.
    /// - [`AuthenticatorError::PublicKeyNotFound`] if the public key is not registered on the
    ///   account. Right after a registration finalizes this can be transient, until the indexer
    ///   catches up.
    /// - Other errors if the seed or configuration is invalid or a network call fails.
    pub async fn init_with_leaf_index(
        seed: &[u8],
        leaf_index: u64,
        config: Config,
        zk_artifact_source: Arc<dyn ZkArtifactSource>,
    ) -> Result<Self, AuthenticatorError> {
        let authenticators = Self::fetch_account_authenticators(leaf_index, &config).await?;
        Self::from_account_authenticators(
            seed,
            leaf_index,
            &authenticators,
            config,
            zk_artifact_source,
        )
    }

    /// Builds the Authenticator for `seed` on the account at `leaf_index` from the account's
    /// `authenticators`, without a network call.
    ///
    /// The off-chain public key derived from `seed` must be registered in `authenticators`. Its
    /// slot becomes [`Authenticator::pubkey_id`] and the account's recovery counter becomes
    /// [`Authenticator::recovery_counter`].
    ///
    /// # Errors
    /// - [`AuthenticatorError::PublicKeyNotFound`] if the public key is not in `authenticators`.
    /// - Other errors if the seed is invalid or the HTTP client cannot be built.
    pub(crate) fn from_account_authenticators(
        seed: &[u8],
        leaf_index: u64,
        authenticators: &AccountAuthenticators,
        config: Config,
        zk_artifact_source: Arc<dyn ZkArtifactSource>,
    ) -> Result<Self, AuthenticatorError> {
        let signer = Signer::from_seed_bytes(seed)?;
        let packed_account_data = authenticators
            .packed_account_data(leaf_index, &signer.offchain_signer_pubkey())
            .ok_or(AuthenticatorError::PublicKeyNotFound)?;
        let http_client = default_http_client()?;
        Ok(Self {
            registry: Self::registry_for(&config, http_client.clone()),
            indexer_client: ServiceClient::new(
                http_client.clone(),
                ServiceKind::Indexer,
                config.indexer(),
            )?,
            gateway_client: ServiceClient::new(
                http_client,
                ServiceKind::Gateway,
                config.gateway(),
            )?,
            config,
            packed_account_data,
            signer,
            ws_connector: ws_connector(),
            zk_artifact_source,
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
        let gateway_client = ServiceClient::new(
            default_http_client()?,
            ServiceKind::Gateway,
            config.gateway(),
        )?;
        InitializingAuthenticator::new(seed, config, recovery_address, gateway_client).await
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
        zk_artifact_source: Arc<dyn ZkArtifactSource>,
    ) -> Result<Self, AuthenticatorError> {
        match Self::init(seed, config.clone(), Arc::clone(&zk_artifact_source)).await {
            Ok(authenticator) => Ok(authenticator),
            Err(AuthenticatorError::AccountDoesNotExist) => {
                let gateway_client = ServiceClient::new(
                    default_http_client()?,
                    ServiceKind::Gateway,
                    config.gateway(),
                )?;
                let initializing_authenticator = InitializingAuthenticator::new(
                    seed,
                    config.clone(),
                    recovery_address,
                    gateway_client,
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
                        Ok(()) => {
                            match Self::init(seed, config.clone(), Arc::clone(&zk_artifact_source))
                                .await
                            {
                                Ok(auth) => Ok(auth),
                                Err(AuthenticatorError::AccountDoesNotExist) => {
                                    Err(PollResult::Retryable)
                                }
                                Err(e) => Err(PollResult::TerminalError(e)),
                            }
                        }
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

    /// Fetches the packed account data for this authenticator from the indexer or registry
    /// without mutating local state.
    ///
    /// # Errors
    /// Will error if the network call fails or if the account does not exist.
    pub async fn fetch_packed_account_data(&self) -> Result<U256, AuthenticatorError> {
        let by_address = self
            .fetch_packed_account_data_of(self.onchain_address())
            .await;
        match by_address {
            // An authenticator never changes accounts or slots, so only accept data for its own
            // leaf and slot. The recovery counter may change.
            Ok(packed)
                if packed & !MASK_RECOVERY_COUNTER
                    == self.packed_account_data & !MASK_RECOVERY_COUNTER =>
            {
                Ok(packed)
            }
            // A Proving Authenticator is registered with the zero address, so its own address is
            // unknown to the registry or registered on another account or slot. Look it up by leaf
            // index and public key instead.
            Ok(_) | Err(AuthenticatorError::AccountDoesNotExist) => {
                let authenticators = Self::fetch_authenticators_for(
                    self.leaf_index(),
                    &self.config,
                    &self.indexer_client,
                )
                .await?;
                // Only a Proving Authenticator may take this path. An Admin Authenticator the
                // registry no longer knows was revoked, and a stale indexed key must not revive it.
                let is_proving = authenticators
                    .find(&self.offchain_pubkey())
                    .is_some_and(|(_, address)| address.is_zero());
                if !is_proving {
                    return Err(AuthenticatorError::AccountDoesNotExist);
                }
                // A recovery revokes every authenticator. If the registry is ahead of the indexed
                // account, the indexed key may already be revoked.
                if let Some(registry) = self.registry() {
                    let current = registry
                        .getRecoveryCounter(self.leaf_index())
                        .call()
                        .await?;
                    if current != U256::from(authenticators.recovery_counter()) {
                        return Err(AuthenticatorError::AccountDoesNotExist);
                    }
                }
                authenticators
                    .packed_account_data(self.leaf_index(), &self.offchain_pubkey())
                    .ok_or(AuthenticatorError::AccountDoesNotExist)
            }
            result => result,
        }
    }

    /// Re-fetches the packed account data for this authenticator and updates local state.
    ///
    /// # Errors
    /// Will error if the network call fails or if the account does not exist.
    pub async fn refresh_packed_account_data(&mut self) -> Result<U256, AuthenticatorError> {
        let packed_account_data = self.fetch_packed_account_data().await?;
        self.packed_account_data = packed_account_data;
        Ok(packed_account_data)
    }

    /// Fetches the packed account data registered for the management key `address`, from the
    /// registry when an RPC URL is configured and from the indexer otherwise.
    ///
    /// # Errors
    /// - [`AuthenticatorError::AccountDoesNotExist`] if no account has `address` registered, or
    ///   a recovery revoked it.
    /// - Other errors if a network call fails.
    pub(crate) async fn fetch_packed_account_data_of(
        &self,
        address: Address,
    ) -> Result<U256, AuthenticatorError> {
        Self::fetch_packed_account_data_for(
            address,
            self.registry().as_deref(),
            &self.config,
            &self.indexer_client,
        )
        .await
    }

    /// Returns the packed account data registered for `onchain_signer_address`: the leaf index of
    /// its account, the account's recovery counter, and the address's `pubkey_id`.
    ///
    /// # Errors
    /// Will error if the network call fails or if the account does not exist.
    async fn fetch_packed_account_data_for(
        onchain_signer_address: Address,
        registry: Option<&WorldIdRegistryInstance<DynProvider>>,
        config: &Config,
        indexer_client: &ServiceClient,
    ) -> Result<U256, AuthenticatorError> {
        // If the registry is available through direct RPC calls, use it. Otherwise fallback to the indexer.
        let raw_index = if let Some(registry) = registry {
            // TODO: Better error handling to expose the specific failure
            let packed_account_data = registry
                .getPackedAccountData(onchain_signer_address)
                .call()
                .await?;

            // The registry keeps stale packed data for authenticators revoked by a recovery,
            // so compare the embedded recovery counter against the account's current one.
            if packed_account_data != U256::ZERO {
                let current_recovery_counter = registry
                    .getRecoveryCounter(leaf_index_of(packed_account_data))
                    .call()
                    .await?;
                if current_recovery_counter > recovery_counter_of(packed_account_data) {
                    return Err(AuthenticatorError::AccountDoesNotExist);
                }
            }

            packed_account_data
        } else {
            let req = IndexerPackedAccountRequest {
                authenticator_address: onchain_signer_address,
            };
            match indexer_client
                .post_json::<_, IndexerPackedAccountResponse>(
                    config.indexer_url(),
                    "/packed-account",
                    &req,
                )
                .await
            {
                Ok(response) => response.packed_account_data,
                Err(AuthenticatorError::IndexerError { status, body }) => {
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
                Err(other) => return Err(other),
            }
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
        leaf_index_of(self.packed_account_data)
    }

    /// Returns the recovery counter for the holder's World ID.
    ///
    /// The recovery counter is used to efficiently invalidate all the old keys when an account is recovered.
    #[must_use]
    pub fn recovery_counter(&self) -> U256 {
        recovery_counter_of(self.packed_account_data)
    }

    /// Returns this authenticator's `pubkey_id`: the slot of its off-chain public key in the
    /// account's key set.
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
        let req = IndexerQueryRequest {
            leaf_index: self.leaf_index(),
        };
        let response: AccountInclusionProof<TREE_DEPTH> = self
            .indexer_client
            .post_json(self.config.indexer_url(), "/inclusion-proof", &req)
            .await?;

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
        let req = IndexerQueryRequest {
            leaf_index: self.leaf_index(),
        };
        let response: IndexerAuthenticatorPubkeysResponse = self
            .indexer_client
            .post_json(self.config.indexer_url(), "/authenticator-pubkeys", &req)
            .await?;
        Self::decode_indexer_pubkeys(response.authenticator_pubkeys)
    }

    /// Fetches the registered authenticators of the account at `leaf_index` from the indexer's
    /// `/authenticators` endpoint, with clients built from `config`. Use it to read an account
    /// without an [`Authenticator`] for it.
    ///
    /// # Errors
    /// - [`AuthenticatorError::AccountDoesNotExist`] if the indexer does not know the account.
    /// - Other errors if a network call fails or the indexer returns an invalid account state.
    pub(crate) async fn fetch_account_authenticators(
        leaf_index: u64,
        config: &Config,
    ) -> Result<AccountAuthenticators, AuthenticatorError> {
        let indexer_client = ServiceClient::new(
            default_http_client()?,
            ServiceKind::Indexer,
            config.indexer(),
        )?;
        Self::fetch_authenticators_for(leaf_index, config, &indexer_client).await
    }

    /// Fetches the registered authenticators of the account at `leaf_index` from the indexer's
    /// `/authenticators` endpoint.
    pub(crate) async fn fetch_authenticators_for(
        leaf_index: u64,
        config: &Config,
        indexer_client: &ServiceClient,
    ) -> Result<AccountAuthenticators, AuthenticatorError> {
        let req = IndexerQueryRequest { leaf_index };
        let response: IndexerAuthenticatorsResponse = match indexer_client
            .post_json(config.indexer_url(), "/authenticators", &req)
            .await
        {
            // Only the indexer's own `not_found` means the account is unknown. Any other 404,
            // e.g. from an indexer without this endpoint or from a proxy, stays an indexer error.
            Err(AuthenticatorError::IndexerError { status, body })
                if status == reqwest::StatusCode::NOT_FOUND
                    && serde_json::from_str::<ServiceApiError<IndexerErrorCode>>(&body)
                        .is_ok_and(|error| matches!(error.code, IndexerErrorCode::NotFound)) =>
            {
                return Err(AuthenticatorError::AccountDoesNotExist);
            }
            result => result?,
        };
        response.try_into()
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
            let req = IndexerQueryRequest {
                leaf_index: self.leaf_index(),
            };
            let response: IndexerSignatureNonceResponse = self
                .indexer_client
                .post_json(self.config.indexer_url(), "/signature-nonce", &req)
                .await?;
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

    pub(crate) fn decode_indexer_pubkeys(
        pubkeys: Vec<Option<U256>>,
    ) -> Result<AuthenticatorPublicKeySet, AuthenticatorError> {
        AuthenticatorPublicKeySet::from_sparse_encoded_pubkeys(pubkeys).map_err(|e| match e {
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

    /// Returns the `WorldIDRegistry` reached through `http_client`, or `None` when no RPC URL is
    /// configured.
    fn registry_for(
        config: &Config,
        http_client: reqwest::Client,
    ) -> Option<Arc<WorldIdRegistryInstance<DynProvider>>> {
        config.rpc_url().map(|rpc_url| {
            let provider = alloy::providers::ProviderBuilder::new()
                .with_chain_id(config.chain_id())
                .connect_reqwest(http_client, rpc_url.clone());
            Arc::new(world_id_registries::world_id::WorldIdRegistry::new(
                *config.registry_address(),
                alloy::providers::Provider::erased(provider),
            ))
        })
    }
}

static MASK_RECOVERY_COUNTER: U256 =
    uint!(0xFFFFFFFF00000000000000000000000000000000000000000000000000000000_U256);
static MASK_PUBKEY_ID: U256 =
    uint!(0x00000000FFFFFFFF000000000000000000000000000000000000000000000000_U256);
static MASK_LEAF_INDEX: U256 =
    uint!(0x000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF_U256);

/// Packs account data as the `WorldIDRegistry`'s `PackedAccountData.pack` does: the recovery
/// counter in bits 224 to 255, the `pubkey_id` in bits 192 to 223 and the leaf index in bits 0 to
/// 63.
pub(crate) fn pack_account_data(recovery_counter: u32, pubkey_id: u32, leaf_index: u64) -> U256 {
    (U256::from(recovery_counter) << 224) | (U256::from(pubkey_id) << 192) | U256::from(leaf_index)
}

/// Returns the leaf index in packed account data.
pub(crate) fn leaf_index_of(packed_account_data: U256) -> u64 {
    (packed_account_data & MASK_LEAF_INDEX).to::<u64>()
}

/// Returns the recovery counter in packed account data.
fn recovery_counter_of(packed_account_data: U256) -> U256 {
    (packed_account_data & MASK_RECOVERY_COUNTER) >> 224
}

/// Returns the connector for WebSocket connections to OPRF nodes: TLS with the web PKI roots on
/// native targets, and the browser's own TLS in a browser.
fn ws_connector() -> Connector {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let rustls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Connector::Rustls(Arc::new(rustls_config))
    }
    #[cfg(target_arch = "wasm32")]
    Connector
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::AuthenticatorError, traits::OnchainKeyRepresentable};
    use alloy::primitives::{U256, address};
    use test_case::test_case;
    use world_id_primitives::MAX_AUTHENTICATOR_KEYS;

    fn test_pubkey(seed_byte: u8) -> EdDSAPublicKey {
        Signer::from_seed_bytes(&[seed_byte; 32])
            .unwrap()
            .offchain_signer_pubkey()
    }

    fn encoded_test_pubkey(seed_byte: u8) -> U256 {
        test_pubkey(seed_byte).to_ethereum_representation().unwrap()
    }

    fn dummy_zk_artifact_source() -> Arc<dyn ZkArtifactSource> {
        Arc::new(world_id_proof::artifacts::dummy::DummyZkArtifactSource)
    }

    #[test]
    fn test_insert_or_reuse_authenticator_key_reuses_empty_slot() {
        let mut key_set =
            AuthenticatorPublicKeySet::new(vec![test_pubkey(1), test_pubkey(2), test_pubkey(4)])
                .unwrap();
        key_set[1] = None;
        let new_key = test_pubkey(3);

        let index = key_set.insert_or_reuse(new_key).unwrap();

        assert_eq!(index, 1);
        assert_eq!(key_set.len(), 3);
        assert_eq!(key_set[1].as_ref().unwrap().pk, test_pubkey(3).pk);
    }

    #[test]
    fn test_insert_or_reuse_authenticator_key_appends_when_no_empty_slot() {
        let mut key_set = AuthenticatorPublicKeySet::new(vec![test_pubkey(1)]).unwrap();
        let new_key = test_pubkey(2);

        let index = key_set.insert_or_reuse(new_key).unwrap();

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

    #[test]
    fn packs_account_data_as_the_registry_does() {
        let packed = pack_account_data(3, 1, 42);

        assert_eq!(
            packed,
            uint!(0x000000030000000100000000000000000000000000000000000000000000002A_U256)
        );
        assert_eq!(leaf_index_of(packed), 42);
        assert_eq!(recovery_counter_of(packed), U256::from(3));
    }

    #[tokio::test]
    async fn registry_requests_end_at_the_http_clients_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let _unresponsive_rpc = tokio::spawn(async move {
            let mut connections = Vec::new();
            loop {
                connections.push(listener.accept().await.unwrap());
            }
        });
        let config = Config::new(
            Some(rpc_url),
            1,
            address!("0x0000000000000000000000000000000000000001"),
            ServiceEndpoint::direct("http://indexer.example.com".to_string()),
            ServiceEndpoint::direct("http://gateway.example.com".to_string()),
            Vec::new(),
            2,
        )
        .unwrap();
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .unwrap();
        let registry = Authenticator::registry_for(&config, http_client).unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            registry.getRecoveryCounter(1).call(),
        )
        .await
        .expect("the HTTP client's timeout ends the RPC request");

        assert!(result.is_err());
    }

    const LEAF_INDEX: u64 = 42;
    const SEED: [u8; 32] = [7; 32];
    const ADMIN: Address = address!("0x0000000000000000000000000000000000000011");

    fn config_with_indexer(indexer_url: String) -> Config {
        Config::new(
            None,
            1,
            address!("0x0000000000000000000000000000000000000001"),
            ServiceEndpoint::direct(indexer_url),
            ServiceEndpoint::direct("http://gateway.example.com".to_string()),
            Vec::new(),
            2,
        )
        .unwrap()
    }

    fn own_pubkey() -> EdDSAPublicKey {
        Signer::from_seed_bytes(&SEED)
            .unwrap()
            .offchain_signer_pubkey()
    }

    /// An `/authenticators` response with each slot's public key and address, and the commitment
    /// to the keys.
    fn authenticators_response(
        slots: &[Option<(EdDSAPublicKey, Address)>],
        recovery_counter: u64,
    ) -> IndexerAuthenticatorsResponse {
        let authenticator_pubkeys: Vec<_> = slots
            .iter()
            .map(|slot| {
                slot.as_ref()
                    .map(|(pubkey, _)| pubkey.to_ethereum_representation().unwrap())
            })
            .collect();
        let key_set = Authenticator::decode_indexer_pubkeys(authenticator_pubkeys.clone()).unwrap();
        IndexerAuthenticatorsResponse {
            authenticator_pubkeys,
            authenticator_addresses: slots
                .iter()
                .map(|slot| slot.as_ref().map(|(_, address)| *address))
                .collect(),
            offchain_signer_commitment: key_set.leaf_hash().into(),
            recovery_counter,
        }
    }

    fn authenticators_body(
        slots: &[Option<(EdDSAPublicKey, Address)>],
        recovery_counter: u64,
    ) -> serde_json::Value {
        serde_json::to_value(authenticators_response(slots, recovery_counter)).unwrap()
    }

    async fn mock_authenticators(
        server: &mut mockito::ServerGuard,
        status: usize,
        body: &serde_json::Value,
    ) -> mockito::Mock {
        server
            .mock("POST", "/authenticators")
            .match_body(mockito::Matcher::JsonString(
                serde_json::json!({ "leaf_index": "0x2a" }).to_string(),
            ))
            .with_status(status)
            .with_header("content-type", "application/json")
            .with_body(body.to_string())
            .create_async()
            .await
    }

    async fn init_with_leaf_index(
        server: &mockito::ServerGuard,
    ) -> Result<Authenticator, AuthenticatorError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Authenticator::init_with_leaf_index(
            &SEED,
            LEAF_INDEX,
            config_with_indexer(server.url()),
            dummy_zk_artifact_source(),
        )
        .await
    }

    #[tokio::test]
    async fn init_with_leaf_index_takes_the_slot_of_the_key() {
        let mut server = mockito::Server::new_async().await;
        let body = authenticators_body(
            &[
                Some((test_pubkey(1), ADMIN)),
                None,
                Some((own_pubkey(), Address::ZERO)),
            ],
            3,
        );
        let mock = mock_authenticators(&mut server, 200, &body).await;

        let authenticator = init_with_leaf_index(&server).await.unwrap();

        assert_eq!(authenticator.leaf_index(), LEAF_INDEX);
        assert_eq!(authenticator.pubkey_id(), U256::from(2));
        assert_eq!(authenticator.recovery_counter(), U256::from(3));
        mock.assert_async().await;
    }

    #[test]
    fn an_authenticator_needs_its_key_in_the_account_authenticators() {
        let authenticators = AccountAuthenticators::try_from(authenticators_response(
            &[Some((test_pubkey(1), ADMIN))],
            0,
        ))
        .unwrap();

        let result = Authenticator::from_account_authenticators(
            &SEED,
            LEAF_INDEX,
            &authenticators,
            config_with_indexer("http://indexer.example.com".to_string()),
            dummy_zk_artifact_source(),
        );

        assert!(matches!(result, Err(AuthenticatorError::PublicKeyNotFound)));
    }

    #[test_case(r#"{ "code": "not_found", "message": "not found" }"#, true; "the indexer's not_found")]
    #[test_case("404 page not found", false; "a 404 from elsewhere")]
    #[tokio::test]
    async fn only_the_indexers_not_found_means_an_unknown_account(
        body: &str,
        is_unknown_account: bool,
    ) {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/authenticators")
            .with_status(404)
            .with_body(body)
            .create_async()
            .await;

        let result = init_with_leaf_index(&server).await;

        if is_unknown_account {
            assert!(matches!(
                result,
                Err(AuthenticatorError::AccountDoesNotExist)
            ));
        } else {
            assert!(matches!(
                result,
                Err(AuthenticatorError::IndexerError { status, .. }) if status == reqwest::StatusCode::NOT_FOUND
            ));
        }
    }

    #[test_case(400, r#"{ "code": "account_does_not_exist", "message": "no account" }"#; "an unknown address")]
    #[test_case(200, r#"{ "packed_account_data": "0x7" }"#; "an address on another account")]
    #[test_case(200, r#"{ "packed_account_data": "0x2a" }"#; "an address at another slot")]
    #[tokio::test]
    async fn proving_authenticator_refreshes_by_leaf_index(
        packed_account_status: usize,
        packed_account_body: &str,
    ) {
        let mut server = mockito::Server::new_async().await;
        let body = authenticators_body(
            &[
                Some((test_pubkey(1), ADMIN)),
                Some((own_pubkey(), Address::ZERO)),
            ],
            3,
        );
        let _authenticators = mock_authenticators(&mut server, 200, &body).await;
        let _by_address = server
            .mock("POST", "/packed-account")
            .with_status(packed_account_status)
            .with_header("content-type", "application/json")
            .with_body(packed_account_body)
            .create_async()
            .await;
        let mut authenticator = init_with_leaf_index(&server).await.unwrap();

        let packed = authenticator.refresh_packed_account_data().await.unwrap();

        let expected = pack_account_data(3, 1, LEAF_INDEX);
        assert_eq!(packed, expected);
        assert_eq!(authenticator.packed_account_data, expected);
    }

    #[tokio::test]
    async fn refresh_does_not_revive_a_revoked_admin_authenticator() {
        let mut server = mockito::Server::new_async().await;
        let own_address = Signer::from_seed_bytes(&SEED)
            .unwrap()
            .onchain_signer_address();
        // The indexer still lists the key with an Admin address, as it would right after a
        // recovery revoked it, while the registry no longer knows the address.
        let body = authenticators_body(&[Some((own_pubkey(), own_address))], 0);
        let _authenticators = mock_authenticators(&mut server, 200, &body).await;
        let _by_address = server
            .mock("POST", "/packed-account")
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({ "code": "account_does_not_exist", "message": "revoked" })
                    .to_string(),
            )
            .create_async()
            .await;
        let mut authenticator = init_with_leaf_index(&server).await.unwrap();

        let result = authenticator.refresh_packed_account_data().await;

        assert!(matches!(
            result,
            Err(AuthenticatorError::AccountDoesNotExist)
        ));
    }

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
                serde_json::json!({ "authenticator_address": test_address }).to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({ "packed_account_data": format!("{:#x}", expected_packed_index) }).to_string(),
            )
            .create_async()
            .await;
        let config = Config::new(
            None,
            1,
            address!("0x0000000000000000000000000000000000000001"),
            ServiceEndpoint::direct(indexer_url),
            ServiceEndpoint::direct("http://gateway.example.com".to_string()),
            Vec::new(),
            2,
        )
        .unwrap();

        let indexer_client = ServiceClient::new(
            reqwest::Client::new(),
            ServiceKind::Indexer,
            config.indexer(),
        )
        .unwrap();

        let result = Authenticator::fetch_packed_account_data_for(
            test_address,
            None, // No registry, force indexer usage
            &config,
            &indexer_client,
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
            .with_body(serde_json::json!({ "code": "account_does_not_exist", "message": "There is no account for this authenticator address" }).to_string())
            .create_async()
            .await;
        let config = Config::new(
            None,
            1,
            address!("0x0000000000000000000000000000000000000001"),
            ServiceEndpoint::direct(indexer_url),
            ServiceEndpoint::direct("http://gateway.example.com".to_string()),
            Vec::new(),
            2,
        )
        .unwrap();

        let indexer_client = ServiceClient::new(
            reqwest::Client::new(),
            ServiceKind::Indexer,
            config.indexer(),
        )
        .unwrap();

        let result = Authenticator::fetch_packed_account_data_for(
            test_address,
            None,
            &config,
            &indexer_client,
        )
        .await;

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
                serde_json::json!({ "leaf_index": format!("{:#x}", leaf_index) }).to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({ "signature_nonce": format!("{:#x}", expected_nonce) })
                    .to_string(),
            )
            .create_async()
            .await;
        let config = Config::new(
            None,
            1,
            address!("0x0000000000000000000000000000000000000001"),
            ServiceEndpoint::direct(indexer_url),
            ServiceEndpoint::direct("http://gateway.example.com".to_string()),
            Vec::new(),
            2,
        )
        .unwrap();

        let http_client = reqwest::Client::new();
        let authenticator = Authenticator {
            config: config.clone(),
            packed_account_data: leaf_index,
            signer: Signer::from_seed_bytes(&[1u8; 32]).unwrap(),
            registry: None,
            indexer_client: ServiceClient::new(
                http_client.clone(),
                ServiceKind::Indexer,
                config.indexer(),
            )
            .unwrap(),
            gateway_client: ServiceClient::new(http_client, ServiceKind::Gateway, config.gateway())
                .unwrap(),
            ws_connector: Connector::Plain,
            zk_artifact_source: dummy_zk_artifact_source(),
        };
        let nonce = authenticator.signing_nonce().await.unwrap();
        assert_eq!(nonce, expected_nonce);
        mock.assert_async().await;
        drop(server);
    }

    #[test]
    fn test_danger_sign_challenge_returns_valid_signature() {
        let config = Config::new(
            None,
            1,
            address!("0x0000000000000000000000000000000000000001"),
            ServiceEndpoint::direct("http://indexer.example.com".to_string()),
            ServiceEndpoint::direct("http://gateway.example.com".to_string()),
            Vec::new(),
            2,
        )
        .unwrap();
        let http_client = reqwest::Client::new();
        let authenticator = Authenticator {
            indexer_client: ServiceClient::new(
                http_client.clone(),
                ServiceKind::Indexer,
                config.indexer(),
            )
            .unwrap(),
            gateway_client: ServiceClient::new(http_client, ServiceKind::Gateway, config.gateway())
                .unwrap(),
            config,
            packed_account_data: U256::from(1),
            signer: Signer::from_seed_bytes(&[1u8; 32]).unwrap(),
            registry: None,
            ws_connector: Connector::Plain,
            zk_artifact_source: dummy_zk_artifact_source(),
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
        let config = Config::new(
            None,
            1,
            address!("0x0000000000000000000000000000000000000001"),
            ServiceEndpoint::direct("http://indexer.example.com".to_string()),
            ServiceEndpoint::direct("http://gateway.example.com".to_string()),
            Vec::new(),
            2,
        )
        .unwrap();
        let http_client = reqwest::Client::new();
        let authenticator = Authenticator {
            indexer_client: ServiceClient::new(
                http_client.clone(),
                ServiceKind::Indexer,
                config.indexer(),
            )
            .unwrap(),
            gateway_client: ServiceClient::new(http_client, ServiceKind::Gateway, config.gateway())
                .unwrap(),
            config,
            packed_account_data: U256::from(1),
            signer: Signer::from_seed_bytes(&[1u8; 32]).unwrap(),
            registry: None,
            ws_connector: Connector::Plain,
            zk_artifact_source: dummy_zk_artifact_source(),
        };
        let sig_a = authenticator.danger_sign_challenge(b"challenge A").unwrap();
        let sig_b = authenticator.danger_sign_challenge(b"challenge B").unwrap();
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn test_danger_sign_challenge_deterministic() {
        let config = Config::new(
            None,
            1,
            address!("0x0000000000000000000000000000000000000001"),
            ServiceEndpoint::direct("http://indexer.example.com".to_string()),
            ServiceEndpoint::direct("http://gateway.example.com".to_string()),
            Vec::new(),
            2,
        )
        .unwrap();
        let http_client = reqwest::Client::new();
        let authenticator = Authenticator {
            indexer_client: ServiceClient::new(
                http_client.clone(),
                ServiceKind::Indexer,
                config.indexer(),
            )
            .unwrap(),
            gateway_client: ServiceClient::new(http_client, ServiceKind::Gateway, config.gateway())
                .unwrap(),
            config,
            packed_account_data: U256::from(1),
            signer: Signer::from_seed_bytes(&[1u8; 32]).unwrap(),
            registry: None,
            ws_connector: Connector::Plain,
            zk_artifact_source: dummy_zk_artifact_source(),
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
            .with_body(serde_json::json!({ "code": "invalid_leaf_index", "message": "Account index cannot be zero" }).to_string())
            .create_async()
            .await;
        let config = Config::new(
            None,
            1,
            address!("0x0000000000000000000000000000000000000001"),
            ServiceEndpoint::direct(indexer_url),
            ServiceEndpoint::direct("http://gateway.example.com".to_string()),
            Vec::new(),
            2,
        )
        .unwrap();

        let http_client = reqwest::Client::new();
        let authenticator = Authenticator {
            config: config.clone(),
            packed_account_data: U256::ZERO,
            signer: Signer::from_seed_bytes(&[1u8; 32]).unwrap(),
            registry: None,
            indexer_client: ServiceClient::new(
                http_client.clone(),
                ServiceKind::Indexer,
                config.indexer(),
            )
            .unwrap(),
            gateway_client: ServiceClient::new(http_client, ServiceKind::Gateway, config.gateway())
                .unwrap(),
            ws_connector: Connector::Plain,
            zk_artifact_source: dummy_zk_artifact_source(),
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
