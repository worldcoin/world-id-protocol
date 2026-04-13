//! This module contains all the base functionality to support Authenticators in World ID. See
//! [`Authenticator`] for a definition.

use crate::{
    error::{AuthenticatorError, PollResult},
    init::InitializingAuthenticator,
};

use std::sync::Arc;

use crate::api_types::{
    AccountInclusionProof, GatewayRequestId, GatewayRequestState, GatewayStatusResponse,
    IndexerAuthenticatorPubkeysResponse, IndexerErrorCode, IndexerPackedAccountRequest,
    IndexerPackedAccountResponse, IndexerQueryRequest, IndexerSignatureNonceResponse,
    ServiceApiError,
};
use world_id_primitives::{Credential, FieldElement, ProofResponse, Signer};

use crate::registry::WorldIdRegistry::WorldIdRegistryInstance;
use alloy::{
    primitives::Address,
    providers::DynProvider,
    signers::{Signature, SignerSync},
};
use ark_serialize::CanonicalSerialize;
use eddsa_babyjubjub::EdDSAPublicKey;
use groth16_material::circom::CircomGroth16Material;
use ruint::{aliases::U256, uint};
use taceo_oprf::client::Connector;
pub use world_id_primitives::{Config, TREE_DEPTH, authenticator::ProtocolSigner};
use world_id_primitives::{
    PrimitiveError,
    authenticator::{
        AuthenticatorPublicKeySet, SparseAuthenticatorPubkeysError,
        decode_sparse_authenticator_pubkeys,
    },
};

/// Shared helper that polls `GET {gateway_url}/status/{request_id}` and
/// returns the current [`GatewayRequestState`].
pub(crate) async fn fetch_gateway_status(
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
    /// The SDK should cache this keyed by [`SessionId::oprf_seed`](world_id_primitives::SessionId::oprf_seed).
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
    pub(crate) signer: Signer,
    pub(crate) registry: Option<Arc<WorldIdRegistryInstance<DynProvider>>>,
    pub(crate) http_client: reqwest::Client,
    pub(crate) ws_connector: Connector,
    pub(crate) query_material: Option<Arc<CircomGroth16Material>>,
    pub(crate) nullifier_material: Option<Arc<CircomGroth16Material>>,
}

impl std::fmt::Debug for Authenticator {
    // avoiding logging other attributes to avoid accidental leak of leaf_index
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

pub(crate) async fn response_body_or_fallback(response: reqwest::Response) -> String {
    response
        .text()
        .await
        .unwrap_or_else(|e| format!("Unable to read response body: {e}"))
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
                let body = response_body_or_fallback(resp).await;
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
                body: response_body_or_fallback(response).await,
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
                body: response_body_or_fallback(response).await,
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
                    body: response_body_or_fallback(resp).await,
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

    pub(crate) fn decode_indexer_pubkeys(
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

    pub(crate) fn insert_or_reuse_authenticator_key(
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::AuthenticatorError, traits::OnchainKeyRepresentable};
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
            indexer_url,
            "http://gateway.example.com".to_string(),
            Vec::new(),
            2,
        )
        .unwrap();
        let http_client = reqwest::Client::new();
        let result =
            Authenticator::get_packed_account_data(test_address, None, &config, &http_client)
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
            indexer_url,
            "http://gateway.example.com".to_string(),
            Vec::new(),
            2,
        )
        .unwrap();
        let authenticator = Authenticator {
            config,
            packed_account_data: leaf_index,
            signer: Signer::from_seed_bytes(&[1u8; 32]).unwrap(),
            registry: None,
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
            .with_body(serde_json::json!({ "code": "invalid_leaf_index", "message": "Account index cannot be zero" }).to_string())
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
