//! The Requesting Authenticator's side of a registration (WIP-109 §3.8).

use std::{sync::Arc, time::Duration};

use backon::{ExponentialBuilder, Retryable as _};
use secrecy::ExposeSecret as _;
use world_id_primitives::{Config, Signer, authenticator_message::Id};
use world_id_proof::artifacts::ZkArtifactSource;

use super::{
    AuthenticatorName, BridgeDomain, PairingSecret, PairingUri, REGISTER_METHOD,
    RegisterRequestMessage, RegisterResponseMessage, RegistrationDigest, RegistrationErrorData,
    RegistrationRequest, RegistrationResult, ResponseSecretKey, TransportError,
    bridge::{BridgeClient, BridgeError, ResponseState},
};
use crate::{Authenticator, AuthenticatorClass, AuthenticatorError};

/// How long [`RegistrationRequester::verify`] waits for the indexer to show a new registration.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(60);

/// The class a Requesting Authenticator asks for. An Admin Authenticator registers the management
/// key derived from its seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestedClass {
    /// Ask to become an Admin Authenticator.
    Admin,
    /// Ask to become a Proving Authenticator.
    Proving,
}

/// What [`RegistrationRequester::poll`] found on the bridge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequesterStatus {
    /// The Approving Authenticator has not opened the Pairing URI yet.
    Waiting,
    /// The Approving Authenticator fetched the request. The user should continue on that device.
    Retrieved,
    /// The Approving Authenticator answered. A successful result still has to be checked with
    /// [`RegistrationRequester::verify`].
    Completed(Result<RegistrationResult, RegistrationErrorData>),
    /// The session expired or its response was lost. Start a new session with the same seed.
    Expired,
}

/// Errors on the Requesting Authenticator's side of a registration.
#[derive(Debug, thiserror::Error)]
pub enum RequesterError {
    /// The bridge could not be reached or rejected an operation.
    #[error(transparent)]
    Bridge(#[from] BridgeError),
    /// Encrypting the request or opening the response failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The seed or a key could not be used, or verifying the registration failed.
    #[error(transparent)]
    Authenticator(#[from] AuthenticatorError),
    /// The response is not a valid registration response for this session.
    #[error("malformed registration response: {0}")]
    MalformedResponse(String),
    /// The registry does not show the new authenticator where the response says it is.
    #[error("the registration result does not match the registry")]
    RegistrationMismatch,
}

/// One registration attempt of a new authenticator.
///
/// A session is driven by the host: [`publish`](Self::publish) the request, show
/// [`pairing_uri`](Self::pairing_uri) as a QR code and link, [`poll`](Self::poll) until the
/// response arrives, then [`verify`](Self::verify) a successful result before importing the vault.
///
/// Retries after an expired or lost session must create a new session from the **same seed**,
/// so that an insertion that already happened is found instead of repeated.
pub struct RegistrationRequester {
    secret: PairingSecret,
    response_key: ResponseSecretKey,
    request: RegistrationRequest,
    digest: RegistrationDigest,
    advertised_bridge: Option<BridgeDomain>,
    bridge: BridgeClient,
}

impl RegistrationRequester {
    /// Starts a session for the authenticator derived from `seed`.
    ///
    /// `bridge` is the bridge the session uses. `advertised_bridge` is the domain written into the
    /// Pairing URI, or `None` to let the Approving Authenticator use its default bridge, which
    /// must then be the same deployment.
    ///
    /// # Errors
    ///
    /// Returns an error if the seed is invalid or the operating system CSPRNG is unavailable.
    pub fn new(
        seed: &[u8],
        class: RequestedClass,
        name: Option<AuthenticatorName>,
        bridge: BridgeClient,
        advertised_bridge: Option<BridgeDomain>,
    ) -> Result<Self, RequesterError> {
        let signer = Signer::from_seed_bytes(seed).map_err(AuthenticatorError::from)?;
        let class = match class {
            RequestedClass::Admin => AuthenticatorClass::Admin {
                address: signer.onchain_signer_address(),
            },
            RequestedClass::Proving => AuthenticatorClass::Proving,
        };
        let secret = PairingSecret::generate();
        let response_key = ResponseSecretKey::generate()?;
        let (request, digest) = RegistrationRequest::new_signed(
            signer.offchain_signer_private_key().expose_secret(),
            class,
            response_key.public_key(),
            name,
            &secret.request_id(),
        )
        .map_err(AuthenticatorError::from)?;
        Ok(Self {
            secret,
            response_key,
            request,
            digest,
            advertised_bridge,
            bridge,
        })
    }

    /// Returns the Pairing URI to show to the user. It is a bearer secret: do not log it.
    #[must_use]
    pub fn pairing_uri(&self) -> PairingUri {
        PairingUri {
            secret: self.secret.clone(),
            digest: self.digest,
            bridge: self.advertised_bridge.clone(),
        }
    }

    /// Returns the request this session asks the Approving Authenticator to approve.
    #[must_use]
    pub const fn request(&self) -> &RegistrationRequest {
        &self.request
    }

    /// Encrypts and publishes the request on the bridge.
    ///
    /// Call it once per session: publishing again after the Approving Authenticator read the
    /// request resets the session on the bridge.
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be encrypted or the bridge rejects it.
    pub async fn publish(&self) -> Result<(), RequesterError> {
        let request_id = self.secret.request_id();
        let message = RegisterRequestMessage::new(
            Id::String(request_id.to_string()),
            REGISTER_METHOD,
            self.request.clone(),
        );
        let plaintext = serde_json::to_vec(&message)
            .map_err(|e| AuthenticatorError::Generic(format!("failed to encode request: {e}")))?;
        let encrypted = self.secret.transport_key().encrypt(&plaintext)?;
        self.bridge.publish_request(&request_id, &encrypted).await?;
        Ok(())
    }

    /// Checks the bridge once for the response. Call it periodically, e.g. every second.
    ///
    /// A completed response is consumed by this call.
    ///
    /// # Errors
    ///
    /// Returns an error if the bridge cannot be reached or the response cannot be opened or
    /// parsed. After a transport error the next poll may report [`RequesterStatus::Expired`],
    /// if the response was consumed but not received.
    pub async fn poll(&self) -> Result<RequesterStatus, RequesterError> {
        let request_id = self.secret.request_id();
        let sealed = match self.bridge.fetch_response(&request_id).await? {
            ResponseState::Initialized => return Ok(RequesterStatus::Waiting),
            ResponseState::Retrieved => return Ok(RequesterStatus::Retrieved),
            ResponseState::NotFound => return Ok(RequesterStatus::Expired),
            ResponseState::Completed(sealed) => sealed,
        };
        let plaintext = self.response_key.unseal(&sealed)?;
        let response: RegisterResponseMessage = serde_json::from_slice(&plaintext)
            .map_err(|e| RequesterError::MalformedResponse(e.to_string()))?;
        if response.id != Id::String(request_id.to_string()) {
            return Err(RequesterError::MalformedResponse(
                "response id does not match the request id".to_string(),
            ));
        }
        Ok(RequesterStatus::Completed(response.outcome.map_err(
            |error| {
                error.data.unwrap_or(RegistrationErrorData {
                    reason: super::RegistrationErrorReason::InternalError,
                    detail: Some(error.message),
                })
            },
        )))
    }

    /// Checks a successful `result` against the account state and returns the new
    /// authenticator, ready to generate proofs.
    ///
    /// The registry, through the indexer, must show this session's key at `result.pubkey_id` on
    /// `result.leaf_index`. Until this succeeds the authenticator must not consider itself
    /// registered. The indexer may lag behind the registry, so this waits up to a minute for the
    /// key to appear.
    ///
    /// Importing the vault is up to the caller, which must validate the imported credentials
    /// against the account.
    ///
    /// # Errors
    ///
    /// - [`RequesterError::RegistrationMismatch`] if the key is registered at another slot.
    /// - [`RequesterError::Authenticator`] if the key does not show up in time or a network
    ///   call fails.
    pub async fn verify(
        &self,
        seed: &[u8],
        result: &RegistrationResult,
        config: Config,
        zk_artifact_source: Arc<dyn ZkArtifactSource>,
    ) -> Result<Authenticator, RequesterError> {
        let signer = Signer::from_seed_bytes(seed).map_err(AuthenticatorError::from)?;
        if signer.offchain_signer_pubkey().pk != self.request.new_authenticator_pubkey.pk {
            return Err(AuthenticatorError::Generic(
                "seed does not belong to this registration session".to_string(),
            )
            .into());
        }
        let init = || {
            Authenticator::init_with_leaf_index(
                seed,
                result.leaf_index,
                config.clone(),
                Arc::clone(&zk_artifact_source),
            )
        };
        let authenticator = init
            .retry(
                ExponentialBuilder::default()
                    .with_min_delay(Duration::from_secs(1))
                    .with_max_delay(Duration::from_secs(8))
                    .without_max_times()
                    .with_total_delay(Some(VERIFY_TIMEOUT))
                    .with_jitter(),
            )
            .when(|e| {
                matches!(
                    e,
                    AuthenticatorError::PublicKeyNotFound
                        | AuthenticatorError::AccountDoesNotExist
                        | AuthenticatorError::NetworkError(_)
                )
            })
            .await?;
        if authenticator.pubkey_id() != ruint::aliases::U256::from(result.pubkey_id) {
            return Err(RequesterError::RegistrationMismatch);
        }
        Ok(authenticator)
    }
}

impl std::fmt::Debug for RegistrationRequester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationRequester")
            .field("request_id", &self.secret.request_id())
            .finish_non_exhaustive()
    }
}
