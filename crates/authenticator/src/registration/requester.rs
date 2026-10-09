//! The Requesting Authenticator's side of a registration (WIP-109 §3.8).

use std::{sync::Arc, time::Duration};

use backon::{ExponentialBuilder, Retryable as _};
use secrecy::ExposeSecret as _;
use web_time::Instant;
use world_id_primitives::{
    Config, Signer,
    authenticator_message::{self, ErrorObject, Id},
};
use world_id_proof::artifacts::ZkArtifactSource;

use super::{
    AuthenticatorName, BridgeDomain, MAX_RESPONSE_SIZE, PairingCode, PairingSecret, PairingUri,
    REGISTER_METHOD, RegisterRequestMessage, RegisterResponseMessage, RegistrationDigest,
    RegistrationErrorData, RegistrationRequest, RegistrationResult, ResponseSecretKey,
    TransportError, TransportKey,
    approver::before,
    bridge::{BridgeClient, BridgeError, ResponseState},
};
use crate::{Authenticator, AuthenticatorClass, AuthenticatorError};

const SESSION_TTL: Duration = Duration::from_secs(15 * 60);

/// How long [`RegistrationRequester::verify`] waits for the indexer to show a new registration.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(60);

/// One registration attempt of a new authenticator.
///
/// A session is driven by the host: [`publish`](Self::publish) the request, show
/// [`pairing_uri`](Self::pairing_uri) as a QR code and link, [`poll`](Self::poll) until the
/// response arrives, then [`verify`](Self::verify) a successful result before importing the vault.
///
/// Retries after an expired or lost session must create a new session from the **same seed**,
/// so that an insertion that already happened is found instead of repeated.
pub struct RegistrationRequester {
    secrets: Option<SessionSecrets>,
    published: bool,
    expires_at: Instant,
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
        let secret = PairingSecret::generate()?;
        let response_key = ResponseSecretKey::generate()?;
        let code = PairingCode::generate()?;
        let transport_key = secret.transport_key(&code)?;
        let (request, digest) = RegistrationRequest::new_signed(
            signer.offchain_signer_private_key().expose_secret(),
            class,
            response_key.public_key(),
            name,
            &secret.request_id(),
        )
        .map_err(AuthenticatorError::from)?;
        Ok(Self {
            secrets: Some(SessionSecrets {
                secret,
                response_key,
                code,
                transport_key,
                code_revealed: false,
            }),
            published: false,
            expires_at: Instant::now() + SESSION_TTL,
            request,
            digest,
            advertised_bridge,
            bridge,
        })
    }

    /// Returns the Pairing URI while the session is active and the code is still hidden.
    /// Replace the URI screen with the code after retrieval. Never log either value.
    #[must_use]
    pub fn pairing_uri(&self) -> Option<PairingUri> {
        let secrets = self.secrets.as_ref()?;
        if secrets.code_revealed || Instant::now() >= self.expires_at {
            return None;
        }
        Some(PairingUri {
            secret: secrets.secret.clone(),
            digest: self.digest,
            bridge: self.advertised_bridge.clone(),
        })
    }

    /// Reveals the code only after polling has observed `retrieved`.
    /// Display it only on this device, with instructions to enter it on the intended approver.
    #[must_use]
    pub fn pairing_code(&self) -> Option<&PairingCode> {
        let secrets = self.secrets.as_ref()?;
        (secrets.code_revealed && Instant::now() < self.expires_at).then_some(&secrets.code)
    }

    /// Ends this attempt and discards its secrets. A retry must create a new requester.
    pub fn cancel(&mut self) {
        self.secrets = None;
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
    pub async fn publish(&mut self) -> Result<(), RequesterError> {
        if Instant::now() >= self.expires_at {
            self.cancel();
        }
        if self.secrets.is_none() {
            return Err(RequesterError::SessionEnded);
        }
        if self.published {
            return Err(RequesterError::AlreadyPublished);
        }
        let secrets = self.secrets.as_ref().ok_or(RequesterError::SessionEnded)?;
        let request_id = secrets.secret.request_id();
        let message = RegisterRequestMessage::new(
            Some(Id::String(request_id.to_string())),
            REGISTER_METHOD,
            self.request.clone(),
        );
        let plaintext = authenticator_message::encode(&message)
            .map_err(|e| AuthenticatorError::Generic(format!("failed to encode request: {e}")))?;
        let encrypted = secrets.transport_key.encrypt_request(&plaintext)?;
        self.published = true;
        match self.bridge.publish_request(&request_id, &encrypted).await {
            Ok(_) => {
                self.expires_at = Instant::now() + SESSION_TTL;
                Ok(())
            }
            Err(error) => {
                self.cancel();
                Err(error.into())
            }
        }
    }

    /// Checks the bridge once for the response. Call it periodically, e.g. every second.
    ///
    /// A completed response is consumed by this call.
    ///
    /// # Errors
    ///
    /// Returns an error if the bridge cannot be reached or the response cannot be opened or
    /// parsed. After a transport error the next poll may report [`RequesterStatus::Expired`],
    /// if the response was consumed but not received. Failures discard the session secrets.
    pub async fn poll(&mut self) -> Result<RequesterStatus, RequesterError> {
        if self.secrets.is_none() || Instant::now() >= self.expires_at {
            self.cancel();
            return Ok(RequesterStatus::Expired);
        }
        if !self.published {
            return Ok(RequesterStatus::Waiting);
        }
        let request_id = self
            .secrets
            .as_ref()
            .ok_or(RequesterError::SessionEnded)?
            .secret
            .request_id();
        let state = before(self.expires_at, self.bridge.fetch_response(&request_id)).await;
        let sealed = match state {
            Some(Ok(ResponseState::Initialized)) => return Ok(RequesterStatus::Waiting),
            Some(Ok(ResponseState::Retrieved)) => {
                let secrets = self.secrets.as_mut().ok_or(RequesterError::SessionEnded)?;
                if !secrets.code_revealed {
                    self.expires_at = Instant::now() + SESSION_TTL;
                    secrets.code_revealed = true;
                }
                return Ok(RequesterStatus::Retrieved);
            }
            None | Some(Ok(ResponseState::NotFound)) => {
                self.cancel();
                return Ok(RequesterStatus::Expired);
            }
            Some(Err(error)) => {
                self.cancel();
                return Err(error.into());
            }
            Some(Ok(ResponseState::Completed(sealed))) => sealed,
        };
        let secrets = self.secrets.take().ok_or(RequesterError::SessionEnded)?;
        let plaintext = secrets
            .transport_key
            .decrypt_response(&secrets.response_key, &sealed)?;
        let response: RegisterResponseMessage =
            authenticator_message::decode(&plaintext, MAX_RESPONSE_SIZE)
                .map_err(|e| RequesterError::MalformedResponse(e.to_string()))?;
        if response.id != Some(Id::String(request_id.to_string())) {
            return Err(RequesterError::MalformedResponse(
                "uncorrelated response or response id does not match the request".to_string(),
            ));
        }
        Ok(RequesterStatus::Completed(response.outcome))
    }

    /// Checks a successful `result` against the account state and returns the new
    /// authenticator, ready to generate proofs.
    ///
    /// The registry, through the indexer, must show this session's key at `result.pubkey_id` on
    /// `result.leaf_index`, with the requested class. Until this succeeds the authenticator must
    /// not consider itself registered. The indexer may lag behind the registry, so this retries
    /// with backoff within a one-minute deadline, including time spent on requests.
    ///
    /// Importing the vault is up to the caller, which must validate the imported credentials
    /// against the account.
    ///
    /// # Errors
    ///
    /// - [`RequesterError::RegistrationMismatch`] if the key is registered at another slot or
    ///   with another class.
    /// - [`RequesterError::VerificationTimeout`] if the key is still not found on the account, or
    ///   the indexer still fails transiently, when the deadline passes. A wrong `leaf_index`
    ///   cannot be told apart from indexer lag, so it also ends here.
    /// - [`RequesterError::Authenticator`] if initialization or an account lookup fails
    ///   permanently.
    pub async fn verify(
        &self,
        seed: &[u8],
        result: &RegistrationResult,
        config: Config,
        zk_artifact_source: Arc<dyn ZkArtifactSource>,
    ) -> Result<Authenticator, RequesterError> {
        let verification = async {
            let signer = Signer::from_seed_bytes(seed).map_err(AuthenticatorError::from)?;
            if signer.offchain_signer_pubkey().pk != self.request.new_authenticator_pubkey.pk {
                return Err(AuthenticatorError::Generic(
                    "seed does not belong to this registration session".to_string(),
                )
                .into());
            }
            let attempt = || async {
                let authenticator = Authenticator::init_with_leaf_index(
                    seed,
                    result.leaf_index,
                    config.clone(),
                    Arc::clone(&zk_artifact_source),
                )
                .await?;
                let registered = Authenticator::fetch_authenticators_for(
                    result.leaf_index,
                    &config,
                    &authenticator.indexer_client,
                )
                .await?
                .find(&self.request.new_authenticator_pubkey)
                // Another indexer replica may still lag behind the one `init` read from.
                .ok_or(AuthenticatorError::PublicKeyNotFound)?;
                Ok::<_, AuthenticatorError>((authenticator, registered))
            };
            let (authenticator, registered) = attempt
                .retry(
                    ExponentialBuilder::default()
                        .with_min_delay(Duration::from_secs(1))
                        .with_max_delay(Duration::from_secs(8))
                        .without_max_times()
                        .with_total_delay(Some(VERIFY_TIMEOUT))
                        .with_jitter(),
                )
                .when(is_transient)
                .await
                .map_err(|error| {
                    if is_transient(&error) {
                        RequesterError::VerificationTimeout
                    } else {
                        error.into()
                    }
                })?;
            if registered != (result.pubkey_id, self.request.class) {
                return Err(RequesterError::RegistrationMismatch);
            }
            Ok(authenticator)
        };
        before(Instant::now() + VERIFY_TIMEOUT, verification)
            .await
            .ok_or(RequesterError::VerificationTimeout)?
    }
}

/// Errors that may clear up while the indexer catches up with the registry or recovers.
fn is_transient(error: &AuthenticatorError) -> bool {
    match error {
        AuthenticatorError::PublicKeyNotFound
        | AuthenticatorError::AccountDoesNotExist
        | AuthenticatorError::NetworkError(_) => true,
        AuthenticatorError::IndexerError { status, .. } => {
            status.is_server_error() || *status == reqwest::StatusCode::TOO_MANY_REQUESTS
        }
        _ => false,
    }
}

impl std::fmt::Debug for RegistrationRequester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationRequester")
            .field("active", &self.secrets.is_some())
            .finish_non_exhaustive()
    }
}

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
    Completed(Result<RegistrationResult, ErrorObject<RegistrationErrorData>>),
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
    /// This attempt has completed, expired, or been cancelled.
    #[error("registration session has ended")]
    SessionEnded,
    /// The account could not be verified before the deadline.
    #[error("registration verification timed out")]
    VerificationTimeout,
    /// The request was already published. Start a fresh attempt instead.
    #[error("registration request was already published")]
    AlreadyPublished,
}

struct SessionSecrets {
    secret: PairingSecret,
    response_key: ResponseSecretKey,
    code: PairingCode,
    transport_key: TransportKey,
    code_revealed: bool,
}

#[cfg(test)]
mod tests {
    use world_id_primitives::authenticator_message::Version;

    use super::*;
    use crate::registration::{ApproverError, PendingRegistration};

    fn requester(server: &mockito::ServerGuard) -> RegistrationRequester {
        RegistrationRequester::new(
            &[77; 32],
            RequestedClass::Proving,
            None,
            BridgeClient::new(server.url().parse().unwrap()).unwrap(),
            None,
        )
        .unwrap()
    }

    async fn pending(
        session: &RegistrationRequester,
        server: &mut mockito::ServerGuard,
        message_id: Option<Id>,
    ) -> PendingRegistration {
        let secrets = session.secrets.as_ref().unwrap();
        let id = secrets.secret.request_id();
        let plaintext = authenticator_message::encode(&RegisterRequestMessage::new(
            message_id,
            REGISTER_METHOD,
            session.request.clone(),
        ))
        .unwrap();
        let payload = secrets.transport_key.encrypt_request(&plaintext).unwrap();
        let mock = server
            .mock("GET", format!("/request/{id}").as_str())
            .with_status(200)
            .with_body(serde_json::to_vec(&payload).unwrap())
            .expect(1)
            .create_async()
            .await;
        let pending =
            PendingRegistration::receive(&session.pairing_uri().unwrap(), session.bridge.clone())
                .await
                .unwrap();
        mock.assert_async().await;
        pending
    }

    #[tokio::test]
    async fn code_is_revealed_only_after_retrieval_and_cleared_on_cancel() {
        let mut server = mockito::Server::new_async().await;
        let mut session = requester(&server);
        assert!(session.pairing_code().is_none());
        let _publish = server
            .mock("POST", "/request")
            .with_status(201)
            .create_async()
            .await;
        session.publish().await.unwrap();
        assert!(session.pairing_code().is_none());
        let id = session.secrets.as_ref().unwrap().secret.request_id();
        let _retrieved = server
            .mock("GET", format!("/response/{id}").as_str())
            .with_status(200)
            .with_body(r#"{"status":"retrieved","response":null}"#)
            .create_async()
            .await;
        assert_eq!(session.poll().await.unwrap(), RequesterStatus::Retrieved);
        assert!(session.pairing_code().is_some());
        assert!(session.pairing_uri().is_none());
        session.cancel();
        assert!(session.pairing_code().is_none());
        assert!(session.secrets.is_none());
        assert_eq!(session.poll().await.unwrap(), RequesterStatus::Expired);
    }

    #[tokio::test]
    async fn code_typo_reuses_ciphertext_and_three_failures_end_attempt() {
        let mut server = mockito::Server::new_async().await;
        let session = requester(&server);
        let secrets = session.secrets.as_ref().unwrap();
        let code = &secrets.code;
        let message_id = Some(Id::String(secrets.secret.request_id().to_string()));
        let wrong: PairingCode = if code.as_str() == "AAAAAA" {
            "BBBBBB"
        } else {
            "AAAAAA"
        }
        .parse()
        .unwrap();
        let mut attempt = pending(&session, &mut server, message_id.clone()).await;
        assert!(matches!(
            attempt.authenticate(&wrong).await,
            Err(ApproverError::IncorrectCode {
                attempts_remaining: 2
            })
        ));
        assert_eq!(
            attempt.authenticate(code).await.unwrap().request(),
            session.request()
        );
        assert!(matches!(
            attempt.authenticate(code).await,
            Err(ApproverError::Expired)
        ));
        let mut attempt = pending(&session, &mut server, message_id).await;
        for remaining in [2, 1, 0] {
            assert!(
                matches!(attempt.authenticate(&wrong).await, Err(ApproverError::IncorrectCode { attempts_remaining }) if attempts_remaining == remaining)
            );
        }
        assert!(matches!(
            attempt.authenticate(code).await,
            Err(ApproverError::Expired)
        ));
    }

    #[tokio::test]
    async fn registration_notification_is_rejected_without_a_response() {
        let mut server = mockito::Server::new_async().await;
        let session = requester(&server);
        let secrets = session.secrets.as_ref().unwrap();
        let id = secrets.secret.request_id();
        let response = server
            .mock("PUT", format!("/response/{id}").as_str())
            .expect(0)
            .create_async()
            .await;
        let mut attempt = pending(&session, &mut server, None).await;

        assert!(matches!(
            attempt.authenticate(&secrets.code).await,
            Err(ApproverError::InvalidRequest {
                responded: false,
                ..
            })
        ));
        assert!(matches!(
            attempt.authenticate(&secrets.code).await,
            Err(ApproverError::Expired)
        ));
        response.assert_async().await;
    }

    #[tokio::test]
    async fn authenticated_errors_preserve_unknown_codes_and_clear_secrets() {
        let mut server = mockito::Server::new_async().await;
        let mut session = requester(&server);
        session.published = true;
        let secrets = session.secrets.as_ref().unwrap();
        let id = secrets.secret.request_id();
        let response = RegisterResponseMessage {
            version: Version::V1,
            id: Some(Id::String(id.to_string())),
            outcome: Err(ErrorObject {
                code: "future_error".into(),
                message: "New method error".into(),
                data: None,
            }),
        };
        let encrypted = secrets
            .transport_key
            .encrypt_response(
                &secrets.response_key.public_key(),
                &authenticator_message::encode(&response).unwrap(),
            )
            .unwrap();
        let _response = server
            .mock("GET", format!("/response/{id}").as_str())
            .with_status(200)
            .with_body(serde_json::json!({"status":"completed", "response":encrypted}).to_string())
            .create_async()
            .await;
        let RequesterStatus::Completed(Err(error)) = session.poll().await.unwrap() else {
            panic!("expected method error");
        };
        assert_eq!(error.code, "future_error");
        assert!(session.secrets.is_none());
    }

    #[tokio::test]
    async fn null_id_is_a_local_protocol_error_and_ends_pairing() {
        let mut server = mockito::Server::new_async().await;
        let mut session = requester(&server);
        session.published = true;
        let secrets = session.secrets.as_ref().unwrap();
        let id = secrets.secret.request_id();
        let response = RegisterResponseMessage {
            version: Version::V1,
            id: None,
            outcome: Err(ErrorObject {
                code: "invalid_request".into(),
                message: "Invalid request".into(),
                data: None,
            }),
        };
        let encrypted = secrets
            .transport_key
            .encrypt_response(
                &secrets.response_key.public_key(),
                &authenticator_message::encode(&response).unwrap(),
            )
            .unwrap();
        let _response = server
            .mock("GET", format!("/response/{id}").as_str())
            .with_status(200)
            .with_body(serde_json::json!({"status":"completed", "response":encrypted}).to_string())
            .create_async()
            .await;
        assert!(matches!(
            session.poll().await,
            Err(RequesterError::MalformedResponse(_))
        ));
        assert!(session.secrets.is_none());
    }
}
