//! The Requesting Authenticator's side of a registration (WIP-109 §3.8).

use std::{sync::Arc, time::Duration};

use backon::Retryable as _;
use secrecy::ExposeSecret as _;
use web_time::Instant;
use world_id_primitives::{
    Config, Signer,
    authenticator_message::{self, ErrorObject, MessageError},
};
use world_id_proof::artifacts::ZkArtifactSource;

use super::{
    AuthenticatorName, EncryptedPayload, MAX_RESPONSE_SIZE, PairingCode, PairingSecret, PairingUri,
    REGISTER_METHOD, RegisterRequestMessage, RegisterResponseMessage, RegistrationDigest,
    RegistrationErrorData, RegistrationRequest, RegistrationResult, RequestId, ResponseSecretKey,
    TransportError, TransportKey,
    bridge::{BridgeClient, BridgeError, ResponseState},
    deadline::{SESSION_TTL, before, polling_backoff},
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
    /// The seed or a key could not be used, or reading the account state failed.
    #[error(transparent)]
    Authenticator(#[from] AuthenticatorError),
    /// The request could not be encoded.
    #[error("failed to encode the registration request: {0}")]
    Encoding(#[source] MessageError),
    /// The response is not a valid registration response.
    #[error("malformed registration response: {0}")]
    MalformedResponse(#[source] MessageError),
    /// The response answers another request.
    #[error("the registration response answers another request")]
    ResponseIdMismatch,
    /// The seed passed to [`RegistrationRequester::verify`] is not the one this session asked to
    /// register.
    #[error("the seed does not belong to this registration session")]
    SeedMismatch,
    /// The registry does not show the new authenticator where the response says it is.
    #[error("the registration result does not match the registry")]
    RegistrationMismatch,
    /// This session has completed, expired, or been cancelled.
    #[error("registration session has ended")]
    SessionEnded,
    /// The account could not be verified before the deadline.
    #[error("registration verification timed out")]
    VerificationTimeout,
    /// The request was already published. Start a new session instead.
    #[error("registration request was already published")]
    AlreadyPublished,
}

/// The secrets of one session (WIP-109 §3.3), discarded when it ends.
#[derive(Debug)]
struct SessionSecrets {
    pairing_secret: PairingSecret,
    code: PairingCode,
    transport_key: TransportKey,
    response_key: ResponseSecretKey,
}

/// Where a session is (WIP-109 §3.8). A live session holds its secrets and its estimated expiry.
#[derive(Debug)]
enum SessionState {
    /// The request is not yet published.
    Created {
        secrets: SessionSecrets,
        expires_at: Instant,
    },
    /// The request is on the bridge; the Pairing URI may be shown.
    Published {
        secrets: SessionSecrets,
        expires_at: Instant,
    },
    /// The Approving Authenticator took the request; the pairing code may be shown.
    Retrieved {
        secrets: SessionSecrets,
        expires_at: Instant,
    },
    /// The session completed, failed, expired or was cancelled, and its secrets are gone.
    Ended,
}

/// The Requesting Authenticator's side of one registration session.
///
/// The host drives the session: [`publish`](Self::publish) the request, show
/// [`pairing_uri`](Self::pairing_uri) as a QR code and link, [`poll`](Self::poll) until the
/// response arrives, showing [`pairing_code`](Self::pairing_code) once the request was
/// retrieved, then [`verify`](Self::verify) a successful result before importing the vault.
///
/// A retry after an expired or lost session must start a new session from the **same seed**, so
/// that an insertion that already happened is found instead of repeated.
#[derive(Debug)]
pub struct RegistrationRequester {
    request: RegistrationRequest,
    digest: RegistrationDigest,
    bridge: BridgeClient,
    state: SessionState,
}

impl RegistrationRequester {
    /// Starts a session for the authenticator derived from `seed`.
    ///
    /// `bridge` is the bridge the session uses. Its domain is written into the Pairing URI.
    ///
    /// # Errors
    ///
    /// Returns an error if the seed is invalid or the operating system CSPRNG is unavailable.
    pub fn new(
        seed: &[u8],
        class: RequestedClass,
        name: Option<AuthenticatorName>,
        bridge: BridgeClient,
    ) -> Result<Self, RequesterError> {
        let signer = Signer::from_seed_bytes(seed).map_err(AuthenticatorError::from)?;
        let class = match class {
            RequestedClass::Admin => AuthenticatorClass::Admin {
                address: signer.onchain_signer_address(),
            },
            RequestedClass::Proving => AuthenticatorClass::Proving,
        };
        let pairing_secret = PairingSecret::generate()?;
        let code = PairingCode::generate()?;
        let secrets = SessionSecrets {
            transport_key: pairing_secret.transport_key(&code)?,
            response_key: ResponseSecretKey::generate()?,
            pairing_secret,
            code,
        };
        let request_id = secrets.pairing_secret.request_id();
        let (request, digest) = RegistrationRequest::new_signed(
            signer.offchain_signer_private_key().expose_secret(),
            class,
            secrets.response_key.public_key(),
            name,
            &request_id,
        )
        .map_err(AuthenticatorError::from)?;
        Ok(Self {
            request,
            digest,
            bridge,
            state: SessionState::Created {
                secrets,
                expires_at: Instant::now() + SESSION_TTL,
            },
        })
    }

    /// Returns the request this session asks the Approving Authenticator to approve.
    #[must_use]
    pub const fn request(&self) -> &RegistrationRequest {
        &self.request
    }

    /// Returns the Pairing URI once the request is published, until the Approving Authenticator
    /// takes it or the session ends. Never log it.
    #[must_use]
    pub fn pairing_uri(&self) -> Option<PairingUri> {
        match &self.state {
            SessionState::Published {
                secrets,
                expires_at,
            } if Instant::now() < *expires_at => Some(PairingUri {
                secret: secrets.pairing_secret.clone(),
                digest: self.digest,
                bridge: self.bridge.domain().clone(),
            }),
            _ => None,
        }
    }

    /// Returns the pairing code once the Approving Authenticator took the request, until the
    /// session ends.
    ///
    /// Show it only on this device, with instructions to enter it only on the intended
    /// Approving Authenticator. Never log it.
    #[must_use]
    pub fn pairing_code(&self) -> Option<&PairingCode> {
        match &self.state {
            SessionState::Retrieved {
                secrets,
                expires_at,
            } if Instant::now() < *expires_at => Some(&secrets.code),
            _ => None,
        }
    }

    /// Ends this session and discards its secrets. A retry must start a new session.
    pub fn cancel(&mut self) {
        self.state = SessionState::Ended;
    }

    /// Encrypts and publishes the request on the bridge.
    ///
    /// Call it once per session: publishing again after the Approving Authenticator read the
    /// request would reset the session on the bridge. The Pairing URI is available only after
    /// this succeeds, so calling it again after an interrupted call is safe (WIP-109 §3.8).
    ///
    /// # Errors
    ///
    /// Returns [`RequesterError::AlreadyPublished`] after a successful publish,
    /// [`RequesterError::SessionEnded`] once the session ended, or the error that ended it.
    pub async fn publish(&mut self) -> Result<(), RequesterError> {
        self.end_if_expired();
        let secrets = match &self.state {
            SessionState::Created { secrets, .. } => secrets,
            SessionState::Published { .. } | SessionState::Retrieved { .. } => {
                return Err(RequesterError::AlreadyPublished);
            }
            SessionState::Ended => return Err(RequesterError::SessionEnded),
        };
        let request_id = secrets.pairing_secret.request_id();
        let message = RegisterRequestMessage::builder()
            .id(request_id.message_id())
            .method(REGISTER_METHOD)
            .params(self.request.clone())
            .build();
        let encrypted = authenticator_message::encode(&message)
            .map_err(RequesterError::Encoding)
            .and_then(|plaintext| Ok(secrets.transport_key.encrypt_request(&plaintext)?));
        let published = match encrypted {
            Ok(encrypted) => self
                .bridge
                .publish_request(&request_id, &encrypted)
                .await
                .map_err(RequesterError::from),
            Err(error) => Err(error),
        };
        // A retry needs a new session, so a failure ends this one and discards its keys.
        if let Err(error) = published {
            self.cancel();
            return Err(error);
        }
        self.state = match std::mem::replace(&mut self.state, SessionState::Ended) {
            SessionState::Created { secrets, .. } => SessionState::Published {
                secrets,
                expires_at: Instant::now() + SESSION_TTL,
            },
            state => state,
        };
        Ok(())
    }

    /// Checks the bridge once for the response. Call it periodically, e.g. every second.
    ///
    /// A completed response is consumed by this call, which ends the session.
    ///
    /// # Errors
    ///
    /// Returns an error if the bridge cannot be reached, or the response cannot be opened or
    /// does not answer this session's request. Errors end the session. After a transport error
    /// the response may have been consumed but not received, so a new session is needed.
    pub async fn poll(&mut self) -> Result<RequesterStatus, RequesterError> {
        self.end_if_expired();
        let (secrets, expires_at) = match &self.state {
            SessionState::Created { .. } => return Ok(RequesterStatus::Waiting),
            SessionState::Published {
                secrets,
                expires_at,
            }
            | SessionState::Retrieved {
                secrets,
                expires_at,
            } => (secrets, *expires_at),
            SessionState::Ended => return Ok(RequesterStatus::Expired),
        };
        let request_id = secrets.pairing_secret.request_id();
        match before(expires_at, self.bridge.fetch_response(&request_id)).await {
            Some(Ok(ResponseState::Initialized)) => Ok(RequesterStatus::Waiting),
            Some(Ok(ResponseState::Retrieved)) => {
                self.state = match std::mem::replace(&mut self.state, SessionState::Ended) {
                    // Retrieval restarts the bridge session (WIP-109 §3.5).
                    SessionState::Published { secrets, .. } => SessionState::Retrieved {
                        secrets,
                        expires_at: Instant::now() + SESSION_TTL,
                    },
                    state => state,
                };
                Ok(RequesterStatus::Retrieved)
            }
            Some(Ok(ResponseState::Completed(sealed))) => {
                let outcome = open_response(secrets, &request_id, &sealed);
                self.cancel();
                outcome.map(RequesterStatus::Completed)
            }
            None | Some(Ok(ResponseState::NotFound)) => {
                self.cancel();
                Ok(RequesterStatus::Expired)
            }
            Some(Err(error)) => {
                self.cancel();
                Err(error.into())
            }
        }
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
    /// - [`RequesterError::SeedMismatch`] if `seed` is not the one this session registers.
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
        let signer = Signer::from_seed_bytes(seed).map_err(AuthenticatorError::from)?;
        if signer.offchain_signer_pubkey().pk != self.request.new_authenticator_pubkey.pk {
            return Err(RequesterError::SeedMismatch);
        }
        let verification = async {
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
                .retry(polling_backoff().with_total_delay(Some(VERIFY_TIMEOUT)))
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

    fn end_if_expired(&mut self) {
        let expires_at = match &self.state {
            SessionState::Created { expires_at, .. }
            | SessionState::Published { expires_at, .. }
            | SessionState::Retrieved { expires_at, .. } => *expires_at,
            SessionState::Ended => return,
        };
        if Instant::now() >= expires_at {
            self.cancel();
        }
    }
}

/// Opens a sealed response and checks that it answers the request `request_id` (WIP-109 §3.8
/// step 5).
fn open_response(
    secrets: &SessionSecrets,
    request_id: &RequestId,
    sealed: &EncryptedPayload,
) -> Result<Result<RegistrationResult, ErrorObject<RegistrationErrorData>>, RequesterError> {
    let plaintext = secrets
        .transport_key
        .decrypt_response(&secrets.response_key, sealed)?;
    let response: RegisterResponseMessage =
        authenticator_message::decode(&plaintext, MAX_RESPONSE_SIZE)
            .map_err(RequesterError::MalformedResponse)?;
    // The outer envelope binds the response to this session, so an uncorrelated error, with a
    // null ID, is accepted too. A success always has an ID.
    if response.id.is_some_and(|id| id != request_id.message_id()) {
        return Err(RequesterError::ResponseIdMismatch);
    }
    Ok(response.outcome)
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

#[cfg(test)]
mod tests {
    use test_case::test_case;
    use world_id_primitives::authenticator_message::{Id, Version};

    use super::*;

    fn requester(server: &mockito::ServerGuard) -> RegistrationRequester {
        RegistrationRequester::new(
            &[77; 32],
            RequestedClass::Proving,
            None,
            BridgeClient::with_base_url(
                "bridge.example.org".parse().unwrap(),
                server.url().parse().unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn secrets(session: &RegistrationRequester) -> &SessionSecrets {
        match &session.state {
            SessionState::Created { secrets, .. }
            | SessionState::Published { secrets, .. }
            | SessionState::Retrieved { secrets, .. } => secrets,
            SessionState::Ended => panic!("the session has ended"),
        }
    }

    async fn published(server: &mut mockito::ServerGuard) -> RegistrationRequester {
        let mut session = requester(server);
        let publish = server
            .mock("POST", "/request")
            .with_status(200)
            .create_async()
            .await;
        session.publish().await.unwrap();
        publish.remove_async().await;
        session
    }

    #[tokio::test]
    async fn the_pairing_uri_follows_publishing_and_the_code_follows_retrieval() {
        let mut server = mockito::Server::new_async().await;
        let session = requester(&server);
        assert_eq!(session.pairing_uri(), None);
        assert_eq!(session.pairing_code(), None);

        let mut session = published(&mut server).await;
        let uri = session.pairing_uri().unwrap();
        assert_eq!(uri.secret, secrets(&session).pairing_secret);
        assert_eq!(uri.bridge.as_str(), "bridge.example.org");
        assert_eq!(session.pairing_code(), None);
        assert!(matches!(
            session.publish().await,
            Err(RequesterError::AlreadyPublished)
        ));

        let _retrieved = server
            .mock(
                "GET",
                format!("/response/{}", uri.secret.request_id()).as_str(),
            )
            .with_status(200)
            .with_body(r#"{"status":"retrieved","response":null}"#)
            .create_async()
            .await;
        assert_eq!(session.poll().await.unwrap(), RequesterStatus::Retrieved);
        assert_eq!(session.pairing_code(), Some(&secrets(&session).code));
        assert_eq!(session.pairing_uri(), None);

        session.cancel();
        assert_eq!(session.pairing_code(), None);
        assert_eq!(session.poll().await.unwrap(), RequesterStatus::Expired);
        assert!(matches!(
            session.publish().await,
            Err(RequesterError::SessionEnded)
        ));
    }

    /// The `id` of a response in a test.
    #[derive(Clone, Copy, Debug)]
    enum ResponseId {
        ThisRequest,
        Null,
        Other(&'static str),
    }

    /// An error response to `session` with `id`, sealed as the Approving Authenticator would.
    fn sealed_error(
        session: &RegistrationRequester,
        id: ResponseId,
        code: &str,
    ) -> EncryptedPayload {
        let secrets = secrets(session);
        let id = match id {
            ResponseId::ThisRequest => Some(secrets.pairing_secret.request_id().message_id()),
            ResponseId::Null => None,
            ResponseId::Other(id) => Some(Id::String(id.to_string())),
        };
        let response = RegisterResponseMessage {
            version: Version::V1,
            id,
            outcome: Err(ErrorObject {
                code: code.into(),
                message: "Registration failed".into(),
                data: None,
            }),
        };
        secrets
            .transport_key
            .encrypt_response(
                &secrets.response_key.public_key(),
                &authenticator_message::encode(&response).unwrap(),
            )
            .unwrap()
    }

    #[test_case(ResponseId::ThisRequest, "future_error", Some("future_error"); "an unknown code for this request")]
    #[test_case(ResponseId::Null, "invalid_request", Some("invalid_request"); "an uncorrelated error")]
    #[test_case(ResponseId::Other("other"), "invalid_request", None; "an error for another request")]
    #[tokio::test]
    async fn completed_errors_are_accepted_only_for_this_request(
        id: ResponseId,
        code: &str,
        accepted_code: Option<&str>,
    ) {
        let mut server = mockito::Server::new_async().await;
        let mut session = published(&mut server).await;
        let sealed = sealed_error(&session, id, code);
        let request_id = secrets(&session).pairing_secret.request_id();
        let _completed = server
            .mock("GET", format!("/response/{request_id}").as_str())
            .with_status(200)
            .with_body(serde_json::json!({ "status": "completed", "response": sealed }).to_string())
            .create_async()
            .await;

        match (session.poll().await, accepted_code) {
            (Ok(RequesterStatus::Completed(Err(error))), Some(expected)) => {
                assert_eq!(error.code, expected);
            }
            (Err(RequesterError::ResponseIdMismatch), None) => {}
            (status, _) => panic!("unexpected poll result: {status:?}"),
        }
        assert!(matches!(session.state, SessionState::Ended));
    }
}
