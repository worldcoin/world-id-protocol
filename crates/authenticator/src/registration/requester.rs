//! The Requesting Authenticator's side of a registration (WIP-109 §3.8).

use std::{sync::Arc, time::Duration};

use alloy::primitives::Address;
use backon::Retryable as _;
use secrecy::ExposeSecret as _;
use web_time::Instant;
use world_id_primitives::{
    Config, Signer,
    authenticator_message::{ErrorObject, MessageError, Response},
};
use world_id_proof::artifacts::ZkArtifactSource;

use super::{
    AuthenticatorName, EncryptedPayload, PairingCode, PairingSecret, PairingUri, REGISTER_METHOD,
    RegisterRequestMessage, RegistrationDigest, RegistrationErrorData, RegistrationRequest,
    RegistrationResult, RequestId, ResponseSecretKey, TransportError, TransportKey,
    bridge::{BridgeClient, BridgeError, ResponseState},
    deadline::{SESSION_TTL, before, polling_backoff},
    decode_response,
};
use crate::{Authenticator, AuthenticatorError};

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
    /// The request is encrypted but not yet published. A publish that was interrupted resends
    /// this exact ciphertext (WIP-109 §3.5).
    Created {
        secrets: SessionSecrets,
        encrypted_request: EncryptedPayload,
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
    /// Starts a session for the authenticator derived from `seed`, and encrypts its request.
    ///
    /// `bridge` is the bridge the session uses. Its domain is written into the Pairing URI.
    ///
    /// # Errors
    ///
    /// Returns an error if the seed is invalid, the operating system CSPRNG is unavailable, or
    /// the request cannot be encoded or encrypted.
    pub fn new(
        seed: &[u8],
        class: RequestedClass,
        name: Option<AuthenticatorName>,
        bridge: BridgeClient,
    ) -> Result<Self, RequesterError> {
        let signer = Signer::from_seed_bytes(seed).map_err(AuthenticatorError::from)?;
        let new_authenticator_address = match class {
            RequestedClass::Admin => Some(signer.onchain_signer_address()),
            RequestedClass::Proving => None,
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
            new_authenticator_address,
            secrets.response_key.public_key(),
            name,
            &request_id,
        )
        .map_err(AuthenticatorError::from)?;
        let message = RegisterRequestMessage::new(
            Some(request_id.message_id()),
            REGISTER_METHOD,
            Some(request.clone()),
        );
        let plaintext = message.encode().map_err(RequesterError::Encoding)?;
        let encrypted_request = secrets.transport_key.encrypt_request(&plaintext)?;
        Ok(Self {
            request,
            digest,
            bridge,
            state: SessionState::Created {
                secrets,
                encrypted_request,
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

    /// Publishes the encrypted request on the bridge.
    ///
    /// Call it once per session: publishing again after the Approving Authenticator read the
    /// request would reset the session on the bridge. The Pairing URI is available only after
    /// this succeeds, so calling it again after an interrupted call is safe; it resends the same
    /// ciphertext (WIP-109 §3.8).
    ///
    /// # Errors
    ///
    /// Returns [`RequesterError::AlreadyPublished`] after a successful publish,
    /// [`RequesterError::SessionEnded`] once the session ended, or the bridge error that ended
    /// it.
    pub async fn publish(&mut self) -> Result<(), RequesterError> {
        self.end_if_expired();
        let (request_id, encrypted_request) = match &self.state {
            SessionState::Created {
                secrets,
                encrypted_request,
                ..
            } => (secrets.pairing_secret.request_id(), encrypted_request),
            SessionState::Published { .. } | SessionState::Retrieved { .. } => {
                return Err(RequesterError::AlreadyPublished);
            }
            SessionState::Ended => return Err(RequesterError::SessionEnded),
        };
        if let Err(error) = self
            .bridge
            .publish_request(&request_id, encrypted_request)
            .await
        {
            self.cancel();
            return Err(error.into());
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
    /// not consider itself registered. The authenticator is built from the same account state
    /// that was checked. The indexer may lag behind the registry, so this retries with backoff
    /// within a one-minute deadline, including time spent on requests.
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
            let lookup = || async {
                let authenticators =
                    Authenticator::fetch_account_authenticators(result.leaf_index, &config).await?;
                let registered = authenticators
                    .find(&self.request.new_authenticator_pubkey)
                    .ok_or(AuthenticatorError::PublicKeyNotFound)?;
                Ok::<_, AuthenticatorError>((authenticators, registered))
            };
            let (authenticators, registered) = lookup
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
            let address = self
                .request
                .new_authenticator_address
                .unwrap_or(Address::ZERO);
            if registered != (result.pubkey_id, address) {
                return Err(RequesterError::RegistrationMismatch);
            }
            Ok(Authenticator::from_account_authenticators(
                seed,
                result.leaf_index,
                &authenticators,
                config,
                zk_artifact_source,
            )?)
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
    let response = decode_response(&plaintext).map_err(RequesterError::MalformedResponse)?;
    // The outer envelope binds the response to this session, so an uncorrelated error, with a
    // null ID, is accepted too.
    let expected_id = request_id.message_id();
    match response {
        Response::Success { id, result, .. } if id == expected_id => Ok(Ok(result)),
        Response::Error { id, error, .. } if id.as_ref().is_none_or(|id| *id == expected_id) => {
            Ok(Err(error))
        }
        _ => Err(RequesterError::ResponseIdMismatch),
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use alloy::primitives::U256;
    use test_case::test_case;
    use tokio::sync::Notify;
    use world_id_primitives::{
        ServiceEndpoint,
        authenticator_message::{Id, Version},
    };
    use world_id_proof::artifacts::dummy::DummyZkArtifactSource;
    use zeroize::Zeroizing;

    use super::*;
    use crate::registration::{RegisterResponseMessage, fixtures::indexed_account};

    const SEED: [u8; 32] = [77; 32];

    /// The `id` of a response in a test.
    #[derive(Clone, Copy, Debug)]
    enum ResponseId {
        ThisRequest,
        Null,
        Other(&'static str),
    }

    impl ResponseId {
        fn value(self, session: &RegistrationRequester) -> Option<Id> {
            match self {
                Self::ThisRequest => {
                    Some(secrets(session).pairing_secret.request_id().message_id())
                }
                Self::Null => None,
                Self::Other(id) => Some(id.to_string()),
            }
        }
    }

    fn requester(server: &mockito::ServerGuard) -> RegistrationRequester {
        RegistrationRequester::new(
            &SEED,
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

    #[tokio::test]
    async fn an_interrupted_publish_resends_the_same_ciphertext() {
        let mut server = mockito::Server::new_async().await;
        let mut session = requester(&server);
        let bodies = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let received = Arc::new(Notify::new());
        let (sink, signal) = (Arc::clone(&bodies), Arc::clone(&received));
        let _slow_bridge = server
            .mock("POST", "/request")
            .match_request(move |request| {
                sink.lock()
                    .unwrap()
                    .push(serde_json::from_slice(request.body().unwrap()).unwrap());
                signal.notify_one();
                // Holds the reply back, so that the first publish is interrupted before it.
                std::thread::sleep(Duration::from_millis(300));
                true
            })
            .with_status(200)
            .create_async()
            .await;

        tokio::select! {
            _ = session.publish() => panic!("the publish was not interrupted"),
            () = received.notified() => {}
        }
        assert_eq!(session.pairing_uri(), None);
        session.publish().await.unwrap();

        let bodies = bodies.lock().unwrap();
        let [interrupted, retried] = bodies.as_slice() else {
            panic!("expected two publish attempts, got {}", bodies.len());
        };
        assert_eq!(interrupted, retried);
        assert!(session.pairing_uri().is_some());
    }

    #[test_case(1, Address::ZERO, Some(1); "the requested slot and class")]
    #[test_case(2, Address::ZERO, None; "another slot")]
    #[test_case(1, Address::repeat_byte(0x11), None; "another class")]
    #[tokio::test]
    async fn verify_builds_the_authenticator_from_the_account_state_it_checked(
        registered_slot: usize,
        registered_address: Address,
        expected_pubkey_id: Option<u64>,
    ) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut indexer = mockito::Server::new_async().await;
        let session = requester(&indexer);
        let approver = Signer::from_seed_bytes(&[1; 32]).unwrap();
        let mut slots = vec![None; registered_slot + 1];
        slots[0] = Some((
            approver.offchain_signer_pubkey(),
            approver.onchain_signer_address(),
        ));
        slots[registered_slot] = Some((
            session.request.new_authenticator_pubkey.clone(),
            registered_address,
        ));
        let lookup = indexer
            .mock("POST", "/authenticators")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&indexed_account(&slots)).unwrap())
            .expect(1)
            .create_async()
            .await;
        let config = Config::new(
            None,
            1,
            Address::repeat_byte(0x01),
            ServiceEndpoint::direct(indexer.url()),
            ServiceEndpoint::direct(indexer.url()),
            Vec::new(),
            2,
        )
        .unwrap();
        let result = RegistrationResult {
            leaf_index: 42,
            pubkey_id: 1,
            authenticators: Vec::new(),
            vault: None,
        };

        let verified = session
            .verify(&SEED, &result, config, Arc::new(DummyZkArtifactSource))
            .await;
        match (verified, expected_pubkey_id) {
            (Ok(authenticator), Some(pubkey_id)) => {
                assert_eq!(authenticator.leaf_index(), 42);
                assert_eq!(authenticator.pubkey_id(), U256::from(pubkey_id));
            }
            (Err(RequesterError::RegistrationMismatch), None) => {}
            (verified, _) => panic!("unexpected verification result: {:?}", verified.err()),
        }
        lookup.assert_async().await;
    }

    #[test_case(ResponseId::ThisRequest; "matching success id")]
    #[test_case(ResponseId::Other("other"); "another success id")]
    #[tokio::test]
    async fn successful_responses_must_match_the_request_id(id: ResponseId) {
        let mut server = mockito::Server::new_async().await;
        let mut session = published(&mut server).await;
        let result = RegistrationResult {
            leaf_index: 42,
            pubkey_id: 1,
            authenticators: Vec::new(),
            vault: None,
        };
        let sealed = sealed_response(
            &session,
            Response::Success {
                version: Version::V1,
                id: id.value(&session).expect("a success has a non-null ID"),
                result: result.clone(),
            },
        );
        let request_id = secrets(&session).pairing_secret.request_id();
        let _completed = server
            .mock("GET", format!("/response/{request_id}").as_str())
            .with_status(200)
            .with_body(serde_json::json!({ "status": "completed", "response": sealed }).to_string())
            .create_async()
            .await;
        match (session.poll().await, id) {
            (Ok(RequesterStatus::Completed(Ok(decoded))), ResponseId::ThisRequest) => {
                assert_eq!(decoded, result)
            }
            (Err(RequesterError::ResponseIdMismatch), ResponseId::Other(_)) => {}
            (status, _) => panic!("unexpected poll result: {status:?}"),
        }
        assert!(matches!(session.state, SessionState::Ended));
    }

    /// A response to `session`, sealed as the Approving Authenticator would.
    fn sealed_response(
        session: &RegistrationRequester,
        response: RegisterResponseMessage,
    ) -> EncryptedPayload {
        let secrets = secrets(session);
        let encoded = Zeroizing::new(response.encode().unwrap());
        secrets
            .transport_key
            .encrypt_response(&secrets.response_key.public_key(), &encoded)
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
        let sealed = sealed_response(
            &session,
            Response::Error {
                version: Version::V1,
                id: id.value(&session),
                error: ErrorObject {
                    code: code.into(),
                    message: "Registration failed".into(),
                    data: None,
                },
            },
        );
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
