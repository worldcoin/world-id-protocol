//! The Approving Authenticator's side of a registration (WIP-109 §3.7).
//!
//! The flow is split into steps so that the host can ask for the user's consent in between:
//!
//! 1. [`PendingRegistration::receive`] fetches the ciphertext before code entry.
//! 2. [`PendingRegistration::authenticate`] validates it after code entry.
//! 3. [`IncomingRegistration::check`] reads the account state and plans the registration.
//! 4. The host shows the consent screen, then calls [`CheckedRegistration::approve`] or
//!    [`CheckedRegistration::reject`].
//!
//! Every step that fails for a reason the Requesting Authenticator should learn about sends it an
//! error response before returning.

use std::{future::Future, time::Duration};

use backon::{BackoffBuilder as _, ExponentialBuilder, Sleeper as _};
use futures_util::future::{Either, select};
use web_time::Instant;
use world_id_primitives::{
    api_types::{GatewayErrorCode, GatewayRequestState, ServiceApiError},
    authenticator_message::{self, ErrorObject, Id, Version},
};

use super::{
    EncryptedPayload, KnownAuthenticator, MAX_RESPONSE_SIZE, PairingCode, PairingUri,
    REGISTER_METHOD, RegisterRequestMessage, RegisterResponseMessage, RegistrationErrorData,
    RegistrationErrorReason, RegistrationRequest, RegistrationResult, RequestId, ResponsePublicKey,
    TransportError, TransportKey, Vault,
    bridge::{BridgeClient, BridgeError, DeliveryOutcome},
};
use crate::{AccountSnapshot, Authenticator, AuthenticatorClass, AuthenticatorError};

/// How long the bridge keeps a session after the request is taken.
const BRIDGE_SESSION_TTL: Duration = Duration::from_secs(15 * 60);

/// How long before the bridge session expires the response is due. WIP-109 recommends 60 s.
const RESPONSE_MARGIN: Duration = Duration::from_secs(60);

/// How long after taking the request the response is due.
pub const DEFAULT_RESPONSE_DEADLINE: Duration =
    Duration::from_secs(BRIDGE_SESSION_TTL.as_secs() - RESPONSE_MARGIN.as_secs());

/// The least time left before the response deadline for [`CheckedRegistration::approve`] to
/// still submit an insertion. With less, the outcome would most likely be `outcome_unknown`.
pub const MIN_TRACKING_TIME: Duration = Duration::from_secs(2 * 60);

/// An encrypted request fetched once, waiting for code entry on the approving device.
///
/// Fetch this before prompting for a code. Code entry does not authorize registration;
/// authentication returns an [`IncomingRegistration`] which still needs checks and consent.
#[derive(Debug)]
pub struct PendingRegistration {
    attempt: Option<PendingAttempt>,
    attempts_remaining: u8,
}

impl PendingRegistration {
    /// Fetches and retains the encrypted request. Never refetch it after a mistyped code.
    /// The host must use an allowlisted bridge or obtain confirmation before contacting it.
    ///
    /// # Errors
    /// Returns [`ApproverError::Expired`] for a used or expired URI, or a bridge error.
    pub async fn receive(uri: &PairingUri, bridge: BridgeClient) -> Result<Self, ApproverError> {
        let encrypted = bridge
            .take_request(&uri.secret.request_id())
            .await?
            .ok_or(ApproverError::Expired)?;
        Ok(Self {
            attempt: Some(PendingAttempt {
                uri: uri.clone(),
                encrypted,
                bridge,
                taken_at: Instant::now(),
            }),
            attempts_remaining: 3,
        })
    }

    /// Ends this attempt and discards the pairing secret and retained ciphertext.
    pub fn cancel(&mut self) {
        self.attempt = None;
    }

    /// Authenticates the retained ciphertext, then validates the CBOR request and signature.
    /// At most three code attempts are allowed before expiry. No response is sent before
    /// authentication, or when CBOR decoding, envelope validation, or digest matching fails.
    ///
    /// # Errors
    /// An incorrect code leaves the ciphertext available for the reported remaining attempts.
    /// All other errors end this attempt and require a fresh pairing.
    pub async fn authenticate(
        &mut self,
        code: &PairingCode,
    ) -> Result<IncomingRegistration, ApproverError> {
        let attempt = self.attempt.as_ref().ok_or(ApproverError::Expired)?;
        if Instant::now() >= attempt.taken_at + BRIDGE_SESSION_TTL {
            self.cancel();
            return Err(ApproverError::Expired);
        }
        self.attempts_remaining -= 1;
        let key = match attempt.uri.secret.transport_key(code) {
            Ok(key) => key,
            Err(error) => {
                self.cancel();
                return Err(error.into());
            }
        };
        let plaintext = match key.decrypt_request(&attempt.encrypted) {
            Ok(plaintext) => plaintext,
            Err(TransportError::Decrypt) => {
                if self.attempts_remaining == 0 {
                    self.cancel();
                }
                return Err(ApproverError::IncorrectCode {
                    attempts_remaining: self.attempts_remaining,
                });
            }
            Err(error) => {
                self.cancel();
                return Err(error.into());
            }
        };
        let attempt = self.attempt.take().ok_or(ApproverError::Expired)?;
        IncomingRegistration::from_authenticated(attempt, key, &plaintext).await
    }
}

/// A validated registration request, taken from the bridge.
#[derive(Debug)]
pub struct IncomingRegistration {
    request: RegistrationRequest,
    channel: ResponseChannel,
    respond_by: Instant,
}

impl IncomingRegistration {
    /// Sets how long from now the response is due, instead of [`DEFAULT_RESPONSE_DEADLINE`]
    /// after the request was taken. This cannot extend the bridge session expiry.
    #[must_use]
    pub fn with_response_deadline(mut self, deadline: Duration) -> Self {
        self.respond_by =
            (Instant::now() + deadline).min(self.channel.expires_at - RESPONSE_MARGIN);
        self
    }

    /// Returns the validated request. Its `name` is untrusted and must be displayed as such.
    #[must_use]
    pub const fn request(&self) -> &RegistrationRequest {
        &self.request
    }

    /// Returns when the response is due. The host can use it to show how long the user has to
    /// decide.
    #[must_use]
    pub const fn respond_by(&self) -> Instant {
        self.respond_by
    }

    /// Reads the account state of `approver` and plans the registration (WIP-109 §3.7.2).
    ///
    /// # Errors
    ///
    /// Returns [`ApproverError::Refused`] after sending the reason when `approver` is not an
    /// Admin Authenticator of its account (`not_authorized`), the key or address is registered
    /// differently (`authenticator_conflict`), there is no free slot
    /// (`max_authenticators_reached`), or the account state cannot be read (`internal_error`).
    pub async fn check(
        self,
        approver: &Authenticator,
    ) -> Result<CheckedRegistration, ApproverError> {
        let snapshot = match before(self.respond_by, approver.fetch_account_snapshot()).await {
            None => {
                return Err(self
                    .refuse(RegistrationErrorReason::InternalError, None)
                    .await);
            }
            Some(Ok(snapshot)) => snapshot,
            Some(Err(error)) => {
                return Err(self
                    .refuse(RegistrationErrorReason::InternalError, Some(error))
                    .await);
            }
        };
        match plan_registration(&snapshot, approver, &self.request) {
            Ok(plan) => Ok(CheckedRegistration {
                incoming: self,
                snapshot,
                plan,
            }),
            Err(reason) => Err(self.refuse(reason, None).await),
        }
    }

    /// Refuses the request, e.g. with `invalid_name` for a name the host does not accept.
    ///
    /// # Errors
    ///
    /// Returns an error if the response cannot be sealed or delivered.
    pub async fn reject(
        self,
        reason: RegistrationErrorReason,
    ) -> Result<DeliveryOutcome, ApproverError> {
        self.channel.send(Err(reason.into_error(None))).await
    }

    async fn from_authenticated(
        attempt: PendingAttempt,
        transport_key: TransportKey,
        plaintext: &[u8],
    ) -> Result<Self, ApproverError> {
        let request_id = attempt.uri.secret.request_id();
        let message: RegisterRequestMessage = authenticator_message::decode(plaintext, 16 * 1024)
            .map_err(|error| ApproverError::InvalidRequest {
            reason: error.to_string(),
            responded: false,
        })?;
        if message.method != REGISTER_METHOD
            || message.id != Some(Id::String(request_id.to_string()))
        {
            return Err(ApproverError::InvalidRequest {
                reason: "unexpected registration method or request id".into(),
                responded: false,
            });
        }
        let request = message
            .params
            .ok_or_else(|| ApproverError::InvalidRequest {
                reason: "missing registration params".into(),
                responded: false,
            })?;
        let digest = request
            .digest(&request_id)
            .map_err(|e| ApproverError::InvalidRequest {
                reason: e.to_string(),
                responded: false,
            })?;
        if digest != attempt.uri.digest {
            tracing::warn!(%request_id, "registration request does not match the pairing link");
            return Err(ApproverError::DigestMismatch);
        }

        let incoming = Self {
            channel: ResponseChannel {
                request_id,
                response_pubkey: request.response_pubkey.clone(),
                transport_key,
                bridge: attempt.bridge,
                expires_at: attempt.taken_at + BRIDGE_SESSION_TTL,
            },
            request,
            respond_by: attempt.taken_at + DEFAULT_RESPONSE_DEADLINE,
        };
        if !incoming.request.verify_signature(&digest) {
            let responded = incoming
                .channel
                .send(Err(RegistrationErrorReason::InvalidParams
                    .into_error(Some("invalid registration_sig".to_string()))))
                .await
                .is_ok();
            tracing::warn!(%request_id, responded, "invalid registration signature");
            return Err(ApproverError::InvalidRequest {
                reason: "invalid registration signature".to_string(),
                responded,
            });
        }
        Ok(incoming)
    }

    async fn refuse(
        &self,
        reason: RegistrationErrorReason,
        source: Option<AuthenticatorError>,
    ) -> ApproverError {
        tracing::warn!(
            request_id = %self.channel.request_id,
            ?reason,
            error = source.as_ref().map(tracing::field::display),
            "refusing authenticator registration"
        );
        let undelivered = self
            .channel
            .send(Err(reason.into_error(None)))
            .await
            .err()
            .map(Box::new);
        ApproverError::Refused {
            reason,
            source,
            undelivered,
        }
    }
}

/// A registration request whose account state was checked, waiting for the user's decision.
#[derive(Debug)]
pub struct CheckedRegistration {
    incoming: IncomingRegistration,
    snapshot: AccountSnapshot,
    plan: RegistrationPlan,
}

impl CheckedRegistration {
    /// Returns the validated request.
    #[must_use]
    pub const fn request(&self) -> &RegistrationRequest {
        &self.incoming.request
    }

    /// Returns how the registration will be carried out.
    #[must_use]
    pub const fn plan(&self) -> RegistrationPlan {
        self.plan
    }

    /// Returns when the response is due.
    #[must_use]
    pub const fn respond_by(&self) -> Instant {
        self.incoming.respond_by
    }

    /// Declines the registration with `user_rejected`.
    ///
    /// # Errors
    ///
    /// Returns an error if the response cannot be sealed or delivered.
    pub async fn reject(self) -> Result<DeliveryOutcome, ApproverError> {
        self.incoming
            .reject(RegistrationErrorReason::UserRejected)
            .await
    }

    /// Carries out an approved registration and sends the response (WIP-109 §3.7.4 and §3.7.5).
    ///
    /// Call it only after the user gave explicit consent. Unless the authenticator is already
    /// registered, this signs and submits `InsertAuthenticator` from the checked snapshot and
    /// tracks it until it is final on-chain or definitively failed. If its outcome is still
    /// unknown at [`respond_by`](Self::respond_by), the response is `outcome_unknown`. A failed
    /// or unknown outcome is never retried with a second insertion.
    ///
    /// If less than [`MIN_TRACKING_TIME`] is left before the deadline, nothing is submitted and
    /// the response is `internal_error`, so the user can start over with a new link.
    #[must_use = "the outcome tells whether the authenticator was registered"]
    pub async fn approve(self, approver: &Authenticator, approval: Approval) -> ApprovalOutcome {
        let request_id = self.incoming.channel.request_id;
        let result = match self.plan {
            _ if !self.response_fits(&approval) => Err((
                RegistrationErrorReason::InternalError,
                Some("the approval exceeds the response size limit".to_string()),
            )),
            RegistrationPlan::AlreadyRegistered { pubkey_id } => Ok(pubkey_id),
            RegistrationPlan::Insert { .. }
                if self
                    .incoming
                    .respond_by
                    .saturating_duration_since(Instant::now())
                    < MIN_TRACKING_TIME =>
            {
                Err((
                    RegistrationErrorReason::InternalError,
                    Some("approved too close to the session expiry".to_string()),
                ))
            }
            RegistrationPlan::Insert { .. } => self.insert(approver).await,
        };
        let (result, outcome) = match result {
            Ok(pubkey_id) => {
                let result = RegistrationResult {
                    leaf_index: self.snapshot.leaf_index,
                    pubkey_id,
                    authenticators: approval.authenticators,
                    vault: approval.vault,
                };
                (Ok(result.clone()), Ok(result))
            }
            Err((reason, detail)) => {
                tracing::warn!(%request_id, ?reason, ?detail, "authenticator registration did not succeed");
                (Err(reason), Err(reason.into_error(detail)))
            }
        };
        let delivery = self.incoming.channel.send(outcome).await;
        ApprovalOutcome { result, delivery }
    }

    /// Whether a successful response carrying `approval` stays within the size the Requesting
    /// Authenticator accepts. Checked before submitting anything, so that an oversized vault does
    /// not leave a registered authenticator that never learns its result.
    fn response_fits(&self, approval: &Approval) -> bool {
        let response = RegisterResponseMessage {
            version: Version::V1,
            id: Some(Id::String(self.incoming.channel.request_id.to_string())),
            outcome: Ok(RegistrationResult {
                leaf_index: self.snapshot.leaf_index,
                // Every valid slot encodes to the same single CBOR byte.
                pubkey_id: 0,
                authenticators: approval.authenticators.clone(),
                vault: approval.vault.clone(),
            }),
        };
        authenticator_message::encode(&response)
            .is_ok_and(|encoded| encoded.len() <= MAX_RESPONSE_SIZE)
    }

    async fn insert(
        &self,
        approver: &Authenticator,
    ) -> Result<u32, (RegistrationErrorReason, Option<String>)> {
        let respond_by = self.incoming.respond_by;
        let submission = approver.insert_authenticator_from_snapshot(
            &self.snapshot,
            self.incoming.request.new_authenticator_pubkey.clone(),
            self.incoming.request.class,
        );
        let insertion = before(respond_by, submission)
            .await
            .ok_or((RegistrationErrorReason::OutcomeUnknown, None))?
            .map_err(classify_submission_error)?;

        let mut delays = ExponentialBuilder::default()
            .with_min_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(8))
            .without_max_times()
            .with_jitter()
            .build();
        let mut submitted = false;
        let mut failed_polls = 0_u32;
        loop {
            let Some(status) =
                before(respond_by, approver.poll_status(&insertion.request_id)).await
            else {
                break;
            };
            match status {
                Ok(GatewayRequestState::Finalized { .. }) => {
                    return self.confirm_registration(approver).await;
                }
                Ok(GatewayRequestState::Failed { error_code, .. }) => {
                    return Err(classify_failure(error_code, submitted));
                }
                Ok(GatewayRequestState::Submitted { .. }) => submitted = true,
                Ok(GatewayRequestState::Queued | GatewayRequestState::Batching) => {}
                Err(error) => {
                    failed_polls += 1;
                    tracing::debug!(request_id = %self.incoming.channel.request_id, %error, failed_polls, "failed to poll gateway request");
                }
            }
            let delay = delays.next().unwrap_or(Duration::from_secs(8));
            if before(respond_by, backon::DefaultSleeper::default().sleep(delay))
                .await
                .is_none()
            {
                break;
            }
        }
        tracing::warn!(
            request_id = %self.incoming.channel.request_id,
            gateway_request_id = %insertion.request_id,
            submitted,
            failed_polls,
            "insertion outcome unknown at the response deadline"
        );
        Err((RegistrationErrorReason::OutcomeUnknown, None))
    }

    async fn confirm_registration(
        &self,
        approver: &Authenticator,
    ) -> Result<u32, (RegistrationErrorReason, Option<String>)> {
        let deadline = self.incoming.respond_by;
        let mut delays = ExponentialBuilder::default()
            .with_min_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(8))
            .without_max_times()
            .with_jitter()
            .build();
        while let Some(state) = before(deadline, approver.fetch_account_snapshot()).await {
            match state {
                Ok(snapshot) => {
                    if let Some((slot, class)) = snapshot
                        .authenticators
                        .find(&self.incoming.request.new_authenticator_pubkey)
                    {
                        if class != self.incoming.request.class {
                            return Err((RegistrationErrorReason::AuthenticatorConflict, None));
                        }
                        return Ok(slot);
                    }
                }
                Err(error) => tracing::debug!(%error, "failed to refresh finalized registration"),
            }
            if before(
                deadline,
                backon::DefaultSleeper::default()
                    .sleep(delays.next().unwrap_or(Duration::from_secs(8))),
            )
            .await
            .is_none()
            {
                break;
            }
        }
        tracing::warn!(request_id = %self.incoming.channel.request_id, "finalized registration not visible before response deadline");
        Err((RegistrationErrorReason::OutcomeUnknown, None))
    }
}

/// How a checked registration will be carried out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationPlan {
    /// Insert the authenticator at `pubkey_id`.
    Insert {
        /// The slot the authenticator will be inserted at.
        pubkey_id: u32,
    },
    /// The authenticator is already registered as requested, e.g. by an earlier attempt whose
    /// response was lost. Approval only sends the result.
    AlreadyRegistered {
        /// The slot the authenticator is registered at.
        pubkey_id: u32,
    },
}

/// What the Approving Authenticator shares with an approved authenticator.
#[derive(Clone, Debug, Default)]
pub struct Approval {
    /// The credential vault. The user or policy may exclude it.
    pub vault: Option<Vault>,
    /// Names of the account's other authenticators.
    pub authenticators: Vec<KnownAuthenticator>,
}

/// The result of [`CheckedRegistration::approve`].
#[derive(Debug)]
pub struct ApprovalOutcome {
    /// The registration result, or the reason it failed. A successful result means the
    /// authenticator is registered on-chain, even if the response was not delivered.
    pub result: Result<RegistrationResult, RegistrationErrorReason>,
    /// Whether the response reached the bridge.
    pub delivery: Result<DeliveryOutcome, ApproverError>,
}

/// Errors on the Approving Authenticator's side of a registration.
#[derive(Debug, thiserror::Error)]
pub enum ApproverError {
    /// The request expired or was already taken. The user should create a new QR code or link
    /// on the new device.
    #[error("the registration request expired or was already used")]
    Expired,
    /// Authentication failed. The ciphertext is retained for the remaining local attempts.
    #[error("pairing code did not authenticate the request ({attempts_remaining} attempts remain)")]
    IncorrectCode {
        /// Number of remaining code attempts; zero means a new pairing is required.
        attempts_remaining: u8,
    },
    /// The request does not match the digest in the Pairing URI. No response was sent.
    #[error("the registration request does not match the pairing link")]
    DigestMismatch,
    /// The request is malformed. `responded` tells whether an `invalid_params` error was sent.
    #[error("invalid registration request: {reason}")]
    InvalidRequest {
        /// What is wrong with the request.
        reason: String,
        /// Whether an error response was sent to the Requesting Authenticator.
        responded: bool,
    },
    /// The registration was refused. The reason was sent to the Requesting Authenticator unless
    /// `undelivered` holds the error that prevented it.
    #[error("registration refused: {reason:?}")]
    Refused {
        /// The reason for the refusal.
        reason: RegistrationErrorReason,
        /// The underlying error, if the refusal was caused by one.
        #[source]
        source: Option<AuthenticatorError>,
        /// The error that prevented sending the reason, if any.
        undelivered: Option<Box<ApproverError>>,
    },
    /// The bridge session expired before the response could be delivered.
    #[error("the bridge session expired before the response was delivered")]
    SessionExpired,
    /// The bridge could not be reached or rejected an operation.
    #[error(transparent)]
    Bridge(#[from] BridgeError),
    /// Decrypting the request or sealing the response failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The response could not be encoded.
    #[error("failed to encode the response: {0}")]
    Encoding(#[from] authenticator_message::MessageError),
}

#[derive(Debug)]
struct PendingAttempt {
    uri: PairingUri,
    encrypted: EncryptedPayload,
    bridge: BridgeClient,
    taken_at: Instant,
}

/// Where and how to send the response of one registration session.
#[derive(Debug)]
struct ResponseChannel {
    request_id: RequestId,
    response_pubkey: ResponsePublicKey,
    transport_key: TransportKey,
    bridge: BridgeClient,
    expires_at: Instant,
}

impl ResponseChannel {
    async fn send(
        &self,
        outcome: Result<RegistrationResult, ErrorObject<RegistrationErrorData>>,
    ) -> Result<DeliveryOutcome, ApproverError> {
        let response = RegisterResponseMessage {
            version: Version::V1,
            id: Some(Id::String(self.request_id.to_string())),
            outcome,
        };
        let sealed = self.transport_key.encrypt_response(
            &self.response_pubkey,
            &authenticator_message::encode(&response)?,
        )?;
        let delivery = before(
            self.expires_at,
            self.bridge.put_response(&self.request_id, &sealed),
        )
        .await
        .ok_or(ApproverError::SessionExpired)
        .and_then(|delivery| delivery.map_err(ApproverError::from));
        if let Err(error) = &delivery {
            tracing::warn!(request_id = %self.request_id, %error, "failed to deliver registration response");
        }
        delivery
    }
}

/// Runs `future` until `deadline`, returning `None` if the deadline passes first.
pub(super) async fn before<F: Future>(deadline: Instant, future: F) -> Option<F::Output> {
    let now = Instant::now();
    if now >= deadline {
        return None;
    }
    let remaining = deadline.saturating_duration_since(now);
    let timeout = backon::DefaultSleeper::default().sleep(remaining);
    match select(std::pin::pin!(future), std::pin::pin!(timeout)).await {
        Either::Left((output, _)) => Some(output),
        Either::Right(_) => None,
    }
}

fn plan_registration(
    snapshot: &AccountSnapshot,
    approver: &Authenticator,
    request: &RegistrationRequest,
) -> Result<RegistrationPlan, RegistrationErrorReason> {
    let authenticators = &snapshot.authenticators;
    let approver_class = AuthenticatorClass::Admin {
        address: approver.onchain_address(),
    };
    if authenticators
        .find(&approver.offchain_pubkey())
        .map(|(_, class)| class)
        != Some(approver_class)
    {
        return Err(RegistrationErrorReason::NotAuthorized);
    }

    if let Some((pubkey_id, class)) = authenticators.find(&request.new_authenticator_pubkey) {
        if class != request.class {
            return Err(RegistrationErrorReason::AuthenticatorConflict);
        }
        return Ok(RegistrationPlan::AlreadyRegistered { pubkey_id });
    }

    if matches!(request.class, AuthenticatorClass::Admin { .. })
        && authenticators.classes.contains(&Some(request.class))
    {
        return Err(RegistrationErrorReason::AuthenticatorConflict);
    }

    authenticators
        .lowest_free_pubkey_id()
        .map(|pubkey_id| RegistrationPlan::Insert { pubkey_id })
        .ok_or(RegistrationErrorReason::MaxAuthenticatorsReached)
}

/// Classifies a failure to submit `InsertAuthenticator`.
///
/// The gateway answering with a client error is definitive: it did not accept the operation.
/// Failing before anything was sent is an internal error. Any other failure happened after the
/// request may have reached the gateway, so its outcome is unknown.
fn classify_submission_error(
    error: AuthenticatorError,
) -> (RegistrationErrorReason, Option<String>) {
    match error {
        AuthenticatorError::MaxAuthenticatorsReached => {
            (RegistrationErrorReason::MaxAuthenticatorsReached, None)
        }
        AuthenticatorError::PrimitiveError(_) => (RegistrationErrorReason::InternalError, None),
        AuthenticatorError::GatewayError { status, body } if status.is_client_error() => {
            let code = serde_json::from_str::<ServiceApiError<GatewayErrorCode>>(&body)
                .map(|error| error.code)
                .ok();
            let reason = match code {
                Some(GatewayErrorCode::AuthenticatorAlreadyExists) => {
                    RegistrationErrorReason::AuthenticatorConflict
                }
                Some(GatewayErrorCode::PubkeyIdOutOfBounds) => {
                    RegistrationErrorReason::MaxAuthenticatorsReached
                }
                _ => RegistrationErrorReason::OperationFailed,
            };
            (reason, code.map(|code| code.to_string()))
        }
        _ => (RegistrationErrorReason::OutcomeUnknown, None),
    }
}

/// Classifies a gateway request that ended as failed.
///
/// A revert is definitive. Before the transaction was submitted, only failures decoded from the
/// registry's own checks are definitive. Every other failure, including the gateway's catch-all
/// `bad_request` for errors sending the transaction, may still land on-chain.
fn classify_failure(
    error_code: Option<GatewayErrorCode>,
    submitted: bool,
) -> (RegistrationErrorReason, Option<String>) {
    let detail = error_code.as_ref().map(ToString::to_string);
    let reason = match error_code {
        Some(GatewayErrorCode::TransactionReverted) => RegistrationErrorReason::OperationFailed,
        _ if submitted => RegistrationErrorReason::OutcomeUnknown,
        Some(GatewayErrorCode::AuthenticatorAlreadyExists) => {
            RegistrationErrorReason::AuthenticatorConflict
        }
        Some(GatewayErrorCode::PubkeyIdOutOfBounds) => {
            RegistrationErrorReason::MaxAuthenticatorsReached
        }
        Some(
            GatewayErrorCode::MismatchedSignatureNonce
            | GatewayErrorCode::PubkeyIdInUse
            | GatewayErrorCode::AuthenticatorDoesNotBelongToAccount,
        ) => RegistrationErrorReason::OperationFailed,
        _ => RegistrationErrorReason::OutcomeUnknown,
    };
    (reason, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_deadline_never_polls_operation() {
        let result = before(Instant::now() - Duration::from_secs(1), async {
            panic!("expired operation was polled");
        })
        .await;
        assert_eq!(result, None::<()>);
    }

    #[test]
    fn reverts_are_definitive_failures() {
        for submitted in [false, true] {
            assert_eq!(
                classify_failure(Some(GatewayErrorCode::TransactionReverted), submitted).0,
                RegistrationErrorReason::OperationFailed
            );
        }
    }

    #[test]
    fn failures_after_submission_are_unknown() {
        for code in [
            Some(GatewayErrorCode::ConfirmationError),
            Some(GatewayErrorCode::MismatchedSignatureNonce),
            Some(GatewayErrorCode::BadRequest),
            Some(GatewayErrorCode::InternalServerError),
            None,
        ] {
            assert_eq!(
                classify_failure(code, true).0,
                RegistrationErrorReason::OutcomeUnknown
            );
        }
    }

    #[test]
    fn registry_checks_before_submission_are_definitive() {
        assert_eq!(
            classify_failure(Some(GatewayErrorCode::MismatchedSignatureNonce), false).0,
            RegistrationErrorReason::OperationFailed
        );
        assert_eq!(
            classify_failure(Some(GatewayErrorCode::AuthenticatorAlreadyExists), false).0,
            RegistrationErrorReason::AuthenticatorConflict
        );
        assert_eq!(
            classify_failure(Some(GatewayErrorCode::PubkeyIdOutOfBounds), false).0,
            RegistrationErrorReason::MaxAuthenticatorsReached
        );
        for unknown in [
            Some(GatewayErrorCode::ConfirmationError),
            Some(GatewayErrorCode::BadRequest),
            None,
        ] {
            assert_eq!(
                classify_failure(unknown, false).0,
                RegistrationErrorReason::OutcomeUnknown
            );
        }
    }

    #[test]
    fn submission_errors_are_definitive_only_for_client_errors() {
        let gateway = |status: u16, code: &str| AuthenticatorError::GatewayError {
            status: reqwest::StatusCode::from_u16(status).unwrap(),
            body: serde_json::json!({ "code": code, "message": "x" }).to_string(),
        };
        assert_eq!(
            classify_submission_error(gateway(400, "authenticator_already_exists")),
            (
                RegistrationErrorReason::AuthenticatorConflict,
                Some("authenticator_already_exists".to_string())
            )
        );
        assert_eq!(
            classify_submission_error(gateway(400, "pubkey_id_out_of_bounds")).0,
            RegistrationErrorReason::MaxAuthenticatorsReached
        );
        assert_eq!(
            classify_submission_error(gateway(429, "rate_limit_exceeded")).0,
            RegistrationErrorReason::OperationFailed
        );
        assert_eq!(
            classify_submission_error(gateway(503, "batcher_unavailable")).0,
            RegistrationErrorReason::OutcomeUnknown
        );
        assert_eq!(
            classify_submission_error(AuthenticatorError::MaxAuthenticatorsReached).0,
            RegistrationErrorReason::MaxAuthenticatorsReached
        );
        assert_eq!(
            classify_submission_error(AuthenticatorError::Generic("relay timeout".into())).0,
            RegistrationErrorReason::OutcomeUnknown
        );
    }
}
