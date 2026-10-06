//! The Approving Authenticator's side of a registration (WIP-109 §3.7).
//!
//! The flow is split into steps so that the host can ask for the user's consent in between:
//!
//! 1. [`IncomingRegistration::receive`] takes and validates the request named by a Pairing URI.
//! 2. [`IncomingRegistration::check`] reads the account state and plans the registration.
//! 3. The host shows the consent screen, then calls [`CheckedRegistration::approve`] or
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
    authenticator_message::{ErrorObject, Id},
};

use super::{
    KnownAuthenticator, PairingUri, REGISTER_METHOD, RegisterRequestMessage,
    RegisterResponseMessage, RegistrationErrorData, RegistrationErrorReason, RegistrationRequest,
    RegistrationResult, RequestId, ResponsePublicKey, TransportError, Vault,
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

/// Errors on the Approving Authenticator's side of a registration.
#[derive(Debug, thiserror::Error)]
pub enum ApproverError {
    /// The request expired or was already taken. The user should create a new QR code or link
    /// on the new device.
    #[error("the registration request expired or was already used")]
    Expired,
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
    Encoding(#[from] serde_json::Error),
}

/// Runs `future` until `deadline`, returning `None` if the deadline passes first.
async fn before<F: Future>(deadline: Instant, future: F) -> Option<F::Output> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let timeout = backon::DefaultSleeper::default().sleep(remaining);
    match select(std::pin::pin!(future), std::pin::pin!(timeout)).await {
        Either::Left((output, _)) => Some(output),
        Either::Right(_) => None,
    }
}

/// Where and how to send the response of one registration session.
#[derive(Debug)]
struct ResponseChannel {
    request_id: RequestId,
    response_pubkey: ResponsePublicKey,
    bridge: BridgeClient,
    expires_at: Instant,
}

impl ResponseChannel {
    async fn send(
        &self,
        outcome: Result<RegistrationResult, ErrorObject<RegistrationErrorData>>,
    ) -> Result<DeliveryOutcome, ApproverError> {
        let response = RegisterResponseMessage {
            id: Id::String(self.request_id.to_string()),
            outcome,
        };
        let sealed = self.response_pubkey.seal(&serde_json::to_vec(&response)?)?;
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

/// Reads `params.response_pubkey` from a request that otherwise failed to parse, so that it can
/// still be answered with `invalid_params`.
fn salvage_response_pubkey(plaintext: &[u8]) -> Option<ResponsePublicKey> {
    let message: serde_json::Value = serde_json::from_slice(plaintext).ok()?;
    let encoded = message.get("params")?.get("response_pubkey")?.as_str()?;
    let bytes = hex::decode(encoded.strip_prefix("0x")?).ok()?;
    ResponsePublicKey::from_bytes(&bytes).ok()
}

/// A validated registration request, taken from the bridge.
#[derive(Debug)]
pub struct IncomingRegistration {
    request: RegistrationRequest,
    channel: ResponseChannel,
    respond_by: Instant,
}

impl IncomingRegistration {
    /// Takes the request named by `uri` from `bridge` and validates it.
    ///
    /// The host picks `bridge` from `uri.bridge`. It should only use allowlisted bridge
    /// deployments, and fall back to its default bridge when the URI names none. Opening the URI
    /// must not imply approval.
    ///
    /// The request can be taken only once. The response is due within
    /// [`DEFAULT_RESPONSE_DEADLINE`].
    ///
    /// # Errors
    ///
    /// - [`ApproverError::Expired`] if the request expired or was already taken.
    /// - [`ApproverError::DigestMismatch`] if the request is not the one the URI commits to. No
    ///   response is sent.
    /// - [`ApproverError::InvalidRequest`] if the request is malformed or its signature is
    ///   invalid. An `invalid_params` response is sent whenever a response key can be read from
    ///   the request.
    /// - [`ApproverError::Bridge`] or [`ApproverError::Transport`] if the request cannot be
    ///   fetched or decrypted.
    pub async fn receive(uri: &PairingUri, bridge: BridgeClient) -> Result<Self, ApproverError> {
        let request_id = uri.secret.request_id();
        let encrypted = bridge
            .take_request(&request_id)
            .await?
            .ok_or(ApproverError::Expired)?;
        let taken_at = Instant::now();
        let expires_at = taken_at + BRIDGE_SESSION_TTL;
        let plaintext = uri.secret.transport_key().decrypt(&encrypted)?;

        let message = serde_json::from_slice::<RegisterRequestMessage>(&plaintext)
            .map_err(|e| format!("cannot parse the request: {e}"))
            .and_then(|message| {
                if message.method != REGISTER_METHOD {
                    return Err("unexpected method".to_string());
                }
                if message.id != Id::String(request_id.to_string()) {
                    return Err("request id does not match the pairing link".to_string());
                }
                Ok(message)
            });
        let message = match message {
            Ok(message) => message,
            Err(reason) => {
                let responded = match salvage_response_pubkey(&plaintext) {
                    Some(response_pubkey) => ResponseChannel {
                        request_id,
                        response_pubkey,
                        bridge,
                        expires_at,
                    }
                    .send(Err(RegistrationErrorReason::InvalidParams.into_error(None)))
                    .await
                    .is_ok(),
                    None => false,
                };
                tracing::warn!(%request_id, %reason, responded, "invalid registration request");
                return Err(ApproverError::InvalidRequest { reason, responded });
            }
        };

        let digest =
            message
                .params
                .digest(&request_id)
                .map_err(|e| ApproverError::InvalidRequest {
                    reason: e.to_string(),
                    responded: false,
                })?;
        if digest != uri.digest {
            tracing::warn!(%request_id, "registration request does not match the pairing link");
            return Err(ApproverError::DigestMismatch);
        }

        let incoming = Self {
            channel: ResponseChannel {
                request_id,
                response_pubkey: message.params.response_pubkey.clone(),
                bridge,
                expires_at,
            },
            request: message.params,
            respond_by: taken_at + DEFAULT_RESPONSE_DEADLINE,
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

    /// Sets how long from now the response is due, instead of [`DEFAULT_RESPONSE_DEADLINE`]
    /// after the request was taken. The bridge session is assumed to expire a minute later.
    #[must_use]
    pub fn with_response_deadline(mut self, deadline: Duration) -> Self {
        self.respond_by = Instant::now() + deadline;
        self.channel.expires_at = self.respond_by + RESPONSE_MARGIN;
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
        let snapshot = match approver.fetch_account_snapshot().await {
            Ok(snapshot) => snapshot,
            Err(e) => {
                return Err(self
                    .refuse(RegistrationErrorReason::InternalError, Some(e))
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
                Ok(GatewayRequestState::Finalized { .. }) => return Ok(insertion.pubkey_id),
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
