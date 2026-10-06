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

use std::time::Duration;

use backon::{BackoffBuilder as _, ExponentialBuilder, Sleeper as _};
use web_time::Instant;
use world_id_primitives::{
    api_types::{GatewayErrorCode, GatewayRequestState, ServiceApiError},
    authenticator_message::{ErrorObject, Id},
};

use super::{
    KnownAuthenticator, PairingUri, REGISTER_METHOD, RegisterRequestMessage,
    RegisterResponseMessage, RegistrationErrorData, RegistrationErrorReason, RegistrationRequest,
    RegistrationResult, RequestId, TransportError, Vault,
    bridge::{BridgeClient, BridgeError, DeliveryOutcome},
};
use crate::{AccountSnapshot, Authenticator, AuthenticatorClass, AuthenticatorError};

/// How long after taking the request the response is due.
///
/// The bridge keeps a session for 15 minutes after the request is taken, and WIP-109 recommends
/// answering `outcome_unknown` 60 seconds before it expires.
pub const DEFAULT_RESPONSE_DEADLINE: Duration = Duration::from_secs(14 * 60);

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
    /// The registration was refused and the Requesting Authenticator was told why.
    #[error("registration refused: {reason:?}")]
    Refused {
        /// The reason sent to the Requesting Authenticator.
        reason: RegistrationErrorReason,
        /// The underlying error, if the refusal was caused by one.
        #[source]
        source: Option<AuthenticatorError>,
    },
    /// The bridge could not be reached or rejected an operation.
    #[error(transparent)]
    Bridge(#[from] BridgeError),
    /// Decrypting the request or sealing the response failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// A validated registration request, taken from the bridge.
#[derive(Debug)]
pub struct IncomingRegistration {
    request_id: RequestId,
    request: RegistrationRequest,
    bridge: BridgeClient,
    deadline: Instant,
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
    /// - [`ApproverError::DigestMismatch`] if the request is not the one the URI commits to.
    /// - [`ApproverError::InvalidRequest`] if the request is malformed or its signature is
    ///   invalid. An `invalid_params` response is sent when the request carries a usable response
    ///   key.
    /// - [`ApproverError::Bridge`] or [`ApproverError::Transport`] if the request cannot be
    ///   fetched or decrypted.
    pub async fn receive(uri: &PairingUri, bridge: BridgeClient) -> Result<Self, ApproverError> {
        let request_id = uri.secret.request_id();
        let encrypted = bridge
            .take_request(&request_id)
            .await?
            .ok_or(ApproverError::Expired)?;
        let deadline = Instant::now() + DEFAULT_RESPONSE_DEADLINE;
        let plaintext = uri.secret.transport_key().decrypt(&encrypted)?;

        let invalid = |reason: &str| ApproverError::InvalidRequest {
            reason: reason.to_string(),
            responded: false,
        };
        let message: RegisterRequestMessage = serde_json::from_slice(&plaintext)
            .map_err(|e| invalid(&format!("cannot parse the request: {e}")))?;
        if message.method != REGISTER_METHOD {
            return Err(invalid("unexpected method"));
        }
        if message.id != Id::String(request_id.to_string()) {
            return Err(invalid("request id does not match the pairing link"));
        }
        let digest = message
            .params
            .digest(&request_id)
            .map_err(|e| invalid(&e.to_string()))?;
        if digest != uri.digest {
            return Err(ApproverError::DigestMismatch);
        }

        let incoming = Self {
            request_id,
            request: message.params,
            bridge,
            deadline,
        };
        if !incoming.request.verify_signature(&digest) {
            incoming
                .respond(Err(RegistrationErrorReason::InvalidParams
                    .into_error(Some("invalid registration_sig".to_string()))))
                .await?;
            return Err(ApproverError::InvalidRequest {
                reason: "invalid registration signature".to_string(),
                responded: true,
            });
        }
        Ok(incoming)
    }

    /// Sets how long from now the response is due, instead of [`DEFAULT_RESPONSE_DEADLINE`]
    /// from when the request was taken.
    #[must_use]
    pub fn with_response_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = Instant::now() + deadline;
        self
    }

    /// Returns the validated request. Its `name` is untrusted and must be displayed as such.
    #[must_use]
    pub const fn request(&self) -> &RegistrationRequest {
        &self.request
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
        self.respond(Err(reason.into_error(None))).await
    }

    async fn refuse(
        &self,
        reason: RegistrationErrorReason,
        source: Option<AuthenticatorError>,
    ) -> ApproverError {
        match self.respond(Err(reason.into_error(None))).await {
            Ok(_) => ApproverError::Refused { reason, source },
            Err(delivery_error) => delivery_error,
        }
    }

    async fn respond(
        &self,
        outcome: Result<RegistrationResult, ErrorObject<RegistrationErrorData>>,
    ) -> Result<DeliveryOutcome, ApproverError> {
        let response = RegisterResponseMessage {
            id: Id::String(self.request_id.to_string()),
            outcome,
        };
        let plaintext = serde_json::to_vec(&response).map_err(|_| TransportError::Encrypt)?;
        let sealed = self.request.response_pubkey.seal(&plaintext)?;
        Ok(self.bridge.put_response(&self.request_id, &sealed).await?)
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
    /// The registration result, or the reason it failed, as sent to the Requesting
    /// Authenticator.
    pub result: Result<RegistrationResult, RegistrationErrorReason>,
    /// Whether the response reached the bridge.
    pub delivery: DeliveryOutcome,
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
    /// unknown at the response deadline, the response is `outcome_unknown`. A failed or unknown
    /// outcome is never retried with a second insertion.
    ///
    /// # Errors
    ///
    /// Returns an error only if the response cannot be sealed or delivered. A failed
    /// registration is reported in [`ApprovalOutcome::result`].
    pub async fn approve(
        self,
        approver: &Authenticator,
        approval: Approval,
    ) -> Result<ApprovalOutcome, ApproverError> {
        let result = match self.plan {
            RegistrationPlan::AlreadyRegistered { pubkey_id } => Ok(pubkey_id),
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
            Err((reason, detail)) => (Err(reason), Err(reason.into_error(detail))),
        };
        let delivery = self.incoming.respond(outcome).await?;
        Ok(ApprovalOutcome { result, delivery })
    }

    async fn insert(
        &self,
        approver: &Authenticator,
    ) -> Result<u32, (RegistrationErrorReason, Option<String>)> {
        let insertion = approver
            .insert_authenticator_from_snapshot(
                &self.snapshot,
                self.incoming.request.new_authenticator_pubkey.clone(),
                self.incoming.request.class,
            )
            .await
            .map_err(classify_submission_error)?;

        let mut delays = ExponentialBuilder::default()
            .with_min_delay(Duration::from_secs(1))
            .with_max_delay(Duration::from_secs(8))
            .without_max_times()
            .with_jitter()
            .build();
        let mut submitted = false;
        loop {
            match approver.poll_status(&insertion.request_id).await {
                Ok(GatewayRequestState::Finalized { .. }) => return Ok(insertion.pubkey_id),
                Ok(GatewayRequestState::Failed { error_code, .. }) => {
                    return Err(classify_failure(error_code, submitted));
                }
                Ok(GatewayRequestState::Submitted { .. }) => submitted = true,
                Ok(GatewayRequestState::Queued | GatewayRequestState::Batching) | Err(_) => {}
            }
            let delay = delays.next().unwrap_or(Duration::from_secs(8));
            if Instant::now() + delay >= self.incoming.deadline {
                return Err((RegistrationErrorReason::OutcomeUnknown, None));
            }
            backon::DefaultSleeper::default().sleep(delay).await;
        }
    }
}

/// Classifies a failure to submit `InsertAuthenticator`. Only a rejection the gateway answered
/// with a client error is definitive: on a server error or a transport failure the operation may
/// have been accepted.
fn classify_submission_error(
    error: AuthenticatorError,
) -> (RegistrationErrorReason, Option<String>) {
    match error {
        AuthenticatorError::MaxAuthenticatorsReached => {
            (RegistrationErrorReason::MaxAuthenticatorsReached, None)
        }
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
        AuthenticatorError::GatewayError { .. } | AuthenticatorError::NetworkError(_) => {
            (RegistrationErrorReason::OutcomeUnknown, None)
        }
        _ => (RegistrationErrorReason::InternalError, None),
    }
}

/// Classifies a gateway request that ended as failed. A revert is definitive. Other failures are
/// definitive only if they were reported before the transaction was submitted and come from the
/// registry's own checks.
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
            | GatewayErrorCode::BadRequest
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
        assert_eq!(
            classify_failure(Some(GatewayErrorCode::ConfirmationError), false).0,
            RegistrationErrorReason::OutcomeUnknown
        );
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
    }
}
