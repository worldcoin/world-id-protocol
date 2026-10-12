//! The Approving Authenticator's side of a registration (WIP-109 §3.7).
//!
//! The flow is split into steps so that the host can ask for the user's consent in between:
//!
//! 1. [`PendingRegistration::receive`] fetches the encrypted request before code entry.
//! 2. [`PendingRegistration::authenticate`] decrypts and validates it after code entry.
//! 3. [`IncomingRegistration::check`] reads the account state and plans the registration.
//! 4. The host shows the consent screen, then calls [`CheckedRegistration::approve`] or
//!    [`CheckedRegistration::reject`].
//!
//! A step that refuses the registration answers the Requesting Authenticator before it returns,
//! and tells the host whether the answer was delivered.

use std::{future::Future, time::Duration};

use alloy::primitives::Address;
use backon::BackoffBuilder as _;
use eddsa_babyjubjub::EdDSAPublicKey;
use web_time::Instant;
use world_id_primitives::{
    api_types::{GatewayErrorCode, GatewayRequestState, ServiceApiError},
    authenticator_message::{self, ErrorObject, Id, Request, Response, Value, Version},
};
use zeroize::Zeroizing;

use super::{
    BridgeDomain, EncryptedPayload, KnownAuthenticator, MAX_REQUEST_SIZE, MAX_RESPONSE_SIZE,
    MAX_VAULT_SIZE, PairingCode, PairingUri, REGISTER_METHOD, RegisterResponseMessage,
    RegistrationDigest, RegistrationErrorData, RegistrationErrorReason, RegistrationRequest,
    RegistrationResult, RequestId, ResponsePublicKey, TransportError, TransportKey, Vault,
    bridge::{BridgeClient, BridgeError, DeliveryOutcome},
    deadline::{SESSION_TTL, before, polling_backoff, sleep},
};
use crate::{AccountSnapshot, Authenticator, AuthenticatorError, authenticator::leaf_index_of};

/// How many times the user may enter the pairing code for one request (WIP-109 §3.7.1 step 3).
const MAX_CODE_ATTEMPTS: u8 = 3;

/// How long before the estimated session expiry the response is due (WIP-109 §3.5).
const RESPONSE_MARGIN: Duration = Duration::from_secs(60);

/// How long after taking the request the response is due.
pub const DEFAULT_RESPONSE_DEADLINE: Duration =
    Duration::from_secs(SESSION_TTL.as_secs() - RESPONSE_MARGIN.as_secs());

/// The least time left before the response deadline for [`CheckedRegistration::approve`] to
/// still submit an insertion. With less, the outcome would most likely be `outcome_unknown`.
pub const MIN_TRACKING_TIME: Duration = Duration::from_secs(2 * 60);

/// Whether an answer reached the bridge: the bridge's verdict, or the error that kept it from
/// being sent. Only [`DeliveryOutcome::Delivered`] means that the Requesting Authenticator can
/// read it.
pub type Delivery = Result<DeliveryOutcome, Box<ApproverError>>;

/// Errors on the Approving Authenticator's side of a registration.
#[derive(Debug, thiserror::Error)]
pub enum ApproverError {
    /// The Pairing URI names a bridge the host does not allow. The host may ask the user to
    /// confirm it, then retry with a client for it.
    #[error("bridge {0} is not allowed")]
    BridgeNotAllowed(BridgeDomain),
    /// The request expired or was already taken. The user should create a new QR code or link
    /// on the new device.
    #[error("the registration request expired or was already used")]
    Expired,
    /// The code did not authenticate the request. The request is retained for the remaining
    /// code attempts.
    #[error("pairing code did not authenticate the request ({attempts_remaining} attempts remain)")]
    IncorrectCode {
        /// Number of remaining code attempts; zero means a new pairing is required.
        attempts_remaining: u8,
    },
    /// The authenticated request is invalid, or is not the one the Pairing URI commits to
    /// (WIP-109 §3.7.1 step 4).
    #[error("invalid registration request: {reason}")]
    InvalidRequest {
        /// What is wrong with the request.
        reason: String,
        /// The delivery of the error answered, or `None` if none was sent: a notification is
        /// never answered, and a request without a readable `response_pubkey` cannot be.
        delivery: Option<Delivery>,
    },
    /// The registration was refused (WIP-109 §3.7.2).
    #[error("registration refused: {reason:?}")]
    Refused {
        /// The reason, which was sent to the Requesting Authenticator.
        reason: RegistrationErrorReason,
        /// The underlying error, if the refusal was caused by one.
        #[source]
        source: Option<AuthenticatorError>,
        /// The delivery of the reason.
        delivery: Delivery,
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

/// How a checked registration will be carried out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationPlan {
    /// Insert the authenticator at `pubkey_id`.
    Insert {
        /// The slot the authenticator will be inserted at.
        pubkey_id: u32,
    },
    /// The authenticator is already registered as requested, e.g. by an earlier session whose
    /// response was lost. Approval only sends the result.
    AlreadyRegistered {
        /// The slot the authenticator is registered at.
        pubkey_id: u32,
    },
}

/// Attests that the platform's local user verification, a fresh device biometric or PIN check,
/// succeeded for this approval (WIP-109 §3.7.3).
///
/// Entering the pairing code or having an unlocked device does not count. Create it only right
/// after the check succeeds, and pass it to [`CheckedRegistration::approve`]. If the check fails
/// or is unavailable, call [`CheckedRegistration::user_verification_failed`]; if the user cancels
/// it, call [`CheckedRegistration::reject`].
#[derive(Debug)]
pub struct UserVerification(());

impl UserVerification {
    /// Attests that the platform's user verification just succeeded for this approval.
    #[must_use]
    pub const fn platform_check_succeeded() -> Self {
        Self(())
    }
}

/// What the Approving Authenticator shares with an approved authenticator.
#[derive(Clone, Debug, Default)]
pub struct Approval {
    /// The credential vault, only if the user chose to share it in a separate, explicit approval
    /// that was not pre-selected (WIP-109 §3.7.3). Policy may still exclude it.
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
    /// Whether the vault was left out because it exceeds [`MAX_VAULT_SIZE`]. The host must tell
    /// the user that the vault was not shared.
    pub vault_omitted: bool,
    /// The delivery of the response. If it was not delivered, the host must tell the user that
    /// the new device may not have received it, and to check it and retry from it if needed.
    pub delivery: Delivery,
}

/// An encrypted request taken from the bridge, retained for code entry (WIP-109 §3.7.1 step 2).
#[derive(Debug)]
struct RetainedRequest {
    uri: PairingUri,
    encrypted: EncryptedPayload,
    bridge: BridgeClient,
    /// When the fetch started, no later than when the successful `GET /request` was sent. The
    /// session expiry is estimated from it (WIP-109 §3.5).
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

/// An authenticated request that fails validation, and where to answer it (WIP-109 §3.7.1
/// step 4).
#[derive(Debug)]
struct RejectedRequest {
    reason: RegistrationErrorReason,
    /// What is wrong with the request; also sent as `error.data.detail`.
    problem: String,
    /// The ID and key to answer with, or `None` if the request must not or cannot be answered.
    reply: Option<Reply>,
}

/// The response ID and key of an answer to an invalid request (WIP-105 §3.1.4).
#[derive(Debug)]
struct Reply {
    id: Option<Id>,
    response_pubkey: ResponsePublicKey,
}

/// Why the Approving Authenticator refuses a valid request (WIP-109 §3.6.3).
#[derive(Debug)]
struct Refusal {
    reason: RegistrationErrorReason,
    /// Sent to the Requesting Authenticator as `error.data.detail`.
    detail: Option<String>,
    /// The failure behind the refusal, reported to the host but never sent.
    cause: Option<AuthenticatorError>,
}

/// An encrypted request fetched once, waiting for code entry on the approving device.
///
/// Fetch this before prompting for a code. Code entry does not authorize registration;
/// authentication returns an [`IncomingRegistration`] which still needs checks and consent.
#[derive(Debug)]
pub struct PendingRegistration {
    request: Option<RetainedRequest>,
    attempts_remaining: u8,
}

/// A validated registration request, taken from the bridge.
#[derive(Debug)]
pub struct IncomingRegistration {
    request: RegistrationRequest,
    channel: ResponseChannel,
    respond_by: Instant,
}

/// A registration request whose account state was checked, waiting for the user's decision.
#[derive(Debug)]
pub struct CheckedRegistration {
    incoming: IncomingRegistration,
    snapshot: AccountSnapshot,
    plan: RegistrationPlan,
}

impl PendingRegistration {
    /// Fetches the encrypted request from the URI's bridge and retains it for code entry.
    ///
    /// Call it before prompting for the code. A mistyped code is retried against the retained
    /// request, which is never fetched again.
    ///
    /// `allowed_bridges` are the bridge deployments the host allows (WIP-109 §3.4). The URI's
    /// bridge must be one of them; to contact another bridge, the host must first get the user's
    /// confirmation and then pass a client for it.
    ///
    /// # Errors
    ///
    /// Returns [`ApproverError::BridgeNotAllowed`] if the URI's bridge is not allowed,
    /// [`ApproverError::Expired`] for a used or expired URI, or a bridge error.
    pub async fn receive(
        uri: &PairingUri,
        allowed_bridges: &[BridgeClient],
    ) -> Result<Self, ApproverError> {
        let bridge = allowed_bridges
            .iter()
            .find(|bridge| *bridge.domain() == uri.bridge)
            .ok_or_else(|| ApproverError::BridgeNotAllowed(uri.bridge.clone()))?
            .clone();
        let taken_at = Instant::now();
        let encrypted = bridge
            .take_request(&uri.secret.request_id())
            .await?
            .ok_or(ApproverError::Expired)?;
        Ok(Self {
            request: Some(RetainedRequest {
                uri: uri.clone(),
                encrypted,
                bridge,
                taken_at,
            }),
            attempts_remaining: MAX_CODE_ATTEMPTS,
        })
    }

    /// Ends this session and discards the pairing secret and the retained request.
    pub fn cancel(&mut self) {
        self.request = None;
    }

    /// Authenticates the retained request with `code`, then validates it (WIP-109 §3.7.1).
    ///
    /// Nothing is sent before the request is authenticated. An authenticated request that fails
    /// validation is answered with the WIP-105 error, if it carries a readable `response_pubkey`
    /// to seal the answer to.
    ///
    /// # Errors
    ///
    /// [`ApproverError::IncorrectCode`] keeps the request for the remaining code attempts, at
    /// most three in total before the session expires. Every other error ends the session; the
    /// user has to start a new pairing.
    pub async fn authenticate(
        &mut self,
        code: &PairingCode,
    ) -> Result<IncomingRegistration, ApproverError> {
        let retained = self.request.take().ok_or(ApproverError::Expired)?;
        if Instant::now() >= retained.expires_at() {
            return Err(ApproverError::Expired);
        }
        self.attempts_remaining -= 1;
        let decrypted = retained.uri.secret.transport_key(code).and_then(|key| {
            let plaintext = key.decrypt_request(&retained.encrypted)?;
            Ok((key, plaintext))
        });
        match decrypted {
            Ok((key, plaintext)) => {
                IncomingRegistration::from_authenticated(retained, key, &plaintext).await
            }
            Err(TransportError::Decrypt) => {
                if self.attempts_remaining > 0 {
                    self.request = Some(retained);
                }
                Err(ApproverError::IncorrectCode {
                    attempts_remaining: self.attempts_remaining,
                })
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl IncomingRegistration {
    /// Sets how long from now the response is due, instead of [`DEFAULT_RESPONSE_DEADLINE`]
    /// after the request was taken. This cannot extend the bridge session expiry.
    #[must_use]
    pub fn with_response_deadline(mut self, deadline: Duration) -> Self {
        let latest = self.channel.expires_at - RESPONSE_MARGIN;
        self.respond_by = Instant::now()
            .checked_add(deadline)
            .map_or(latest, |due| due.min(latest));
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
    /// Returns [`ApproverError::Refused`] after answering with the reason when `approver` is not
    /// an Admin Authenticator of its account (`not_authorized`), the key or address is
    /// registered differently (`authenticator_conflict`), there is no free slot
    /// (`max_authenticators_reached`), or the account state cannot be read in time
    /// (`internal_error`).
    pub async fn check(
        self,
        approver: &Authenticator,
    ) -> Result<CheckedRegistration, ApproverError> {
        match self.plan(approver).await {
            Ok((snapshot, plan)) => Ok(CheckedRegistration {
                incoming: self,
                snapshot,
                plan,
            }),
            Err(refusal) => Err(self.refuse(refusal).await),
        }
    }

    /// Refuses a request whose `name` the host does not accept, with `invalid_name`
    /// (WIP-109 §3.7.1 step 4).
    ///
    /// # Errors
    ///
    /// Returns an error if the answer cannot be sealed or sent.
    pub async fn reject_name(self) -> Result<DeliveryOutcome, ApproverError> {
        self.channel
            .send(Err(RegistrationErrorReason::InvalidName.into_error(None)))
            .await
    }

    async fn from_authenticated(
        retained: RetainedRequest,
        transport_key: TransportKey,
        plaintext: &[u8],
    ) -> Result<Self, ApproverError> {
        let request_id = retained.uri.secret.request_id();
        let request = parse_request(plaintext, &request_id).and_then(|request| {
            check_pairing(&request, &request_id, &retained.uri.digest)?;
            Ok(request)
        });
        match request {
            Ok(request) => Ok(Self {
                respond_by: retained.taken_at + DEFAULT_RESPONSE_DEADLINE,
                channel: ResponseChannel::new(
                    retained,
                    transport_key,
                    request.response_pubkey.clone(),
                ),
                request,
            }),
            Err(rejected) => Err(rejected.answer(retained, transport_key).await),
        }
    }

    /// Reads the account state of `approver` and decides how to register the authenticator
    /// (WIP-109 §3.7.2).
    async fn plan(
        &self,
        approver: &Authenticator,
    ) -> Result<(AccountSnapshot, RegistrationPlan), Refusal> {
        // Step 1: the registry, not the snapshot, decides whether the approver is still an Admin
        // Authenticator of its account.
        match self
            .before_deadline(approver.fetch_packed_account_data_of(approver.onchain_address()))
            .await?
        {
            Ok(packed) if leaf_index_of(packed) == approver.leaf_index() => {}
            Ok(_) | Err(AuthenticatorError::AccountDoesNotExist) => {
                return Err(RegistrationErrorReason::NotAuthorized.into());
            }
            Err(error) => return Err(Refusal::internal_error(error)),
        }
        let snapshot = self
            .before_deadline(approver.fetch_account_snapshot())
            .await?
            .map_err(Refusal::internal_error)?;
        let plan = plan_registration(
            &snapshot,
            &approver.offchain_pubkey(),
            approver.onchain_address(),
            &self.request,
        )?;
        // Step 4: a new Admin address must not be registered to any account yet.
        if let (RegistrationPlan::Insert { .. }, Some(address)) =
            (plan, self.request.new_authenticator_address)
        {
            match self
                .before_deadline(approver.fetch_packed_account_data_of(address))
                .await?
            {
                Err(AuthenticatorError::AccountDoesNotExist) => {}
                Ok(_) => return Err(RegistrationErrorReason::AuthenticatorConflict.into()),
                Err(error) => return Err(Refusal::internal_error(error)),
            }
        }
        Ok((snapshot, plan))
    }

    /// Runs `future` until the response is due, and refuses with `internal_error` after that.
    async fn before_deadline<F: Future>(&self, future: F) -> Result<F::Output, Refusal> {
        before(self.respond_by, future)
            .await
            .ok_or_else(|| RegistrationErrorReason::InternalError.into())
    }

    /// Answers `refusal` and reports it to the host.
    async fn refuse(&self, refusal: Refusal) -> ApproverError {
        tracing::warn!(
            request = %log_tag(&self.channel.request_id),
            reason = ?refusal.reason,
            error = refusal.cause.as_ref().map(tracing::field::display),
            "refusing authenticator registration"
        );
        let delivery = self.channel.send(Err(refusal.to_error())).await;
        ApproverError::Refused {
            reason: refusal.reason,
            source: refusal.cause,
            delivery: delivery.map_err(Box::new),
        }
    }
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

    /// Declines the registration with `user_rejected`, when the user rejects the request or
    /// cancels device verification (WIP-109 §3.7.3).
    ///
    /// # Errors
    ///
    /// Returns an error if the answer cannot be sealed or sent.
    pub async fn reject(self) -> Result<DeliveryOutcome, ApproverError> {
        self.incoming
            .channel
            .send(Err(RegistrationErrorReason::UserRejected.into_error(None)))
            .await
    }

    /// Ends the registration with `internal_error` because the platform's user verification
    /// failed or is unavailable (WIP-109 §3.7.3). Nothing is registered and the vault is not
    /// shared.
    ///
    /// # Errors
    ///
    /// Returns an error if the answer cannot be sealed or sent.
    pub async fn user_verification_failed(self) -> Result<DeliveryOutcome, ApproverError> {
        self.incoming
            .channel
            .send(Err(RegistrationErrorReason::InternalError.into_error(None)))
            .await
    }

    /// Carries out an approved registration and sends the response (WIP-109 §3.7.4 and §3.7.5).
    ///
    /// Call it only after the user consented on the consent screen and a fresh platform user
    /// verification succeeded, which `verified` attests (WIP-109 §3.7.3). That holds for an
    /// already registered authenticator too, because the vault is shared.
    ///
    /// Unless the authenticator is already registered, this signs and submits
    /// `InsertAuthenticator` from the checked snapshot and tracks it until it is final on-chain
    /// or has definitively failed. If its outcome is still unknown at
    /// [`respond_by`](Self::respond_by), the response is `outcome_unknown`. A failed or unknown
    /// outcome is never retried with a second insertion. If less than [`MIN_TRACKING_TIME`] is
    /// left before the deadline, nothing is submitted and the response is `internal_error`, so
    /// the user can start over with a new link.
    ///
    /// A vault over [`MAX_VAULT_SIZE`] is left out and the registration proceeds without it;
    /// [`ApprovalOutcome::vault_omitted`] tells the host to tell the user (WIP-109 §3.6.2).
    #[must_use = "the outcome tells whether the authenticator was registered"]
    pub async fn approve(
        self,
        approver: &Authenticator,
        approval: Approval,
        verified: UserVerification,
    ) -> ApprovalOutcome {
        let UserVerification(()) = verified;
        let (vault, vault_omitted) = match approval.vault {
            Some(vault) if vault.data.len() > MAX_VAULT_SIZE => (None, true),
            vault => (vault, false),
        };
        let approval = Approval { vault, ..approval };
        let result = self
            .register(approver, &approval)
            .await
            .map(|pubkey_id| RegistrationResult {
                leaf_index: self.snapshot.leaf_index,
                pubkey_id,
                authenticators: approval.authenticators,
                vault: approval.vault,
            });
        if let Err(refusal) = &result {
            tracing::warn!(
                request = %log_tag(&self.incoming.channel.request_id),
                reason = ?refusal.reason,
                detail = refusal.detail,
                error = refusal.cause.as_ref().map(tracing::field::display),
                "authenticator registration did not succeed"
            );
        }
        let delivery = self
            .incoming
            .channel
            .send(result.as_ref().map_err(Refusal::to_error))
            .await;
        ApprovalOutcome {
            result: result.map_err(|refusal| refusal.reason),
            vault_omitted,
            delivery: delivery.map_err(Box::new),
        }
    }

    /// Registers the authenticator as planned and returns its slot.
    async fn register(
        &self,
        approver: &Authenticator,
        approval: &Approval,
    ) -> Result<u32, Refusal> {
        // Checked before submitting, so that an oversized response cannot leave a registered
        // authenticator that never learns its result.
        if !self.response_fits(approval) {
            return Err(Refusal::from(RegistrationErrorReason::InternalError)
                .with_detail("the approval exceeds the response size limit"));
        }
        let time_left = self
            .incoming
            .respond_by
            .saturating_duration_since(Instant::now());
        match self.plan {
            RegistrationPlan::AlreadyRegistered { pubkey_id } => Ok(pubkey_id),
            RegistrationPlan::Insert { .. } if time_left < MIN_TRACKING_TIME => {
                Err(Refusal::from(RegistrationErrorReason::InternalError)
                    .with_detail("approved too close to the session expiry"))
            }
            RegistrationPlan::Insert { .. } => self.insert(approver).await,
        }
    }

    /// Whether a successful response carrying `approval` stays within the size the Requesting
    /// Authenticator accepts.
    fn response_fits(&self, approval: &Approval) -> bool {
        let response = RegisterResponseMessage {
            version: Version::V1,
            id: Some(self.incoming.channel.request_id.message_id()),
            outcome: Ok(RegistrationResult {
                leaf_index: self.snapshot.leaf_index,
                // Every valid slot encodes to the same single CBOR byte.
                pubkey_id: 0,
                authenticators: approval.authenticators.clone(),
                vault: approval.vault.clone(),
            }),
        };
        authenticator_message::encode(&response)
            .map(Zeroizing::new)
            .is_ok_and(|encoded| encoded.len() <= MAX_RESPONSE_SIZE)
    }

    /// Submits `InsertAuthenticator` from the checked snapshot and tracks it until it is final,
    /// has definitively failed, or the response is due (WIP-109 §3.7.4).
    async fn insert(&self, approver: &Authenticator) -> Result<u32, Refusal> {
        let respond_by = self.incoming.respond_by;
        let submission = approver.insert_authenticator_from_snapshot(
            &self.snapshot,
            self.incoming.request.new_authenticator_pubkey.clone(),
            onchain_address(&self.incoming.request),
        );
        let insertion = before(respond_by, submission)
            .await
            .ok_or_else(|| Refusal::from(RegistrationErrorReason::OutcomeUnknown))?
            .map_err(classify_submission_error)?;

        let mut submitted = false;
        let mut failed_polls = 0_u32;
        for delay in polling_backoff().build() {
            let Some(status) = before(respond_by, approver.poll_status(&insertion)).await else {
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
                    tracing::warn!(
                        request = %log_tag(&self.incoming.channel.request_id),
                        %error,
                        failed_polls,
                        "failed to poll the gateway request"
                    );
                }
            }
            if before(respond_by, sleep(delay)).await.is_none() {
                break;
            }
        }
        tracing::warn!(
            request = %log_tag(&self.incoming.channel.request_id),
            gateway_request_id = %insertion,
            submitted,
            failed_polls,
            "insertion outcome unknown at the response deadline"
        );
        Err(RegistrationErrorReason::OutcomeUnknown.into())
    }

    /// Refreshes the account state until it shows the inserted authenticator, and returns its
    /// slot (WIP-109 §3.7.4 step 5).
    async fn confirm_registration(&self, approver: &Authenticator) -> Result<u32, Refusal> {
        let respond_by = self.incoming.respond_by;
        let request = &self.incoming.request;
        for delay in polling_backoff().build() {
            let Some(snapshot) = before(respond_by, approver.fetch_account_snapshot()).await else {
                break;
            };
            match snapshot {
                Ok(snapshot) => {
                    if let Some((slot, address)) = snapshot
                        .authenticators
                        .find(&request.new_authenticator_pubkey)
                    {
                        return if address == onchain_address(request) {
                            Ok(slot)
                        } else {
                            Err(RegistrationErrorReason::AuthenticatorConflict.into())
                        };
                    }
                }
                Err(error) => tracing::warn!(
                    request = %log_tag(&self.incoming.channel.request_id),
                    %error,
                    "failed to refresh the account state after the insertion"
                ),
            }
            if before(respond_by, sleep(delay)).await.is_none() {
                break;
            }
        }
        tracing::warn!(
            request = %log_tag(&self.incoming.channel.request_id),
            "finalized registration not visible before the response deadline"
        );
        Err(RegistrationErrorReason::OutcomeUnknown.into())
    }
}

impl RetainedRequest {
    fn expires_at(&self) -> Instant {
        self.taken_at + SESSION_TTL
    }
}

impl ResponseChannel {
    fn new(
        retained: RetainedRequest,
        transport_key: TransportKey,
        response_pubkey: ResponsePublicKey,
    ) -> Self {
        Self {
            request_id: retained.uri.secret.request_id(),
            response_pubkey,
            transport_key,
            expires_at: retained.expires_at(),
            bridge: retained.bridge,
        }
    }

    /// Sends `outcome` as the response to the request.
    async fn send(
        &self,
        outcome: Result<&RegistrationResult, ErrorObject<RegistrationErrorData>>,
    ) -> Result<DeliveryOutcome, ApproverError> {
        self.reply(Some(self.request_id.message_id()), outcome)
            .await
    }

    /// Sends `outcome` with response ID `id`, which differs from the request's own only for an
    /// invalid request (WIP-105 §3.1.4).
    async fn reply(
        &self,
        id: Option<Id>,
        outcome: Result<&RegistrationResult, ErrorObject<RegistrationErrorData>>,
    ) -> Result<DeliveryOutcome, ApproverError> {
        let delivery = async {
            let response = Response {
                version: Version::V1,
                id,
                outcome,
            };
            let encoded = Zeroizing::new(authenticator_message::encode(&response)?);
            let sealed = self
                .transport_key
                .encrypt_response(&self.response_pubkey, &encoded)?;
            before(
                self.expires_at,
                self.bridge.put_response(&self.request_id, &sealed),
            )
            .await
            .ok_or(ApproverError::SessionExpired)?
            .map_err(ApproverError::from)
        }
        .await;
        match &delivery {
            Ok(DeliveryOutcome::Delivered) => {}
            Ok(outcome) => tracing::warn!(
                request = %log_tag(&self.request_id),
                ?outcome,
                "the bridge did not take the registration response"
            ),
            Err(error) => tracing::warn!(
                request = %log_tag(&self.request_id),
                %error,
                "failed to deliver the registration response"
            ),
        }
        delivery
    }
}

impl RejectedRequest {
    /// Answers the request if it can be, and reports it to the host.
    async fn answer(
        self: Box<Self>,
        retained: RetainedRequest,
        transport_key: TransportKey,
    ) -> ApproverError {
        let request = log_tag(&retained.uri.secret.request_id());
        let delivery = match self.reply {
            Some(Reply {
                id,
                response_pubkey,
            }) => {
                let channel = ResponseChannel::new(retained, transport_key, response_pubkey);
                let error = self.reason.into_error(Some(self.problem.clone()));
                Some(channel.reply(id, Err(error)).await.map_err(Box::new))
            }
            None => None,
        };
        tracing::warn!(
            request,
            reason = ?self.reason,
            problem = self.problem,
            answered = delivery.is_some(),
            "invalid registration request"
        );
        ApproverError::InvalidRequest {
            reason: self.problem,
            delivery,
        }
    }
}

impl Refusal {
    /// A refusal with `internal_error`, because reading the account state failed.
    fn internal_error(cause: AuthenticatorError) -> Self {
        Self {
            cause: Some(cause),
            ..RegistrationErrorReason::InternalError.into()
        }
    }

    fn with_detail(self, detail: impl Into<String>) -> Self {
        Self {
            detail: Some(detail.into()),
            ..self
        }
    }

    fn to_error(&self) -> ErrorObject<RegistrationErrorData> {
        self.reason.into_error(self.detail.clone())
    }
}

impl From<RegistrationErrorReason> for Refusal {
    fn from(reason: RegistrationErrorReason) -> Self {
        Self {
            reason,
            detail: None,
            cause: None,
        }
    }
}

/// Parses a decrypted registration request in the order of WIP-109 §3.7.1 step 4: CBOR
/// (`parse_error`), envelope and ID (`invalid_request`), method (`method_not_found`) and params
/// (`invalid_params`).
///
/// The answer to an invalid request carries its ID, or null if the ID cannot be read, and is
/// sealed to its `params.response_pubkey`; without a readable key it cannot be sent. A
/// notification, a valid request without an ID, is never answered (WIP-105 §3.1.2).
fn parse_request(
    plaintext: &[u8],
    request_id: &RequestId,
) -> Result<RegistrationRequest, Box<RejectedRequest>> {
    let value: Value =
        authenticator_message::decode(plaintext, MAX_REQUEST_SIZE).map_err(|error| {
            Box::new(RejectedRequest {
                reason: RegistrationErrorReason::ParseError,
                problem: error.to_string(),
                reply: None,
            })
        })?;
    let reply_to = |id| {
        response_pubkey_of(&value).map(|response_pubkey| Reply {
            id,
            response_pubkey,
        })
    };
    let envelope: Request<Value> = value.deserialized().map_err(|error| {
        Box::new(RejectedRequest {
            reason: RegistrationErrorReason::InvalidRequest,
            problem: error.to_string(),
            reply: reply_to(unique_field(&value, "id").and_then(|id| id.deserialized().ok())),
        })
    })?;
    let Some(id) = envelope.id else {
        return Err(Box::new(RejectedRequest {
            reason: RegistrationErrorReason::InvalidRequest,
            problem: "the request is a notification".to_string(),
            reply: None,
        }));
    };
    let rejected = |reason, problem: String| {
        Box::new(RejectedRequest {
            reason,
            problem,
            reply: reply_to(Some(id.clone())),
        })
    };
    if id != request_id.message_id() {
        return Err(rejected(
            RegistrationErrorReason::InvalidRequest,
            "the request id does not match the pairing link".to_string(),
        ));
    }
    if envelope.method != REGISTER_METHOD {
        return Err(rejected(
            RegistrationErrorReason::MethodNotFound,
            format!("unexpected method {}", envelope.method.as_str()),
        ));
    }
    let params = envelope.params.ok_or_else(|| {
        rejected(
            RegistrationErrorReason::InvalidParams,
            "missing params".to_string(),
        )
    })?;
    let invalid_params = |error: &dyn std::fmt::Display| {
        rejected(RegistrationErrorReason::InvalidParams, error.to_string())
    };
    super::reject_tags(&params).map_err(|error| invalid_params(&error))?;
    params
        .deserialized()
        .map_err(|error| invalid_params(&error))
}

/// Reads `params.response_pubkey` from a request that failed validation, to seal the answer to.
fn response_pubkey_of(request: &Value) -> Option<ResponsePublicKey> {
    let key = unique_field(unique_field(request, "params")?, "response_pubkey")?.as_bytes()?;
    ResponsePublicKey::from_bytes(key).ok()
}

/// Returns the value of `key` in `map`, if `map` is a map that has it exactly once.
fn unique_field<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    let mut values = map
        .as_map()?
        .iter()
        .filter(|(k, _)| k.as_text() == Some(key))
        .map(|(_, value)| value);
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

/// Checks that `request` is the one the Pairing URI commits to, signed by the key it asks to
/// register (WIP-109 §3.7.1 step 4). A mismatch is answered with `invalid_params`.
fn check_pairing(
    request: &RegistrationRequest,
    request_id: &RequestId,
    uri_digest: &RegistrationDigest,
) -> Result<(), Box<RejectedRequest>> {
    let rejected = |problem: String| {
        Box::new(RejectedRequest {
            reason: RegistrationErrorReason::InvalidParams,
            problem,
            reply: Some(Reply {
                id: Some(request_id.message_id()),
                response_pubkey: request.response_pubkey.clone(),
            }),
        })
    };
    let digest = request
        .digest(request_id)
        .map_err(|error| rejected(error.to_string()))?;
    if digest != *uri_digest {
        return Err(rejected(
            "the request does not match the pairing link".to_string(),
        ));
    }
    if !request.verify_signature(&digest) {
        return Err(rejected("invalid registration_sig".to_string()));
    }
    Ok(())
}

/// Decides how to register the requested authenticator on the account `snapshot` shows, for
/// the approver with `approver_pubkey` and management key `approver_address` (WIP-109 §3.7.2
/// steps 1, 3 and 5).
fn plan_registration(
    snapshot: &AccountSnapshot,
    approver_pubkey: &EdDSAPublicKey,
    approver_address: Address,
    request: &RegistrationRequest,
) -> Result<RegistrationPlan, RegistrationErrorReason> {
    let authenticators = &snapshot.authenticators;
    if authenticators
        .find(approver_pubkey)
        .map(|(_, address)| address)
        != Some(approver_address)
    {
        return Err(RegistrationErrorReason::NotAuthorized);
    }

    if let Some((pubkey_id, address)) = authenticators.find(&request.new_authenticator_pubkey) {
        if address != onchain_address(request) {
            return Err(RegistrationErrorReason::AuthenticatorConflict);
        }
        return Ok(RegistrationPlan::AlreadyRegistered { pubkey_id });
    }

    if request
        .new_authenticator_address
        .is_some_and(|address| authenticators.addresses().contains(&Some(address)))
    {
        return Err(RegistrationErrorReason::AuthenticatorConflict);
    }

    snapshot
        .lowest_free_pubkey_id()
        .map(|pubkey_id| RegistrationPlan::Insert { pubkey_id })
        .ok_or(RegistrationErrorReason::MaxAuthenticatorsReached)
}

/// The address the registry records for the requested authenticator: its management key, or the
/// zero address for a Proving Authenticator (WIP-104).
fn onchain_address(request: &RegistrationRequest) -> Address {
    request.new_authenticator_address.unwrap_or(Address::ZERO)
}

/// Classifies a failure to submit `InsertAuthenticator`.
///
/// The gateway answering with a client error is definitive: it did not accept the operation.
/// Failing before anything was sent is an internal error. Any other failure happened after the
/// request may have reached the gateway, so its outcome is unknown.
fn classify_submission_error(error: AuthenticatorError) -> Refusal {
    let (reason, code) = match &error {
        AuthenticatorError::MaxAuthenticatorsReached => {
            (RegistrationErrorReason::MaxAuthenticatorsReached, None)
        }
        AuthenticatorError::PrimitiveError(_) => (RegistrationErrorReason::InternalError, None),
        AuthenticatorError::GatewayError { status, body } if status.is_client_error() => {
            let code = serde_json::from_str::<ServiceApiError<GatewayErrorCode>>(body)
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
            (reason, code)
        }
        _ => (RegistrationErrorReason::OutcomeUnknown, None),
    };
    Refusal {
        reason,
        detail: code.map(|code| code.to_string()),
        cause: Some(error),
    }
}

/// Classifies a gateway request that ended as failed.
///
/// A revert is definitive. Before the transaction was submitted, only failures decoded from the
/// registry's own checks are definitive. Every other failure, including the gateway's catch-all
/// `bad_request` for errors sending the transaction, may still land on-chain.
fn classify_failure(error_code: Option<GatewayErrorCode>, submitted: bool) -> Refusal {
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
    Refusal {
        reason,
        detail,
        cause: None,
    }
}

/// A short tag that correlates log lines of one session. The request id itself is never logged:
/// it is the only key to the session's bridge routes.
fn log_tag(request_id: &RequestId) -> String {
    use sha2::Digest as _;
    hex::encode(&sha2::Sha256::digest(request_id.as_bytes())[..4])
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use alloy::primitives::U256;
    use secrecy::ExposeSecret as _;
    use test_case::test_case;
    use world_id_primitives::Signer;

    use super::*;
    use crate::registration::{
        PairingSecret, RegisterRequestMessage, RequestedClass, ResponseSecretKey, decode_response,
        fixtures::indexed_account,
    };

    /// The Requesting Authenticator's side of a session, built from the protocol primitives.
    struct Requester {
        uri: PairingUri,
        code: PairingCode,
        response_key: ResponseSecretKey,
        request: RegistrationRequest,
    }

    /// A change to the valid request message.
    #[derive(Debug)]
    enum Tamper {
        Nothing,
        /// Replaces the whole message.
        Bytes(Vec<u8>),
        /// Removes a top-level field.
        Remove(&'static str),
        /// Sets the field at a dot-separated path.
        Set(&'static str, Value),
    }

    /// How a rejected request is answered.
    #[derive(Debug)]
    enum ExpectedReply {
        NoAnswer,
        RequestId,
        OtherId(&'static str),
        NullId,
    }

    impl Requester {
        fn new() -> Self {
            let pairing_secret = PairingSecret::from_bytes([7; 32]);
            let response_key = ResponseSecretKey::from_seed(&[8; 32]);
            let signer = Signer::from_seed_bytes(&[9; 32]).unwrap();
            let (request, digest) = RegistrationRequest::new_signed(
                signer.offchain_signer_private_key().expose_secret(),
                None,
                response_key.public_key(),
                None,
                &pairing_secret.request_id(),
            )
            .unwrap();
            Self {
                uri: PairingUri {
                    secret: pairing_secret,
                    digest,
                    bridge: "bridge.example.org".parse().unwrap(),
                },
                code: "QJTWPK".parse().unwrap(),
                response_key,
                request,
            }
        }

        fn request_id(&self) -> RequestId {
            self.uri.secret.request_id()
        }

        fn transport_key(&self) -> TransportKey {
            self.uri.secret.transport_key(&self.code).unwrap()
        }

        /// The encoded request message, changed by `tamper`.
        fn message(&self, tamper: Tamper) -> Vec<u8> {
            let valid = RegisterRequestMessage::builder()
                .id(self.request_id().message_id())
                .method(REGISTER_METHOD)
                .params(self.request.clone())
                .build();
            let valid = authenticator_message::encode(&valid).unwrap();
            let mut message: Value =
                authenticator_message::decode(&valid, MAX_REQUEST_SIZE).unwrap();
            match tamper {
                Tamper::Nothing => {}
                Tamper::Bytes(bytes) => return bytes,
                Tamper::Remove(key) => message
                    .as_map_mut()
                    .unwrap()
                    .retain(|(k, _)| k.as_text() != Some(key)),
                Tamper::Set(path, value) => set_field(&mut message, path, value),
            }
            authenticator_message::encode(&message).unwrap()
        }

        /// Serves `plaintext`, encrypted, as the request of this session on `server`, and receives
        /// it. The returned mock fails its assertion if the request is fetched again.
        async fn serve(
            &self,
            server: &mut mockito::ServerGuard,
            plaintext: &[u8],
        ) -> (PendingRegistration, mockito::Mock) {
            let encrypted = self.transport_key().encrypt_request(plaintext).unwrap();
            let fetch = server
                .mock("GET", format!("/request/{}", self.request_id()).as_str())
                .with_status(200)
                .with_body(serde_json::to_vec(&encrypted).unwrap())
                .expect(1)
                .create_async()
                .await;
            let pending = PendingRegistration::receive(&self.uri, &[bridge(server)])
                .await
                .unwrap();
            (pending, fetch)
        }

        fn open(&self, sealed: &EncryptedPayload) -> RegisterResponseMessage {
            let plaintext = self
                .transport_key()
                .decrypt_response(&self.response_key, sealed)
                .unwrap();
            decode_response(&plaintext).unwrap()
        }
    }

    fn bridge(server: &mockito::ServerGuard) -> BridgeClient {
        BridgeClient::with_base_url(
            "bridge.example.org".parse().unwrap(),
            server.url().parse().unwrap(),
        )
        .unwrap()
    }

    /// Replaces the value at the dot-separated `path` of a CBOR map.
    fn set_field(map: &mut Value, path: &str, new: Value) {
        let (key, rest) = path
            .split_once('.')
            .map_or((path, None), |(key, rest)| (key, Some(rest)));
        let value = map
            .as_map_mut()
            .unwrap()
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, value)| value)
            .unwrap();
        match rest {
            Some(rest) => set_field(value, rest, new),
            None => *value = new,
        }
    }

    /// Records the body of every `PUT /response` of `requester`'s session, answered with `status`.
    async fn capture_answers(
        requester: &Requester,
        server: &mut mockito::ServerGuard,
        status: usize,
    ) -> Arc<Mutex<Vec<EncryptedPayload>>> {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&captured);
        server
            .mock(
                "PUT",
                format!("/response/{}", requester.request_id()).as_str(),
            )
            .match_request(move |request| {
                let payload = serde_json::from_slice(request.body().unwrap()).unwrap();
                sink.lock().unwrap().push(payload);
                true
            })
            .with_status(status)
            .create_async()
            .await;
        captured
    }

    #[tokio::test]
    async fn receive_contacts_only_an_allowed_bridge() {
        let mut server = mockito::Server::new_async().await;
        let untouched = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;
        let requester = Requester::new();
        let other = BridgeClient::with_base_url(
            "other.example.org".parse().unwrap(),
            server.url().parse().unwrap(),
        )
        .unwrap();
        assert!(matches!(
            PendingRegistration::receive(&requester.uri, &[other]).await,
            Err(ApproverError::BridgeNotAllowed(domain)) if domain == requester.uri.bridge
        ));
        untouched.assert_async().await;
    }

    #[tokio::test]
    async fn a_mistyped_code_is_retried_against_the_retained_request() {
        let mut server = mockito::Server::new_async().await;
        let requester = Requester::new();
        let (mut pending, fetch) = requester
            .serve(&mut server, &requester.message(Tamper::Nothing))
            .await;
        let wrong = "AAAAAA".parse().unwrap();

        assert!(matches!(
            pending.authenticate(&wrong).await,
            Err(ApproverError::IncorrectCode {
                attempts_remaining: 2
            })
        ));
        let incoming = pending.authenticate(&requester.code).await.unwrap();
        assert_eq!(incoming.request(), &requester.request);
        assert!(matches!(
            pending.authenticate(&requester.code).await,
            Err(ApproverError::Expired)
        ));
        fetch.assert_async().await;
    }

    #[tokio::test]
    async fn the_last_wrong_code_ends_the_session() {
        let mut server = mockito::Server::new_async().await;
        let requester = Requester::new();
        let (mut pending, fetch) = requester
            .serve(&mut server, &requester.message(Tamper::Nothing))
            .await;
        let wrong = "AAAAAA".parse().unwrap();

        for remaining in (0..MAX_CODE_ATTEMPTS).rev() {
            assert!(matches!(
                pending.authenticate(&wrong).await,
                Err(ApproverError::IncorrectCode { attempts_remaining }) if attempts_remaining == remaining
            ));
        }
        assert!(matches!(
            pending.authenticate(&requester.code).await,
            Err(ApproverError::Expired)
        ));
        fetch.assert_async().await;
    }

    #[test]
    fn parse_request_accepts_the_committed_request() {
        let requester = Requester::new();
        let request =
            parse_request(&requester.message(Tamper::Nothing), &requester.request_id()).unwrap();
        assert_eq!(request, requester.request);
        check_pairing(&request, &requester.request_id(), &requester.uri.digest).unwrap();
    }

    #[test_case(Tamper::Bytes(vec![0xff]), RegistrationErrorReason::ParseError, ExpectedReply::NoAnswer; "not CBOR")]
    #[test_case(Tamper::Remove("id"), RegistrationErrorReason::InvalidRequest, ExpectedReply::NoAnswer; "a notification")]
    #[test_case(Tamper::Remove("params"), RegistrationErrorReason::InvalidParams, ExpectedReply::NoAnswer; "no response key to seal to")]
    #[test_case(Tamper::Set("id", Value::Bool(true)), RegistrationErrorReason::InvalidRequest, ExpectedReply::NullId; "an unreadable id")]
    #[test_case(Tamper::Set("version", "2.0".into()), RegistrationErrorReason::InvalidRequest, ExpectedReply::RequestId; "an unsupported version")]
    #[test_case(Tamper::Set("id", "other".into()), RegistrationErrorReason::InvalidRequest, ExpectedReply::OtherId("other"); "another id")]
    #[test_case(Tamper::Set("method", "worldid_auth_v1_other".into()), RegistrationErrorReason::MethodNotFound, ExpectedReply::RequestId; "another method")]
    #[test_case(Tamper::Set("params.registration_sig", Value::Bytes(vec![0; 63])), RegistrationErrorReason::InvalidParams, ExpectedReply::RequestId; "malformed params")]
    fn parse_request_answers_an_invalid_request_only_when_it_may_and_can(
        tamper: Tamper,
        reason: RegistrationErrorReason,
        expected_reply: ExpectedReply,
    ) {
        let requester = Requester::new();
        let rejected =
            parse_request(&requester.message(tamper), &requester.request_id()).unwrap_err();
        assert_eq!(rejected.reason, reason);
        let expected_id = match expected_reply {
            ExpectedReply::NoAnswer => None,
            ExpectedReply::RequestId => Some(Some(requester.request_id().message_id())),
            ExpectedReply::OtherId(id) => Some(Some(Id::String(id.to_string()))),
            ExpectedReply::NullId => Some(None),
        };
        let reply_id = rejected.reply.map(|reply| {
            assert_eq!(reply.response_pubkey, requester.response_key.public_key());
            reply.id
        });
        assert_eq!(reply_id, expected_id);
    }

    #[test]
    fn check_pairing_rejects_a_request_the_link_does_not_commit_to() {
        let requester = Requester::new();
        let other_digest = RegistrationDigest::from_bytes([0; 32]);
        let rejected =
            check_pairing(&requester.request, &requester.request_id(), &other_digest).unwrap_err();
        assert_eq!(rejected.reason, RegistrationErrorReason::InvalidParams);
        assert_eq!(
            rejected.problem,
            "the request does not match the pairing link"
        );
    }

    #[test]
    fn check_pairing_rejects_a_signature_over_another_session() {
        let requester = Requester::new();
        let signer = Signer::from_seed_bytes(&[9; 32]).unwrap();
        let (other_session, _) = RegistrationRequest::new_signed(
            signer.offchain_signer_private_key().expose_secret(),
            None,
            requester.response_key.public_key(),
            None,
            &PairingSecret::from_bytes([10; 32]).request_id(),
        )
        .unwrap();
        let request = RegistrationRequest {
            registration_sig: other_session.registration_sig,
            ..requester.request.clone()
        };
        let rejected =
            check_pairing(&request, &requester.request_id(), &requester.uri.digest).unwrap_err();
        assert_eq!(rejected.reason, RegistrationErrorReason::InvalidParams);
        assert_eq!(rejected.problem, "invalid registration_sig");
    }

    /// A slot of an account in a planning test.
    #[derive(Clone, Copy, Debug)]
    enum Slot {
        /// The approver's key, registered with its management key or as a Proving Authenticator.
        Approver(RequestedClass),
        /// The requested key, registered with the requested address or as a Proving
        /// Authenticator.
        Requested(RequestedClass),
        /// Another key, registered with the requested address.
        RequestedAddress,
        /// Another Admin Authenticator.
        Other,
        Removed,
    }

    const APPROVER_SEED: [u8; 32] = [1; 32];
    const OTHER_SEED: [u8; 32] = [3; 32];
    const REQUESTED_ADDRESS: Address = Address::repeat_byte(0x22);

    /// The on-chain address of an authenticator of `class` with management key `admin_address`.
    fn address_of(class: RequestedClass, admin_address: Address) -> Address {
        match class {
            RequestedClass::Admin => admin_address,
            RequestedClass::Proving => Address::ZERO,
        }
    }

    #[test_case(&[Slot::Other], 7, RequestedClass::Proving, Err(RegistrationErrorReason::NotAuthorized); "an approver not on the account")]
    #[test_case(&[Slot::Approver(RequestedClass::Proving)], 7, RequestedClass::Proving, Err(RegistrationErrorReason::NotAuthorized); "a Proving approver")]
    #[test_case(&[Slot::Approver(RequestedClass::Admin), Slot::Requested(RequestedClass::Proving)], 7, RequestedClass::Proving, Ok(RegistrationPlan::AlreadyRegistered { pubkey_id: 1 }); "the key already registered as requested")]
    #[test_case(&[Slot::Approver(RequestedClass::Admin), Slot::Requested(RequestedClass::Admin)], 7, RequestedClass::Proving, Err(RegistrationErrorReason::AuthenticatorConflict); "the key registered as another class")]
    #[test_case(&[Slot::Approver(RequestedClass::Admin), Slot::RequestedAddress], 7, RequestedClass::Admin, Err(RegistrationErrorReason::AuthenticatorConflict); "the address registered for another key")]
    #[test_case(&[Slot::Approver(RequestedClass::Admin), Slot::Removed, Slot::Other], 7, RequestedClass::Admin, Ok(RegistrationPlan::Insert { pubkey_id: 1 }); "the lowest free slot")]
    #[test_case(&[Slot::Approver(RequestedClass::Admin), Slot::Other], 2, RequestedClass::Proving, Err(RegistrationErrorReason::MaxAuthenticatorsReached); "no free slot below the registry maximum")]
    fn plan_registration_follows_the_account_state(
        slots: &[Slot],
        max_authenticators: usize,
        requested: RequestedClass,
        expected: Result<RegistrationPlan, RegistrationErrorReason>,
    ) {
        let approver = Signer::from_seed_bytes(&APPROVER_SEED).unwrap();
        let other = Signer::from_seed_bytes(&OTHER_SEED).unwrap();
        let requester = Requester::new();
        let indexed: Vec<_> = slots
            .iter()
            .map(|slot| match *slot {
                Slot::Approver(class) => Some((
                    approver.offchain_signer_pubkey(),
                    address_of(class, approver.onchain_signer_address()),
                )),
                Slot::Requested(class) => Some((
                    requester.request.new_authenticator_pubkey.clone(),
                    address_of(class, REQUESTED_ADDRESS),
                )),
                Slot::RequestedAddress => Some((other.offchain_signer_pubkey(), REQUESTED_ADDRESS)),
                Slot::Other => Some((
                    other.offchain_signer_pubkey(),
                    other.onchain_signer_address(),
                )),
                Slot::Removed => None,
            })
            .collect();
        let snapshot = AccountSnapshot {
            leaf_index: 42,
            signature_nonce: U256::ZERO,
            authenticators: indexed_account(&indexed).try_into().unwrap(),
            max_authenticators: Some(max_authenticators),
        };
        let request = RegistrationRequest {
            new_authenticator_address: match requested {
                RequestedClass::Admin => Some(REQUESTED_ADDRESS),
                RequestedClass::Proving => None,
            },
            ..requester.request
        };

        let plan = plan_registration(
            &snapshot,
            &approver.offchain_signer_pubkey(),
            approver.onchain_signer_address(),
            &request,
        );
        assert_eq!(plan, expected);
    }

    #[test_case(201, DeliveryOutcome::Delivered; "delivered")]
    #[test_case(409, DeliveryOutcome::Rejected; "rejected by the bridge")]
    #[tokio::test]
    async fn an_authenticated_invalid_request_is_answered_with_a_sealed_error(
        status: usize,
        expected_delivery: DeliveryOutcome,
    ) {
        let mut server = mockito::Server::new_async().await;
        let requester = Requester::new();
        let other_method = Tamper::Set("method", "worldid_auth_v1_other".into());
        let (mut pending, _) = requester
            .serve(&mut server, &requester.message(other_method))
            .await;
        let answers = capture_answers(&requester, &mut server, status).await;

        let error = pending.authenticate(&requester.code).await.unwrap_err();
        assert!(matches!(
            error,
            ApproverError::InvalidRequest {
                delivery: Some(Ok(delivery)),
                ..
            } if delivery == expected_delivery
        ));
        let answers = std::mem::take(&mut *answers.lock().unwrap());
        let [answer] = answers.as_slice() else {
            panic!("expected one answer, got {}", answers.len());
        };
        let response = requester.open(answer);
        assert_eq!(response.id, Some(requester.request_id().message_id()));
        assert_eq!(response.outcome.unwrap_err().code, "method_not_found");
        assert!(matches!(
            pending.authenticate(&requester.code).await,
            Err(ApproverError::Expired)
        ));
    }

    #[test_case(Some(GatewayErrorCode::TransactionReverted), false, RegistrationErrorReason::OperationFailed; "a revert before submission")]
    #[test_case(Some(GatewayErrorCode::TransactionReverted), true, RegistrationErrorReason::OperationFailed; "a revert after submission")]
    #[test_case(Some(GatewayErrorCode::ConfirmationError), true, RegistrationErrorReason::OutcomeUnknown; "a confirmation error after submission")]
    #[test_case(Some(GatewayErrorCode::MismatchedSignatureNonce), true, RegistrationErrorReason::OutcomeUnknown; "a registry check after submission")]
    #[test_case(Some(GatewayErrorCode::BadRequest), true, RegistrationErrorReason::OutcomeUnknown; "a catch-all after submission")]
    #[test_case(Some(GatewayErrorCode::InternalServerError), true, RegistrationErrorReason::OutcomeUnknown; "an internal error after submission")]
    #[test_case(None, true, RegistrationErrorReason::OutcomeUnknown; "no code after submission")]
    #[test_case(Some(GatewayErrorCode::MismatchedSignatureNonce), false, RegistrationErrorReason::OperationFailed; "a stale nonce before submission")]
    #[test_case(Some(GatewayErrorCode::AuthenticatorAlreadyExists), false, RegistrationErrorReason::AuthenticatorConflict; "an existing authenticator before submission")]
    #[test_case(Some(GatewayErrorCode::PubkeyIdOutOfBounds), false, RegistrationErrorReason::MaxAuthenticatorsReached; "a slot out of bounds before submission")]
    #[test_case(Some(GatewayErrorCode::ConfirmationError), false, RegistrationErrorReason::OutcomeUnknown; "a confirmation error before submission")]
    #[test_case(Some(GatewayErrorCode::BadRequest), false, RegistrationErrorReason::OutcomeUnknown; "a catch-all before submission")]
    #[test_case(None, false, RegistrationErrorReason::OutcomeUnknown; "no code before submission")]
    fn failed_insertions_are_definitive_only_when_they_cannot_land(
        error_code: Option<GatewayErrorCode>,
        submitted: bool,
        expected: RegistrationErrorReason,
    ) {
        assert_eq!(classify_failure(error_code, submitted).reason, expected);
    }

    fn gateway_error(status: u16, code: &str) -> AuthenticatorError {
        AuthenticatorError::GatewayError {
            status: reqwest::StatusCode::from_u16(status).unwrap(),
            body: serde_json::json!({ "code": code, "message": "x" }).to_string(),
        }
    }

    #[test_case(gateway_error(400, "authenticator_already_exists"), RegistrationErrorReason::AuthenticatorConflict, Some("authenticator_already_exists"); "an existing authenticator")]
    #[test_case(gateway_error(400, "pubkey_id_out_of_bounds"), RegistrationErrorReason::MaxAuthenticatorsReached, Some("pubkey_id_out_of_bounds"); "a slot out of bounds")]
    #[test_case(gateway_error(429, "rate_limit_exceeded"), RegistrationErrorReason::OperationFailed, Some("rate_limit_exceeded"); "a rate limit")]
    #[test_case(gateway_error(503, "batcher_unavailable"), RegistrationErrorReason::OutcomeUnknown, None; "a server error")]
    #[test_case(AuthenticatorError::MaxAuthenticatorsReached, RegistrationErrorReason::MaxAuthenticatorsReached, None; "no free slot")]
    #[test_case(AuthenticatorError::Generic("relay timeout".into()), RegistrationErrorReason::OutcomeUnknown, None; "a transport failure")]
    fn submission_errors_are_definitive_only_for_client_errors(
        error: AuthenticatorError,
        expected: RegistrationErrorReason,
        detail: Option<&str>,
    ) {
        let refusal = classify_submission_error(error);
        assert_eq!(
            (refusal.reason, refusal.detail.as_deref()),
            (expected, detail)
        );
    }
}
