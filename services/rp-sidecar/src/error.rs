//! How a verification that did not accept the proof is answered.
//!
//! Every answer carries a `result` the caller branches on and a stable `code` for logs and
//! metrics. Only `200` means accepted, so a caller that checks just the status cannot accept a
//! rejected proof.

use std::time::Duration;

use axum::{
    Json,
    extract::rejection::JsonRejection,
    http::{HeaderValue, StatusCode, header::RETRY_AFTER},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tokio::task::JoinError;
use world_id_primitives::ValidationError;
use world_id_proof::ProofError;
use world_id_rp::embedding_similarity::EmbeddingSimilarityVerificationError;

/// A verification that did not accept the proof.
#[derive(Debug)]
pub struct ApiError {
    code: Code,
    message: String,
}

impl ApiError {
    pub const fn code(&self) -> Code {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn overloaded() -> Self {
        Self {
            code: Code::Overloaded,
            message: "every verification slot is busy".to_owned(),
        }
    }

    pub fn timeout(timeout: Duration) -> Self {
        Self {
            code: Code::Timeout,
            message: format!(
                "the verification did not finish within {}s",
                timeout.as_secs()
            ),
        }
    }

    pub fn verification_panicked(error: &JoinError) -> Self {
        Self {
            code: Code::VerificationPanicked,
            message: format!("the verification did not finish: {error}"),
        }
    }
}

impl From<EmbeddingSimilarityVerificationError> for ApiError {
    fn from(error: EmbeddingSimilarityVerificationError) -> Self {
        use EmbeddingSimilarityVerificationError as Error;

        let code = match &error {
            Error::NotEmbeddingSimilarity => Code::NotEmbeddingSimilarity,
            Error::Response(ValidationError::InvalidProofRequest(_)) => Code::InvalidRequest,
            Error::Response(_) => Code::ResponseMismatch,
            Error::RequestExpired { .. } => Code::RequestExpired,
            Error::Attestation(_) => Code::AttestationNotAccepted,
            Error::AttestedKeyMismatch => Code::AttestedKeyMismatch,
            Error::EngineNotAccepted(_) => Code::EngineNotAccepted,
            Error::Stale { .. } => Code::StaleProof,
            Error::InvalidRoot(_) => Code::InvalidRoot,
            Error::UntrustedIssuerKey => Code::UntrustedIssuerKey,
            Error::AatRequired => Code::AatRequired,
            Error::AatNotAccepted(_) => Code::AatNotAccepted,
            Error::Proof(ProofError::Verification(_)) => Code::InvalidProof,
            Error::RootCheck(_) => Code::RootCheckFailed,
            Error::IssuerCheck(_) => Code::IssuerCheckFailed,
            Error::Clock(_) => Code::ClockError,
            Error::Proof(_) => Code::ProofVerifierFailed,
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        let code = if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            Code::BodyTooLarge
        } else {
            Code::InvalidBody
        };
        Self {
            code,
            message: rejection.body_text(),
        }
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    result: &'static str,
    code: &'static str,
    message: &'a str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let failure = self.code.failure();
        let body = Json(ErrorBody {
            result: failure.as_str(),
            code: self.code.as_str(),
            message: &self.message,
        });
        let mut response = (self.code.status(), body).into_response();
        if failure == Failure::Unavailable {
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}

/// Why a verification did not accept the proof, as the response's `code`.
///
/// Callers and dashboards match on these names, so they must not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// The body is not JSON of the expected shape.
    InvalidBody,
    /// The body is larger than `MAX_BODY_BYTES`.
    BodyTooLarge,
    /// The request is not a Proof of Embedding Similarity request.
    NotEmbeddingSimilarity,
    /// The request is not a valid Proof of Embedding Similarity request.
    InvalidRequest,
    /// The response does not answer the request.
    ResponseMismatch,
    /// The request expired.
    RequestExpired,
    /// The Flamingo Verifier's attestation is not accepted.
    AttestationNotAccepted,
    /// The attestation attests another key than the one that signed the token.
    AttestedKeyMismatch,
    /// The Engine configuration is not accepted.
    EngineNotAccepted,
    /// The proof's time is not recent.
    StaleProof,
    /// The root is not a valid root of the `WorldIDRegistry`.
    InvalidRoot,
    /// The Issuer key is not the Proof of Human Issuer's.
    UntrustedIssuerKey,
    /// The policy requires an AAT and the proof carries none.
    AatRequired,
    /// An AAT value is outside the policy.
    AatNotAccepted,
    /// The proof does not verify.
    InvalidProof,
    /// The `WorldIDRegistry` could not be read.
    RootCheckFailed,
    /// The `CredentialSchemaIssuerRegistry` could not be read.
    IssuerCheckFailed,
    /// Every verification slot is busy.
    Overloaded,
    /// The verification did not finish within `REQUEST_TIMEOUT_SECS`.
    Timeout,
    /// The system clock is before the Unix epoch.
    ClockError,
    /// The proof verifier failed, e.g. its artifacts are broken.
    ProofVerifierFailed,
    /// The verification panicked.
    VerificationPanicked,
}

impl Code {
    /// The name in responses, logs and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidBody => "invalid_body",
            Self::BodyTooLarge => "body_too_large",
            Self::NotEmbeddingSimilarity => "not_embedding_similarity",
            Self::InvalidRequest => "invalid_request",
            Self::ResponseMismatch => "response_mismatch",
            Self::RequestExpired => "request_expired",
            Self::AttestationNotAccepted => "attestation_not_accepted",
            Self::AttestedKeyMismatch => "attested_key_mismatch",
            Self::EngineNotAccepted => "engine_not_accepted",
            Self::StaleProof => "stale_proof",
            Self::InvalidRoot => "invalid_root",
            Self::UntrustedIssuerKey => "untrusted_issuer_key",
            Self::AatRequired => "aat_required",
            Self::AatNotAccepted => "aat_not_accepted",
            Self::InvalidProof => "invalid_proof",
            Self::RootCheckFailed => "root_check_failed",
            Self::IssuerCheckFailed => "issuer_check_failed",
            Self::Overloaded => "overloaded",
            Self::Timeout => "timeout",
            Self::ClockError => "clock_error",
            Self::ProofVerifierFailed => "proof_verifier_failed",
            Self::VerificationPanicked => "verification_panicked",
        }
    }

    /// The response's `result` for this code.
    pub const fn failure(self) -> Failure {
        match self {
            Self::InvalidBody
            | Self::BodyTooLarge
            | Self::NotEmbeddingSimilarity
            | Self::InvalidRequest => Failure::Invalid,
            Self::ResponseMismatch
            | Self::RequestExpired
            | Self::AttestationNotAccepted
            | Self::AttestedKeyMismatch
            | Self::EngineNotAccepted
            | Self::StaleProof
            | Self::InvalidRoot
            | Self::UntrustedIssuerKey
            | Self::AatRequired
            | Self::AatNotAccepted
            | Self::InvalidProof => Failure::Rejected,
            Self::RootCheckFailed | Self::IssuerCheckFailed | Self::Overloaded | Self::Timeout => {
                Failure::Unavailable
            }
            Self::ClockError | Self::ProofVerifierFailed | Self::VerificationPanicked => {
                Failure::Internal
            }
        }
    }

    const fn status(self) -> StatusCode {
        match (self, self.failure()) {
            (Self::BodyTooLarge, _) => StatusCode::PAYLOAD_TOO_LARGE,
            (_, Failure::Invalid) => StatusCode::BAD_REQUEST,
            (_, Failure::Rejected) => StatusCode::UNPROCESSABLE_ENTITY,
            (_, Failure::Unavailable) => StatusCode::SERVICE_UNAVAILABLE,
            (_, Failure::Internal) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// The response's `result` for a [`Code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The body is not a verification of a Proof of Embedding Similarity request. Retrying the
    /// same body fails again.
    Invalid,
    /// The proof does not satisfy the RP's request or policy.
    Rejected,
    /// No verdict was reached, e.g. a registry was unreachable or the sidecar is at capacity. The
    /// same body may be retried.
    Unavailable,
    /// The sidecar failed.
    Internal,
}

impl Failure {
    /// The name in responses and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Rejected => "rejected",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }
}
