//! How a verification that did not accept the proof is answered.
//!
//! Every answer carries a `result` the caller branches on and a stable `code` for logs and
//! metrics. Only `200` means accepted, so a caller that checks just the status cannot accept a
//! rejected proof.

use axum::{
    Json,
    extract::rejection::JsonRejection,
    http::{HeaderValue, StatusCode, header::RETRY_AFTER},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tokio::task::JoinError;
use world_id_proof::ProofError;
use world_id_rp::embedding_similarity::EmbeddingSimilarityVerificationError;

/// A verification that did not accept the proof.
#[derive(Debug, Clone)]
pub struct ApiError {
    status: StatusCode,
    result: Failure,
    code: &'static str,
    message: String,
}

/// Why a verification did not accept the proof, as the response's `result`.
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
    /// The sidecar failed, e.g. its verification artifacts are broken.
    Internal,
}

impl Failure {
    /// The response's `result`, also the metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalid => "invalid",
            Self::Rejected => "rejected",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }
}

impl ApiError {
    pub const fn result(&self) -> Failure {
        self.result
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn overloaded() -> Self {
        Self::unavailable(
            "overloaded",
            "every proof verification slot is busy".to_owned(),
        )
    }

    pub fn timeout(timeout_secs: u64) -> Self {
        Self::unavailable(
            "timeout",
            format!("the request did not finish within {timeout_secs}s"),
        )
    }

    pub fn verification_panicked(error: &JoinError) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            result: Failure::Internal,
            code: "verification_panicked",
            message: format!("the proof verification did not finish: {error}"),
        }
    }

    const fn unavailable(code: &'static str, message: String) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            result: Failure::Unavailable,
            code,
            message,
        }
    }
}

impl From<EmbeddingSimilarityVerificationError> for ApiError {
    fn from(error: EmbeddingSimilarityVerificationError) -> Self {
        use EmbeddingSimilarityVerificationError as Error;

        let (status, result, code) = match &error {
            Error::NotEmbeddingSimilarity => (
                StatusCode::BAD_REQUEST,
                Failure::Invalid,
                "not_embedding_similarity",
            ),
            Error::Proof(ProofError::ProofInputError(_)) => {
                (StatusCode::BAD_REQUEST, Failure::Invalid, "invalid_request")
            }
            Error::Response(_) => rejected("response_mismatch"),
            Error::RequestExpired { .. } => rejected("request_expired"),
            Error::Attestation(_) => rejected("attestation_not_accepted"),
            Error::AttestedKeyMismatch => rejected("attested_key_mismatch"),
            Error::EngineNotAccepted(_) => rejected("engine_not_accepted"),
            Error::Stale { .. } => rejected("stale_proof"),
            Error::InvalidRoot(_) => rejected("invalid_root"),
            Error::UntrustedIssuerKey => rejected("untrusted_issuer_key"),
            Error::AatRequired => rejected("aat_required"),
            Error::AatNotAccepted(_) => rejected("aat_not_accepted"),
            Error::Proof(ProofError::Verification(_)) => rejected("invalid_proof"),
            Error::RootCheck(_) => unavailable("root_check_failed"),
            Error::IssuerCheck(_) => unavailable("issuer_check_failed"),
            Error::Clock(_) => internal("clock"),
            Error::Proof(_) => internal("proof_verifier"),
        };
        Self {
            status,
            result,
            code,
            message: error.to_string(),
        }
    }
}

const fn rejected(code: &'static str) -> (StatusCode, Failure, &'static str) {
    (StatusCode::UNPROCESSABLE_ENTITY, Failure::Rejected, code)
}

const fn unavailable(code: &'static str) -> (StatusCode, Failure, &'static str) {
    (StatusCode::SERVICE_UNAVAILABLE, Failure::Unavailable, code)
}

const fn internal(code: &'static str) -> (StatusCode, Failure, &'static str) {
    (StatusCode::INTERNAL_SERVER_ERROR, Failure::Internal, code)
}

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        let (status, code) = if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            (StatusCode::PAYLOAD_TOO_LARGE, "body_too_large")
        } else {
            (StatusCode::BAD_REQUEST, "invalid_body")
        };
        Self {
            status,
            result: Failure::Invalid,
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
        let body = Json(ErrorBody {
            result: self.result.as_str(),
            code: self.code,
            message: &self.message,
        });
        let mut response = (self.status, body).into_response();
        if self.result == Failure::Unavailable {
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}
