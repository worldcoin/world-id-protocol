use axum::{http::StatusCode, response::IntoResponse};
use uuid::Uuid;

use crate::auth::{
    issuer_schema_watcher::IssuerSchemaWatcherError, merkle_watcher::MerkleWatcherError,
    signature_history::DuplicateSignatureError,
};

/// Errors returned by the [`WorldOprfReqAuthenticator`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum OprfRequestAuthError {
    /// The client Groth16 proof did not verify.
    #[error("client proof did not verify")]
    InvalidProof,
    /// The current time stamp difference between client and service is larger than allowed.
    #[error("the time stamp difference is too large")]
    TimeStampDifference,
    /// A nonce signature was uses more than once
    #[error(transparent)]
    DuplicateSignatureError(#[from] DuplicateSignatureError),
    /// The provided merkle root is not valid
    #[error(transparent)]
    MerkleWatcherError(#[from] MerkleWatcherError),
    /// Invalid credential issuer with id
    #[error(transparent)]
    IssuerSchemaWatcherError(#[from] IssuerSchemaWatcherError),
    /// Internal server error
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

impl IntoResponse for OprfRequestAuthError {
    fn into_response(self) -> axum::response::Response {
        tracing::debug!("{self:#?}");
        match self {
            OprfRequestAuthError::InvalidProof => {
                (StatusCode::BAD_REQUEST, "invalid proof").into_response()
            }
            OprfRequestAuthError::TimeStampDifference => (
                StatusCode::BAD_REQUEST,
                "the time stamp difference is too large",
            )
                .into_response(),
            OprfRequestAuthError::DuplicateSignatureError(err) => {
                (StatusCode::BAD_REQUEST, err.to_string()).into_response()
            }
            OprfRequestAuthError::MerkleWatcherError(merkle_watcher_error) => {
                merkle_watcher_error.into_response()
            }
            OprfRequestAuthError::InternalServerError(err) => {
                let error_id = Uuid::new_v4();
                tracing::error!("{error_id} - {err:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("An internal server error has occurred. Error ID={error_id}"),
                )
                    .into_response()
            }
            OprfRequestAuthError::IssuerSchemaWatcherError(issuer_schema_watcher_error) => {
                issuer_schema_watcher_error.into_response()
            }
        }
    }
}

impl IntoResponse for MerkleWatcherError {
    fn into_response(self) -> axum::response::Response {
        match self {
            MerkleWatcherError::InvalidMerkleRoot => {
                (StatusCode::BAD_REQUEST, "invalid merkle root").into_response()
            }
            MerkleWatcherError::AlloyError(err) => {
                let error_id = Uuid::new_v4();
                tracing::error!("{error_id} - {err:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("An internal server error has occurred. Error ID={error_id}"),
                )
                    .into_response()
            }
        }
    }
}

impl IntoResponse for IssuerSchemaWatcherError {
    fn into_response(self) -> axum::response::Response {
        match self {
            IssuerSchemaWatcherError::InvalidCredentialId(uint) => (
                StatusCode::BAD_REQUEST,
                format!("cannot find credential issuer with if {uint}"),
            )
                .into_response(),
            IssuerSchemaWatcherError::AlloyError(err) => {
                let error_id = Uuid::new_v4();
                tracing::error!("{error_id} - {err:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("An internal server error has occurred. Error ID={error_id}"),
                )
                    .into_response()
            }
        }
    }
}
