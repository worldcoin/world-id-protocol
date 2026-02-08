use common::ProviderError;
use std::backtrace::Backtrace;
use thiserror::Error;
use world_id_core::{
    api_types::{GatewayErrorCode, ServiceApiError},
    world_id_registry::WorldIdRegistry::{
        AuthenticatorAddressAlreadyInUse, AuthenticatorDoesNotBelongToAccount,
        AuthenticatorDoesNotExist, MismatchedSignatureNonce, PubkeyIdInUse, PubkeyIdOutOfBounds,
    },
};

use alloy::sol_types::SolError;
use axum::{http::StatusCode, response::IntoResponse};

pub type GatewayResult<T> = Result<T, GatewayError>;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("provider error: {source}")]
    Provider {
        #[source]
        source: Box<ProviderError>,
        backtrace: String,
    },
    #[error("failed to bind listener: {source}")]
    Bind {
        #[source]
        source: std::io::Error,
        backtrace: String,
    },
    #[error("failed to read listener address: {source}")]
    ListenerAddr {
        #[source]
        source: std::io::Error,
        backtrace: String,
    },
    #[error("server error: {source}")]
    Serve {
        #[source]
        source: std::io::Error,
        backtrace: String,
    },
    #[error("serialization error: {source}")]
    Serialization {
        #[source]
        source: serde_json::Error,
        backtrace: String,
    },
    #[error("redis error: {source}")]
    Redis {
        #[source]
        source: redis::RedisError,
        backtrace: String,
    },
    #[error("redis not configured")]
    RedisNotConfigured,
    #[error("join error: {source}")]
    Join {
        #[source]
        source: tokio::task::JoinError,
        backtrace: String,
    },
}

impl From<ProviderError> for GatewayError {
    fn from(source: ProviderError) -> Self {
        Self::Provider {
            source: Box::new(source),
            backtrace: Backtrace::capture().to_string(),
        }
    }
}

impl From<serde_json::Error> for GatewayError {
    fn from(source: serde_json::Error) -> Self {
        Self::Serialization {
            source,
            backtrace: Backtrace::capture().to_string(),
        }
    }
}

impl From<redis::RedisError> for GatewayError {
    fn from(source: redis::RedisError) -> Self {
        Self::Redis {
            source,
            backtrace: Backtrace::capture().to_string(),
        }
    }
}

impl From<tokio::task::JoinError> for GatewayError {
    fn from(source: tokio::task::JoinError) -> Self {
        Self::Join {
            source,
            backtrace: Backtrace::capture().to_string(),
        }
    }
}

/// Error response body used by the gateway APIs.
pub type GatewayErrorBody = ServiceApiError<GatewayErrorCode>;

/// Error response used by the gateway APIs.
#[derive(Debug, Clone)]
pub struct GatewayErrorResponse {
    status: StatusCode,
    error: GatewayErrorBody,
}

impl GatewayErrorResponse {
    #[must_use]
    pub const fn new(code: GatewayErrorCode, message: String, status: StatusCode) -> Self {
        Self {
            status,
            error: ServiceApiError::new(code, message),
        }
    }

    #[must_use]
    pub fn internal_server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: ServiceApiError::new(
                GatewayErrorCode::InternalServerError,
                "Internal server error. Please try again.".to_string(),
            ),
        }
    }

    #[must_use]
    pub fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error: ServiceApiError::new(GatewayErrorCode::NotFound, "Not found.".to_string()),
        }
    }

    #[must_use]
    pub fn bad_request(code: GatewayErrorCode) -> Self {
        let message = code.to_string();
        Self::new(code, message, StatusCode::BAD_REQUEST)
    }

    #[must_use]
    pub const fn bad_request_message(message: String) -> Self {
        Self::new(
            GatewayErrorCode::BadRequest,
            message,
            StatusCode::BAD_REQUEST,
        )
    }

    #[must_use]
    pub fn batcher_unavailable() -> Self {
        Self::new(
            GatewayErrorCode::BatcherUnavailable,
            "Batcher service is unavailable. Please try again.".to_string(),
            StatusCode::SERVICE_UNAVAILABLE,
        )
    }

    #[must_use]
    pub fn from_simulation_error(e: impl std::fmt::Display) -> Self {
        let error_str = e.to_string();
        let code = parse_contract_error(&error_str);
        let message = if matches!(code, GatewayErrorCode::BadRequest) {
            error_str
        } else {
            code.to_string()
        };
        Self::new(code, message, StatusCode::BAD_REQUEST)
    }
}

impl std::fmt::Display for GatewayErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Error Code: `{}`. Message: {}",
            self.error.code, self.error.message,
        )
    }
}

impl std::error::Error for GatewayErrorResponse {}

impl IntoResponse for GatewayErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (self.status, axum::Json(self.error)).into_response()
    }
}

fn selector_hex(selector: [u8; 4]) -> String {
    format!("0x{}", hex::encode(selector))
}

#[must_use]
pub fn parse_contract_error(error: &str) -> GatewayErrorCode {
    if error.contains(&selector_hex(AuthenticatorAddressAlreadyInUse::SELECTOR)) {
        return GatewayErrorCode::AuthenticatorAlreadyExists;
    }
    if error.contains(&selector_hex(AuthenticatorDoesNotExist::SELECTOR)) {
        return GatewayErrorCode::AuthenticatorDoesNotExist;
    }
    if error.contains(&selector_hex(MismatchedSignatureNonce::SELECTOR)) {
        return GatewayErrorCode::MismatchedSignatureNonce;
    }
    if error.contains(&selector_hex(PubkeyIdInUse::SELECTOR)) {
        return GatewayErrorCode::PubkeyIdInUse;
    }
    if error.contains(&selector_hex(PubkeyIdOutOfBounds::SELECTOR)) {
        return GatewayErrorCode::PubkeyIdOutOfBounds;
    }
    if error.contains(&selector_hex(AuthenticatorDoesNotBelongToAccount::SELECTOR)) {
        return GatewayErrorCode::AuthenticatorDoesNotBelongToAccount;
    }

    GatewayErrorCode::BadRequest
}
