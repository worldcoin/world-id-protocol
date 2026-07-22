use std::backtrace::Backtrace;
use thiserror::Error;
use world_id_primitives::api_types::{GatewayErrorCode, ServiceApiError};
use world_id_services_common::ProviderError;

use crate::contract_errors::DecodedRegistryError;
use alloy::transports::{RpcError, TransportErrorKind};
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
    #[error("join error: {source}")]
    Join {
        #[source]
        source: tokio::task::JoinError,
        backtrace: String,
    },
    #[error("config error: {0}")]
    Config(String),
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
    pub fn request_timeout(timeout_secs: u64) -> Self {
        Self::new(
            GatewayErrorCode::RequestTimeout,
            format!("Request timed out after {timeout_secs}s"),
            StatusCode::GATEWAY_TIMEOUT,
        )
    }

    #[must_use]
    pub fn rate_limit_exceeded(window_secs: u64, max_requests: u64) -> Self {
        Self::new(
            GatewayErrorCode::RateLimitExceeded,
            format!(
                "Rate limit exceeded: maximum {} requests per {} seconds for this leaf_index",
                max_requests, window_secs
            ),
            StatusCode::TOO_MANY_REQUESTS,
        )
    }

    /// Build an error response from a decoded on-chain revert.
    #[must_use]
    pub fn from_decoded_revert(decoded: &DecodedRegistryError) -> Self {
        Self::new(
            decoded.to_error_code(),
            decoded.human_message(),
            StatusCode::BAD_REQUEST,
        )
    }

    /// Build an error response from a raw alloy RPC error returned by
    /// `provider.call(...)`. Valid registry reverts are ABI-decoded; all other
    /// errors retain their original message as a generic bad request.
    #[must_use]
    pub fn from_rpc_error(err: &RpcError<TransportErrorKind>) -> Self {
        DecodedRegistryError::from_transport_error(err).map_or_else(
            || Self::bad_request_message(err.to_string()),
            |decoded| Self::from_decoded_revert(&decoded),
        )
    }

    /// Build an error response from a raw alloy contract error returned by
    /// `sol!`-generated call builders. Valid registry reverts are ABI-decoded;
    /// all other errors retain their original message as a generic bad request.
    #[must_use]
    pub fn from_contract_error(err: &alloy::contract::Error) -> Self {
        DecodedRegistryError::from_contract_error(err).map_or_else(
            || Self::bad_request_message(err.to_string()),
            |decoded| Self::from_decoded_revert(&decoded),
        )
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

#[cfg(test)]
mod tests {
    use alloy::{primitives::Address, sol_types::SolError};
    use world_id_registries::world_id::WorldIdRegistryV2::AuthenticatorAddressAlreadyInUse;

    use super::*;

    #[test]
    fn from_decoded_revert_produces_human_message() {
        let revert = AuthenticatorAddressAlreadyInUse {
            authenticatorAddress: Address::ZERO,
        };
        let decoded = DecodedRegistryError::decode(&revert.abi_encode()).expect("valid revert");
        let resp = GatewayErrorResponse::from_decoded_revert(&decoded);
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
        assert!(matches!(
            resp.error.code,
            GatewayErrorCode::AuthenticatorAlreadyExists
        ));
        assert!(
            resp.error.message.starts_with("WorldID:"),
            "expected human message, got {:?}",
            resp.error.message
        );
    }
}
