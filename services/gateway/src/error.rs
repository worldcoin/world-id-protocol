use alloy::sol_types::SolError;
use axum::{http::StatusCode, response::IntoResponse};

use world_id_core::account_registry::AccountRegistry::{
    AuthenticatorAddressAlreadyInUse, AuthenticatorDoesNotBelongToAccount,
    AuthenticatorDoesNotExist, MismatchedSignatureNonce, PubkeyIdInUse, PubkeyIdOutOfBounds,
};
pub use world_id_core::types::GatewayErrorCode as ErrorCode;
use world_id_core::types::ServiceApiError;

pub type ErrorBody = ServiceApiError<ErrorCode>;

/// Helper to format a selector as a hex string for matching in error messages.
fn selector_hex(selector: [u8; 4]) -> String {
    format!("0x{}", hex::encode(selector))
}

/// Parses a contract error string and returns a specific error code if recognized.
pub fn parse_contract_error(error: &str) -> ErrorCode {
    if error.contains(&selector_hex(AuthenticatorAddressAlreadyInUse::SELECTOR)) {
        return ErrorCode::AuthenticatorAlreadyExists;
    }
    if error.contains(&selector_hex(AuthenticatorDoesNotExist::SELECTOR)) {
        return ErrorCode::AuthenticatorDoesNotExist;
    }
    if error.contains(&selector_hex(MismatchedSignatureNonce::SELECTOR)) {
        return ErrorCode::MismatchedSignatureNonce;
    }
    if error.contains(&selector_hex(PubkeyIdInUse::SELECTOR)) {
        return ErrorCode::PubkeyIdInUse;
    }
    if error.contains(&selector_hex(PubkeyIdOutOfBounds::SELECTOR)) {
        return ErrorCode::PubkeyIdOutOfBounds;
    }
    if error.contains(&selector_hex(AuthenticatorDoesNotBelongToAccount::SELECTOR)) {
        return ErrorCode::AuthenticatorDoesNotBelongToAccount;
    }

    ErrorCode::BadRequest
}

#[derive(Debug, Clone)]
pub struct ErrorResponse {
    status: StatusCode,
    error: ErrorBody,
}

impl ErrorResponse {
    pub fn new(code: ErrorCode, message: String, status: StatusCode) -> Self {
        Self {
            status,
            error: ServiceApiError::new(code, message),
        }
    }

    #[must_use]
    pub fn internal_server_error() -> Self {
        Self::new(
            ErrorCode::InternalServerError,
            "Internal server error. Please try again.".to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    }

    #[must_use]
    pub fn not_found() -> Self {
        Self::new(
            ErrorCode::NotFound,
            "Not found.".to_string(),
            StatusCode::NOT_FOUND,
        )
    }

    #[must_use]
    pub fn bad_request(message: String) -> Self {
        Self::new(ErrorCode::BadRequest, message, StatusCode::BAD_REQUEST)
    }

    #[must_use]
    pub fn batcher_unavailable() -> Self {
        Self::new(
            ErrorCode::BatcherUnavailable,
            "Batcher service is unavailable. Please try again.".to_string(),
            StatusCode::SERVICE_UNAVAILABLE,
        )
    }

    /// Creates an error response from a contract simulation error.
    /// Parses the error to extract a specific error code if possible.
    #[must_use]
    pub fn from_simulation_error(e: impl std::fmt::Display) -> Self {
        let error_str = e.to_string();
        let code = parse_contract_error(&error_str);
        Self::new(code.clone(), code.to_string(), StatusCode::BAD_REQUEST)
    }
}

impl std::fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Error Code: `{}`. Message: {}",
            self.error.code, self.error.message,
        )
    }
}

impl std::error::Error for ErrorResponse {}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (self.status, axum::Json(self.error)).into_response()
    }
}
