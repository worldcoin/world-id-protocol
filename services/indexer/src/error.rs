use axum::response::IntoResponse;
use http::StatusCode;

pub use world_id_core::types::IndexerErrorCode as ErrorCode;
use world_id_core::types::ServiceApiError;

pub type ErrorBody = ServiceApiError<ErrorCode>;

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
    pub fn bad_request(code: ErrorCode, message: String) -> Self {
        Self::new(code, message, StatusCode::BAD_REQUEST)
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
