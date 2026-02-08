use axum::response::IntoResponse;
use http::StatusCode;
use world_id_core::api_types::{IndexerErrorCode, ServiceApiError};

/// Error response body used by the indexer APIs.
pub type IndexerErrorBody = ServiceApiError<IndexerErrorCode>;

/// Error response used by the indexer APIs.
#[derive(Debug, Clone)]
pub struct IndexerErrorResponse {
    status: StatusCode,
    error: IndexerErrorBody,
}

impl IndexerErrorResponse {
    #[must_use]
    pub const fn new(code: IndexerErrorCode, message: String, status: StatusCode) -> Self {
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
                IndexerErrorCode::InternalServerError,
                "Internal server error. Please try again.".to_string(),
            ),
        }
    }

    #[must_use]
    pub fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            error: ServiceApiError::new(IndexerErrorCode::NotFound, "Not found.".to_string()),
        }
    }

    #[must_use]
    pub const fn bad_request(code: IndexerErrorCode, message: String) -> Self {
        Self::new(code, message, StatusCode::BAD_REQUEST)
    }
}

impl std::fmt::Display for IndexerErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Error Code: `{}`. Message: {}",
            self.error.code, self.error.message,
        )
    }
}

impl std::error::Error for IndexerErrorResponse {}

impl IntoResponse for IndexerErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (self.status, axum::Json(self.error)).into_response()
    }
}
