use axum::response::IntoResponse;
use http::StatusCode;
use serde::Serialize;
use strum::EnumString;
use utoipa::ToSchema;

#[derive(Debug, Clone, strum::Display, EnumString, Serialize, ToSchema)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InternalServerError,
    NotFound,
    InvalidAccountIndex,
    Locked,
    AccountDoesNotExist,
}

#[derive(Debug, Clone)]
pub struct ErrorResponse {
    status: StatusCode,
    error: ErrorObject,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ErrorObject {
    code: ErrorCode,
    message: String,
}

impl ErrorResponse {
    pub fn new(code: ErrorCode, message: String, status: StatusCode) -> Self {
        Self {
            status,
            error: ErrorObject { code, message },
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
        #[derive(Serialize)]
        struct ErrorResponseBody {
            error: ErrorObject,
        }
        (
            self.status,
            axum::Json(ErrorResponseBody { error: self.error }),
        )
            .into_response()
    }
}
