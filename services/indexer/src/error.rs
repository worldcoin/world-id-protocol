use axum::response::IntoResponse;
use http::StatusCode;
use strum::EnumString;

#[derive(Debug, Clone, strum::Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ErrorCode {
    InternalServerError,
    NotFound,
    InvalidAccountIndex,
    Locked,
    AccountDoesNotExist,
}

#[derive(Debug, Clone)]
pub struct ErrorResponse {
    code: ErrorCode,
    message: String,
    status: StatusCode,
}

impl ErrorResponse {
    pub fn new(code: ErrorCode, message: String, status: StatusCode) -> Self {
        Self {
            code,
            message,
            status,
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
        write!(f, "Error Code: `{}`. Message: {}", self.code, self.message,)
    }
}

impl std::error::Error for ErrorResponse {}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> axum::response::Response {
        #[derive(serde::Serialize)]
        struct ErrorObjectResponse {
            code: String,
            message: String,
        }
        (
            self.status,
            axum::Json(ErrorObjectResponse {
                code: self.code.to_string(),
                message: self.message,
            }),
        )
            .into_response()
    }
}
