use axum::response::IntoResponse;
use http::StatusCode;
use strum::EnumString;

#[derive(Debug, Clone, strum::Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ErrorCode {
    InternalServerError,
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

    pub fn internal_server_error() -> Self {
        Self::new(
            ErrorCode::InternalServerError,
            "Internal server error. Please try again.".to_string(),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
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
