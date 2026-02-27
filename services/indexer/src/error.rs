use crate::{blockchain::BlockchainError, config::ConfigError, db::DBError, tree::TreeError};
use axum::response::IntoResponse;
use http::StatusCode;
use std::backtrace::Backtrace;
use thiserror::Error;
use world_id_core::api_types::{IndexerErrorCode, ServiceApiError};

pub type IndexerResult<T> = Result<T, IndexerError>;

#[derive(Debug, Error)]
pub enum IndexerError {
    #[error("blockchain error: {source}")]
    Blockchain {
        #[source]
        source: BlockchainError,
        backtrace: String,
    },
    #[error("config error: {source}")]
    Config {
        #[source]
        source: ConfigError,
        backtrace: String,
    },
    #[error("database error: {source}")]
    Db {
        #[source]
        source: DBError,
        backtrace: String,
    },
    #[error("tree error: {source}")]
    Tree {
        #[source]
        source: TreeError,
        backtrace: String,
    },
    #[error("failed to bind listener: {source}")]
    Bind {
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
    #[error("blockchain reorg detected at block {block_number}: {reason}")]
    ReorgDetected { block_number: u64, reason: String },
    #[error("contract call failed: {0}")]
    ContractCall(String),
}

impl From<BlockchainError> for IndexerError {
    fn from(source: BlockchainError) -> Self {
        Self::Blockchain {
            source,
            backtrace: Backtrace::capture().to_string(),
        }
    }
}

impl From<ConfigError> for IndexerError {
    fn from(source: ConfigError) -> Self {
        Self::Config {
            source,
            backtrace: Backtrace::capture().to_string(),
        }
    }
}

impl From<DBError> for IndexerError {
    fn from(source: DBError) -> Self {
        Self::Db {
            source,
            backtrace: Backtrace::capture().to_string(),
        }
    }
}

impl From<TreeError> for IndexerError {
    fn from(source: TreeError) -> Self {
        Self::Tree {
            source,
            backtrace: Backtrace::capture().to_string(),
        }
    }
}

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
