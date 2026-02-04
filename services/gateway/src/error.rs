use common::ProviderError;
use std::backtrace::Backtrace;
use thiserror::Error;

pub type GatewayResult<T> = Result<T, GatewayError>;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("provider error: {source}")]
    Provider {
        #[source]
        source: ProviderError,
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
            source,
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
