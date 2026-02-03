use thiserror::Error;

pub type GatewayResult<T> = Result<T, GatewayError>;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("provider error: {0}")]
    Provider(String),
    #[error("failed to bind listener: {0}")]
    Bind(#[from] std::io::Error),
    #[error("server error: {0}")]
    Serve(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("redis not configured")]
    RedisNotConfigured,
    #[error("join error: {0}")]
    Join(#[from] tokio::task::JoinError),
}
