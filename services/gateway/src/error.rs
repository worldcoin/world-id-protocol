use thiserror::Error;

pub type GatewayResult<T> = Result<T, GatewayError>;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("provider error: {0}")]
    Provider(String),
    #[error("http server error: {0}")]
    HttpServer(#[from] std::io::Error),
    #[error("http service error: {0}")]
    HttpService(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("redis not configured")]
    RedisNotConfigured,
    #[error("join error: {0}")]
    Join(#[from] tokio::task::JoinError),
}
