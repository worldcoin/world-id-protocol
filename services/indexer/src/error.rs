use thiserror::Error;

use crate::{blockchain::BlockchainError, config::ConfigError, db::DBError, tree::TreeError};

pub type IndexerResult<T> = Result<T, IndexerError>;

#[derive(Debug, Error)]
pub enum IndexerError {
    #[error(transparent)]
    Blockchain(#[from] BlockchainError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Db(#[from] DBError),
    #[error(transparent)]
    Tree(#[from] TreeError),
    #[error("http server error: {0}")]
    HttpServer(#[from] std::io::Error),
    #[error("http service error: {0}")]
    HttpService(#[source] Box<dyn std::error::Error + Send + Sync>),
}
