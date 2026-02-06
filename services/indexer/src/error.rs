use crate::{blockchain::BlockchainError, config::ConfigError, db::DBError, tree::TreeError};
use std::backtrace::Backtrace;
use thiserror::Error;

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
