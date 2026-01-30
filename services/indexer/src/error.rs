use std::path::PathBuf;

use alloy::primitives::{FixedBytes, U256};
use semaphore_rs_trees::lazy::DenseMMapError;
use thiserror::Error;

pub type IndexerResult<T, E = IndexerError> = Result<T, E>;

#[derive(Debug, Error)]
pub enum IndexerError {
    #[error("missing environment variable: {var}")]
    MissingEnvVar { var: &'static str },
    #[error("invalid log for decoding")]
    InvalidLogForDecoding,
    #[error("log has no topics")]
    MissingLogTopics,
    #[error("missing block number")]
    MissingBlockNumber,
    #[error("missing transaction hash")]
    MissingTransactionHash,
    #[error("missing log index")]
    MissingLogIndex,
    #[error("unknown event signature: {signature:?}")]
    UnknownEventSignature { signature: FixedBytes<32> },
    #[error("leaf index {leaf_index} out of range for tree depth {depth}")]
    LeafIndexOutOfRange { leaf_index: U256, depth: usize },
    #[error("account index cannot be zero")]
    AccountIndexZero,
    #[error("invalid cache file path")]
    InvalidCacheFilePath,
    #[error("failed to restore tree from cache")]
    MmapRestoreFailed { source: DenseMMapError },
    #[error("failed to create mmap tree")]
    MmapCreateFailed { source: DenseMMapError },
    #[error("root mismatch: expected {expected}, got {actual}")]
    RootMismatch { expected: String, actual: String },
    #[error("metadata file does not exist: {path}")]
    MetadataFileMissing { path: PathBuf },
    #[error("failed to read metadata file: {path}")]
    MetadataRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse metadata file: {path}")]
    MetadataParse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("failed to serialize metadata")]
    MetadataSerialize { source: serde_json::Error },
    #[error("failed to write metadata file: {path}")]
    MetadataWrite {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to rename {from} to {to}")]
    MetadataRename {
        from: PathBuf,
        to: PathBuf,
        source: std::io::Error,
    },
    #[error("unknown world tree event type: {value}")]
    UnknownWorldTreeEventType { value: String },
    #[error("unknown world tree root event type: {value}")]
    UnknownWorldTreeRootEventType { value: String },
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    SqlxMigrate(#[from] sqlx::migrate::MigrateError),
    #[error(transparent)]
    Transport(#[from] alloy::transports::TransportError),
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    SolType(#[from] alloy::sol_types::Error),
}
