use alloy::transports::TransportError;

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("rpc error: {0}")]
    Rpc(#[from] TransportError),

    #[error("contract error: {0}")]
    Contract(#[from] alloy::contract::Error),

    #[error("contract call reverted: {0}")]
    ContractRevert(String),

    #[error("dispute game not found within timeout for WC block {0}")]
    DisputeGameTimeout(u64),

    #[error("dispute game output root mismatch: expected {expected}, got {actual}")]
    OutputRootMismatch {
        expected: alloy_primitives::B256,
        actual: alloy_primitives::B256,
    },

    #[error("helios prover error: {0}")]
    Prover(String),

    #[error("helios prover timeout after {0:?}")]
    ProverTimeout(std::time::Duration),

    #[error("no storage proof returned for slot {0}")]
    MissingStorageProof(alloy_primitives::B256),

    #[error("config error: {0}")]
    Config(String),

    #[error("event decode error: {0}")]
    EventDecode(String),

    #[error(transparent)]
    Provider(#[from] world_id_services_common::ProviderError),

    #[error(transparent)]
    Other(#[from] eyre::Report),
}

impl RelayError {
    /// Returns true if this error is transient and the operation should be retried.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::Rpc(_) | Self::DisputeGameTimeout(_) | Self::ProverTimeout(_)
        )
    }
}
