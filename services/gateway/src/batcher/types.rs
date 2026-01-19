use alloy::primitives::{Address, Bytes, B256, U256};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;
use world_id_core::types::{GatewayErrorCode, GatewayRequestState};

/// Inner data for an operation envelope (policy-agnostic).
///
/// This contains all the operation data without any ordering semantics.
/// Use `OpEnvelope<P>` from the ordering module for heap-compatible operations.
#[derive(Debug, Clone)]
pub struct OpEnvelopeInner {
    /// Unique identifier for tracking
    pub id: Uuid,
    /// The operation payload
    pub op: Operation,
    /// When the operation was received
    pub received_at: Instant,
    /// Signer address (extracted from operation)
    pub signer: Address,
    /// Operation nonce for ordering
    pub nonce: U256,
}

impl OpEnvelopeInner {
    pub fn new(op: Operation, signer: Address, nonce: U256) -> Self {
        Self {
            id: Uuid::new_v4(),
            op,
            received_at: Instant::now(),
            signer,
            nonce,
        }
    }

    pub fn with_id(id: Uuid, op: Operation, signer: Address, nonce: U256) -> Self {
        Self {
            id,
            op,
            received_at: Instant::now(),
            signer,
            nonce,
        }
    }

    pub fn estimated_gas(&self) -> u64 {
        self.op.estimated_gas()
    }
}

/// All supported operation types
#[derive(Debug, Clone)]
pub enum Operation {
    CreateAccount(CreateAccountOp),
    InsertAuthenticator(InsertAuthenticatorOp),
    UpdateAuthenticator(UpdateAuthenticatorOp),
    RemoveAuthenticator(RemoveAuthenticatorOp),
    RecoverAccount(RecoverAccountOp),
}

impl Operation {
    /// Estimated gas for this operation type
    pub fn estimated_gas(&self) -> u64 {
        match self {
            // TODO:
            Self::CreateAccount(_) => 150_000,
            Self::InsertAuthenticator(_) => 100_000,
            Self::UpdateAuthenticator(_) => 100_000,
            Self::RemoveAuthenticator(_) => 80_000,
            Self::RecoverAccount(_) => 200_000,
        }
    }

    /// Operation type name for metrics/logging
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::CreateAccount(_) => "create_account",
            Self::InsertAuthenticator(_) => "insert_authenticator",
            Self::UpdateAuthenticator(_) => "update_authenticator",
            Self::RemoveAuthenticator(_) => "remove_authenticator",
            Self::RecoverAccount(_) => "recover_account",
        }
    }
}

/// Create account operation
#[derive(Debug, Clone)]
pub struct CreateAccountOp {
    pub initial_commitment: U256,
    pub signature: Bytes,
}

/// Insert authenticator operation
#[derive(Debug, Clone)]
pub struct InsertAuthenticatorOp {
    pub leaf_index: U256,
    pub new_authenticator_address: Address,
    pub pubkey_id: u32,
    pub new_authenticator_pubkey: U256,
    pub old_commit: U256,
    pub new_commit: U256,
    pub signature: Bytes,
    pub sibling_nodes: Vec<U256>,
    pub nonce: U256,
}

/// Update authenticator operation
#[derive(Debug, Clone)]
pub struct UpdateAuthenticatorOp {
    pub leaf_index: U256,
    pub old_authenticator_address: Address,
    pub new_authenticator_address: Address,
    pub pubkey_id: u32,
    pub new_authenticator_pubkey: U256,
    pub old_commit: U256,
    pub new_commit: U256,
    pub signature: Bytes,
    pub sibling_nodes: Vec<U256>,
    pub nonce: U256,
}

/// Remove authenticator operation
#[derive(Debug, Clone)]
pub struct RemoveAuthenticatorOp {
    pub leaf_index: U256,
    pub authenticator_address: Address,
    pub pubkey_id: u32,
    pub authenticator_pubkey: U256,
    pub old_commit: U256,
    pub new_commit: U256,
    pub signature: Bytes,
    pub sibling_nodes: Vec<U256>,
    pub nonce: U256,
}

/// Account recovery operation
#[derive(Debug, Clone)]
pub struct RecoverAccountOp {
    pub leaf_index: U256,
    pub new_authenticator_address: Address,
    pub new_authenticator_pubkey: U256,
    pub old_commit: U256,
    pub new_commit: U256,
    pub signature: Bytes,
    pub sibling_nodes: Vec<U256>,
    pub nonce: U256,
}

// ============================================================================
// Status Types
// ============================================================================

/// Final status of an operation after batch resolution
#[derive(Debug, Clone)]
pub enum OpStatus {
    /// Successfully finalized on-chain
    Finalized {
        tx_hash: B256,
        block_number: u64,
        gas_used: u64,
    },
    /// Failed during simulation or execution
    Failed { reason: FailureReason },
    /// Evicted from batch (may be retried)
    Evicted { reason: EvictionReason },
}

impl From<OpStatus> for GatewayRequestState {
    fn from(status: OpStatus) -> Self {
        match status {
            OpStatus::Finalized {
                tx_hash,
                block_number: _,
                ..
            } => GatewayRequestState::Finalized {
                tx_hash: format!("{:#x}", tx_hash),
            },
            OpStatus::Failed { reason } => GatewayRequestState::Failed {
                error: reason.to_string(),
                error_code: Some(GatewayErrorCode::BadRequest),
            },
            OpStatus::Evicted { reason } => GatewayRequestState::Failed {
                error: reason.to_string(),
                error_code: None,
            },
        }
    }
}

impl OpStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Finalized { .. } | Self::Failed { .. })
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Finalized { .. })
    }
}

/// Reason for operation failure
#[derive(Debug, Clone)]
pub enum FailureReason {
    /// Reverted during simulation
    SimulationReverted {
        message: String,
        revert_data: Option<Bytes>,
    },
    /// Reverted during execution
    ExecutionReverted {
        message: String,
        revert_data: Option<Bytes>,
    },
    /// Nonce is lower than on-chain nonce
    NonceTooLow { expected: U256, got: U256 },
    /// Nonce gap too large
    NonceTooHigh { expected: U256, got: U256 },
    /// Signer has insufficient balance
    InsufficientBalance,
    /// Invalid signature format or recovery
    InvalidSignature(String),
    /// Pre-flight validation failed
    ValidationFailed(String),
    /// Contract-specific error
    ContractError { code: String, message: String },
    /// Unknown error
    Unknown(String),
}

impl std::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SimulationReverted { message, .. } => {
                write!(f, "simulation reverted: {}", message)
            }
            Self::ExecutionReverted { message, .. } => {
                write!(f, "execution reverted: {}", message)
            }
            Self::NonceTooLow { expected, got } => {
                write!(f, "nonce too low: expected {}, got {}", expected, got)
            }
            Self::NonceTooHigh { expected, got } => {
                write!(f, "nonce too high: expected {}, got {}", expected, got)
            }
            Self::InsufficientBalance => write!(f, "insufficient balance"),
            Self::InvalidSignature(msg) => write!(f, "invalid signature: {}", msg),
            Self::ValidationFailed(msg) => write!(f, "validation failed: {}", msg),
            Self::ContractError { code, message } => {
                write!(f, "contract error {}: {}", code, message)
            }
            Self::Unknown(msg) => write!(f, "unknown error: {}", msg),
        }
    }
}

/// Reason for operation eviction from batch
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvictionReason {
    /// Batch reached gas limit
    BatchFull,
    /// Nonce dependency not ready
    DependencyNotReady,
    /// Individual op would exceed gas limit
    GasLimitExceeded,
    /// Operation timed out waiting
    Timeout,
    /// Batch was cancelled
    BatchCancelled,
    /// Simulation showed operation would fail
    SimulationFailed { message: String },
}

impl std::fmt::Display for EvictionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BatchFull => write!(f, "batch full"),
            Self::DependencyNotReady => write!(f, "nonce dependency not ready"),
            Self::GasLimitExceeded => write!(f, "gas limit exceeded"),
            Self::Timeout => write!(f, "timeout"),
            Self::BatchCancelled => write!(f, "batch cancelled"),
            Self::SimulationFailed { message } => write!(f, "simulation failed: {message}"),
        }
    }
}

// ============================================================================
// Batch Types
// ============================================================================

/// Result of a fully resolved batch
#[derive(Debug, Clone)]
pub struct FinalizedBatch {
    /// Unique batch identifier
    pub batch_id: Uuid,
    /// Final transaction hash (if submitted)
    pub tx_hash: Option<B256>,
    /// Block number where included
    pub block_number: Option<u64>,
    /// Total gas used by the batch
    pub gas_used: u64,
    /// Status of each operation by ID
    pub statuses: HashMap<Uuid, OpStatus>,
    /// Timing information
    pub timing: BatchTiming,
}

impl FinalizedBatch {
    /// Count of successfully finalized operations
    pub fn success_count(&self) -> usize {
        self.statuses.values().filter(|s| s.is_success()).count()
    }

    /// Count of failed operations
    pub fn failure_count(&self) -> usize {
        self.statuses
            .values()
            .filter(|s| matches!(s, OpStatus::Failed { .. }))
            .count()
    }

    /// Count of evicted operations
    pub fn evicted_count(&self) -> usize {
        self.statuses
            .values()
            .filter(|s| matches!(s, OpStatus::Evicted { .. }))
            .count()
    }
}

/// Timing metrics for a batch
#[derive(Debug, Clone)]
pub struct BatchTiming {
    /// When the batch was created
    pub created_at: Instant,
    /// When simulation completed
    pub simulation_completed_at: Option<Instant>,
    /// When transaction was first submitted
    pub submitted_at: Option<Instant>,
    /// When batch was finalized
    pub finalized_at: Instant,
    /// Total duration from creation to finalization
    pub total_duration: Duration,
    /// Number of times transaction was resubmitted
    pub resubmission_count: u32,
}

impl BatchTiming {
    pub fn new(created_at: Instant) -> Self {
        Self {
            created_at,
            simulation_completed_at: None,
            submitted_at: None,
            finalized_at: Instant::now(),
            total_duration: Duration::ZERO,
            resubmission_count: 0,
        }
    }

    pub fn finalize(&mut self) {
        self.finalized_at = Instant::now();
        self.total_duration = self.created_at.elapsed();
    }

    pub fn simulation_duration(&self) -> Option<Duration> {
        self.simulation_completed_at
            .map(|t| t.duration_since(self.created_at))
    }

    pub fn submission_to_finalization(&self) -> Option<Duration> {
        self.submitted_at
            .map(|t| self.finalized_at.duration_since(t))
    }
}

// ============================================================================
// Chain State
// ============================================================================

/// Snapshot of current chain state
#[derive(Debug, Clone)]
pub struct ChainState {
    /// Current block number
    pub block_number: u64,
    /// Current base fee in wei
    pub base_fee: u64,
    /// Exponential moving average of base fee
    pub base_fee_ema: f64,
    /// Base fee trend: -1 (falling) to +1 (rising)
    pub base_fee_trend: f64,
    /// Block gas limit
    pub block_gas_limit: u64,
    /// Recent average utilization (0-1)
    pub recent_utilization: f64,
    /// When this state was captured
    pub last_updated: Instant,
}

impl Default for ChainState {
    fn default() -> Self {
        Self {
            block_number: 0,
            base_fee: 0,
            base_fee_ema: 0.0,
            base_fee_trend: 0.0,
            block_gas_limit: 30_000_000,
            recent_utilization: 0.5,
            last_updated: Instant::now(),
        }
    }
}

impl ChainState {
    /// Check if state is stale
    pub fn is_stale(&self, max_age: Duration) -> bool {
        self.last_updated.elapsed() > max_age
    }

    /// Base fee in gwei
    pub fn base_fee_gwei(&self) -> f64 {
        self.base_fee as f64 / 1e9
    }
}
