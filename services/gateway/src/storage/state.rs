//! Internal request state machine with validated transitions.
//!
//! This is separate from `GatewayRequestState` (the API type) to:
//! - Enforce valid state transitions at compile/runtime
//! - Keep internal state machine logic out of the shared core crate
//! - Allow richer internal state (e.g., batch_id) not exposed in API

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use world_id_core::types::{GatewayErrorCode, GatewayRequestState};

/// Internal request status with validated state transitions.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Status {
    /// Request created, waiting to be batched.
    #[default]
    Queued,
    /// Request assigned to a batch.
    Batching { batch_id: Uuid },
    /// Batch submitted on-chain.
    Submitted { batch_id: Uuid, tx_hash: String },
    /// Request finalized on-chain.
    Finalized { tx_hash: String, block: u64 },
    /// Request failed.
    Failed {
        reason: String,
        code: Option<GatewayErrorCode>,
    },
}

impl Status {
    /// Check if this is a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Finalized { .. } | Self::Failed { .. })
    }

    /// Check if transition to `next` is valid.
    pub fn can_transition_to(&self, next: &Self) -> bool {
        use Status::*;
        matches!(
            (self, next),
            // From Queued
            (Queued, Batching { .. }) | (Queued, Failed { .. }) |
            // From Batching
            (Batching { .. }, Submitted { .. }) | (Batching { .. }, Failed { .. }) |
            // From Submitted
            (Submitted { .. }, Finalized { .. }) | (Submitted { .. }, Failed { .. })
        )
    }

    /// Create a Failed status.
    pub fn failed(reason: impl Into<String>, code: Option<GatewayErrorCode>) -> Self {
        Self::Failed {
            reason: reason.into(),
            code,
        }
    }
}

/// Convert internal Status to API GatewayRequestState.
impl From<Status> for GatewayRequestState {
    fn from(status: Status) -> Self {
        match status {
            Status::Queued => GatewayRequestState::Queued,
            Status::Batching { .. } => GatewayRequestState::Batching,
            Status::Submitted { tx_hash, .. } => GatewayRequestState::Submitted { tx_hash },
            Status::Finalized { tx_hash, .. } => GatewayRequestState::Finalized { tx_hash },
            Status::Failed { reason, code } => GatewayRequestState::Failed {
                error: reason,
                error_code: code,
            },
        }
    }
}

impl From<&Status> for GatewayRequestState {
    fn from(status: &Status) -> Self {
        status.clone().into()
    }
}

/// Convert API GatewayRequestState to internal Status.
/// Note: Some internal details (batch_id, block) are lost in the API type,
/// so we use defaults when converting back.
impl From<GatewayRequestState> for Status {
    fn from(state: GatewayRequestState) -> Self {
        match state {
            GatewayRequestState::Queued => Status::Queued,
            GatewayRequestState::Batching => Status::Batching {
                batch_id: Uuid::nil(),
            },
            GatewayRequestState::Submitted { tx_hash } => Status::Submitted {
                batch_id: Uuid::nil(),
                tx_hash,
            },
            GatewayRequestState::Finalized { tx_hash } => Status::Finalized { tx_hash, block: 0 },
            GatewayRequestState::Failed { error, error_code } => Status::Failed {
                reason: error,
                code: error_code,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        let batch_id = Uuid::new_v4();
        let tx_hash = "0x123".to_string();

        assert!(Status::Queued.can_transition_to(&Status::Batching { batch_id }));
        assert!(Status::Queued.can_transition_to(&Status::failed("err", None)));

        assert!(
            Status::Batching { batch_id }.can_transition_to(&Status::Submitted {
                batch_id,
                tx_hash: tx_hash.clone(),
            })
        );

        assert!(Status::Submitted {
            batch_id,
            tx_hash: tx_hash.clone()
        }
        .can_transition_to(&Status::Finalized {
            tx_hash: tx_hash.clone(),
            block: 100,
        }));
    }

    #[test]
    fn test_invalid_transitions() {
        let tx_hash = "0x123".to_string();

        // Can't skip states
        assert!(!Status::Queued.can_transition_to(&Status::Finalized {
            tx_hash: tx_hash.clone(),
            block: 100,
        }));

        // Terminal states can't transition
        assert!(!Status::Finalized {
            tx_hash,
            block: 100
        }
        .can_transition_to(&Status::Queued));
    }

    #[test]
    fn test_terminal_states() {
        assert!(!Status::Queued.is_terminal());
        assert!(Status::Finalized {
            tx_hash: "0x123".into(),
            block: 100
        }
        .is_terminal());
        assert!(Status::failed("err", None).is_terminal());
    }
}
