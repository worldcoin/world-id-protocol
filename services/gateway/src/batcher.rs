//! Unified batcher abstraction for routing commands to the appropriate batcher.

use crate::{
    create_batcher::{CreateBatcherHandle, CreateReqEnvelope},
    ops_batcher::{OpsBatcherHandle, OpsEnvelope},
};
use alloy::primitives::Bytes;
use uuid::Uuid;
use world_id_core::api_types::CreateAccountRequest;

/// Default gas estimates for operation types.
pub(super) mod defaults {
    pub const DEFAULT_CREATE_ACCOUNT_GAS: u64 = 600_000;
    pub const DEFAULT_INSERT_AUTHENTICATOR_GAS: u64 = 252_784;
    pub const DEFAULT_UPDATE_AUTHENTICATOR_GAS: u64 = 385_775;
    pub const DEFAULT_REMOVE_AUTHENTICATOR_GAS: u64 = 721_044;
    pub const DEFAULT_RECOVER_ACCOUNT_GAS: u64 = 516_400;
}

/// Unified batcher handle that routes to the appropriate batcher.
#[derive(Clone)]
pub struct BatcherHandle {
    pub create: CreateBatcherHandle,
    pub ops: OpsBatcherHandle,
}

impl BatcherHandle {
    /// Submit a command to the appropriate batcher.
    pub async fn submit(&self, cmd: Command) -> bool {
        match cmd {
            Command::CreateAccount { id, req, .. } => {
                let envelope = CreateReqEnvelope {
                    id: id.to_string(),
                    req,
                };
                self.create.tx.send(envelope).await.is_ok()
            }
            Command::Operation { id, calldata, .. } => {
                let envelope = OpsEnvelope {
                    id: id.to_string(),
                    calldata,
                };
                self.ops.tx.send(envelope).await.is_ok()
            }
        }
    }
}

/// Unified command type for all batcher operations.
pub enum Command {
    CreateAccount {
        id: Uuid,
        req: CreateAccountRequest,
        #[allow(dead_code)]
        gas: u64,
    },
    Operation {
        id: Uuid,
        calldata: Bytes,
        #[allow(dead_code)]
        gas: u64,
    },
}

impl Command {
    /// Create a new account creation command.
    pub fn create_account(id: Uuid, req: CreateAccountRequest, gas: u64) -> Self {
        Self::CreateAccount { id, req, gas }
    }

    /// Create a new operation command (insert/update/remove/recover).
    pub fn operation(id: Uuid, calldata: Bytes, gas: u64) -> Self {
        Self::Operation { id, calldata, gas }
    }
}
