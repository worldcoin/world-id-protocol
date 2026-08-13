use alloy::primitives::Address;
use redis::aio::ConnectionManager;

use crate::{
    error::GatewayResult,
    storage::types::{Assignment, BatchId, Timestamp},
};

/// Durable mapping between locally configured wallet addresses and batches.
///
/// # Redis schema
///
/// - `gateway:wallet-assignment:<address>` stores the [`BatchId`] currently
///   assigned to that address.
/// - `gateway:batch:<batch-id>` stores the reciprocal wallet address in its
///   assigned, pending, or included state.
///
/// Redis does not store wallet configuration, enabled/disabled status, idle
/// state, KMS key IDs, or quarantine state. The gateway derives its candidate
/// addresses from local configuration and resolves nonce inconsistencies using
/// chain RPC. The assignment key exists to prevent one address from owning two
/// batches and is changed atomically with the batch record.
#[derive(Clone)]
pub(crate) struct AssignmentRepository {
    manager: ConnectionManager,
}

impl AssignmentRepository {
    /// Creates a repository backed by the supplied Redis connection manager.
    ///
    /// This does not read or modify any Redis key.
    pub(crate) fn new(manager: ConnectionManager) -> Self {
        unimplemented!()
    }

    /// Assigns one ready batch to one unassigned local wallet address.
    ///
    /// Atomically selects an address from `candidate_wallets` without a
    /// `gateway:wallet-assignment:<address>` key, removes one batch from
    /// `gateway:batches:ready`, creates the assignment key, and moves the batch
    /// from ready to assigned. Candidate order defines wallet preference.
    ///
    /// `candidate_wallets` must contain only locally configured, enabled wallets
    /// whose KMS keys are available to this gateway. Disabled wallets are omitted
    /// here but must still be passed to [`Self::assigned_many`] until drained.
    pub(crate) async fn assign_ready(
        &self,
        candidate_wallets: &[Address],
        assigned_at: Timestamp,
    ) -> GatewayResult<Option<Assignment>> {
        unimplemented!()
    }

    /// Loads the active assignment for one locally configured wallet.
    ///
    /// Reads `gateway:wallet-assignment:<address>` and the referenced
    /// `gateway:batch:<batch-id>`. Returns `None` when the assignment key does
    /// not exist. A missing or mismatched batch record is a storage
    /// inconsistency, not an idle wallet.
    pub(crate) async fn assigned(&self, wallet: Address) -> GatewayResult<Option<Assignment>> {
        unimplemented!()
    }

    /// Loads active assignments for locally configured wallet addresses.
    ///
    /// Reads only the supplied addresses, including disabled wallets retained
    /// for draining. Redis never enumerates or introduces wallets to the gateway.
    /// Results contain assignments whose reciprocal
    /// batch records agree with their assignment keys.
    pub(crate) async fn assigned_many(
        &self,
        wallets: &[Address],
    ) -> GatewayResult<Vec<Assignment>> {
        unimplemented!()
    }
}
