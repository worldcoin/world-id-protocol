// This module defines the planned storage interface before its adapters are wired in.
#![allow(dead_code, unused_imports, unused_variables)]

mod assignment_repository;
mod batch_repository;
mod rate_limiter;
mod request_repository;
mod types;

use crate::error::GatewayResult;

pub(crate) use assignment_repository::AssignmentRepository;
pub(crate) use batch_repository::{BatchRepository, SealBatchOutcome};
pub(crate) use rate_limiter::{RateLimitOutcome, RateLimiter};
pub(crate) use request_repository::{AcceptRequestOutcome, RequestRepository};
pub(crate) use types::*;

/// Entry point for durable gateway storage modules sharing one Redis manager.
///
/// The repositories use the `gateway:` Redis namespace. Records are serialized
/// domain values stored at singular keys; sorted sets and sets are disposable
/// indexes for queue order and availability. Multi-record state transitions use
/// atomic Lua scripts because the deployment uses one Redis instance.
#[derive(Clone)]
pub(crate) struct Storage {
    /// Request records, batching queues, and admission resource locks.
    pub(crate) requests: RequestRepository,
    /// Batch records, ready queue, and the single signed submission per batch.
    pub(crate) batches: BatchRepository,
    /// Durable wallet-to-batch assignments; wallet state remains local.
    pub(crate) assignments: AssignmentRepository,
    /// Per-account sliding-window admission limits.
    pub(crate) rate_limiter: RateLimiter,
}

impl Storage {
    /// Connects to `redis_url` and constructs all repositories over one manager.
    ///
    /// This does not create schema keys or persist wallet configuration. The
    /// caller supplies locally enabled wallet addresses when assigning work and
    /// inspecting assignments.
    pub(crate) async fn connect(redis_url: &str) -> GatewayResult<Self> {
        unimplemented!()
    }
}
