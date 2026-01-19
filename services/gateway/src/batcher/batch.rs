//! Type-safe batch lifecycle with compile-time state guarantees.
//!
//! # State Machine
//! ```text
//! Queued ─► Assigned ─► Submitted ─► Finalized
//!               │            │
//!               └──► Failed ◄┘
//! ```

use crate::batcher::types::OpEnvelopeInner;
use alloy::primitives::B256;
use std::collections::HashMap;
use tokio::time::Instant;
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════════════════
// REQUEST
// ═══════════════════════════════════════════════════════════════════════════

/// A request wrapping operation data with tracking metadata.
#[derive(Clone)]
pub struct Request<T = OpEnvelopeInner> {
    pub id: Uuid,
    pub data: T,
    pub received_at: Instant,
}

impl<T: std::fmt::Debug> std::fmt::Debug for Request<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("id", &self.id)
            .field("data", &self.data)
            .field("received_at", &self.received_at)
            .finish_non_exhaustive()
    }
}

impl<T> Request<T> {
    /// Create a request with a specific ID.
    pub fn with_id(id: Uuid, data: T) -> Self {
        Self {
            id,
            data,
            received_at: Instant::now(),
        }
    }
}

impl From<OpEnvelopeInner> for Request<OpEnvelopeInner> {
    fn from(op: OpEnvelopeInner) -> Self {
        Self::with_id(op.id, op)
    }
}

// type-state markers for batch lifecycle
mod sealed {
    pub trait Sealed {}
}

/// Marker trait for valid batch states.
pub trait State: sealed::Sealed {}

pub struct Queued;
pub struct Assigned {
    pub batch_id: Uuid,
}
pub struct Submitted {
    pub batch_id: Uuid,
    pub tx_hash: B256,
}
pub struct Finalized {
    pub tx_hash: B256,
    pub block: u64,
}
pub struct Failed {
    pub reason: String,
}

impl sealed::Sealed for Queued {}
impl sealed::Sealed for Assigned {}
impl sealed::Sealed for Submitted {}
impl sealed::Sealed for Finalized {}
impl sealed::Sealed for Failed {}

impl<T> State for T where T: sealed::Sealed {}

/// A batch of requests to be submitted together.
#[must_use = "batches must be driven to terminal state"]
pub struct Batch<S: State, R = Request<OpEnvelopeInner>> {
    requests: Vec<R>,
    state: S,
    created_at: Instant,
}

// --- Common (all states) ---
impl<S: State, R> Batch<S, R> {
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    pub fn requests(&self) -> &[R] {
        &self.requests
    }

    fn to<S2: State>(self, state: S2) -> Batch<S2, R> {
        Batch {
            requests: self.requests,
            state,
            created_at: self.created_at,
        }
    }
}

// --- Queued ---
impl<R> Batch<Queued, R> {
    pub fn new(requests: Vec<R>) -> Self {
        Self {
            requests,
            state: Queued,
            created_at: Instant::now(),
        }
    }

    /// Assign to a batch.
    pub fn assign(self, batch_id: Uuid) -> Batch<Assigned, R> {
        self.to(Assigned { batch_id })
    }
}

// --- Assigned ---
impl<R> Batch<Assigned, R> {
    pub fn batch_id(&self) -> Uuid {
        self.state.batch_id
    }

    /// Filter requests, returning evicted ones.
    pub fn filter(&mut self, mut keep: impl FnMut(&R) -> bool) -> Vec<R> {
        let (k, e) = std::mem::take(&mut self.requests)
            .into_iter()
            .partition(|r| keep(r));

        self.requests = k;
        e
    }

    /// Transition to Submitted.
    pub fn submit(self, tx_hash: B256) -> Batch<Submitted, R> {
        let batch_id = self.state.batch_id;
        self.to(Submitted { batch_id, tx_hash })
    }

    /// Evict all requests with a reason.
    pub fn evict(self, reason: &str) -> Batch<Failed, R> {
        self.to(Failed {
            reason: reason.into(),
        })
    }
}

impl<T> Batch<Assigned, Request<T>> {
    /// Evict specific requests by ID.
    pub fn evict_many(&mut self, evictions: &HashMap<Uuid, String>) -> Vec<Request<T>> {
        self.filter(|r| !evictions.contains_key(&r.id))
    }
}

// --- Submitted ---
impl<R> Batch<Submitted, R> {
    pub fn batch_id(&self) -> Uuid {
        self.state.batch_id
    }

    pub fn tx_hash(&self) -> B256 {
        self.state.tx_hash
    }

    /// Finalize the batch.
    pub fn finalize(self, block: u64) -> Batch<Finalized, R> {
        let tx_hash = self.state.tx_hash;
        self.to(Finalized { tx_hash, block })
    }

    /// Fail the batch.
    pub fn fail(self, reason: &str) -> Batch<Failed, R> {
        self.to(Failed {
            reason: reason.into(),
        })
    }
}

// --- Terminal ---
impl<R> Batch<Finalized, R> {
    pub fn tx_hash(&self) -> B256 {
        self.state.tx_hash
    }

    pub fn block(&self) -> u64 {
        self.state.block
    }
}

impl<R> Batch<Failed, R> {
    pub fn reason(&self) -> &str {
        &self.state.reason
    }
}
/// Operations that can be performed on batches.
pub trait BatchOps<T = OpEnvelopeInner>: Send + Sync {
    /// Filter operations via simulation. Return IDs to evict with reasons.
    fn simulate(
        &self,
        batch: &Batch<Assigned, Request<T>>,
    ) -> impl std::future::Future<Output = HashMap<Uuid, String>> + Send;

    /// Build and submit transaction.
    fn submit(
        &self,
        batch: &Batch<Assigned, Request<T>>,
    ) -> impl std::future::Future<Output = Result<B256, String>> + Send;

    /// Wait for on-chain confirmation.
    fn confirm(
        &self,
        batch: &Batch<Submitted, Request<T>>,
    ) -> impl std::future::Future<Output = Result<u64, String>> + Send;
}

// Blanket impl: &B implements BatchOps if B does
impl<B: BatchOps<T> + ?Sized, T: Send + Sync> BatchOps<T> for &B {
    fn simulate(
        &self,
        batch: &Batch<Assigned, Request<T>>,
    ) -> impl std::future::Future<Output = HashMap<Uuid, String>> + Send {
        (*self).simulate(batch)
    }

    fn submit(
        &self,
        batch: &Batch<Assigned, Request<T>>,
    ) -> impl std::future::Future<Output = Result<B256, String>> + Send {
        (*self).submit(batch)
    }

    fn confirm(
        &self,
        batch: &Batch<Submitted, Request<T>>,
    ) -> impl std::future::Future<Output = Result<u64, String>> + Send {
        (*self).confirm(batch)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PIPELINE HELPER
// ═══════════════════════════════════════════════════════════════════════════

/// Result of running a batch through the pipeline.
pub struct BatchRunResult<T> {
    /// The final batch state (finalized or failed)
    pub result: Result<Batch<Finalized, Request<T>>, Batch<Failed, Request<T>>>,
    /// Operations that were evicted during simulation, with their failure reasons
    pub evictions: Vec<(Request<T>, String)>,
}

/// Run a batch through the full pipeline.
/// Returns both the batch result and any evicted operations with their failure reasons.
pub async fn run_batch<B, T>(
    ops: &B,
    requests: Vec<Request<T>>,
    batch_id: Uuid,
) -> BatchRunResult<T>
where
    B: BatchOps<T>,
    T: Send + Sync + Clone,
{
    let mut batch = Batch::new(requests).assign(batch_id);

    // 1. Simulate - evict failures
    let eviction_map = ops.simulate(&batch).await;
    let evicted_requests = batch.evict_many(&eviction_map);

    // Pair evicted requests with their failure reasons
    let evictions: Vec<(Request<T>, String)> = evicted_requests
        .into_iter()
        .filter_map(|req| {
            eviction_map
                .get(&req.id)
                .map(|reason| (req, reason.clone()))
        })
        .collect();

    if batch.is_empty() {
        return BatchRunResult {
            result: Err(batch.evict("all evicted")),
            evictions,
        };
    }

    // 2. Submit
    let tx_hash = match ops.submit(&batch).await {
        Ok(h) => h,
        Err(e) => {
            return BatchRunResult {
                result: Err(batch.evict(&e)),
                evictions,
            }
        }
    };
    // TODO: We could execute this as allowRevert.
    let batch = batch.submit(tx_hash);

    // 3. Confirm
    let result = match ops.confirm(&batch).await {
        Ok(block) => Ok(batch.finalize(block)),
        Err(e) => Err(batch.fail(&e)),
    };

    BatchRunResult { result, evictions }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_state_transitions() {
        let requests = vec![Request::with_id(Uuid::new_v4(), ())];
        let batch = Batch::new(requests);

        // Queued -> Assigned
        let batch = batch.assign(Uuid::new_v4());
        assert_eq!(batch.len(), 1);

        // Assigned -> Submitted
        let batch = batch.submit(B256::ZERO);
        assert_eq!(batch.tx_hash(), B256::ZERO);

        // Submitted -> Finalized
        let batch = batch.finalize(100);
        assert_eq!(batch.block(), 100);
    }

    #[test]
    fn test_batch_eviction() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let requests = vec![Request::with_id(id1, ()), Request::with_id(id2, ())];

        let mut batch = Batch::new(requests).assign(Uuid::new_v4());

        let mut evictions = HashMap::new();
        evictions.insert(id1, "test error".to_string());

        let evicted = batch.evict_many(&evictions);
        assert_eq!(evicted.len(), 1);
        assert_eq!(batch.len(), 1);
    }

    struct MockBatchOps;

    impl BatchOps<()> for MockBatchOps {
        async fn simulate(&self, _: &Batch<Assigned, Request<()>>) -> HashMap<Uuid, String> {
            HashMap::new()
        }

        async fn submit(&self, _: &Batch<Assigned, Request<()>>) -> Result<B256, String> {
            Ok(B256::ZERO)
        }

        async fn confirm(&self, _: &Batch<Submitted, Request<()>>) -> Result<u64, String> {
            Ok(42)
        }
    }

    #[tokio::test]
    async fn test_run_batch_success() {
        let requests = vec![Request::with_id(Uuid::new_v4(), ())];
        let result = run_batch(&MockBatchOps, requests, Uuid::new_v4()).await;
        assert!(result.result.is_ok());
        assert!(result.evictions.is_empty());
    }
}
