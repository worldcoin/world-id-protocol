//! Type-safe batch lifecycle with compile-time state guarantees.
//!
//! # State Machine
//! ```text
//! Queued ─► Assigned ─► Submitted ─► Finalized
//!               │            │
//!               └──► Failed ◄┘
//! ```
//!
//! # Compile-Time Guarantees
//! - Only valid transitions compile
//! - Terminal states auto-sync via installed `Synced` dispatcher
//! - `#[must_use]` prevents dropped batches
//!
//! # Sync Pattern
//!
//! Each `Request` owns a watch channel and registers with the global `Synced`
//! dispatcher on creation. State changes flow through the Request's channel,
//! and the dispatcher persists them to the `RequestTracker`.
//!
//! ```ignore
//! // At startup
//! Synced::install(request_tracker);
//!
//! // Requests register on creation
//! let req = Request::new(data);  // auto-registers with dispatcher
//!
//! // State changes flow through the Request's channel
//! req.set_state(GatewayRequestState::Queued);
//! ```

use crate::batcher::types::{FinalizedBatch, OpEnvelopeInner, OpStatus};
use crate::request_tracker::RequestTracker;
use alloy::primitives::B256;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::Instant;
use uuid::Uuid;
use world_id_core::types::GatewayRequestState;

// ═══════════════════════════════════════════════════════════════════════════
// TRACKED TRAIT - Anonymous state tracking via marker trait
// ═══════════════════════════════════════════════════════════════════════════

/// Marker trait for types that have their state tracked by the global dispatcher.
///
/// Types implementing this trait automatically have their state changes
/// persisted to the `RequestTracker` when `set_state` is called.
///
/// The tracking is "anonymous" - the dispatcher doesn't know about the concrete
/// type, only that it has an ID and can report state changes.
///
/// # Default Implementations
/// State is stored in a thread-local registry keyed by UUID. Implementors only
/// need to provide `id()` - state storage is handled automatically.
pub trait Tracked {
    /// The unique identifier for this tracked item.
    fn id(&self) -> Uuid;

    /// Set state in the global registry and notify the dispatcher.
    fn set_state(&self, state: GatewayRequestState) {
        let id = self.id();
        STATE_REGISTRY.with(|reg| {
            reg.borrow_mut().insert(id, state.clone());
        });
        Synced::on_state_change(id, state);
    }

    /// Get the current state from the global registry.
    fn state(&self) -> GatewayRequestState {
        STATE_REGISTRY.with(|reg| {
            reg.borrow()
                .get(&self.id())
                .cloned()
                .unwrap_or(GatewayRequestState::Queued)
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SYNCED - Global dispatcher that watches Tracked items
// ═══════════════════════════════════════════════════════════════════════════

thread_local! {
    /// Global state registry for all Tracked items.
    /// State is keyed by UUID and managed by the Tracked trait's default implementations.
    static STATE_REGISTRY: RefCell<HashMap<Uuid, GatewayRequestState>> = RefCell::default();

    static DISPATCHER: RefCell<Option<SyncedState>> = const { RefCell::new(None) };

    #[cfg(test)]
    static TEST_DISPATCHER: RefCell<Option<TestDispatcher>> = const { RefCell::new(None) };
}

#[cfg(test)]
struct TestDispatcher {
    states: watch::Sender<HashMap<Uuid, GatewayRequestState>>,
}

struct SyncedState {
    states: watch::Sender<HashMap<Uuid, GatewayRequestState>>,
    states_rx: watch::Receiver<HashMap<Uuid, GatewayRequestState>>,
    tracker: Arc<RequestTracker>,
}

impl std::fmt::Debug for SyncedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncedState").finish_non_exhaustive()
    }
}

/// Global sync dispatcher for `GatewayRequestState` transitions.
///
/// Requests register their watch channel receivers on creation. When state
/// changes, they send through their owned channel, and the dispatcher
/// persists to the `RequestTracker`.
///
/// **Like tracing**: silently does nothing if no dispatcher is installed.
///
/// # Example
///
/// ```ignore
/// // At application startup
/// Synced::install(request_tracker);
///
/// // Requests auto-register on creation
/// let req = Request::new(data);
/// req.set_state(GatewayRequestState::Queued);
/// ```
#[derive(Clone, Copy)]
pub struct Synced;

/// Watch handle for observing state transitions.
#[derive(Clone)]
pub struct SyncedWatch(watch::Receiver<HashMap<Uuid, GatewayRequestState>>);

impl Synced {
    /// Install the global dispatcher with a RequestTracker.
    ///
    /// # Panics
    /// Panics if called more than once.
    pub fn install(tracker: Arc<RequestTracker>) {
        let (states, states_rx) = watch::channel(HashMap::new());
        let state = SyncedState {
            states,
            states_rx,
            tracker,
        };
        DISPATCHER.with(|d| {
            let mut borrowed = d.borrow_mut();
            if borrowed.is_some() {
                panic!("Synced already installed");
            }
            *borrowed = Some(state);
        });
    }

    /// Get a watch handle for observing state transitions.
    ///
    /// # Panics
    /// Panics if `Synced::install` was not called.
    pub fn watch() -> SyncedWatch {
        DISPATCHER.with(|d| {
            let borrowed = d.borrow();
            let state = borrowed.as_ref().expect("Synced not installed");
            SyncedWatch(state.states_rx.clone())
        })
    }

    /// Check if the dispatcher is installed.
    pub fn is_installed() -> bool {
        DISPATCHER.with(|d| d.borrow().is_some())
    }

    /// Install a test dispatcher (thread-local).
    ///
    /// Returns a watch handle for asserting states in tests.
    #[cfg(test)]
    pub fn install_test() -> SyncedWatch {
        let (states, states_rx) = watch::channel(HashMap::new());
        TEST_DISPATCHER.with(|d| *d.borrow_mut() = Some(TestDispatcher { states }));
        SyncedWatch(states_rx)
    }

    /// Called by Request when state changes. Persists to RequestTracker.
    ///
    /// **Like tracing**: silently does nothing if no dispatcher is installed.
    #[inline]
    fn on_state_change(id: Uuid, state: GatewayRequestState) {
        // Check test dispatcher first (thread-local)
        #[cfg(test)]
        {
            let handled = TEST_DISPATCHER.with(|d| {
                if let Some(dispatcher) = d.borrow().as_ref() {
                    dispatcher.states.send_modify(|s| {
                        s.insert(id, state.clone());
                    });
                    true
                } else {
                    false
                }
            });
            if handled {
                return;
            }
        }

        // Global dispatcher - silently skip if not installed (like tracing)
        DISPATCHER.with(|d| {
            if let Some(dispatcher) = d.borrow().as_ref() {
                dispatcher.states.send_modify(|s| {
                    s.insert(id, state.clone());
                });

                // Sync to RequestTracker
                let tracker = dispatcher.tracker.clone();
                tokio::spawn(async move {
                    tracker.set_status(&id.to_string(), state).await;
                });
            }
        });
    }
}

impl SyncedWatch {
    /// Get the current state for an operation ID.
    pub fn get(&self, id: &Uuid) -> Option<GatewayRequestState> {
        self.0.borrow().get(id).cloned()
    }

    /// Wait for the next change.
    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        self.0.changed().await
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// REQUEST - Lightweight tracked request using global registry
// ═══════════════════════════════════════════════════════════════════════════

/// A tracked request whose state is managed by the global registry.
///
/// State is stored in the thread-local `STATE_REGISTRY` and accessed via
/// the `Tracked` trait's default implementations.
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
    /// Create a new request with a fresh ID.
    pub fn new(data: T) -> Self {
        Self::with_id(Uuid::new_v4(), data)
    }

    /// Create a request with a specific ID.
    pub fn with_id(id: Uuid, data: T) -> Self {
        Self {
            id,
            data,
            received_at: Instant::now(),
        }
    }
}

// Implement Tracked for Request - state is managed by global registry
impl<T> Tracked for Request<T> {
    fn id(&self) -> Uuid {
        self.id
    }
    // set_state and state use default implementations from Tracked trait
}

impl From<OpEnvelopeInner> for Request<OpEnvelopeInner> {
    fn from(op: OpEnvelopeInner) -> Self {
        Self::with_id(op.id, op)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// STATE MARKERS (sealed trait for compile-time safety)
// ═══════════════════════════════════════════════════════════════════════════

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
impl State for Queued {}
impl State for Assigned {}
impl State for Submitted {}
impl State for Finalized {}
impl State for Failed {}

// ═══════════════════════════════════════════════════════════════════════════
// BATCH<S, R> - Generic over any Tracked type
// ═══════════════════════════════════════════════════════════════════════════

/// A batch of tracked requests progressing through the state machine.
///
/// `Batch` is generic over `R: Tracked`, meaning it works with any type that
/// implements the `Tracked` trait. This decouples the batch logic from the
/// concrete `Request<T>` type.
#[must_use = "batches must be driven to terminal state"]
pub struct Batch<S: State, R: Tracked = Request<OpEnvelopeInner>> {
    requests: Vec<R>,
    state: S,
    created_at: Instant,
}

// --- Common (all states) ---
impl<S: State, R: Tracked> Batch<S, R> {
    pub fn len(&self) -> usize {
        self.requests.len()
    }
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }
    pub fn requests(&self) -> &[R] {
        &self.requests
    }
    pub fn ids(&self) -> impl Iterator<Item = Uuid> + '_ {
        self.requests.iter().map(|r| r.id())
    }
    pub fn into_requests(self) -> Vec<R> {
        self.requests
    }

    fn to<S2: State>(self, state: S2) -> Batch<S2, R> {
        Batch {
            requests: self.requests,
            state,
            created_at: self.created_at,
        }
    }

    /// Set state on all requests via the Tracked trait.
    fn set_all(&self, state: GatewayRequestState) {
        for r in &self.requests {
            r.set_state(state.clone());
        }
    }
}

// --- Queued ---
impl<R: Tracked> Batch<Queued, R> {
    pub fn new(requests: Vec<R>) -> Self {
        // Set Queued state on all requests via Tracked trait
        for r in &requests {
            r.set_state(GatewayRequestState::Queued);
        }
        Self {
            requests,
            state: Queued,
            created_at: Instant::now(),
        }
    }

    /// Assign to a batch. Sets Batching state on all requests.
    pub fn assign(self, batch_id: Uuid) -> Batch<Assigned, R> {
        self.set_all(GatewayRequestState::Batching);
        self.to(Assigned { batch_id })
    }
}

// --- Assigned ---
impl<R: Tracked> Batch<Assigned, R> {
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

    /// Transition to Submitted. Sets Submitted state on all requests.
    pub fn submit(self, tx_hash: B256) -> Batch<Submitted, R> {
        let batch_id = self.state.batch_id;
        let tx_str = format!("{tx_hash:#x}");
        self.set_all(GatewayRequestState::Submitted { tx_hash: tx_str });
        self.to(Submitted { batch_id, tx_hash })
    }

    /// Evict all requests with a reason. Sets Failed state on all.
    pub fn evict(self, reason: &str) -> Batch<Failed, R> {
        self.set_all(GatewayRequestState::Failed {
            error: reason.into(),
            error_code: None,
        });
        self.to(Failed {
            reason: reason.into(),
        })
    }

    /// Evict specific requests. Sets Failed state on each evicted request.
    pub fn evict_many(&mut self, evictions: &HashMap<Uuid, String>) -> Vec<R> {
        let evicted = self.filter(|r| !evictions.contains_key(&r.id()));
        for req in &evicted {
            let reason = evictions.get(&req.id()).cloned().unwrap_or_default();
            req.set_state(GatewayRequestState::Failed {
                error: reason,
                error_code: None,
            });
        }
        evicted
    }
}

// --- Submitted ---
impl<R: Tracked> Batch<Submitted, R> {
    pub fn batch_id(&self) -> Uuid {
        self.state.batch_id
    }
    pub fn tx_hash(&self) -> B256 {
        self.state.tx_hash
    }

    /// Finalize the batch. Sets Finalized state on all requests.
    pub fn finalize(self, _block: u64) -> Batch<Finalized, R> {
        let tx_hash = self.state.tx_hash;
        let tx_str = format!("{tx_hash:#x}");
        self.set_all(GatewayRequestState::Finalized { tx_hash: tx_str });
        self.to(Finalized {
            tx_hash,
            block: _block,
        })
    }

    /// Fail the batch. Sets Failed state on all requests.
    pub fn fail(self, reason: &str) -> Batch<Failed, R> {
        self.set_all(GatewayRequestState::Failed {
            error: reason.into(),
            error_code: None,
        });
        self.to(Failed {
            reason: reason.into(),
        })
    }
}

// --- Terminal ---
impl<R: Tracked> Batch<Finalized, R> {
    pub fn tx_hash(&self) -> B256 {
        self.state.tx_hash
    }
    pub fn block(&self) -> u64 {
        self.state.block
    }
}

impl<R: Tracked> Batch<Failed, R> {
    pub fn reason(&self) -> &str {
        &self.state.reason
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BATCHOPS TRAIT - pure batch operations
// ═══════════════════════════════════════════════════════════════════════════

/// Operations that can be performed on batches.
///
/// Batches contain `Request<T>` items where each Request implements `Tracked`.
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

/// Run a batch through the full pipeline with automatic sync.
///
/// This is a convenience function that handles the common simulate → submit → confirm
/// flow with proper sync dispatch at each step.
///
/// # Example
/// ```ignore
/// let result = run_batch(&batch_ops, ops, batch_id).await;
/// ```
pub async fn run_batch<B, T>(
    ops: &B,
    requests: Vec<Request<T>>,
    batch_id: Uuid,
) -> Result<Batch<Finalized, Request<T>>, Batch<Failed, Request<T>>>
where
    B: BatchOps<T>,
    T: Send + Sync,
{
    let mut batch = Batch::new(requests).assign(batch_id);

    // 1. Simulate - evict failures
    let evictions = ops.simulate(&batch).await;
    batch.evict_many(&evictions);
    if batch.is_empty() {
        return Err(batch.evict("all evicted"));
    }

    // 2. Submit
    let tx_hash = match ops.submit(&batch).await {
        Ok(h) => h,
        Err(e) => return Err(batch.evict(&e)),
    };
    let batch = batch.submit(tx_hash);

    // 3. Confirm
    match ops.confirm(&batch).await {
        Ok(block) => Ok(batch.finalize(block)),
        Err(e) => Err(batch.fail(&e)),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// LEGACY CONVERSION
// ═══════════════════════════════════════════════════════════════════════════

impl Batch<Finalized, Request<OpEnvelopeInner>> {
    pub fn into_finalized_batch(self, batch_id: Uuid) -> FinalizedBatch {
        FinalizedBatch {
            batch_id,
            tx_hash: Some(self.state.tx_hash),
            block_number: Some(self.state.block),
            gas_used: 0,
            statuses: self
                .requests
                .iter()
                .map(|r| {
                    (
                        r.id(),
                        OpStatus::Finalized {
                            tx_hash: self.state.tx_hash,
                            block_number: self.state.block,
                            gas_used: 0,
                        },
                    )
                })
                .collect(),
            timing: crate::batcher::types::BatchTiming::new(self.created_at),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_finalize_auto_dispatches() {
        let watch = Synced::install_test();
        let ids: Vec<_> = (0..3).map(|_| Uuid::new_v4()).collect();

        // State transitions auto-dispatch through installed Synced
        let _ = Batch::new(ids.iter().map(|&id| Request::with_id(id, ())).collect())
            .assign(Uuid::new_v4())
            .submit(B256::ZERO)
            .finalize(100);

        for id in &ids {
            assert!(matches!(
                watch.get(id),
                Some(GatewayRequestState::Finalized { .. })
            ));
        }
    }

    #[tokio::test]
    async fn test_evict_auto_dispatches() {
        let watch = Synced::install_test();
        let ids: Vec<_> = (0..2).map(|_| Uuid::new_v4()).collect();

        let _ = Batch::new(ids.iter().map(|&id| Request::with_id(id, ())).collect())
            .assign(Uuid::new_v4())
            .evict("fail");

        for id in &ids {
            assert!(matches!(
                watch.get(id),
                Some(GatewayRequestState::Failed { .. })
            ));
        }
    }

    #[tokio::test]
    async fn test_fail_auto_dispatches() {
        let watch = Synced::install_test();
        let ids: Vec<_> = (0..2).map(|_| Uuid::new_v4()).collect();

        let _ = Batch::new(ids.iter().map(|&id| Request::with_id(id, ())).collect())
            .assign(Uuid::new_v4())
            .submit(B256::ZERO)
            .fail("submission failed");

        for id in &ids {
            let state = watch.get(id);
            assert!(
                matches!(state, Some(GatewayRequestState::Failed { .. })),
                "expected Failed, got: {:?}",
                state
            );
        }
    }

    #[tokio::test]
    async fn test_state_transitions() {
        let watch = Synced::install_test();
        let id = Uuid::new_v4();
        let requests = vec![Request::with_id(id, ())];

        // Queued
        let batch = Batch::new(requests);
        assert!(matches!(watch.get(&id), Some(GatewayRequestState::Queued)));

        // Batching
        let batch = batch.assign(Uuid::new_v4());
        assert!(matches!(
            watch.get(&id),
            Some(GatewayRequestState::Batching)
        ));

        // Submitted
        let batch = batch.submit(B256::ZERO);
        assert!(matches!(
            watch.get(&id),
            Some(GatewayRequestState::Submitted { .. })
        ));

        // Finalized
        let _ = batch.finalize(100);
        assert!(matches!(
            watch.get(&id),
            Some(GatewayRequestState::Finalized { .. })
        ));
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

    #[tokio::test(flavor = "current_thread")]
    async fn test_run_batch_success() {
        let watch = Synced::install_test();
        let ids: Vec<_> = (0..3).map(|_| Uuid::new_v4()).collect();
        let requests: Vec<_> = ids.iter().map(|&id| Request::with_id(id, ())).collect();

        let result = run_batch(&MockBatchOps, requests, Uuid::new_v4()).await;

        assert!(result.is_ok());
        for id in &ids {
            let state = watch.get(id);
            assert!(
                matches!(state, Some(GatewayRequestState::Finalized { .. })),
                "expected Finalized, got: {:?}",
                state
            );
        }
    }

    struct FailingMockBatchOps;
    impl BatchOps<()> for FailingMockBatchOps {
        async fn simulate(&self, _: &Batch<Assigned, Request<()>>) -> HashMap<Uuid, String> {
            HashMap::new()
        }
        async fn submit(&self, _: &Batch<Assigned, Request<()>>) -> Result<B256, String> {
            Err("submit failed".into())
        }
        async fn confirm(&self, _: &Batch<Submitted, Request<()>>) -> Result<u64, String> {
            Ok(42)
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_run_batch_submit_failure() {
        let watch = Synced::install_test();
        let ids: Vec<_> = (0..2).map(|_| Uuid::new_v4()).collect();
        let requests: Vec<_> = ids.iter().map(|&id| Request::with_id(id, ())).collect();

        let result = run_batch(&FailingMockBatchOps, requests, Uuid::new_v4()).await;

        assert!(result.is_err());
        for id in &ids {
            let state = watch.get(id);
            assert!(
                matches!(state, Some(GatewayRequestState::Failed { .. })),
                "expected Failed, got: {:?}",
                state
            );
        }
    }
}
