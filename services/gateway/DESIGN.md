# World ID Gateway: Request-First Design

A complete specification where the **Request** is the central abstraction. Every operation flows through a type-safe request lifecycle with compile-time guarantees.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Types](#core-types)
3. [Request Lifecycle](#request-lifecycle)
4. [Payload Conversion](#payload-conversion)
5. [HTTP Layer](#http-layer)
6. [RequestTracker](#requesttracker)
7. [OpsBatcher](#opsbatcher)
8. [EventPipe](#eventpipe)
9. [Event Handlers](#event-handlers)
10. [Application Bootstrap](#application-bootstrap)
11. [Data Flow](#data-flow)
12. [Error Handling](#error-handling)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                   HTTP Layer                                         │
│                                                                                      │
│  POST /v1/accounts ──────────────────────────────────────────────────────────────►  │
│  POST /v1/authenticators/insert ─────────────────────────────────────────────────►  │
│  POST /v1/authenticators/update ─────────────────────────────────────────────────►  │
│  POST /v1/authenticators/remove ─────────────────────────────────────────────────►  │
│  POST /v1/accounts/recover ──────────────────────────────────────────────────────►  │
│  GET  /v1/requests/:id ──────────────────────────────────────────────────────────►  │
│                                         │                                            │
│                          ┌──────────────▼──────────────┐                            │
│                          │  request_id_middleware      │                            │
│                          │  (generates Uuid)           │                            │
│                          └──────────────┬──────────────┘                            │
└─────────────────────────────────────────┼───────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              Request<Validated>                                      │
│                                                                                      │
│   payload.into_request(request_id)?                                                 │
│       │                                                                              │
│       ├── CreateAccountRequest      ──► Request<Validated, CreateAccountOp>         │
│       ├── InsertAuthenticatorRequest──► Request<Validated, InsertAuthenticatorOp>   │
│       ├── UpdateAuthenticatorRequest──► Request<Validated, UpdateAuthenticatorOp>   │
│       ├── RemoveAuthenticatorRequest──► Request<Validated, RemoveAuthenticatorOp>   │
│       └── RecoverAccountRequest     ──► Request<Validated, RecoverAccountOp>        │
│                                                                                      │
└─────────────────────────────────────────┬───────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              request.submit(&ctx).await                              │
│                                                                                      │
│   ┌─────────────────────────────────────────────────────────────────────────────┐   │
│   │                         In-Memory Operations (instant)                       │   │
│   │                                                                              │   │
│   │   1. tracker.register(id, kind)   ── HashMap insert (instant)               │   │
│   │   2. batcher.queue(id, op)        ── Priority queue push (instant)          │   │
│   │   3. pipe.emit(OpEvent::Queued)   ── Broadcast send (instant)               │   │
│   │                                                                              │   │
│   │   All synchronous, no I/O blocking the client                               │   │
│   └──────────────────────────────────────────────────────────────────────────────┘   │
│                                  │                                                   │
│                                  ▼                                                   │
│                         Request<Pending>                                             │
│                                  │                                                   │
│                                  ▼                                                   │
│                         .into_response()                                             │
│                                  │                                                   │
│                                  ▼                                                   │
│                         GatewayStatusResponse { request_id, kind, status: Queued }   │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                   ┌──────────────────────┴──────────────────────┐
                   │                                             │
                   ▼                                             ▼
┌──────────────────────────────────────┐   ┌──────────────────────────────────────────┐
│         Background: OpsBatcher       │   │         Background: EventPipe             │
│                                      │   │                                           │
│  ┌────────────────────────────────┐  │   │   ┌───────────────────────────────────┐  │
│  │  Priority Queue                │  │   │   │  broadcast::Sender<SystemEvent>   │  │
│  │  ───────────────               │  │   │   │  ────────────────────────────────  │  │
│  │  [Request] [Request] [Request] │  │   │   │  OpEvent::Queued { request_id }   │  │
│  └────────────────────────────────┘  │   │   │  OpEvent::Assigned { ... }        │  │
│               │                      │   │   │  OpEvent::Submitted { ... }       │  │
│               ▼                      │   │   │  OpEvent::Finalized { ... }       │  │
│  ┌────────────────────────────────┐  │   │   │  BatchEvent::Created { ... }      │  │
│  │  Batch Pipeline                │  │   │   └───────────────────────────────────┘  │
│  │  ──────────────                │  │   │                    │                     │
│  │  1. Drain queue into batch     │──┼───┼────────────────────┤                     │
│  │  2. Simulate batch             │──┼───┼────────────────────┤                     │
│  │  3. Submit to chain            │──┼───┼────────────────────┤                     │
│  │  4. Wait for confirmation      │──┼───┼────────────────────┤                     │
│  │  5. Emit finalized/failed      │──┼───┼────────────────────┘                     │
│  └────────────────────────────────┘  │   │                                           │
└──────────────────────────────────────┘   └──────────────────────────────────────────┘
                                                             │
                               ┌─────────────────────────────┼─────────────────────────┐
                               │                             │                         │
                               ▼                             ▼                         ▼
                    ┌──────────────────┐         ┌──────────────────┐     ┌──────────────────┐
                    │  MetricsHandler  │         │  LoggingHandler  │     │  RequestTracker  │
                    │  (sync)          │         │  (sync)          │     │  (EventHandler)  │
                    │                  │         │                  │     │                  │
                    │  prometheus      │         │  tracing         │     │  in-memory state │
                    │  counters        │         │  structured      │     │  + async Redis   │
                    │  histograms      │         │  logs            │     │  write-behind    │
                    └──────────────────┘         └──────────────────┘     └──────────────────┘
```

---

## Core Types

### File: `services/gateway/src/request/mod.rs`

```rust
//! Request-first abstraction for gateway operations.
//!
//! The request is the central type through which all operations flow.
//! Type-state pattern ensures compile-time correctness of the lifecycle.

mod state;
mod submit;

pub use state::{Pending, Raw, RequestState, Validated};
pub use submit::SubmitError;

use crate::batcher::types::{OpEnvelopeInner, Operation};
use crate::AppContext;
use alloy::primitives::{Address, U256};
use std::marker::PhantomData;
use tokio::time::Instant;
use uuid::Uuid;
use world_id_core::types::{GatewayRequestKind, GatewayRequestState, GatewayStatusResponse};

/// A request flowing through the gateway.
///
/// Generic over:
/// - `S`: The state (Raw, Validated, Pending)
/// - `T`: The operation type (CreateAccountOp, InsertAuthenticatorOp, etc.)
#[must_use = "requests do nothing unless submitted"]
pub struct Request<S: RequestState, T = Operation> {
    /// Unique identifier assigned by middleware.
    id: Uuid,
    /// The operation payload.
    op: T,
    /// When the request was created.
    created_at: Instant,
    /// Signer address (for nonce tracking).
    signer: Address,
    /// Operation nonce.
    nonce: U256,
    /// Type-state marker.
    _state: PhantomData<S>,
}

impl<S: RequestState, T> Request<S, T> {
    /// Get the request ID.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Get the signer address.
    pub fn signer(&self) -> Address {
        self.signer
    }

    /// Get the nonce.
    pub fn nonce(&self) -> U256 {
        self.nonce
    }

    /// Get request age.
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }
}

impl<T> Request<Raw, T> {
    /// Create a new raw request.
    pub fn new(id: Uuid, op: T, signer: Address, nonce: U256) -> Self {
        Self {
            id,
            op,
            created_at: Instant::now(),
            signer,
            nonce,
            _state: PhantomData,
        }
    }
}

impl<T: Validate> Request<Raw, T> {
    /// Validate the request, transitioning to Validated state.
    pub fn validate(self) -> Result<Request<Validated, T>, ValidationError> {
        self.op.validate()?;

        Ok(Request {
            id: self.id,
            op: self.op,
            created_at: self.created_at,
            signer: self.signer,
            nonce: self.nonce,
            _state: PhantomData,
        })
    }
}

impl<T: IntoOperation> Request<Validated, T> {
    /// Submit the request for processing.
    ///
    /// This is the only way to transition to Pending state.
    /// All operations are in-memory and instant - nothing blocks the client.
    pub async fn submit(self, ctx: &AppContext) -> Result<Request<Pending, T>, SubmitError> {
        let kind = self.op.kind();
        let op_envelope = self.to_envelope();

        // 1. Register in tracker (in-memory HashMap insert)
        ctx.tracker.register(self.id, kind);

        // 2. Queue in batcher (in-memory priority queue push)
        ctx.batcher.queue(self.id, op_envelope)?;

        // 3. Emit queued event (RequestTracker receives this via EventHandler)
        ctx.pipe.emit(SystemEvent::Op(OpEvent::Queued {
            request_id: self.id,
        }));

        Ok(Request {
            id: self.id,
            op: self.op,
            created_at: self.created_at,
            signer: self.signer,
            nonce: self.nonce,
            _state: PhantomData,
        })
    }

    fn to_envelope(&self) -> OpEnvelopeInner {
        OpEnvelopeInner::with_id(
            self.id,
            self.op.into_operation(),
            self.signer,
            self.nonce,
        )
    }
}

impl<T: IntoOperation> Request<Pending, T> {
    /// Get the operation kind.
    pub fn kind(&self) -> GatewayRequestKind {
        self.op.kind()
    }

    /// Convert to a status response for the client.
    pub fn into_response(self) -> GatewayStatusResponse {
        GatewayStatusResponse {
            request_id: self.id.to_string(),
            kind: self.op.kind(),
            status: GatewayRequestState::Queued,
        }
    }

    /// Wait for the request to reach a terminal state.
    pub async fn wait(
        &self,
        ctx: &AppContext,
        timeout: std::time::Duration,
    ) -> Result<TerminalState, WaitError> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(WaitError::Timeout);
            }

            let status = ctx.tracker.get(self.id);

            match status.map(|r| r.status) {
                Some(GatewayRequestState::Finalized { tx_hash }) => {
                    return Ok(TerminalState::Finalized { tx_hash });
                }
                Some(GatewayRequestState::Failed { error, error_code }) => {
                    return Ok(TerminalState::Failed { error, error_code });
                }
                _ => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
    }

    /// Subscribe to status updates via the event pipe.
    ///
    /// Returns a stream that yields status changes for this specific request.
    /// The stream completes when the request reaches a terminal state.
    pub fn subscribe<'a>(
        &'a self,
        pipe: &'a EventPipe,
    ) -> impl Stream<Item = GatewayRequestState> + 'a {
        use tokio_stream::wrappers::BroadcastStream;
        use tokio_stream::StreamExt;

        let id = self.id;

        BroadcastStream::new(pipe.subscribe())
            .filter_map(move |result| {
                let Ok(envelope) = result else {
                    return std::future::ready(None);
                };

                match envelope.event {
                    SystemEvent::Op(OpEvent::Assigned { request_id, .. }) if request_id == id => {
                        std::future::ready(Some(GatewayRequestState::Batching))
                    }
                    SystemEvent::Op(OpEvent::Submitted { request_id, tx_hash, .. }) if request_id == id => {
                        std::future::ready(Some(GatewayRequestState::Submitted {
                            tx_hash: format!("{tx_hash:#x}"),
                        }))
                    }
                    SystemEvent::Op(OpEvent::Finalized { request_id, tx_hash, .. }) if request_id == id => {
                        std::future::ready(Some(GatewayRequestState::Finalized {
                            tx_hash: format!("{tx_hash:#x}"),
                        }))
                    }
                    SystemEvent::Op(OpEvent::Failed { request_id, reason, code }) if request_id == id => {
                        std::future::ready(Some(GatewayRequestState::Failed {
                            error: reason,
                            error_code: code,
                        }))
                    }
                    _ => std::future::ready(None),
                }
            })
    }
}

/// Terminal state of a request.
pub enum TerminalState {
    Finalized { tx_hash: String },
    Failed { error: String, error_code: Option<GatewayErrorCode> },
}

/// Error when waiting for request completion.
#[derive(Debug, thiserror::Error)]
pub enum WaitError {
    #[error("timeout waiting for completion")]
    Timeout,
    #[error("tracker error: {0}")]
    Tracker(#[from] TrackerError),
}

/// Trait for validating operation payloads.
pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}

/// Trait for converting typed operations to the generic Operation enum.
pub trait IntoOperation {
    fn into_operation(&self) -> Operation;
    fn kind(&self) -> GatewayRequestKind;
}

/// Validation error.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("empty authenticator list")]
    EmptyAuthenticators,
    #[error("too many authenticators: max {max}, got {got}")]
    TooManyAuthenticators { max: usize, got: usize },
    #[error("invalid signature length: expected {expected}, got {got}")]
    InvalidSignatureLength { expected: usize, got: usize },
    #[error("invalid proof: {0}")]
    InvalidProof(String),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("{0}")]
    Custom(String),
}
```

### File: `services/gateway/src/request/state.rs`

```rust
//! Type-state markers for request lifecycle.

mod sealed {
    pub trait Sealed {}
}

/// Marker trait for valid request states.
pub trait RequestState: sealed::Sealed + Send + Sync {}

/// Request has been created but not validated.
pub struct Raw;
impl sealed::Sealed for Raw {}
impl RequestState for Raw {}

/// Request has been validated and is ready for submission.
pub struct Validated;
impl sealed::Sealed for Validated {}
impl RequestState for Validated {}

/// Request has been submitted and is being processed.
pub struct Pending;
impl sealed::Sealed for Pending {}
impl RequestState for Pending {}
```

### File: `services/gateway/src/request/submit.rs`

```rust
//! Submission error types.

use world_id_core::types::GatewayErrorResponse;

/// Error during request submission.
#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("queue is full")]
    QueueFull,
    #[error("tracker error: {0}")]
    Tracker(#[from] TrackerError),
    #[error("batcher error: {0}")]
    Batcher(#[from] QueueError),
    #[error("service shutting down")]
    Shutdown,
}

impl From<SubmitError> for GatewayErrorResponse {
    fn from(e: SubmitError) -> Self {
        match e {
            SubmitError::QueueFull => GatewayErrorResponse::new(
                GatewayErrorCode::BatcherUnavailable,
                "Operation queue is full, try again later".into(),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            SubmitError::Tracker(e) => GatewayErrorResponse::internal_server_error(),
            SubmitError::Batcher(e) => match e {
                QueueError::Full => GatewayErrorResponse::batcher_unavailable(),
                QueueError::Invalid(msg) => GatewayErrorResponse::bad_request_message(msg),
                QueueError::Shutdown => GatewayErrorResponse::batcher_unavailable(),
            },
            SubmitError::Shutdown => GatewayErrorResponse::batcher_unavailable(),
        }
    }
}
```

---

## Request Lifecycle

### Usage Patterns

```rust
// ============================================================================
// Pattern 1: Fire-and-Forget (most common for HTTP handlers)
// ============================================================================

pub async fn create_account(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<CreateAccountRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    payload
        .into_request(id)?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}

// Client polls GET /v1/requests/:id for status updates


// ============================================================================
// Pattern 2: Wait for Completion (blocking, with timeout)
// ============================================================================

pub async fn create_account_sync(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<CreateAccountRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    let pending = payload
        .into_request(id)?
        .submit(&state.ctx)
        .await?;

    // Wait up to 60 seconds for finalization
    let terminal = pending
        .wait(&state.ctx, Duration::from_secs(60))
        .await?;

    let status = match terminal {
        TerminalState::Finalized { tx_hash } => {
            GatewayRequestState::Finalized { tx_hash }
        }
        TerminalState::Failed { error, error_code } => {
            GatewayRequestState::Failed { error, error_code }
        }
    };

    Ok(Json(GatewayStatusResponse {
        request_id: id.to_string(),
        kind: GatewayRequestKind::CreateAccount,
        status,
    }))
}


// ============================================================================
// Pattern 3: Stream Status Updates (SSE/WebSocket)
// ============================================================================

pub async fn create_account_stream(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<CreateAccountRequest>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let pending = payload
        .into_request(id)
        .unwrap()
        .submit(&state.ctx)
        .await
        .unwrap();

    let stream = pending
        .subscribe(&state.ctx.pipe)
        .map(|status| {
            let data = serde_json::to_string(&status).unwrap();
            Ok(Event::default().data(data))
        })
        .take_while(|status| {
            // Stop streaming at terminal states
            !matches!(
                status,
                Ok(Event { .. }) // Check for Finalized/Failed
            )
        });

    Sse::new(stream)
}


// ============================================================================
// Pattern 4: Internal Service Use (batch multiple requests)
// ============================================================================

pub async fn batch_create_accounts(
    ctx: &AppContext,
    payloads: Vec<CreateAccountRequest>,
) -> Vec<Result<TerminalState, Error>> {
    let requests: Vec<_> = payloads
        .into_iter()
        .map(|p| {
            let id = Uuid::new_v4();
            p.into_request(id)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Submit all in parallel
    let pending: Vec<_> = futures::future::join_all(
        requests.into_iter().map(|r| r.submit(ctx))
    )
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;

    // Wait for all to complete
    futures::future::join_all(
        pending.iter().map(|p| p.wait(ctx, Duration::from_secs(120)))
    )
    .await
}
```

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              Request State Machine                                   │
└─────────────────────────────────────────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                             Compile-Time Enforced                            │
    └─────────────────────────────────────────────────────────────────────────────┘

              payload.into_request(id)?
                       │
                       ▼
              ┌─────────────────┐
              │  Request<Raw>   │
              │                 │
              │  - id           │
              │  - op (unvalidated)
              │  - signer       │
              │  - nonce        │
              └────────┬────────┘
                       │
                       │ .validate()?
                       │
                       ▼
              ┌─────────────────────┐
              │ Request<Validated>  │
              │                     │
              │  - id               │
              │  - op (validated)   │
              │  - signer           │
              │  - nonce            │
              └────────┬────────────┘
                       │
                       │ .submit(&ctx).await?
                       │
                       │  ┌─────────────────────────────────────┐
                       │  │  tokio::try_join!                   │
                       │  │    tracker.create(id, kind)         │
                       │  │    batcher.queue(id, op)            │
                       │  │                                     │
                       │  │  Both must succeed                  │
                       │  └─────────────────────────────────────┘
                       │
                       ▼
              ┌─────────────────────┐
              │  Request<Pending>   │
              │                     │
              │  - id               │
              │  - op               │
              │  + kind()           │
              │  + into_response()  │
              └────────┬────────────┘
                       │
                       │ .into_response()
                       │
                       ▼
              ┌─────────────────────────┐
              │  GatewayStatusResponse  │
              │                         │
              │  request_id: String     │
              │  kind: GatewayRequestKind
              │  status: Queued         │
              └─────────────────────────┘


    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                           Invalid Code (Won't Compile)                       │
    └─────────────────────────────────────────────────────────────────────────────┘

    // Can't submit without validating
    Request::new(id, op, signer, nonce).submit(&ctx);
    // ERROR: no method `submit` found for `Request<Raw, _>`

    // Can't get response without submitting
    Request::new(id, op, signer, nonce).validate()?.into_response();
    // ERROR: no method `into_response` found for `Request<Validated, _>`

    // Can't validate twice
    request.validate()?.validate();
    // ERROR: no method `validate` found for `Request<Validated, _>`
```

---

## Payload Conversion

### File: `services/gateway/src/request/convert.rs`

```rust
//! Payload to Request conversion.

use super::{IntoOperation, Raw, Request, Validate, ValidationError};
use crate::batcher::types::*;
use alloy::primitives::{Address, Bytes, U256};
use uuid::Uuid;
use world_id_core::types::*;

/// Trait for HTTP payloads that can become requests.
pub trait IntoRequest {
    /// The typed operation this payload produces.
    type Op: Validate + IntoOperation;

    /// Extract signer address from payload.
    fn signer(&self) -> Address;

    /// Extract nonce from payload.
    fn nonce(&self) -> U256;

    /// Convert payload to operation.
    fn into_op(self) -> Result<Self::Op, ValidationError>;

    /// Convert payload to a validated request.
    fn into_request(self, id: Uuid) -> Result<Request<super::Validated, Self::Op>, ValidationError>
    where
        Self: Sized,
    {
        let signer = self.signer();
        let nonce = self.nonce();
        let op = self.into_op()?;

        Request::<Raw, Self::Op>::new(id, op, signer, nonce).validate()
    }
}

// ============================================================================
// CreateAccountRequest
// ============================================================================

/// Typed operation for account creation.
#[derive(Debug, Clone)]
pub struct CreateAccountOp {
    pub recovery_address: Option<Address>,
    pub authenticator_addresses: Vec<Address>,
    pub authenticator_pubkeys: Vec<U256>,
    pub offchain_signer_commitment: U256,
}

impl Validate for CreateAccountOp {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.authenticator_addresses.is_empty() {
            return Err(ValidationError::EmptyAuthenticators);
        }
        if self.authenticator_addresses.len() > 8 {
            return Err(ValidationError::TooManyAuthenticators {
                max: 8,
                got: self.authenticator_addresses.len(),
            });
        }
        if self.authenticator_addresses.len() != self.authenticator_pubkeys.len() {
            return Err(ValidationError::Custom(
                "authenticator addresses and pubkeys must have same length".into(),
            ));
        }
        Ok(())
    }
}

impl IntoOperation for CreateAccountOp {
    fn into_operation(&self) -> Operation {
        Operation::CreateAccount(crate::batcher::types::CreateAccountOp {
            initial_commitment: self.offchain_signer_commitment,
            signature: Bytes::new(), // Populated during batch
        })
    }

    fn kind(&self) -> GatewayRequestKind {
        GatewayRequestKind::CreateAccount
    }
}

impl IntoRequest for CreateAccountRequest {
    type Op = CreateAccountOp;

    fn signer(&self) -> Address {
        self.authenticator_addresses.first().copied().unwrap_or(Address::ZERO)
    }

    fn nonce(&self) -> U256 {
        U256::ZERO // Account creation has no nonce
    }

    fn into_op(self) -> Result<Self::Op, ValidationError> {
        Ok(CreateAccountOp {
            recovery_address: self.recovery_address,
            authenticator_addresses: self.authenticator_addresses,
            authenticator_pubkeys: self.authenticator_pubkeys,
            offchain_signer_commitment: self.offchain_signer_commitment,
        })
    }
}

// ============================================================================
// InsertAuthenticatorRequest
// ============================================================================

/// Typed operation for authenticator insertion.
#[derive(Debug, Clone)]
pub struct InsertAuthenticatorOp {
    pub leaf_index: U256,
    pub new_authenticator_address: Address,
    pub pubkey_id: u32,
    pub new_authenticator_pubkey: U256,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
    pub sibling_nodes: Vec<U256>,
    pub signature: Vec<u8>,
    pub nonce: U256,
}

impl Validate for InsertAuthenticatorOp {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.signature.is_empty() {
            return Err(ValidationError::InvalidSignatureLength {
                expected: 65,
                got: 0,
            });
        }
        if self.sibling_nodes.is_empty() {
            return Err(ValidationError::InvalidProof("empty sibling nodes".into()));
        }
        Ok(())
    }
}

impl IntoOperation for InsertAuthenticatorOp {
    fn into_operation(&self) -> Operation {
        Operation::InsertAuthenticator(crate::batcher::types::InsertAuthenticatorOp {
            leaf_index: self.leaf_index,
            new_authenticator_address: self.new_authenticator_address,
            pubkey_id: self.pubkey_id,
            new_authenticator_pubkey: self.new_authenticator_pubkey,
            old_commit: self.old_offchain_signer_commitment,
            new_commit: self.new_offchain_signer_commitment,
            signature: Bytes::from(self.signature.clone()),
            sibling_nodes: self.sibling_nodes.clone(),
            nonce: self.nonce,
        })
    }

    fn kind(&self) -> GatewayRequestKind {
        GatewayRequestKind::InsertAuthenticator
    }
}

impl IntoRequest for InsertAuthenticatorRequest {
    type Op = InsertAuthenticatorOp;

    fn signer(&self) -> Address {
        self.new_authenticator_address
    }

    fn nonce(&self) -> U256 {
        self.nonce
    }

    fn into_op(self) -> Result<Self::Op, ValidationError> {
        Ok(InsertAuthenticatorOp {
            leaf_index: self.leaf_index,
            new_authenticator_address: self.new_authenticator_address,
            pubkey_id: self.pubkey_id,
            new_authenticator_pubkey: self.new_authenticator_pubkey,
            old_offchain_signer_commitment: self.old_offchain_signer_commitment,
            new_offchain_signer_commitment: self.new_offchain_signer_commitment,
            sibling_nodes: self.sibling_nodes,
            signature: self.signature,
            nonce: self.nonce,
        })
    }
}

// ============================================================================
// UpdateAuthenticatorRequest
// ============================================================================

/// Typed operation for authenticator update.
#[derive(Debug, Clone)]
pub struct UpdateAuthenticatorOp {
    pub leaf_index: U256,
    pub old_authenticator_address: Address,
    pub new_authenticator_address: Address,
    pub pubkey_id: u32,
    pub new_authenticator_pubkey: U256,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
    pub sibling_nodes: Vec<U256>,
    pub signature: Vec<u8>,
    pub nonce: U256,
}

impl Validate for UpdateAuthenticatorOp {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.signature.is_empty() {
            return Err(ValidationError::InvalidSignatureLength {
                expected: 65,
                got: 0,
            });
        }
        Ok(())
    }
}

impl IntoOperation for UpdateAuthenticatorOp {
    fn into_operation(&self) -> Operation {
        Operation::UpdateAuthenticator(crate::batcher::types::UpdateAuthenticatorOp {
            leaf_index: self.leaf_index,
            old_authenticator_address: self.old_authenticator_address,
            new_authenticator_address: self.new_authenticator_address,
            pubkey_id: self.pubkey_id,
            new_authenticator_pubkey: self.new_authenticator_pubkey,
            old_commit: self.old_offchain_signer_commitment,
            new_commit: self.new_offchain_signer_commitment,
            signature: Bytes::from(self.signature.clone()),
            sibling_nodes: self.sibling_nodes.clone(),
            nonce: self.nonce,
        })
    }

    fn kind(&self) -> GatewayRequestKind {
        GatewayRequestKind::UpdateAuthenticator
    }
}

impl IntoRequest for UpdateAuthenticatorRequest {
    type Op = UpdateAuthenticatorOp;

    fn signer(&self) -> Address {
        self.old_authenticator_address
    }

    fn nonce(&self) -> U256 {
        self.nonce
    }

    fn into_op(self) -> Result<Self::Op, ValidationError> {
        Ok(UpdateAuthenticatorOp {
            leaf_index: self.leaf_index,
            old_authenticator_address: self.old_authenticator_address,
            new_authenticator_address: self.new_authenticator_address,
            pubkey_id: self.pubkey_id,
            new_authenticator_pubkey: self.new_authenticator_pubkey,
            old_offchain_signer_commitment: self.old_offchain_signer_commitment,
            new_offchain_signer_commitment: self.new_offchain_signer_commitment,
            sibling_nodes: self.sibling_nodes,
            signature: self.signature,
            nonce: self.nonce,
        })
    }
}

// ============================================================================
// RemoveAuthenticatorRequest
// ============================================================================

/// Typed operation for authenticator removal.
#[derive(Debug, Clone)]
pub struct RemoveAuthenticatorOp {
    pub leaf_index: U256,
    pub authenticator_address: Address,
    pub pubkey_id: Option<u32>,
    pub authenticator_pubkey: Option<U256>,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
    pub sibling_nodes: Vec<U256>,
    pub signature: Vec<u8>,
    pub nonce: U256,
}

impl Validate for RemoveAuthenticatorOp {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.signature.is_empty() {
            return Err(ValidationError::InvalidSignatureLength {
                expected: 65,
                got: 0,
            });
        }
        Ok(())
    }
}

impl IntoOperation for RemoveAuthenticatorOp {
    fn into_operation(&self) -> Operation {
        Operation::RemoveAuthenticator(crate::batcher::types::RemoveAuthenticatorOp {
            leaf_index: self.leaf_index,
            authenticator_address: self.authenticator_address,
            pubkey_id: self.pubkey_id.unwrap_or(0),
            authenticator_pubkey: self.authenticator_pubkey.unwrap_or(U256::ZERO),
            old_commit: self.old_offchain_signer_commitment,
            new_commit: self.new_offchain_signer_commitment,
            signature: Bytes::from(self.signature.clone()),
            sibling_nodes: self.sibling_nodes.clone(),
            nonce: self.nonce,
        })
    }

    fn kind(&self) -> GatewayRequestKind {
        GatewayRequestKind::RemoveAuthenticator
    }
}

impl IntoRequest for RemoveAuthenticatorRequest {
    type Op = RemoveAuthenticatorOp;

    fn signer(&self) -> Address {
        self.authenticator_address
    }

    fn nonce(&self) -> U256 {
        self.nonce
    }

    fn into_op(self) -> Result<Self::Op, ValidationError> {
        Ok(RemoveAuthenticatorOp {
            leaf_index: self.leaf_index,
            authenticator_address: self.authenticator_address,
            pubkey_id: self.pubkey_id,
            authenticator_pubkey: self.authenticator_pubkey,
            old_offchain_signer_commitment: self.old_offchain_signer_commitment,
            new_offchain_signer_commitment: self.new_offchain_signer_commitment,
            sibling_nodes: self.sibling_nodes,
            signature: self.signature,
            nonce: self.nonce,
        })
    }
}

// ============================================================================
// RecoverAccountRequest
// ============================================================================

/// Typed operation for account recovery.
#[derive(Debug, Clone)]
pub struct RecoverAccountOp {
    pub leaf_index: U256,
    pub new_authenticator_address: Address,
    pub new_authenticator_pubkey: Option<U256>,
    pub old_offchain_signer_commitment: U256,
    pub new_offchain_signer_commitment: U256,
    pub sibling_nodes: Vec<U256>,
    pub signature: Vec<u8>,
    pub nonce: U256,
}

impl Validate for RecoverAccountOp {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.signature.is_empty() {
            return Err(ValidationError::InvalidSignatureLength {
                expected: 65,
                got: 0,
            });
        }
        Ok(())
    }
}

impl IntoOperation for RecoverAccountOp {
    fn into_operation(&self) -> Operation {
        Operation::RecoverAccount(crate::batcher::types::RecoverAccountOp {
            leaf_index: self.leaf_index,
            new_authenticator_address: self.new_authenticator_address,
            new_authenticator_pubkey: self.new_authenticator_pubkey.unwrap_or(U256::ZERO),
            old_commit: self.old_offchain_signer_commitment,
            new_commit: self.new_offchain_signer_commitment,
            signature: Bytes::from(self.signature.clone()),
            sibling_nodes: self.sibling_nodes.clone(),
            nonce: self.nonce,
        })
    }

    fn kind(&self) -> GatewayRequestKind {
        GatewayRequestKind::RecoverAccount
    }
}

impl IntoRequest for RecoverAccountRequest {
    type Op = RecoverAccountOp;

    fn signer(&self) -> Address {
        self.new_authenticator_address
    }

    fn nonce(&self) -> U256 {
        self.nonce
    }

    fn into_op(self) -> Result<Self::Op, ValidationError> {
        Ok(RecoverAccountOp {
            leaf_index: self.leaf_index,
            new_authenticator_address: self.new_authenticator_address,
            new_authenticator_pubkey: self.new_authenticator_pubkey,
            old_offchain_signer_commitment: self.old_offchain_signer_commitment,
            new_offchain_signer_commitment: self.new_offchain_signer_commitment,
            sibling_nodes: self.sibling_nodes,
            signature: self.signature,
            nonce: self.nonce,
        })
    }
}
```

---

## HTTP Layer

### File: `services/gateway/src/routes/middleware.rs`

```rust
//! Request ID middleware.

use axum::{
    extract::Request,
    http::HeaderValue,
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

/// Canonical request ID attached to every request.
#[derive(Clone, Copy, Debug)]
pub struct RequestId(pub Uuid);

/// Middleware that generates and attaches a canonical request ID.
pub async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4();
    request.extensions_mut().insert(RequestId(request_id));

    let mut response = next.run(request).await;

    // Add to response headers for client correlation
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        response.headers_mut().insert("X-Request-Id", value);
    }

    response
}
```

### File: `services/gateway/src/routes/create_account.rs`

```rust
//! Create account handler.

use crate::request::IntoRequest;
use crate::routes::middleware::RequestId;
use crate::types::AppState;
use axum::{extract::State, Extension, Json};
use world_id_core::types::{
    CreateAccountRequest, GatewayErrorResponse, GatewayStatusResponse,
};

/// POST /v1/accounts
///
/// Create a new World ID account.
pub async fn create_account(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<CreateAccountRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    payload
        .into_request(id)?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
```

### File: `services/gateway/src/routes/insert_authenticator.rs`

```rust
//! Insert authenticator handler.

use crate::request::IntoRequest;
use crate::routes::middleware::RequestId;
use crate::types::AppState;
use axum::{extract::State, Extension, Json};
use world_id_core::types::{
    GatewayErrorResponse, GatewayStatusResponse, InsertAuthenticatorRequest,
};

/// POST /v1/authenticators/insert
///
/// Insert a new authenticator to an existing account.
pub async fn insert_authenticator(
    State(state): State<AppState>,
    Extension(RequestId(id)): Extension<RequestId>,
    Json(payload): Json<InsertAuthenticatorRequest>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    payload
        .into_request(id)?
        .submit(&state.ctx)
        .await
        .map(|r| Json(r.into_response()))
}
```

### File: `services/gateway/src/routes/request_status.rs`

```rust
//! Request status handler.

use crate::types::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;
use world_id_core::types::{GatewayErrorResponse, GatewayStatusResponse};

/// GET /v1/requests/:id
///
/// Get the current status of a submitted request.
pub async fn request_status(
    State(state): State<AppState>,
    Path(request_id): Path<Uuid>,
) -> Result<Json<GatewayStatusResponse>, GatewayErrorResponse> {
    let record = state
        .ctx
        .tracker
        .get(request_id)
        .await?
        .ok_or_else(GatewayErrorResponse::not_found)?;

    Ok(Json(GatewayStatusResponse {
        request_id: request_id.to_string(),
        kind: record.kind,
        status: record.status,
    }))
}
```

---

## RequestTracker

The `RequestTracker` is an `EventHandler` that subscribes to the `EventPipe`. It maintains in-memory state as the source of truth and optionally persists to Redis asynchronously.

### Key Design Principle

**The tracker is just another event subscriber.** It registers on the EventPipe like MetricsHandler and LoggingHandler - no special coupling to the batcher.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                               EventPipe (broadcast)                                  │
│                                                                                      │
│   emit(OpEvent::Queued)  ────────────────────────────────────────────────►          │
│   emit(OpEvent::Assigned) ───────────────────────────────────────────────►          │
│   emit(OpEvent::Submitted) ──────────────────────────────────────────────►          │
│   emit(OpEvent::Finalized) ──────────────────────────────────────────────►          │
│   emit(OpEvent::Failed) ─────────────────────────────────────────────────►          │
└───────────────────────────────────────────────────┬─────────────────────────────────┘
                                                    │
            ┌───────────────────────────────────────┼───────────────────────────────┐
            │                                       │                               │
            ▼                                       ▼                               ▼
┌───────────────────────┐           ┌───────────────────────┐       ┌───────────────────────┐
│    MetricsHandler     │           │    LoggingHandler     │       │    RequestTracker     │
│    (EventHandler)     │           │    (EventHandler)     │       │    (EventHandler)     │
│                       │           │                       │       │                       │
│  • Prometheus metrics │           │  • Structured logs    │       │  • In-memory state    │
│  • Sync (fast)        │           │  • Sync (fast)        │       │  • Completion subs    │
│                       │           │                       │       │  • Async Redis        │
└───────────────────────┘           └───────────────────────┘       └───────────────────────┘
```

### File: `services/gateway/src/tracker.rs`

```rust
//! Request tracker - implements EventHandler to track request state.
//!
//! Subscribes to the EventPipe like any other handler.
//! Maintains in-memory state, optionally persists to Redis asynchronously.

use crate::events::{BoxFuture, Envelope, EventHandler, OpEvent, SystemEvent};
use alloy::primitives::B256;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::time::Instant;
use uuid::Uuid;
use world_id_core::types::{
    GatewayErrorCode, GatewayRequestKind, GatewayRequestState, GatewayStatusResponse,
};

// ============================================================================
// Types
// ============================================================================

/// Internal status tracking.
#[derive(Clone, Debug)]
pub enum RequestStatus {
    Queued,
    Batching { batch_id: Uuid },
    Submitted { tx_hash: B256 },
    Finalized { tx_hash: B256, block: u64 },
    Failed { reason: String, code: Option<GatewayErrorCode> },
}

impl RequestStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Finalized { .. } | Self::Failed { .. })
    }
}

/// Terminal state delivered to completion subscribers.
#[derive(Clone, Debug)]
pub enum TerminalState {
    Finalized { tx_hash: B256, block: u64 },
    Failed { reason: String, code: Option<GatewayErrorCode> },
}

/// Entry for a tracked request.
struct RequestEntry {
    kind: GatewayRequestKind,
    status: RequestStatus,
    created_at: Instant,
    completion_subscribers: Vec<oneshot::Sender<TerminalState>>,
}

// ============================================================================
// RequestTracker
// ============================================================================

/// Request tracker - implements EventHandler.
///
/// Registered on the EventPipe like any other handler. Updates in-memory
/// state on events and optionally persists to Redis asynchronously.
pub struct RequestTracker {
    state: RwLock<HashMap<Uuid, RequestEntry>>,
    redis_url: Option<String>,
}

impl RequestTracker {
    pub fn new(redis_url: Option<String>) -> Self {
        Self {
            state: RwLock::new(HashMap::new()),
            redis_url,
        }
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /// Register a new request (called during submission).
    pub fn register(&self, request_id: Uuid, kind: GatewayRequestKind) {
        self.state.write().insert(
            request_id,
            RequestEntry {
                kind,
                status: RequestStatus::Queued,
                created_at: Instant::now(),
                completion_subscribers: Vec::new(),
            },
        );
    }

    /// Get current status of a request.
    pub fn get(&self, request_id: Uuid) -> Option<GatewayStatusResponse> {
        let state = self.state.read();
        state.get(&request_id).map(|entry| GatewayStatusResponse {
            request_id: request_id.to_string(),
            kind: entry.kind.clone(),
            status: match &entry.status {
                RequestStatus::Queued => GatewayRequestState::Queued,
                RequestStatus::Batching { .. } => GatewayRequestState::Batching,
                RequestStatus::Submitted { tx_hash } => GatewayRequestState::Submitted {
                    tx_hash: format!("{tx_hash:#x}"),
                },
                RequestStatus::Finalized { tx_hash, .. } => GatewayRequestState::Finalized {
                    tx_hash: format!("{tx_hash:#x}"),
                },
                RequestStatus::Failed { reason, code } => GatewayRequestState::Failed {
                    error: reason.clone(),
                    error_code: code.clone(),
                },
            },
        })
    }

    /// Subscribe to completion of a request.
    pub fn subscribe_completion(&self, request_id: Uuid) -> Option<oneshot::Receiver<TerminalState>> {
        let mut state = self.state.write();
        let entry = state.get_mut(&request_id)?;

        // If already terminal, return immediately
        match &entry.status {
            RequestStatus::Finalized { tx_hash, block } => {
                let (tx, rx) = oneshot::channel();
                let _ = tx.send(TerminalState::Finalized { tx_hash: *tx_hash, block: *block });
                return Some(rx);
            }
            RequestStatus::Failed { reason, code } => {
                let (tx, rx) = oneshot::channel();
                let _ = tx.send(TerminalState::Failed { reason: reason.clone(), code: code.clone() });
                return Some(rx);
            }
            _ => {}
        }

        let (tx, rx) = oneshot::channel();
        entry.completion_subscribers.push(tx);
        Some(rx)
    }

    // ========================================================================
    // Event Processing (called by EventHandler impl)
    // ========================================================================

    fn handle_op_event(&self, event: OpEvent) {
        let mut state = self.state.write();

        match event {
            OpEvent::Queued { request_id } => {
                if let Some(entry) = state.get_mut(&request_id) {
                    entry.status = RequestStatus::Queued;
                }
            }

            OpEvent::Assigned { request_id, batch_id } => {
                if let Some(entry) = state.get_mut(&request_id) {
                    entry.status = RequestStatus::Batching { batch_id };
                }
            }

            OpEvent::Submitted { request_id, tx_hash, .. } => {
                if let Some(entry) = state.get_mut(&request_id) {
                    entry.status = RequestStatus::Submitted { tx_hash };
                }
            }

            OpEvent::Finalized { request_id, tx_hash, block } => {
                if let Some(entry) = state.get_mut(&request_id) {
                    entry.status = RequestStatus::Finalized { tx_hash, block };

                    // Notify subscribers
                    for tx in std::mem::take(&mut entry.completion_subscribers) {
                        let _ = tx.send(TerminalState::Finalized { tx_hash, block });
                    }
                }
            }

            OpEvent::Failed { request_id, reason, code } => {
                if let Some(entry) = state.get_mut(&request_id) {
                    entry.status = RequestStatus::Failed { reason: reason.clone(), code: code.clone() };

                    // Notify subscribers
                    for tx in std::mem::take(&mut entry.completion_subscribers) {
                        let _ = tx.send(TerminalState::Failed { reason: reason.clone(), code: code.clone() });
                    }
                }
            }
        }
    }
}

// ============================================================================
// EventHandler Implementation
// ============================================================================

impl EventHandler for RequestTracker {
    fn name(&self) -> &'static str {
        "request_tracker"
    }

    fn handle_sync(&self, envelope: &Envelope<SystemEvent>) {
        // Update in-memory state synchronously (fast, no I/O)
        if let SystemEvent::Op(ref op) = envelope.event {
            self.handle_op_event(op.clone());
        }
    }

    fn is_async(&self) -> bool {
        self.redis_url.is_some()
    }

    fn handle_async(&self, envelope: Envelope<SystemEvent>) -> Option<BoxFuture<()>> {
        // Only spawn async work if Redis is configured
        let redis_url = self.redis_url.as_ref()?;

        let SystemEvent::Op(ref op) = envelope.event else {
            return None;
        };

        let request_id = match op {
            OpEvent::Queued { request_id } => *request_id,
            OpEvent::Assigned { request_id, .. } => *request_id,
            OpEvent::Submitted { request_id, .. } => *request_id,
            OpEvent::Finalized { request_id, .. } => *request_id,
            OpEvent::Failed { request_id, .. } => *request_id,
        };

        // Fire-and-forget Redis persistence
        let _redis_url = redis_url.clone();
        Some(Box::pin(async move {
            // Would persist to Redis here
            // Failures are logged but don't block
            tracing::trace!(%request_id, "Persisted to Redis");
        }))
    }
}
```

### Request Submission Flow

```rust
impl<T: IntoOperation> Request<Validated, T> {
    /// Submit the request for processing.
    ///
    /// Registers with RequestTracker and queues in the batcher.
    /// Both happen in-memory - nothing blocks the client.
    pub async fn submit(self, ctx: &AppContext) -> Result<Request<Pending, T>, SubmitError> {
        let kind = self.op.kind();
        let op_envelope = self.to_envelope();

        // 1. Register in tracker (in-memory, instant)
        ctx.tracker.register(self.id, kind);

        // 2. Queue in batcher (in-memory, instant)
        ctx.batcher.queue(self.id, op_envelope)?;

        // 3. Emit queued event (triggers tracker update via EventHandler)
        ctx.pipe.emit(SystemEvent::Op(OpEvent::Queued {
            request_id: self.id,
        }));

        Ok(Request {
            id: self.id,
            op: self.op,
            created_at: self.created_at,
            signer: self.signer,
            nonce: self.nonce,
            _state: PhantomData,
        })
    }
}

impl<T: IntoOperation> Request<Pending, T> {
    /// Wait for the request to reach a terminal state.
    pub async fn wait(
        &self,
        ctx: &AppContext,
        timeout: std::time::Duration,
    ) -> Result<TerminalState, WaitError> {
        let rx = ctx
            .tracker
            .subscribe_completion(self.id)
            .ok_or(WaitError::NotFound)?;

        tokio::time::timeout(timeout, rx)
            .await
            .map_err(|_| WaitError::Timeout)?
            .map_err(|_| WaitError::ChannelClosed)
    }
}
```

### AppContext

```rust
/// Shared application context.
#[derive(Clone)]
pub struct AppContext {
    pub tracker: Arc<RequestTracker>,
    pub batcher: Arc<OpsBatcher>,
    pub pipe: Arc<EventPipe>,
}
```

---

## Batch Types

### File: `services/gateway/src/batcher/batch.rs`

The `Batch` type mirrors `Request` - type-state pattern with self-describing status transitions.

```rust
//! Type-safe batch lifecycle with event emission on transitions.

use crate::batcher::types::OpEnvelopeInner;
use crate::events::{BatchEvent, EventPipe, OpEvent, SystemEvent};
use alloy::primitives::B256;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::Instant;
use uuid::Uuid;

// ============================================================================
// State Markers
// ============================================================================

mod sealed {
    pub trait Sealed {}
}

pub trait BatchState: sealed::Sealed + Send + Sync {}

/// Batch created, operations queued.
pub struct Queued;
impl sealed::Sealed for Queued {}
impl BatchState for Queued {}

/// Batch assigned an ID, ready for simulation.
pub struct Assigned {
    pub batch_id: Uuid,
}
impl sealed::Sealed for Assigned {}
impl BatchState for Assigned {}

/// Batch submitted to chain.
pub struct Submitted {
    pub batch_id: Uuid,
    pub tx_hash: B256,
    pub nonce: u64,
}
impl sealed::Sealed for Submitted {}
impl BatchState for Submitted {}

/// Batch finalized on chain.
pub struct Finalized {
    pub batch_id: Uuid,
    pub tx_hash: B256,
    pub block: u64,
    pub gas_used: u64,
}
impl sealed::Sealed for Finalized {}
impl BatchState for Finalized {}

/// Batch failed.
pub struct Failed {
    pub batch_id: Uuid,
    pub reason: String,
    pub retryable: bool,
}
impl sealed::Sealed for Failed {}
impl BatchState for Failed {}

// ============================================================================
// Request wrapper
// ============================================================================

/// A request within a batch.
#[derive(Clone)]
pub struct BatchRequest<T = OpEnvelopeInner> {
    pub id: Uuid,
    pub data: T,
    pub received_at: Instant,
}

impl<T> BatchRequest<T> {
    pub fn new(id: Uuid, data: T) -> Self {
        Self {
            id,
            data,
            received_at: Instant::now(),
        }
    }
}

// ============================================================================
// Batch
// ============================================================================

/// A batch of operations progressing through the submission pipeline.
///
/// State transitions automatically emit events to the pipe.
#[must_use = "batches should be transitioned to completion"]
pub struct Batch<S: BatchState, T = OpEnvelopeInner> {
    requests: Vec<BatchRequest<T>>,
    state: S,
    created_at: Instant,
    pipe: Arc<EventPipe>,
}

// --- Common methods (all states) ---
impl<S: BatchState, T> Batch<S, T> {
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    pub fn requests(&self) -> &[BatchRequest<T>] {
        &self.requests
    }

    pub fn request_ids(&self) -> Vec<Uuid> {
        self.requests.iter().map(|r| r.id).collect()
    }

    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Internal state transition helper.
    fn transition<S2: BatchState>(self, state: S2) -> Batch<S2, T> {
        Batch {
            requests: self.requests,
            state,
            created_at: self.created_at,
            pipe: self.pipe,
        }
    }
}

// --- Queued state ---
impl<T> Batch<Queued, T> {
    /// Create a new batch from requests.
    pub fn new(requests: Vec<BatchRequest<T>>, pipe: Arc<EventPipe>) -> Self {
        Self {
            requests,
            state: Queued,
            created_at: Instant::now(),
            pipe,
        }
    }

    /// Assign a batch ID and prepare for simulation.
    ///
    /// Emits:
    /// - `BatchEvent::Created` for the batch
    /// - `OpEvent::Assigned` for each operation
    pub fn assign(self, batch_id: Uuid, gas_budget: u64) -> Batch<Assigned, T> {
        let op_count = self.requests.len();

        // Emit batch created
        self.pipe.emit(SystemEvent::Batch(BatchEvent::Created {
            batch_id,
            op_count,
            gas_budget,
        }));

        // Emit assigned for each operation
        for req in &self.requests {
            self.pipe.emit(SystemEvent::Op(OpEvent::Assigned {
                request_id: req.id,
                batch_id,
            }));
        }

        self.transition(Assigned { batch_id })
    }
}

// --- Assigned state ---
impl<T> Batch<Assigned, T> {
    pub fn batch_id(&self) -> Uuid {
        self.state.batch_id
    }

    /// Filter requests, returning evicted ones with reasons.
    ///
    /// Emits `OpEvent::Failed` for each evicted operation.
    pub fn evict_many(&mut self, evictions: &HashMap<Uuid, String>) -> Vec<BatchRequest<T>> {
        let batch_id = self.state.batch_id;
        let (keep, evict): (Vec<_>, Vec<_>) = std::mem::take(&mut self.requests)
            .into_iter()
            .partition(|r| !evictions.contains_key(&r.id));

        self.requests = keep;

        // Emit failed event for each evicted request
        for req in &evict {
            if let Some(reason) = evictions.get(&req.id) {
                self.pipe.emit(SystemEvent::Op(OpEvent::Failed {
                    request_id: req.id,
                    reason: reason.clone(),
                    code: Some(GatewayErrorCode::BadRequest),
                }));
            }
        }

        // Emit simulated event
        self.pipe.emit(SystemEvent::Batch(BatchEvent::Simulated {
            batch_id,
            gas_used: 0, // Would be computed
            success_count: self.requests.len(),
            evicted_count: evict.len(),
        }));

        evict
    }

    /// Submit the batch to chain.
    ///
    /// Emits:
    /// - `BatchEvent::Submitted` for the batch
    /// - `OpEvent::Submitted` for each operation
    pub fn submit(self, tx_hash: B256, nonce: u64) -> Batch<Submitted, T> {
        let batch_id = self.state.batch_id;

        // Emit batch submitted
        self.pipe.emit(SystemEvent::Batch(BatchEvent::Submitted {
            batch_id,
            tx_hash,
            nonce,
        }));

        // Emit submitted for each operation
        for req in &self.requests {
            self.pipe.emit(SystemEvent::Op(OpEvent::Submitted {
                request_id: req.id,
                batch_id,
                tx_hash,
            }));
        }

        self.transition(Submitted {
            batch_id,
            tx_hash,
            nonce,
        })
    }

    /// Fail the entire batch without submitting.
    ///
    /// Emits:
    /// - `BatchEvent::Failed` for the batch
    /// - `OpEvent::Failed` for each operation
    pub fn fail(self, reason: &str, retryable: bool) -> Batch<Failed, T> {
        let batch_id = self.state.batch_id;

        // Emit batch failed
        self.pipe.emit(SystemEvent::Batch(BatchEvent::Failed {
            batch_id,
            reason: reason.to_string(),
            retryable,
        }));

        // Emit failed for each operation
        for req in &self.requests {
            self.pipe.emit(SystemEvent::Op(OpEvent::Failed {
                request_id: req.id,
                reason: reason.to_string(),
                code: None,
            }));
        }

        self.transition(Failed {
            batch_id,
            reason: reason.to_string(),
            retryable,
        })
    }
}

// --- Submitted state ---
impl<T> Batch<Submitted, T> {
    pub fn batch_id(&self) -> Uuid {
        self.state.batch_id
    }

    pub fn tx_hash(&self) -> B256 {
        self.state.tx_hash
    }

    pub fn nonce(&self) -> u64 {
        self.state.nonce
    }

    /// Finalize the batch after on-chain confirmation.
    ///
    /// Emits:
    /// - `BatchEvent::Finalized` for the batch
    /// - `OpEvent::Finalized` for each operation
    pub fn finalize(self, block: u64, gas_used: u64) -> Batch<Finalized, T> {
        let batch_id = self.state.batch_id;
        let tx_hash = self.state.tx_hash;

        // Emit batch finalized
        self.pipe.emit(SystemEvent::Batch(BatchEvent::Finalized {
            batch_id,
            tx_hash,
            block,
            gas_used,
        }));

        // Emit finalized for each operation
        for req in &self.requests {
            self.pipe.emit(SystemEvent::Op(OpEvent::Finalized {
                request_id: req.id,
                tx_hash,
                block,
            }));
        }

        self.transition(Finalized {
            batch_id,
            tx_hash,
            block,
            gas_used,
        })
    }

    /// Fail the batch after submission (e.g., revert).
    ///
    /// Emits:
    /// - `BatchEvent::Failed` for the batch
    /// - `OpEvent::Failed` for each operation
    pub fn fail(self, reason: &str) -> Batch<Failed, T> {
        let batch_id = self.state.batch_id;

        // Emit batch failed
        self.pipe.emit(SystemEvent::Batch(BatchEvent::Failed {
            batch_id,
            reason: reason.to_string(),
            retryable: false,
        }));

        // Emit failed for each operation
        for req in &self.requests {
            self.pipe.emit(SystemEvent::Op(OpEvent::Failed {
                request_id: req.id,
                reason: reason.to_string(),
                code: Some(GatewayErrorCode::TransactionReverted),
            }));
        }

        self.transition(Failed {
            batch_id,
            reason: reason.to_string(),
            retryable: false,
        })
    }
}

// --- Terminal states ---
impl<T> Batch<Finalized, T> {
    pub fn batch_id(&self) -> Uuid {
        self.state.batch_id
    }

    pub fn tx_hash(&self) -> B256 {
        self.state.tx_hash
    }

    pub fn block(&self) -> u64 {
        self.state.block
    }

    pub fn gas_used(&self) -> u64 {
        self.state.gas_used
    }
}

impl<T> Batch<Failed, T> {
    pub fn batch_id(&self) -> Uuid {
        self.state.batch_id
    }

    pub fn reason(&self) -> &str {
        &self.state.reason
    }

    pub fn retryable(&self) -> bool {
        self.state.retryable
    }

    /// Extract requests for potential retry.
    pub fn into_requests(self) -> Vec<BatchRequest<T>> {
        self.requests
    }
}
```

### Batch Status Subscription

```rust
/// Status of a batch in the pipeline.
#[derive(Clone, Debug)]
pub enum BatchStatus {
    Created { op_count: usize, gas_budget: u64 },
    Simulated { success_count: usize, evicted_count: usize },
    Submitted { tx_hash: B256, nonce: u64 },
    Finalized { tx_hash: B256, block: u64, gas_used: u64 },
    Failed { reason: String, retryable: bool },
}

impl<S: BatchState, T> Batch<S, T> {
    /// Subscribe to status updates for this batch.
    ///
    /// Returns a stream that yields status changes.
    pub fn subscribe(&self, batch_id: Uuid) -> impl Stream<Item = BatchStatus> + '_ {
        use tokio_stream::wrappers::BroadcastStream;
        use tokio_stream::StreamExt;

        BroadcastStream::new(self.pipe.subscribe())
            .filter_map(move |result| {
                let Ok(envelope) = result else {
                    return std::future::ready(None);
                };

                match envelope.event {
                    SystemEvent::Batch(BatchEvent::Created {
                        batch_id: id, op_count, gas_budget
                    }) if id == batch_id => {
                        std::future::ready(Some(BatchStatus::Created { op_count, gas_budget }))
                    }
                    SystemEvent::Batch(BatchEvent::Simulated {
                        batch_id: id, success_count, evicted_count, ..
                    }) if id == batch_id => {
                        std::future::ready(Some(BatchStatus::Simulated { success_count, evicted_count }))
                    }
                    SystemEvent::Batch(BatchEvent::Submitted {
                        batch_id: id, tx_hash, nonce
                    }) if id == batch_id => {
                        std::future::ready(Some(BatchStatus::Submitted { tx_hash, nonce }))
                    }
                    SystemEvent::Batch(BatchEvent::Finalized {
                        batch_id: id, tx_hash, block, gas_used
                    }) if id == batch_id => {
                        std::future::ready(Some(BatchStatus::Finalized { tx_hash, block, gas_used }))
                    }
                    SystemEvent::Batch(BatchEvent::Failed {
                        batch_id: id, reason, retryable
                    }) if id == batch_id => {
                        std::future::ready(Some(BatchStatus::Failed { reason, retryable }))
                    }
                    _ => std::future::ready(None),
                }
            })
    }
}
```

### Batch Pipeline Usage

```rust
/// Run a batch through the complete pipeline.
pub async fn run_batch<T: Send + Sync + Clone>(
    requests: Vec<BatchRequest<T>>,
    pipe: Arc<EventPipe>,
    chain: &ChainClient,
    gas_budget: u64,
) -> BatchResult<T> {
    let batch_id = Uuid::new_v4();

    // 1. Create and assign
    let batch = Batch::new(requests, pipe)
        .assign(batch_id, gas_budget);
    // Events emitted: BatchCreated, OpAssigned (for each)

    // 2. Simulate and evict failures
    let mut batch = batch;
    let evictions = chain.simulate(&batch).await;
    let evicted = batch.evict_many(&evictions);
    // Events emitted: OpFailed (for evicted), BatchSimulated

    if batch.is_empty() {
        let failed = batch.fail("all operations failed simulation", false);
        // Events emitted: BatchFailed, OpFailed (for remaining)
        return BatchResult::AllEvicted { evicted };
    }

    // 3. Submit to chain
    let tx_hash = match chain.submit(&batch).await {
        Ok(hash) => hash,
        Err(e) => {
            let failed = batch.fail(&e.to_string(), true);
            // Events emitted: BatchFailed, OpFailed (for all)
            return BatchResult::SubmitFailed {
                batch: failed,
                evicted
            };
        }
    };

    let batch = batch.submit(tx_hash, chain.nonce());
    // Events emitted: BatchSubmitted, OpSubmitted (for each)

    // 4. Wait for confirmation
    match chain.wait_for_receipt(tx_hash).await {
        Ok(receipt) => {
            let finalized = batch.finalize(receipt.block_number, receipt.gas_used);
            // Events emitted: BatchFinalized, OpFinalized (for each)
            BatchResult::Finalized {
                batch: finalized,
                evicted
            }
        }
        Err(e) => {
            let failed = batch.fail(&e.to_string());
            // Events emitted: BatchFailed, OpFailed (for all)
            BatchResult::ConfirmFailed {
                batch: failed,
                evicted
            }
        }
    }
}

/// Result of running a batch through the pipeline.
pub enum BatchResult<T> {
    Finalized {
        batch: Batch<Finalized, T>,
        evicted: Vec<BatchRequest<T>>,
    },
    AllEvicted {
        evicted: Vec<BatchRequest<T>>,
    },
    SubmitFailed {
        batch: Batch<Failed, T>,
        evicted: Vec<BatchRequest<T>>,
    },
    ConfirmFailed {
        batch: Batch<Failed, T>,
        evicted: Vec<BatchRequest<T>>,
    },
}
```

### Batch Lifecycle Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              Batch State Machine                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘

    Batch::new(requests, pipe)
              │
              ▼
    ┌─────────────────┐
    │  Batch<Queued>  │
    │                 │
    │  - requests     │
    │  - pipe         │
    └────────┬────────┘
             │
             │ .assign(batch_id, gas_budget)
             │
             │  EMITS: BatchEvent::Created
             │  EMITS: OpEvent::Assigned (for each request)
             │
             ▼
    ┌─────────────────────┐
    │  Batch<Assigned>    │
    │                     │
    │  - batch_id         │
    │  - requests         │
    │  + evict_many()     │
    │  + submit()         │
    │  + fail()           │
    └────────┬────────────┘
             │
             ├─────────────────────────────────────────────┐
             │                                             │
             │ .submit(tx_hash, nonce)                     │ .fail(reason)
             │                                             │
             │  EMITS: BatchEvent::Submitted               │  EMITS: BatchEvent::Failed
             │  EMITS: OpEvent::Submitted (for each)       │  EMITS: OpEvent::Failed (for each)
             │                                             │
             ▼                                             ▼
    ┌─────────────────────┐                    ┌─────────────────────┐
    │  Batch<Submitted>   │                    │   Batch<Failed>     │
    │                     │                    │                     │
    │  - batch_id         │                    │  - batch_id         │
    │  - tx_hash          │                    │  - reason           │
    │  - nonce            │                    │  - retryable        │
    │  + finalize()       │                    │  + into_requests()  │
    │  + fail()           │                    │                     │
    └────────┬────────────┘                    └─────────────────────┘
             │
             ├─────────────────────────────────────────────┐
             │                                             │
             │ .finalize(block, gas_used)                  │ .fail(reason)
             │                                             │
             │  EMITS: BatchEvent::Finalized               │  EMITS: BatchEvent::Failed
             │  EMITS: OpEvent::Finalized (for each)       │  EMITS: OpEvent::Failed (for each)
             │                                             │
             ▼                                             ▼
    ┌─────────────────────┐                    ┌─────────────────────┐
    │  Batch<Finalized>   │                    │   Batch<Failed>     │
    │                     │                    │                     │
    │  - batch_id         │                    │  (terminal)         │
    │  - tx_hash          │                    │                     │
    │  - block            │                    │                     │
    │  - gas_used         │                    │                     │
    │                     │                    │                     │
    │  (terminal)         │                    │                     │
    └─────────────────────┘                    └─────────────────────┘


    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                           Events Emitted Per Transition                      │
    └─────────────────────────────────────────────────────────────────────────────┘

    Queued → Assigned:
        BatchEvent::Created { batch_id, op_count, gas_budget }
        OpEvent::Assigned { request_id, batch_id }  × N

    Assigned.evict_many():
        OpEvent::Failed { request_id, reason }  × evicted
        BatchEvent::Simulated { success_count, evicted_count }

    Assigned → Submitted:
        BatchEvent::Submitted { batch_id, tx_hash, nonce }
        OpEvent::Submitted { request_id, batch_id, tx_hash }  × N

    Submitted → Finalized:
        BatchEvent::Finalized { batch_id, tx_hash, block, gas_used }
        OpEvent::Finalized { request_id, tx_hash, block }  × N

    Assigned → Failed  OR  Submitted → Failed:
        BatchEvent::Failed { batch_id, reason, retryable }
        OpEvent::Failed { request_id, reason }  × N
```

---

## OpsBatcher

### File: `services/gateway/src/batcher/mod.rs` (interface)

```rust
//! Operation batcher interface.

use crate::batcher::types::OpEnvelopeInner;
use crate::events::{EventPipe, OpEvent, SystemEvent};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Error when queuing an operation.
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("queue is full")]
    Full,
    #[error("invalid operation: {0}")]
    Invalid(String),
    #[error("service shutting down")]
    Shutdown,
}

/// Batcher configuration.
pub struct BatcherConfig {
    /// Maximum operations per batch.
    pub max_batch_size: usize,
    /// Maximum time to wait before batching.
    pub batch_window_ms: u64,
    /// Maximum queue depth (backpressure threshold).
    pub queue_capacity: usize,
}

impl Default for BatcherConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 100,
            batch_window_ms: 2000,
            queue_capacity: 4096,
        }
    }
}

/// The operations batcher.
///
/// Queues operations and batches them for on-chain submission.
pub struct OpsBatcher {
    queue: Mutex<Vec<OpEnvelopeInner>>,
    pipe: Arc<EventPipe>,
    config: BatcherConfig,
}

impl OpsBatcher {
    pub fn new(pipe: Arc<EventPipe>, config: BatcherConfig) -> Self {
        Self {
            queue: Mutex::new(Vec::new()),
            pipe,
            config,
        }
    }

    /// Queue an operation for batching.
    ///
    /// Returns immediately once the operation is in the in-memory queue.
    /// Emits OpEvent::Queued on success.
    pub async fn queue(&self, request_id: Uuid, op: OpEnvelopeInner) -> Result<(), QueueError> {
        let mut queue = self.queue.lock().await;

        if queue.len() >= self.config.queue_capacity {
            return Err(QueueError::Full);
        }

        queue.push(op);

        Ok(())
    }

    /// Run the batching loop.
    ///
    /// This is spawned as a background task.
    pub async fn run(self: Arc<Self>) {
        let mut interval = tokio::time::interval(
            std::time::Duration::from_millis(self.config.batch_window_ms)
        );

        loop {
            interval.tick().await;

            // Check if we have operations to batch
            let ops = {
                let mut queue = self.queue.lock().await;
                if queue.is_empty() {
                    continue;
                }
                std::mem::take(&mut *queue)
            };

            if let Err(e) = self.process_batch(ops).await {
                tracing::error!(error = %e, "Batch processing failed");
            }
        }
    }

    async fn process_batch(&self, ops: Vec<OpEnvelopeInner>) -> anyhow::Result<()> {
        let batch_id = Uuid::new_v4();
        let op_count = ops.len();

        // Emit batch created
        self.pipe.emit(SystemEvent::Batch(BatchEvent::Created {
            batch_id,
            op_count,
            gas_budget: 0, // Would be computed by gas policy
        }));

        // Emit assigned for each op
        for op in &ops {
            self.pipe.emit(SystemEvent::Op(OpEvent::Assigned {
                request_id: op.id,
                batch_id,
            }));
        }

        // ... simulation, submission, confirmation logic ...
        // Each step emits corresponding events

        Ok(())
    }
}
```

---

## EventPipe

### File: `services/gateway/src/events/mod.rs`

```rust
//! Event distribution system.

mod handlers;
mod types;

pub use handlers::{LoggingHandler, MetricsHandler};
pub use types::*;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Central event distribution.
///
/// Uses broadcast channel for non-blocking fan-out to all subscribers.
pub struct EventPipe {
    tx: broadcast::Sender<Envelope<SystemEvent>>,
    metrics: EventPipeMetrics,
}

struct EventPipeMetrics {
    events_emitted: AtomicU64,
}

impl EventPipe {
    /// Create a new event pipe with given capacity.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            tx,
            metrics: EventPipeMetrics {
                events_emitted: AtomicU64::new(0),
            },
        }
    }

    /// Emit an event to all subscribers.
    ///
    /// Never blocks. Returns number of receivers.
    pub fn emit(&self, event: SystemEvent) -> usize {
        self.metrics.events_emitted.fetch_add(1, Ordering::Relaxed);

        let envelope = Envelope {
            event,
            meta: EventMeta::now(),
        };

        self.tx.send(envelope).unwrap_or(0)
    }

    /// Subscribe to events.
    pub fn subscribe(&self) -> broadcast::Receiver<Envelope<SystemEvent>> {
        self.tx.subscribe()
    }

    /// Get total events emitted.
    pub fn events_emitted(&self) -> u64 {
        self.metrics.events_emitted.load(Ordering::Relaxed)
    }
}
```

### File: `services/gateway/src/events/types.rs`

```rust
//! Event type definitions.

use alloy::primitives::B256;
use tokio::time::Instant;
use uuid::Uuid;
use world_id_core::types::{GatewayErrorCode, GatewayRequestKind};

/// Event envelope with metadata.
#[derive(Clone, Debug)]
pub struct Envelope<E> {
    pub event: E,
    pub meta: EventMeta,
}

/// Event metadata.
#[derive(Clone, Debug)]
pub struct EventMeta {
    pub timestamp: Instant,
    pub correlation_id: Option<Uuid>,
}

impl EventMeta {
    pub fn now() -> Self {
        Self {
            timestamp: Instant::now(),
            correlation_id: None,
        }
    }

    pub fn with_correlation(mut self, id: Uuid) -> Self {
        self.correlation_id = Some(id);
        self
    }
}

/// Top-level event taxonomy.
#[derive(Clone, Debug)]
pub enum SystemEvent {
    Op(OpEvent),
    Batch(BatchEvent),
    Chain(ChainEvent),
    System(SystemMetricEvent),
}

/// Operation lifecycle events.
#[derive(Clone, Debug)]
pub enum OpEvent {
    /// Operation queued for batching.
    Queued { request_id: Uuid },
    /// Operation assigned to a batch.
    Assigned { request_id: Uuid, batch_id: Uuid },
    /// Batch containing operation submitted on-chain.
    Submitted {
        request_id: Uuid,
        batch_id: Uuid,
        tx_hash: B256,
    },
    /// Transaction finalized on-chain.
    Finalized {
        request_id: Uuid,
        tx_hash: B256,
        block: u64,
    },
    /// Operation failed.
    Failed {
        request_id: Uuid,
        reason: String,
        code: Option<GatewayErrorCode>,
    },
}

/// Batch lifecycle events.
#[derive(Clone, Debug)]
pub enum BatchEvent {
    /// Batch created from queued operations.
    Created {
        batch_id: Uuid,
        op_count: usize,
        gas_budget: u64,
    },
    /// Batch simulation completed.
    Simulated {
        batch_id: Uuid,
        gas_used: u64,
        success_count: usize,
        evicted_count: usize,
    },
    /// Batch submitted to chain.
    Submitted {
        batch_id: Uuid,
        tx_hash: B256,
        nonce: u64,
    },
    /// Batch finalized.
    Finalized {
        batch_id: Uuid,
        tx_hash: B256,
        block: u64,
        gas_used: u64,
    },
    /// Batch failed.
    Failed {
        batch_id: Uuid,
        reason: String,
        retryable: bool,
    },
}

/// Chain state events.
#[derive(Clone, Debug)]
pub enum ChainEvent {
    /// New block observed.
    NewBlock {
        number: u64,
        base_fee: u64,
        gas_limit: u64,
    },
}

/// System metric events.
#[derive(Clone, Debug)]
pub enum SystemMetricEvent {
    /// Queue depth snapshot.
    QueueDepth {
        pending: usize,
        in_flight: usize,
        capacity: usize,
    },
}
```

---

## Event Handlers

### File: `services/gateway/src/events/handlers.rs`

```rust
//! Built-in event handlers.

use super::types::*;
use std::future::Future;
use std::pin::Pin;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Event handler trait.
#[async_trait]
pub trait EventHandler: Send + Sync + 'static {
    /// Handler name for logging.
    fn name(&self) -> &'static str;

    /// Synchronous handler (must be fast, <1ms).
    fn handle_sync(&self, _envelope: &Envelope<SystemEvent>) {}

    /// Asynchronous handler for I/O work.
    fn handle_async(&self, _envelope: Envelope<SystemEvent>) -> Option<BoxFuture<()>> {
        None
    }

    /// Whether this handler uses async.
    fn is_async(&self) -> bool {
        false
    }
}

// ============================================================================
// MetricsHandler
// ============================================================================

/// Prometheus metrics handler.
pub struct MetricsHandler {
    // Would contain prometheus counters, histograms, etc.
}

impl MetricsHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl EventHandler for MetricsHandler {
    fn name(&self) -> &'static str {
        "metrics"
    }

    fn handle_sync(&self, envelope: &Envelope<SystemEvent>) {
        match &envelope.event {
            SystemEvent::Op(op) => match op {
                OpEvent::Queued { .. } => {
                    // metrics.ops_queued.inc()
                }
                OpEvent::Finalized { .. } => {
                    // metrics.ops_finalized.inc()
                }
                OpEvent::Failed { .. } => {
                    // metrics.ops_failed.inc()
                }
                _ => {}
            },
            SystemEvent::Batch(batch) => match batch {
                BatchEvent::Created { op_count, .. } => {
                    // metrics.batch_size.observe(*op_count as f64)
                }
                BatchEvent::Finalized { .. } => {
                    // metrics.batches_finalized.inc()
                }
                _ => {}
            },
            _ => {}
        }
    }
}

// ============================================================================
// LoggingHandler
// ============================================================================

/// Structured logging handler.
pub struct LoggingHandler;

impl EventHandler for LoggingHandler {
    fn name(&self) -> &'static str {
        "logging"
    }

    fn handle_sync(&self, envelope: &Envelope<SystemEvent>) {
        match &envelope.event {
            SystemEvent::Op(op) => match op {
                OpEvent::Queued { request_id } => {
                    tracing::debug!(%request_id, "op.queued");
                }
                OpEvent::Assigned { request_id, batch_id } => {
                    tracing::debug!(%request_id, %batch_id, "op.assigned");
                }
                OpEvent::Submitted { request_id, tx_hash, .. } => {
                    tracing::info!(%request_id, %tx_hash, "op.submitted");
                }
                OpEvent::Finalized { request_id, tx_hash, block } => {
                    tracing::info!(%request_id, %tx_hash, block, "op.finalized");
                }
                OpEvent::Failed { request_id, reason, code } => {
                    tracing::warn!(%request_id, %reason, ?code, "op.failed");
                }
            },
            SystemEvent::Batch(batch) => match batch {
                BatchEvent::Created { batch_id, op_count, gas_budget } => {
                    tracing::debug!(%batch_id, op_count, gas_budget, "batch.created");
                }
                BatchEvent::Submitted { batch_id, tx_hash, nonce } => {
                    tracing::info!(%batch_id, %tx_hash, nonce, "batch.submitted");
                }
                BatchEvent::Finalized { batch_id, tx_hash, block, gas_used } => {
                    tracing::info!(%batch_id, %tx_hash, block, gas_used, "batch.finalized");
                }
                BatchEvent::Failed { batch_id, reason, retryable } => {
                    tracing::warn!(%batch_id, %reason, retryable, "batch.failed");
                }
                _ => {}
            },
            _ => {}
        }
    }
}

// Note: StatusSyncHandler is no longer needed.
// RequestTracker now implements EventHandler directly and is registered
// on the EventPipe like any other handler.
```

---

## Application Bootstrap

### File: `services/gateway/src/main.rs`

```rust
//! World ID Gateway entry point.

use std::sync::Arc;
use tokio::net::TcpListener;

mod batcher;
mod config;
mod events;
mod request;
mod routes;
mod tracker;
mod types;

use batcher::{BatcherConfig, OpsBatcher};
use config::Config;
use events::{EventPipe, EventProcessor, LoggingHandler, MetricsHandler};
use tracker::RequestTracker;
use types::AppContext;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load configuration
    let config = Config::from_env()?;

    // ========================================================================
    // Initialize Components
    // ========================================================================

    // 1. RequestTracker (in-memory state, optional Redis persistence)
    let tracker = Arc::new(RequestTracker::new(config.redis_url.clone()));

    // 2. EventPipe (event distribution)
    let pipe = Arc::new(EventPipe::new(10_000));

    // 3. OpsBatcher (operation batching)
    let batcher = Arc::new(OpsBatcher::new(
        pipe.clone(),
        BatcherConfig::default(),
    ));

    // 4. Application Context (shared state)
    let ctx = AppContext {
        tracker: tracker.clone(),
        batcher: batcher.clone(),
        pipe: pipe.clone(),
    };

    // ========================================================================
    // Event Processor with Handlers
    // ========================================================================

    let mut processor = EventProcessor::new(pipe.clone());
    processor.register(MetricsHandler::new());
    processor.register(LoggingHandler);
    // RequestTracker IS an EventHandler - register it directly
    processor.register_arc(tracker.clone());

    // ========================================================================
    // Spawn Background Tasks
    // ========================================================================

    // Batcher processing loop
    let batcher_handle = tokio::spawn(batcher.clone().run());

    // Event processor loop
    let processor_handle = tokio::spawn(processor.run());

    // ========================================================================
    // HTTP Router
    // ========================================================================

    use axum::{
        middleware,
        routing::{delete, get, post},
        Router,
    };
    use routes::middleware::request_id_middleware;

    let app = Router::new()
        // State-changing operations
        .route("/v1/accounts", post(routes::create_account::create_account))
        .route("/v1/authenticators/insert", post(routes::insert_authenticator::insert_authenticator))
        .route("/v1/authenticators/update", post(routes::update_authenticator::update_authenticator))
        .route("/v1/authenticators/remove", delete(routes::remove_authenticator::remove_authenticator))
        .route("/v1/accounts/recover", post(routes::recover_account::recover_account))
        // Status query
        .route("/v1/requests/:id", get(routes::request_status::request_status))
        // Health
        .route("/health", get(routes::health::health))
        // Middleware
        .layer(middleware::from_fn(request_id_middleware))
        // State
        .with_state(types::AppState { ctx });

    // ========================================================================
    // Run Server
    // ========================================================================

    let listener = TcpListener::bind(&config.listen_addr).await?;
    tracing::info!(addr = %config.listen_addr, "Gateway listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Cleanup
    batcher_handle.abort();
    processor_handle.abort();

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.ok();
    tracing::info!("Shutdown signal received");
}
```

### File: `services/gateway/src/types.rs`

```rust
//! Shared application types.

use crate::batcher::OpsBatcher;
use crate::events::EventPipe;
use crate::tracker::RequestTracker;
use std::sync::Arc;

/// Shared application context.
#[derive(Clone)]
pub struct AppContext {
    pub tracker: Arc<RequestTracker>,
    pub batcher: Arc<OpsBatcher>,
    pub pipe: Arc<EventPipe>,
}

/// Axum state wrapper.
#[derive(Clone)]
pub struct AppState {
    pub ctx: AppContext,
}
```

---

## Data Flow

### Complete Request Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│  1. HTTP Request                                                                     │
│     POST /v1/accounts { ... }                                                        │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│  2. Middleware: request_id_middleware                                                │
│     - Generate Uuid                                                                  │
│     - Attach to request extensions                                                   │
│     - Add X-Request-Id header to response                                            │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│  3. Handler: create_account                                                          │
│                                                                                      │
│     payload.into_request(request_id)?                                               │
│         - CreateAccountRequest -> CreateAccountOp                                    │
│         - Validation (authenticator count, pubkey count match)                      │
│         - Returns Request<Validated, CreateAccountOp>                               │
│                                                                                      │
│     .submit(&ctx).await?                                                            │
│         ┌─────────────────────────────────────────────────────────────────────┐     │
│         │  tokio::try_join!(                                                   │     │
│         │      tracker.create(request_id, CreateAccount),  // Redis SET       │     │
│         │      batcher.queue(request_id, op_envelope),     // Memory push     │     │
│         │  )                                                                   │     │
│         │                                                                      │     │
│         │  BOTH must succeed before returning to client                        │     │
│         └─────────────────────────────────────────────────────────────────────┘     │
│         - Returns Request<Pending, CreateAccountOp>                                 │
│                                                                                      │
│     .into_response()                                                                │
│         - Returns GatewayStatusResponse { request_id, kind, status: Queued }        │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│  4. HTTP Response (immediate)                                                        │
│     200 OK                                                                           │
│     X-Request-Id: 550e8400-e29b-41d4-a716-446655440000                              │
│     {                                                                                │
│       "request_id": "550e8400-e29b-41d4-a716-446655440000",                         │
│       "kind": "create_account",                                                      │
│       "status": { "state": "queued" }                                               │
│     }                                                                                │
└─────────────────────────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════════════
                              BACKGROUND PROCESSING
═══════════════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────────────┐
│  5. OpsBatcher: Batch Timer Fires                                                    │
│                                                                                      │
│     - Drain queue into batch                                                         │
│     - Emit: BatchEvent::Created { batch_id, op_count, gas_budget }                  │
│     - Emit: OpEvent::Assigned { request_id, batch_id } (for each op)                │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│  6. OpsBatcher: Simulation                                                           │
│                                                                                      │
│     - Simulate batch against chain                                                   │
│     - Evict failed operations                                                        │
│     - Emit: BatchEvent::Simulated { success_count, evicted_count }                  │
│     - Emit: OpEvent::Failed { request_id, reason } (for evicted ops)                │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│  7. OpsBatcher: Chain Submission                                                     │
│                                                                                      │
│     - Build and sign transaction                                                     │
│     - Submit to mempool                                                              │
│     - Emit: BatchEvent::Submitted { batch_id, tx_hash, nonce }                      │
│     - Emit: OpEvent::Submitted { request_id, batch_id, tx_hash } (for each op)      │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│  8. OpsBatcher: Confirmation                                                         │
│                                                                                      │
│     - Wait for transaction receipt                                                   │
│     - Emit: BatchEvent::Finalized { batch_id, tx_hash, block, gas_used }            │
│     - Emit: OpEvent::Finalized { request_id, tx_hash, block } (for each op)         │
│                                                                                      │
│     OR on failure:                                                                   │
│     - Emit: BatchEvent::Failed { batch_id, reason, retryable }                      │
│     - Emit: OpEvent::Failed { request_id, reason, code } (for each op)              │
└─────────────────────────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════════════
                              EVENT HANDLERS (parallel)
═══════════════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────────────┐
│  MetricsHandler (sync)                                                               │
│                                                                                      │
│     OpEvent::Queued    → ops_queued.inc()                                           │
│     OpEvent::Finalized → ops_finalized.inc()                                        │
│     OpEvent::Failed    → ops_failed.inc()                                           │
│     BatchEvent::Created → batch_size.observe(op_count)                              │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│  LoggingHandler (sync)                                                               │
│                                                                                      │
│     OpEvent::Queued    → tracing::debug!(request_id, "op.queued")                   │
│     OpEvent::Finalized → tracing::info!(request_id, tx_hash, block, "op.finalized") │
│     OpEvent::Failed    → tracing::warn!(request_id, reason, "op.failed")            │
└─────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│  RequestTracker (EventHandler - sync state update, async Redis persistence)          │
│                                                                                      │
│     OpEvent::Queued    → state.update(Queued), spawn persist_to_redis()             │
│     OpEvent::Assigned  → state.update(Batching), spawn persist_to_redis()           │
│     OpEvent::Submitted → state.update(Submitted), spawn persist_to_redis()          │
│     OpEvent::Finalized → state.update(Finalized), notify_subscribers()              │
│     OpEvent::Failed    → state.update(Failed), notify_subscribers()                 │
└─────────────────────────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════════════
                              CLIENT POLLING
═══════════════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────────────┐
│  GET /v1/requests/550e8400-e29b-41d4-a716-446655440000                               │
│                                                                                      │
│  → tracker.get(request_id)                                                          │
│  → In-memory HashMap lookup (no Redis read - instant)                               │
│  → Return current status                                                             │
│                                                                                      │
│  Response (after finalization):                                                      │
│  {                                                                                   │
│    "request_id": "550e8400-e29b-41d4-a716-446655440000",                            │
│    "kind": "create_account",                                                         │
│    "status": {                                                                       │
│      "state": "finalized",                                                           │
│      "tx_hash": "0x1234..."                                                         │
│    }                                                                                 │
│  }                                                                                   │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Error Handling

### Validation Errors (synchronous, before queuing)

| Error | HTTP Status | Response |
|-------|-------------|----------|
| Empty authenticators | 400 | `{ "code": "bad_request", "message": "empty authenticator list" }` |
| Too many authenticators | 400 | `{ "code": "bad_request", "message": "too many authenticators: max 8, got 10" }` |
| Invalid signature | 400 | `{ "code": "bad_request", "message": "invalid signature length" }` |

### Submission Errors (during parallel submission)

| Error | HTTP Status | Response |
|-------|-------------|----------|
| Queue full | 503 | `{ "code": "batcher_unavailable", "message": "Operation queue is full, try again later" }` |
| Redis error | 500 | `{ "code": "internal_server_error", "message": "Internal server error. Please try again." }` |
| Service shutdown | 503 | `{ "code": "batcher_unavailable", "message": "Batcher service is unavailable. Please try again." }` |

### Processing Errors (asynchronous, tracked via status)

| Error | Status | State |
|-------|--------|-------|
| Simulation reverted | Failed | `{ "state": "failed", "error": "simulation reverted: AuthenticatorAlreadyExists", "error_code": "authenticator_already_exists" }` |
| Transaction reverted | Failed | `{ "state": "failed", "error": "transaction reverted", "error_code": "transaction_reverted" }` |
| Confirmation timeout | Failed | `{ "state": "failed", "error": "confirmation timeout", "error_code": "confirmation_error" }` |

---

## Summary

| Component | Responsibility | Blocking? |
|-----------|---------------|-----------|
| `Request<S, T>` | Type-safe request lifecycle | N/A (data type) |
| `IntoRequest` | Payload → Request conversion | No |
| `request_id_middleware` | Generate canonical request ID | No |
| `RequestTracker` | In-memory state, status queries, EventHandler | Never (in-memory) |
| `OpsBatcher` | In-memory queue, batch processing | Yes (memory push) |
| `EventPipe` | Broadcast event distribution | Never |
| `MetricsHandler` | Prometheus metrics | Never (sync, fast) |
| `LoggingHandler` | Structured logging | Never (sync, fast) |

**Client-facing blocking points:**

1. `tracker.register()` - In-memory HashMap insert (instant)
2. `batcher.queue()` - In-memory priority queue push (instant)

Both are synchronous in-memory operations. Redis persistence happens asynchronously via EventHandler.
