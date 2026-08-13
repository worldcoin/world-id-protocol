use alloy::primitives::{Address, B256, Bytes, TxHash, U256};
use uuid::Uuid;
use world_id_primitives::api_types::CreateAccountRequest;

/// Unix timestamp in seconds.
pub(crate) type Timestamp = u64;

/// Internal request identity.
///
/// The `gw_` prefix used by HTTP responses is presentation only and is not
/// stored as part of this UUID.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RequestId(pub(crate) Uuid);

/// Identity of one immutable sealed batch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct BatchId(pub(crate) Uuid);

/// Resource whose conflicting requests must not execute concurrently.
///
/// A lock is acquired when a request is accepted and released only when that
/// request reaches a terminal state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ResourceLock {
    /// Authenticator address reserved by an account-creation request.
    Authenticator(Address),
    /// Account leaf index reserved by an account-operation request.
    Account(u64),
}

/// Complete validated request data needed to rebuild a batch after restart.
#[derive(Debug)]
pub(crate) enum RequestPayload {
    /// Original account-creation request used to build `createManyAccounts`.
    CreateAccount(CreateAccountRequest),
    /// Encoded registry call used as one item in an operations multicall.
    Operation(Bytes),
}

/// Durable lifecycle of an accepted gateway request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RequestState {
    /// Persisted and available in its ordered batching queue.
    Queued,
    /// Sealed into the identified immutable batch.
    Batched(BatchId),
    /// Successfully executed by a transaction that reached safe confirmation.
    Finalized(TxHash),
    /// Permanently rejected or included in a safely resolved failed batch.
    Failed(String),
}

/// Input for atomically accepting a request.
///
/// [`crate::storage::RequestRepository::accept`] supplies the initial `Queued`
/// state and sets `updated_at` from `accepted_at`.
#[derive(Debug)]
pub(crate) struct NewRequest {
    /// Caller-generated internal request identity.
    pub(crate) id: RequestId,
    /// Complete validated payload to persist.
    pub(crate) payload: RequestPayload,
    /// Time at which gateway admission accepted the request.
    pub(crate) accepted_at: Timestamp,
    /// Resources to acquire in the same atomic operation as persistence.
    pub(crate) resource_locks: Vec<ResourceLock>,
}

/// Source-of-truth record stored at `gateway:request:<request-id>`.
#[derive(Debug)]
pub(crate) struct StoredRequest {
    /// Stable internal request identity.
    pub(crate) id: RequestId,
    /// Complete payload retained for restart recovery.
    pub(crate) payload: RequestPayload,
    /// Current durable lifecycle state.
    pub(crate) state: RequestState,
    /// Original admission time, which never changes.
    pub(crate) accepted_at: Timestamp,
    /// Time of the latest durable state transition.
    pub(crate) updated_at: Timestamp,
    /// Locks owned by this request until it reaches a terminal state.
    pub(crate) resource_locks: Vec<ResourceLock>,
}

/// Transaction construction strategy for a batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BatchKind {
    /// Direct `WorldIDRegistry.createManyAccounts` transaction.
    CreateAccounts,
    /// `Multicall3.aggregate3` transaction containing account operations.
    Operations,
}

/// Immutable transaction fields produced when a batch is sealed.
///
/// The submitter adds the assigned wallet, nonce, chain ID, and EIP-1559 fee
/// fields before signing the single transaction for this batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransactionIntent {
    /// Registry or Multicall3 destination.
    pub(crate) to: Address,
    /// Complete encoded call data.
    pub(crate) calldata: Bytes,
    /// Native token value sent with the call.
    pub(crate) value: U256,
    /// Fixed execution gas limit used by the signed transaction.
    pub(crate) gas_limit: u64,
}

/// Input for atomically sealing queued requests into a batch.
#[derive(Debug)]
pub(crate) struct NewBatch {
    /// Caller-generated batch identity.
    pub(crate) id: BatchId,
    /// Construction strategy shared by every member request.
    pub(crate) kind: BatchKind,
    /// Ordered request membership, immutable after sealing.
    pub(crate) request_ids: Vec<RequestId>,
    /// Transaction fields, immutable after sealing.
    pub(crate) transaction: TransactionIntent,
    /// Time used to order the batch in the ready queue.
    pub(crate) created_at: Timestamp,
}

/// Durable submission lifecycle of a sealed batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BatchState {
    /// Published to the ready queue with no assigned wallet.
    Ready,
    /// Durably assigned to a wallet, before its nonce is persisted.
    Assigned {
        /// Wallet reserved until finalization, safe revert, or receipt timeout.
        wallet: Address,
    },
    /// The batch's single signed transaction has been durably prepared.
    Pending {
        /// Wallet that signed the transaction.
        wallet: Address,
        /// Nonce encoded in the signed transaction.
        nonce: u64,
    },
    /// The transaction has a receipt but has not reached safe confirmation.
    Included {
        /// Hash of the included batch transaction.
        tx_hash: TxHash,
        /// Block hash used to detect a reorganization.
        block_hash: B256,
        /// Block number compared with the chain's safe head.
        block_number: u64,
    },
    /// Successful batch transaction reached safe confirmation.
    Finalized(TxHash),
    /// Transaction safely reverted, exceeded its receipt timeout, or failed before broadcast.
    Failed(String),
}

/// Source-of-truth record stored at `gateway:batch:<batch-id>`.
///
/// `request_ids` and `transaction` become immutable when the record is created.
/// State, the optional prepared submission, and `updated_at` change as
/// submission progresses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Batch {
    /// Stable batch identity.
    pub(crate) id: BatchId,
    /// Transaction construction strategy.
    pub(crate) kind: BatchKind,
    /// Ordered immutable request membership.
    pub(crate) request_ids: Vec<RequestId>,
    /// Immutable fields used to build the signed transaction.
    pub(crate) transaction: TransactionIntent,
    /// Current durable submission state.
    pub(crate) state: BatchState,
    /// Single signed transaction, present after preparation.
    pub(crate) submission: Option<PreparedSubmission>,
    /// Time at which queued requests were sealed into this batch.
    pub(crate) created_at: Timestamp,
    /// Time of the latest durable state or submission transition.
    pub(crate) updated_at: Timestamp,
}

/// The batch's single signed transaction, persisted before broadcast.
///
/// Signed bytes form the submission write-ahead log. They allow another worker
/// to query the locally computed hash and rebroadcast the exact transaction
/// after an ambiguous RPC response or process crash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedSubmission {
    /// Wallet nonce encoded in `signed_transaction`.
    pub(crate) nonce: u64,
    /// Hash computed locally from `signed_transaction`.
    pub(crate) tx_hash: TxHash,
    /// Exact EIP-2718 encoded transaction bytes sent to the provider.
    pub(crate) signed_transaction: Bytes,
    /// EIP-1559 maximum total fee per gas.
    pub(crate) max_fee_per_gas: U256,
    /// EIP-1559 maximum priority fee per gas.
    pub(crate) max_priority_fee_per_gas: U256,
    /// Time at which the write-ahead record committed the transaction for broadcast.
    ///
    /// The configured receipt timeout starts here. The submitter must broadcast
    /// immediately after confirming this durable write; recovery rebroadcasts
    /// the same bytes when the original RPC result is unknown.
    pub(crate) submitted_at: Timestamp,
    /// Time the RPC broadcast completed, or `None` when its result is unknown.
    pub(crate) broadcast_at: Option<Timestamp>,
}

/// Consistent snapshot of a durable wallet-to-batch assignment.
///
/// Wallet credentials and assignment eligibility remain in local gateway
/// configuration and are deliberately absent from this persisted model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Assignment {
    /// Locally configured address assigned to the batch.
    pub(crate) wallet: Address,
    /// Durably assigned batch and its prepared submission, when present.
    pub(crate) batch: Batch,
}
