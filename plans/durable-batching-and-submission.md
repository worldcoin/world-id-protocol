# Durable gateway batching and transaction submission

## Status

Design draft. No implementation has started.

## Goal

Make request batching and on-chain submission durable across gateway restarts and safe across multiple gateway replicas.

Every gateway replica runs the same roles:

1. Accept and validate API requests.
2. Build create-account and operation batches.
3. Submit ready batches using any configured gateway KMS wallet.
4. Reconcile abandoned work after another replica crashes.

Redis is the shared source of truth. Tokio tasks perform work from Redis state, but do not own durable state.

## Decisions

### Keep two batch types

The gateway builds two kinds of transactions:

- `CreateAccounts`: one direct `WorldIDRegistry.createManyAccounts(...)` call.
- `Operations`: one `Multicall3.aggregate3(...)` call containing encoded account operations.

They remain separate because:

1. `createManyAccounts` performs an optimized bulk tree insertion and records one root.
2. Calls routed through Multicall3 see `msg.sender == Multicall3`, not the KMS wallet. Registration-fee collection in `createManyAccounts` would therefore charge Multicall3 and fail when fees are enabled.
3. Mixing creates with operations increases the failure domain. One stale operation would revert all included creations when `allowFailure` is false.
4. The two transaction forms have different sizing and gas characteristics.

Batch type is relevant while building a transaction. The submitter receives a uniform, immutable transaction intent and does not need batch-specific behavior.

### Persist requests and complete payloads

The API must persist enough data to rebuild a request after a gateway restart. The current design stores request status in Redis but leaves full payloads in process-local Tokio channels.

A stored request should contain:

```rust
struct StoredRequest {
    id: RequestId,
    payload: RequestPayload,
    state: RequestState,
    accepted_at: Timestamp,
    updated_at: Timestamp,
    resource_locks: Vec<ResourceLock>,
}

enum RequestPayload {
    CreateAccount(CreateAccountRequest),
    Operation(Bytes),
}
```

`RequestId` should be a typed UUID newtype. The `gw_` prefix belongs to HTTP serialization, not internal identity.

### Use Redis queues as accumulating batches

Do not maintain a shared mutable "open batch" record. Persist requests in two ordered Redis queues:

```text
gateway:requests:create
gateway:requests:ops
```

Use sorted sets ordered by acceptance sequence or timestamp. The queue itself accumulates work. When policy decides to send, a Lua script atomically seals selected requests into an immutable batch.

Atomic sealing must:

1. Select up to the target number of oldest queued requests.
2. Verify each request is still queued.
3. Create a batch record.
4. Change every selected request to `Batched(batch_id)`.
5. Remove selected requests from the request queue.
6. Add the batch to the ready-batch queue.

Multiple replicas may attempt to seal batches concurrently. Redis atomicity must ensure each request belongs to at most one batch.

### Persist immutable batches

```rust
struct Batch {
    id: BatchId,
    kind: BatchKind,
    request_ids: Vec<RequestId>,
    transaction: TransactionIntent,
    state: BatchState,
    created_at: Timestamp,
    updated_at: Timestamp,
}

enum BatchKind {
    CreateAccounts,
    Operations,
}

struct TransactionIntent {
    to: Address,
    calldata: Bytes,
    value: U256,
    gas_limit: u64,
}
```

Once sealed, `request_ids` and `transaction` are immutable. Fee replacements reuse the same wallet, nonce, destination, calldata, value, and gas limit.

Both batch builders publish to one submission queue:

```text
gateway:batches:ready
```

### Every replica can use every configured KMS wallet

The wallet pool is service configuration, not Redis configuration. Each gateway replica receives the same comma-separated list of KMS key IDs through `AWS_KMS_KEY_IDS`. KMS permission provisioning is outside the scope of this design.

```rust
struct WalletConfig {
    kms_key_id: KmsKeyId,
    address: Address,
}
```

Redis stores runtime state for configured wallet addresses only:

```rust
struct WalletRuntimeState {
    state: WalletState,
}

enum WalletState {
    Idle,
    Assigned { batch_id: BatchId },
    Quarantined { reason: String },
}
```

At startup, a replica loads `AWS_KMS_KEY_IDS`, resolves each key's address, and reconciles the configured set with Redis. Redis must not introduce a wallet that is absent from service configuration. Replicas compare a deterministic fingerprint of the configured key IDs so mismatched configurations fail readiness.

Configuration changes require care:

- Adding a wallet is safe after its chain nonce is reconciled and Redis initializes it as idle.
- Removing an idle wallet is safe.
- A wallet with an assigned or unresolved transaction must remain configured until that nonce reaches the required confirmation level or is manually reconciled.
- Replicas with different wallet configurations must fail readiness rather than operate on inconsistent pools.

A wallet handles at most one unresolved transaction at a time. This avoids nonce pipelines and nonce collisions while gaining throughput from multiple wallets.

### Separate wallet assignment from worker lease

Wallet assignment is durable:

```text
wallet A is assigned to batch B until B's nonce is resolved
```

A worker lease is temporary:

```text
replica R is currently responsible for progressing batch B
```

If a replica crashes, its lease expires but the wallet remains assigned. Another replica claims the lease and resumes the same batch and nonce.

A Redis lease must never make a wallet idle when it expires.

## State machines

### Request

```text
Queued -> Batched(batch_id) -> Finalized(tx_hash)
                            -> Failed(reason)
```

Resource locks are acquired when the request is accepted and released only when its request reaches a terminal state.

### Batch

```text
Ready
  -> Assigned(wallet)
  -> Pending(wallet, nonce, attempts)
  -> Included(tx_hash, block)
  -> Finalized(tx_hash)
```

Failure paths:

```text
Ready -> Failed(pre-broadcast failure)
Pending -> Included -> Failed(reverted)
Pending -> Stalled(replacement policy exhausted)
Pending -> Cancelling -> Failed(cancel transaction finalized)
```

A pending batch cannot be declared safely failed merely because it disappeared from one node's mempool or exceeded a retry limit. Its original transaction may still be accepted later.

### Wallet

```text
Idle -> Assigned -> Idle
                -> Quarantined
```

A wallet returns to `Idle` only after its assigned nonce is resolved by:

- A successful transaction reaching the required confirmation level.
- A reverted transaction reaching the required confirmation level.
- A cancellation transaction using the same nonce reaching the required confirmation level.

## Submitter behavior

The submitter is a Tokio task inside every gateway replica. It operates only through persisted Redis state.

### Assignment

A Lua script atomically:

1. Selects one ready batch.
2. Selects one idle wallet.
3. Assigns the batch to the wallet.
4. Removes the batch and wallet from their available indexes.
5. Creates the initial worker lease.

### Initial submission

For a newly assigned batch:

1. Fetch both `eth_getTransactionCount(wallet, "latest")` and `eth_getTransactionCount(wallet, "pending")`.
2. Reconcile both chain nonces with persisted wallet state. Do not broadcast if they reveal unexplained wallet activity.
3. Persist the selected pending nonce on the batch.
4. Fill gas limit and EIP-1559 fee fields.
5. Sign with the assigned KMS key.
6. Compute the transaction hash locally from the signed bytes.
7. Persist the signed transaction, local hash, and attempt metadata as `Prepared`.
8. Read the persisted attempt back or otherwise require a confirmed Redis write.
9. Broadcast the exact signed bytes with `eth_sendRawTransaction`.
10. Mark the attempt `Broadcast` after the RPC call. Failure to persist this final transition is recoverable because the signed bytes and hash were stored before broadcast.

Fetching `pending` nonce happens only for initial assignment. Every replacement uses the persisted nonce.

### Attempt history

```rust
struct SubmissionAttempt {
    tx_hash: TxHash,
    signed_transaction: Bytes,
    max_fee_per_gas: U256,
    max_priority_fee_per_gas: U256,
    broadcast_at: Timestamp,
}
```

Persisting signed bytes before broadcast is the submission write-ahead log. It closes the dangerous send-before-save gap:

- If persisting `Prepared` fails, do not broadcast.
- If the Redis response is ambiguous, reconnect and read the attempt by ID before deciding whether to broadcast.
- If the process crashes during or after the RPC call, another worker queries the locally known hash and may rebroadcast the exact signed bytes. Rebroadcast is idempotent at the transaction level.
- An RPC response hash must equal the locally computed hash. A mismatch is a fatal provider-integrity error and quarantines the wallet.

The post-broadcast Redis update is advisory for progress, not required to rediscover the transaction.

### Replacement policy

A configurable policy determines when and how fees are increased. Its values are supplied through service configuration:

```rust
struct ReplacementPolicy {
    check_interval: Duration,
    replace_after: Duration,
    fee_multiplier_bps: u64,
    max_attempts: u32,
    max_total_age: Duration,
    max_fee_cap: U256,
}
```

A replacement changes fee fields only. "Gas bump" means increasing `max_fee_per_gas` and `max_priority_fee_per_gas`, not increasing the gas limit.

When the policy is exhausted, mark the batch `Stalled` and quarantine the wallet. Continue checking known attempts. Do not release the wallet immediately.

### Cancellation after replacement exhaustion

A pending transaction cannot be declared failed safely just because the replacement policy ended. A copy may still exist in another node's mempool and execute later.

A cancellation transaction is a new transaction from the same wallet using the same nonce, usually a zero-value transfer to the wallet itself, with a fee high enough to replace the batch transaction. Whichever transaction is included first consumes the nonce:

- If a batch attempt is included, process its success or revert normally.
- If the cancellation is included and reaches `safe`, mark the batch failed and release the wallet.
- If neither is included, keep the batch stalled and the wallet quarantined.

Cancellation starts automatically when the configured batch replacement policy is exhausted. The submitter persists and broadcasts a same-nonce self-transfer, then tracks the cancellation and every prior batch attempt concurrently. If a prior batch attempt wins the race, process its success or revert normally. If the cancellation reaches `safe`, mark the batch failed and release the wallet.

Cancellation has its own configurable replacement interval, attempt limit, total age, and fee cap. If its policy is also exhausted without resolving the nonce, keep the batch `Stalled` and the wallet quarantined for operator reconciliation.

### Confirmation

Receipt inclusion is insufficient to release a wallet because the containing block can be reorganized.

The submitter must:

1. Find a receipt for any known attempt.
2. Record its block hash and block number.
3. Verify the receipt remains canonical.
4. Wait until the receipt block reaches the configured confirmation level.
5. Atomically finalize the batch, all member requests, resource locks, and wallet assignment.

The confirmation level is `safe`. The submitter releases a wallet only after the receipt's canonical block is at or below the chain's safe head. Support for a configurable `finalized` mode may be added later if required.

## RPC checks and reconciliation

RPC state is a safety check and reconciliation source, not the primary submission queue. A node cannot reliably answer "does this wallet have any transaction in flight?" with enough detail to replace Redis:

- `eth_getTransactionCount(address, "pending") > eth_getTransactionCount(address, "latest")` indicates pending nonce consumption visible to that node, but does not identify the transaction or its intended batch.
- Mempool visibility differs between RPC nodes. A transaction sent through one provider may be absent from another provider's pending view.
- `txpool_*` methods are non-standard and commonly unavailable on hosted RPC services.
- A dropped transaction may disappear from the queried node while remaining in another mempool.

Before first broadcast, the submitter still checks `latest` and `pending`. For an idle wallet they must agree with the expected next nonce. An unexplained difference quarantines the wallet. This guard catches many inconsistencies but does not prove globally that no transaction is in flight.

Every replica runs a periodic reconciler. It claims expired worker leases and resumes batches from Redis.

For each assigned wallet:

1. Load its active batch, persisted nonce, and attempt history.
2. For each `Prepared` attempt, query its locally computed hash and rebroadcast the persisted signed bytes when needed.
3. Check receipts for every known transaction hash.
4. Compare `latest` and `pending` transaction counts with the persisted nonce.
5. Resume receipt tracking, rebroadcast, fee replacement, cancellation, or quarantine.

Safety cases:

- Redis says a wallet is idle but `pending nonce > latest nonce`: quarantine it because an unknown transaction is pending.
- A wallet nonce has advanced past the assigned nonce but no known attempt has a receipt: quarantine and reconcile chain history before reuse.
- A worker lease expires: reassign the worker lease, not the wallet.
- Redis loses pending submission state: quarantine affected wallets until chain state is reconciled.

The current orphan sweeper should eventually be replaced by batch and wallet reconciliation. Recovery should operate on persisted batches rather than infer batches by grouping request records by transaction hash.

## Redis model

Initial key layout:

```text
gateway:request:<request-id>       request payload and state
gateway:requests:create            ordered create request queue
gateway:requests:ops               ordered operation request queue

gateway:batch:<batch-id>           immutable intent and mutable state
gateway:batches:ready               ordered ready-batch queue

gateway:wallet:<address>           runtime state for a configured wallet
gateway:wallets:idle               available configured-wallet index

gateway:lease:<batch-id>           worker lease with TTL
gateway:resource:<resource-id>      conflicting-request lock
```

The deployment uses one Redis instance, not Redis Cluster. Atomic Lua scripts can therefore access these keys without cluster hash tags.

Atomic transitions are implemented as Lua scripts shipped and versioned with the gateway. Redis Functions are not needed initially: they require server-side installation and version management, while Lua scripts can be loaded and invoked directly by each replica.

Redis is durable infrastructure for this design. It requires:

- AOF persistence.
- Replication and failover.
- `noeviction` for scheduler state.
- Memory and persistence alerts.
- Backups and restore procedures.

## Interfaces

Keep the modules deep and separate by responsibility:

```text
RequestRepository
    accept, load, and transition requests

BatchRepository
    inspect queues, atomically seal batches, and queue transaction intents

WalletPool
    atomically assign wallets and manage durable assignment state

Submitter
    sign, broadcast, replace, and track one assigned transaction

Reconciler
    recover expired leases and resolve Redis/chain inconsistencies

RateLimiter
    enforce request admission limits independently of request tracking
```

Tokio channels or Redis pub/sub may wake workers for low latency. Workers must also poll because wakeups are not durable.

## Required invariants

1. A request belongs to at most one batch.
2. A sealed batch's transaction intent never changes.
3. A wallet has at most one assigned batch.
4. An assigned batch uses exactly one wallet and nonce.
5. Every replacement preserves wallet, nonce, destination, calldata, value, and gas limit.
6. Worker lease expiry never releases a wallet.
7. A wallet is reusable only after its nonce is resolved at the configured confirmation level.
8. Request terminal transitions, resource-lock release, batch finalization, and wallet release happen atomically in Redis.
9. A failed Redis write cannot be treated as a successful state transition.
10. Any unexplained wallet nonce state causes quarantine rather than automatic reuse.

## Migration sequence

### Phase 1: typed domain identifiers

Introduce `RequestId`, `BatchId`, `ResourceLock`, and typed transaction hashes/nonces. Remove internal `String` request IDs and reserve `GatewayRequestId` formatting for HTTP.

### Phase 2: durable request payloads and queues

Persist complete validated request payloads. Replace Tokio channels as the source of truth with ordered Redis create and ops queues. Channels may remain as wakeups.

### Phase 3: durable batch sealing

Implement atomic create and ops batch sealing. Persist immutable transaction intents and publish them to one ready queue. Keep the existing single-wallet sending path temporarily.

### Phase 4: durable multi-wallet submitter

Read the complete gateway KMS wallet pool from `AWS_KMS_KEY_IDS`. Require every replica to load the same configuration fingerprint. Add startup wallet reconciliation, atomic batch/wallet assignment, persisted nonces, signed attempts, worker leases, and safe-block confirmation tracking.

### Phase 5: replacement and cancellation

Implement configurable EIP-1559 fee replacement. When the batch replacement policy is exhausted, automatically start a configurable same-nonce cancellation policy. Quarantine the wallet if cancellation cannot resolve the nonce.

### Phase 6: reconciliation and cleanup

Add startup and periodic reconciliation. Remove process-local receipt trackers, the global send mutex, and the request-level orphan sweeper after durable batch recovery covers their responsibilities.

## Production rollout

Use a planned downtime deployment. No legacy and durable gateway processes run concurrently.

### Pre-deployment drain

1. Disable external traffic to all gateway endpoints.
2. Keep the legacy gateway replicas running so their process-local create and ops queues can drain.
3. Wait until Redis contains no legacy requests in queued, batching, or submitted states.
4. For every legacy gateway wallet, verify `latest == pending` and wait until its last known transaction reaches `safe`.
5. Stop every legacy gateway replica. Confirm no gateway process can sign or broadcast.
6. Back up Redis before modifying gateway keys.

If the legacy pipeline cannot drain a request, resolve or explicitly fail it before proceeding. Do not migrate requests from process-local queues whose ownership cannot be proven.

### Deploy durable gateway

1. Remove legacy gateway request-tracking keys after the backup, or use a fresh key namespace for the durable schema.
2. Deploy all replicas with the same binary and `AWS_KMS_KEY_IDS` value while external traffic remains disabled.
3. On startup, resolve every configured KMS key to its address and verify the wallet-configuration fingerprint is identical across replicas.
4. Reconcile each wallet's `latest` and `pending` nonce. Initialize it in Redis only when no unexplained transaction is in flight; otherwise quarantine it.
5. Run Redis schema and Lua-script self-checks.
6. Verify queues are empty, no wallet is unexpectedly assigned, and at least one wallet is idle.
7. Enable external traffic.
8. Submit a controlled request and observe persistence, batch sealing, wallet assignment, prepared-attempt persistence, broadcast, safe confirmation, and wallet release.
9. Monitor queue age, stalled batches, quarantined wallets, Redis errors, replacement attempts, and safe-confirmation latency.

### Rollback

- Before external traffic is enabled, stop the durable deployment and restore the legacy binary and Redis backup.
- After durable requests are accepted but before any broadcast, stop admission and workers, then either discard test requests explicitly or migrate their persisted payloads with a reviewed one-off procedure.
- After any durable transaction is broadcast, do not restore transaction ownership to the legacy submitter. Keep the durable submitter and reconciler running until every assigned nonce reaches `safe`. Roll forward with a fixed durable binary if needed.

Keep a submitter-only recovery mode so API admission and batch building can remain disabled while outstanding durable transactions are resolved.

### Future schema changes

Treat later Redis schema changes as expand-and-contract migrations. Never deploy a schema version that an older submitter could misinterpret while it may still own a wallet lease.

## Tests

Minimum integration scenarios:

1. Two replicas attempt to seal the same queued requests; each request appears in one batch.
2. Two replicas attempt to claim the same wallet; only one succeeds.
3. A submitter crashes before broadcast, during an ambiguous RPC send, after broadcast but before updating Redis, and after inclusion; another replica resumes from the prepared signed bytes.
4. Redis rejects or ambiguously acknowledges the prepared-attempt write; no unpersisted transaction is broadcast.
5. A transaction is dropped and replaced several times with the same nonce and increasing fees.
6. Replacement policy exhaustion starts automatic cancellation without releasing the wallet.
7. A reverted transaction reaches safe state and fails every request in its batch.
8. A short reorg removes an included receipt; the wallet remains assigned and tracking resumes.
9. Redis reports an idle wallet with an unexplained pending nonce; reconciliation quarantines it.
10. Different RPC nodes disagree about pending visibility; the persisted attempt remains authoritative.
11. Create and ops queues seal independently and produce `createManyAccounts` and `aggregate3` intents respectively.
12. Registration fees enabled: direct create batches continue to charge the KMS wallet correctly.

## Configuration defaults

- Confirmation level: `safe`.
- Terminal request and batch retention: configurable, default one day after reaching a terminal state.
- Batch replacement timing, fee bump, attempt limit, total age, and fee cap: configurable.
- Cancellation: automatic after batch replacement policy exhaustion.
- Cancellation replacement timing, attempt limit, total age, and fee cap: configurable.
- Wallet pool: comma-separated KMS key IDs in `AWS_KMS_KEY_IDS`.
- Atomic Redis transitions: Lua scripts shipped with the gateway.
