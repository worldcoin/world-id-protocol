# Durable gateway batching and transaction submission

## Status

Design draft. No implementation has started.

## Goal

Make request batching and on-chain submission durable across gateway restarts and safe across multiple gateway replicas.

Every gateway replica runs the same roles:

1. Accept and validate API requests.
2. Build create-account and operation batches.
3. Submit ready batches using any configured gateway KMS wallet.
4. Resume its own assigned transactions after restart.

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

Once sealed, `request_ids` and `transaction` are immutable. Each batch produces one signed transaction; the gateway does not create fee replacements or cancellation transactions.

Both batch builders publish to one submission queue:

```text
gateway:batches:ready
```

### Each gateway owns a private wallet pool

Each gateway process slot receives its own KMS key configuration. Wallet sets are disjoint by deployment configuration. KMS permission provisioning and wallet-set validation are outside the Redis model.

```rust
struct WalletConfig {
    kms_key_id: KmsKeyId,
    address: Address,
    enabled: bool,
}
```

Redis stores no wallet configuration or runtime state. It stores only active transaction ownership:

```text
gateway:wallet-assignment:<address> = batch_id
```

The reciprocal batch record contains the wallet address, nonce, hash, and signed bytes. Creating and deleting the assignment key is atomic with the corresponding batch transition. Its existence prevents an address from receiving two batches.

A disabled wallet is omitted from new-assignment candidates but remains in the gateway's local recovery set while it owns an assignment. Once that assignment is terminal and its Redis key is deleted, a later config update can remove the wallet.

Configuration changes require care:

- Adding a wallet is safe after its `latest` and `pending` nonces are reconciled.
- Disabling an unassigned wallet stops assignment immediately.
- Disabling an assigned wallet lets its transaction finish but prevents another assignment.
- Removing a wallet is safe only when `gateway:wallet-assignment:<address>` is absent.
- A gateway restart must restore every KMS key that still has an assignment.
- Configuring one wallet in multiple gateways violates the deployment contract. The assignment key still prevents concurrent batches, but either gateway could progress the transaction.

A wallet handles at most one active transaction. If its gateway crashes, the assignment waits in Redis until a process with that KMS key restarts.

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
  -> Pending(wallet, nonce)
  -> Included(tx_hash, block)
  -> Finalized(tx_hash)
```

Failure paths:

```text
Ready -> Failed(pre-broadcast failure)
Pending -> Failed(receipt timeout)
Pending -> Included -> Failed(reverted)
```

The initial implementation waits for a receipt until a large configurable timeout measured from the durable submission timestamp. If no receipt exists when the timeout expires, it assumes the transaction was globally dropped and fails the batch. This is a deliberate simplification: global mempool disappearance cannot be proven through standard RPC.

### Wallet availability (local, not persisted)

```text
Available -> Assigned -> Available
                     -> Blocked
```

The gateway derives `Assigned` from `gateway:wallet-assignment:<address>` and derives `Blocked` from nonce reconciliation. A restart recomputes both states. A wallet becomes available after:

- A successful transaction reaches the required confirmation level.
- A reverted transaction reaches the required confirmation level.
- The configured receipt timeout expires with no receipt.

## Submitter behavior

The submitter is a Tokio task inside every gateway process. Durable transaction data comes from Redis; wallet configuration and availability policy remain local.

### Assignment

A Lua script atomically:

1. Selects one ready batch.
2. Selects the first locally supplied enabled address without an assignment key.
3. Assigns the batch to that address.
4. Removes the batch from the ready index and creates `gateway:wallet-assignment:<address>`.

### Initial submission

For a newly assigned batch:

1. Fetch both `eth_getTransactionCount(wallet, "latest")` and `eth_getTransactionCount(wallet, "pending")`.
2. Reconcile both chain nonces with the batch assignment and prepared submission, if present. Do not broadcast if they reveal unexplained wallet activity.
3. Select the pending nonce and fill gas limit and EIP-1559 fee fields.
4. Sign with the assigned KMS key.
5. Compute the transaction hash locally from the signed bytes.
6. Atomically persist the nonce, signed transaction, local hash, and submission metadata as `Prepared`, transitioning the batch from `Assigned` to `Pending`.
7. Read the persisted submission back or otherwise require a confirmed Redis write.
8. Broadcast the exact signed bytes with `eth_sendRawTransaction`.
9. Mark the submission `Broadcast` after the RPC call. Failure to persist this final transition is recoverable because the nonce, signed bytes, and hash were stored before broadcast.

### Prepared submission

```rust
struct PreparedSubmission {
    nonce: u64,
    tx_hash: TxHash,
    signed_transaction: Bytes,
    max_fee_per_gas: U256,
    max_priority_fee_per_gas: U256,
    submitted_at: Timestamp,
    broadcast_at: Option<Timestamp>,
}
```

Persisting signed bytes before broadcast is the submission write-ahead log. It closes the dangerous send-before-save gap:

- If persisting `Prepared` fails, do not broadcast.
- If the Redis response is ambiguous, reconnect and read the batch's prepared submission before deciding whether to broadcast.
- If the process crashes during or after the RPC call, the restarted gateway queries the locally known hash and may rebroadcast the exact signed bytes. Rebroadcast is idempotent at the transaction level.
- An RPC response hash must equal the locally computed hash. A mismatch blocks that wallet locally until reconciliation.

The post-broadcast Redis update is advisory for progress, not required to rediscover the transaction.

### No automatic replacement

The gateway signs and broadcasts one transaction per batch. It does not bump fees or submit a same-nonce cancellation. The submitter polls for a receipt until the configurable receipt timeout expires. On timeout, it performs one final receipt and nonce check. It fails the batch and releases the assignment only when no receipt exists and the latest nonce has not advanced past the submitted nonce. An advanced nonce without the known receipt is an inconsistency that blocks automatic wallet reuse.

### Confirmation

Receipt inclusion is insufficient to release a wallet because the containing block can be reorganized.

The submitter must:

1. Find the receipt for the persisted submission.
2. Record its block hash and block number.
3. Verify the receipt remains canonical.
4. Wait until the receipt block reaches the configured confirmation level.
5. Atomically finalize the batch, all member requests, resource locks, and wallet assignment.

The confirmation level is `safe`. The submitter releases a wallet only after the receipt's canonical block is at or below the chain's safe head. Support for a configurable `finalized` mode may be added later if required.

### Transaction metrics

Emit metrics at durable state transitions, using batch kind and terminal outcome as bounded labels. Do not label metrics by request ID, batch ID, wallet address, or transaction hash.

Minimum measurements:

- Submission-to-inclusion duration.
- Inclusion-to-safe duration.
- Submission-to-terminal duration, split by finalized, reverted, and timed out.
- Current assigned transaction count and age of the oldest pending submission.
- Receipt-timeout, reorg, rebroadcast, and nonce-inconsistency counters.

`PreparedSubmission.submitted_at` is the common latency origin. Transition timestamps passed to `mark_included`, `finalize`, and `fail` provide the endpoints. Metrics are operational output rather than durable scheduler state.

## RPC checks and reconciliation

RPC state is a safety check and reconciliation source, not the primary submission queue. `eth_getTransactionCount(address, "pending") > eth_getTransactionCount(address, "latest")` indicates pending nonce consumption but does not identify the transaction or its intended batch.

Receipt-timeout expiry is treated as global drop. This first version accepts that mempool visibility differs across providers and does not try to prove global disappearance.

Before first broadcast, the submitter still checks `latest` and `pending`. For an unassigned wallet they must agree. An unexplained difference blocks the wallet locally. This guard catches many inconsistencies but does not prove globally that no transaction is in flight.

Every gateway runs a periodic reconciler for its own wallet set and resumes its assignments from Redis after restart.

For each of its assigned wallets:

1. Load its active batch and prepared submission.
2. If the submission is only `Prepared`, query its locally computed hash and rebroadcast the persisted signed bytes when needed.
3. Check the receipt for the persisted transaction hash.
4. Compare `latest` and `pending` transaction counts with the persisted nonce.
5. Resume receipt and timeout tracking, or block the wallet on unexplained nonce state.

Safety cases:

- No assignment exists but `pending nonce > latest nonce`: keep the wallet out of local assignment candidates because an unknown transaction is pending.
- A wallet nonce has advanced past the assigned nonce but the persisted transaction has no receipt: block it and reconcile chain history before reuse.
- A gateway is offline: its assignment remains untouched until a process with that wallet's KMS key restarts.
- Redis loses pending submission state: keep affected wallets out of assignment until chain state is reconciled.

The current orphan sweeper should eventually be replaced by batch and wallet reconciliation. Recovery should operate on persisted batches rather than infer batches by grouping request records by transaction hash.

## Redis model

Initial key layout:

```text
gateway:request:<request-id>       request payload and state
gateway:requests:create            ordered create request queue
gateway:requests:ops               ordered operation request queue

gateway:batch:<batch-id>           immutable intent and mutable state
gateway:batches:ready               ordered ready-batch queue

gateway:wallet-assignment:<address> batch assigned to a wallet address

gateway:resource:<resource-id>            conflicting-request lock
gateway:ratelimit:leaf:<leaf-index>       sliding-window admission set
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

AssignmentRepository
    atomically map locally supplied wallet addresses to ready batches

Submitter
    sign, broadcast, and track one transaction using a locally owned wallet

Reconciler
    resume this gateway's assignments and resolve Redis/chain inconsistencies

RateLimiter
    atomically check and record per-account sliding-window admission independently of request tracking
```

Tokio channels or Redis pub/sub may wake workers for low latency. Workers must also poll because wakeups are not durable.

## Required invariants

1. A request belongs to at most one batch.
2. A sealed batch's transaction intent never changes.
3. A wallet has at most one assigned batch.
4. An assigned batch uses exactly one wallet and nonce.
5. A batch has at most one prepared signed transaction.
6. Gateways supply assignment candidates from local configuration; Redis never supplies wallet addresses.
7. A wallet is reusable after safe success, safe revert, or receipt-timeout expiry with no receipt and no unexplained nonce advancement.
8. Request terminal transitions, resource-lock release, batch finalization, and assignment-key deletion happen atomically in Redis.
9. A failed Redis write cannot be treated as a successful state transition.
10. Any unexplained wallet nonce state removes the wallet from local assignment candidates until reconciliation.

## Migration sequence

### Phase 1: typed domain identifiers

Introduce `RequestId`, `BatchId`, `ResourceLock`, and typed transaction hashes/nonces. Remove internal `String` request IDs and reserve `GatewayRequestId` formatting for HTTP.

### Phase 2: durable request payloads and queues

Persist complete validated request payloads. Replace Tokio channels as the source of truth with ordered Redis create and ops queues. Channels may remain as wakeups.

### Phase 3: durable batch sealing

Implement atomic create and ops batch sealing. Persist immutable transaction intents and publish them to one ready queue. Keep the existing single-wallet sending path temporarily.

### Phase 4: durable multi-wallet submitter

Give each gateway process slot a disjoint KMS wallet pool. Add atomic assignment using locally supplied enabled addresses, persisted signed submissions, receipt-timeout tracking, and safe-block confirmation tracking.

### Phase 5: reconciliation and cleanup

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
2. Deploy all gateways with the same binary and disjoint KMS wallet sets while external traffic remains disabled.
3. On startup, resolve each gateway's configured KMS keys and load any `gateway:wallet-assignment:<address>` records for those addresses.
4. Reconcile each wallet's `latest` and `pending` nonce. Keep any wallet with unexplained activity out of local assignment candidates.
5. Run Redis schema and Lua-script self-checks.
6. Verify queues are empty, no wallet is unexpectedly assigned, and at least one wallet is locally available.
7. Enable external traffic.
8. Submit a controlled request and observe persistence, batch sealing, wallet assignment, prepared-submission persistence, broadcast, safe confirmation, and wallet release.
9. Monitor queue age, receipt timeouts, locally blocked wallets, Redis errors, submission-to-inclusion latency, submission-to-finalization latency, and safe-confirmation latency.

### Rollback

- Before external traffic is enabled, stop the durable deployment and restore the legacy binary and Redis backup.
- After durable requests are accepted but before any broadcast, stop admission and workers, then either discard test requests explicitly or migrate their persisted payloads with a reviewed one-off procedure.
- After any durable transaction is broadcast, do not restore transaction ownership to the legacy submitter. Keep the durable submitter and reconciler running until every assigned transaction is terminal. Roll forward with a fixed durable binary if needed.

Keep a submitter-only recovery mode so API admission and batch building can remain disabled while outstanding durable transactions are resolved.

### Future schema changes

Treat later Redis schema changes as expand-and-contract migrations. Never deploy a schema version that an older submitter could misinterpret while it still owns a wallet assignment.

## Tests

Minimum integration scenarios:

1. Two replicas attempt to seal the same queued requests; each request appears in one batch.
2. Two replicas attempt to claim the same wallet; only one succeeds.
3. A gateway crashes before broadcast, during an ambiguous RPC send, after broadcast but before updating Redis, and after inclusion; a process restored with that wallet's KMS key resumes from the prepared signed bytes.
4. Redis rejects or ambiguously acknowledges the prepared-submission write; no unpersisted transaction is broadcast.
5. No receipt appears before the configured timeout; final receipt and nonce checks are consistent with a drop, then the batch and requests fail and the assignment is released.
6. A reverted transaction reaches safe state and fails every request in its batch.
7. A short reorg removes an included receipt; the wallet remains assigned and tracking resumes.
8. An unassigned wallet has an unexplained pending nonce; reconciliation keeps it out of assignment candidates.
9. A transaction remains pending before its timeout; its requests, locks, and assignment remain intact.
10. Create and ops queues seal independently and produce `createManyAccounts` and `aggregate3` intents respectively.
11. Registration fees enabled: direct create batches continue to charge the KMS wallet correctly.

## Configuration defaults

- Confirmation level: `safe`.
- Terminal request and batch retention: configurable, default one day after reaching a terminal state.
- Transaction polling interval and receipt timeout: configurable.
- Automatic fee replacement and cancellation are not supported.
- Wallet pool: a disjoint set of KMS key IDs configured per gateway process slot.
- Atomic Redis transitions: Lua scripts shipped with the gateway.
