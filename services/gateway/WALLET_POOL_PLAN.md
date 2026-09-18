# Gateway transaction wallets: rework plan

Status: proposal, for review.
Related: #937, #949, #920, #935, #936; closed #921/#923/#924/#925/#928.

---

## 0. TL;DR

1. **The goal is small and good**: N wallets, one in-flight transaction per wallet, cycled.
   No chain indexing, no durable batch/assignment state machine.
2. **#937 does not follow its own stated scope.** It ships multi-wallet pooling, deletes
   `request_tracker.rs` (412 lines) and `orphan_sweeper.rs` (164 lines), makes
   `ProviderArgs::http()` return `Vec<DynProvider>` (forcing edits in indexer and common tests
   for a gateway-only feature), and is 36 commits behind `main` and conflicting. Reviewer
   feedback on it was dismissed with "fine" / "won't fix, added TODO".
3. **The durable wallet lease is the right core** — the one piece of persisted state that earns
   its keep, because after a restart a wallet must not be reused while a transaction of unknown
   fate is outstanding. P1's task supervision (from #949) is kept too.
4. **Rework in three PRs.** `P1` is independently mergeable and deployable. `P2` and `P3` form
   one logical change: `P2` merges first, neither deploys without the other, and prod enablement
   is gated on the §9 benchmark run in staging (§4.1, §8).
5. **The closed batch/assignment stack is the right target architecture, and Stage 3 adopts it.**
   It is additive once two free compatibility fixes are made, its `Included`/safe-head state
   answers the reorg question §5.3 leaves open, and its documented `fail()` contract is exactly
   the resolver §5.4 specifies. It is also about half a specification rather than finished code,
   so this is new work, not a resurrected PR (§4.3).
6. **Redis: additive only.** One new key family — a per-wallet record — and one additive field on
   `RequestRecord`. No renames, no shape changes to existing keys, no migration script (§6).
7. **The pool is conditional.** If it does not beat `main`'s pipelined single wallet, keep
   `main` and keep only P1 (§5.3).

---

## 1. What we are building, and the invariants

The gateway holds a pool of `N` signing wallets; a batch of requests is assigned to a wallet that
is currently free; that wallet is not used again until its transaction has a definitive on-chain
outcome. Cyclic assignment gives `N` transactions in flight at once.

| # | Invariant | Why |
|---|---|---|
| **I1** | A wallet has at most one nonce-consuming transaction of unknown fate at any time. | Two signed transactions from one wallet with the same nonce collide; a lost transaction leaves a nonce gap that stalls every later transaction from that wallet. |
| **I2** | Every request reaches a terminal state, and every wallet lease is eventually released or explicitly parked. | Today a leaked `gateway:pending_requests` member lives forever; a leaked lease would lock a wallet forever. |
| **I3** | Every fact needed to satisfy I1 and I2 survives a process restart. | A crashed replica must not re-sign a nonce whose predecessor is still outstanding. |
| **I4** | Rolling deploys never let two gateway versions drive the same wallet without coordination. | Mixed-version windows are where nonce bugs ship. |

I1 holds **up to the chain's reorg depth**, which is what `WALLET_RELEASE_CONFIRMATIONS` encodes
(§5.3); the default of 1 does not make it absolute.

---

## 2. Current state

### 2.1 Merged into `main` (keep)

| PR | What landed | Relevance |
|---|---|---|
| #920 | `storage/request_store.rs` owns the Redis schema for requests. | The schema baseline we must not break. |
| #935 | `ProviderArgs`/`SignerArgs` normalised; `AWS_KMS_KEY_IDS` picks one KMS key per pod ordinal. | Wallet identity comes from `HOSTNAME`. |
| #936 | `ProviderWallet` with fill-before-send. | The signing primitive we build on. |
| #956, #961 | testcontainers + hermetic anvil for gateway tests. | We can write real Redis+anvil tests. |

### 2.2 `main` mechanism today

- `RequestTracker` (in-process) spawns one detached receipt task per batch; it records
  confirmation metrics and finalizes request IDs.
- `OrphanSweeper` (in-process loop, `ORPHAN_SWEEPER_INTERVAL_SECS` default 30) is the restart
  safety net: it scans `gateway:pending_requests`, fails `Queued`/`Batching` requests older than
  `STALE_QUEUED_THRESHOLD_SECS` (default 60), re-queries receipts for `Submitted` requests older
  than `STALE_SUBMITTED_THRESHOLD_SECS` (default 600), and fails them if no receipt appears.
- The batcher serialises *sends* with an in-process `tx_send_lock` and does **not** wait for a
  receipt before sending the next batch. Nonces come from `SimpleNonceManager`, i.e. the RPC
  node's pending transaction count. Batch queues are bounded tokio `mpsc` channels.
- One wallet per pod. Prod runs 2 replicas
  (`world-id-protocol-deploy:infrastructure/world-id-protocol/prod/us-east-1/world-id-gateway.tf`,
  `gateway_replica_count = 2`).

Today's pipeline is already fast: sends are pipelined and serialised, and correctness rests on
"the node's pending count is accurate". The pool replaces that with "one transaction per wallet,
released only on a definitive outcome".

### 2.3 Open PRs

**#937 — `feat(gateway): persist transactions before broadcast`.** Adds
`storage/wallet_store.rs` (key `gateway:wallet_transaction:{address}`, `Reserved` with a 60s TTL
or `Submitted` with no TTL because `SET` without `EX` drops it), `transaction_submitter.rs`
(748 lines: turn-based `SET NX` acquire, sign → persist → broadcast, then a sequential
`run_tracker` receipt poll), the `BatchType` enum (small and good), and the
comma-per-pod/semicolon-per-wallet `AWS_KMS_KEY_IDS` format with `http()`/`http_wallets()`
returning `Vec`. Removes `request_tracker.rs`, `orphan_sweeper.rs`, `tests/test_orphan_sweeper.rs`
and `RequestStore::remove_pending_request`. The PR body claims single-wallet scope while commit
`c9409197` and `tests/test_wallet_pool.rs` ship the pool; the reviewer scope objection is correct.

**#949 — `refactor(gateway): centralize application lifecycle`.** Stacks on #937. Adds `app.rs`
with a `Gateway` struct, runs background tasks in a `JoinSet`, swaps the batch queues to bounded
`flume` channels, and flattens config. Draft, CI-green, no review comments. Two corrections: the
`flume` swap has no stated requirement — `main` already uses bounded tokio `mpsc` and has no
`Mutex` on the receiver, so P1 keeps tokio `mpsc`; and its `supervise` is fail-fast (any task
exit or panic terminates the process), not restart-on-panic.

**#921/#923/#924/#925/#928 (closed).** A durable batch/assignment design, and the target
architecture for Stage 3 (§4.3). Schema: `gateway:requests:create|ops` (ordered queues),
`gateway:batch:{id}`, `gateway:wallet-assignment:{address}`, and
`gateway:resource:{authenticator|account}:*` in place of `gateway:inflight:*`. Lifecycle:
`RequestState::{Queued, Batched, Finalized, Failed}` and `BatchState::{Ready, Assigned, Pending,
Included, Finalized, Failed}`. It contains no chain indexing — reorg handling is a receipt
`block_hash` checked against the block at the same height, plus a safe-head comparison.

Implemented and tested in that stack: `RequestRepository::{accept, load, load_many,
oldest_queued, queue_len, fail_queued}`, `BatchRepository::{seal, load, ready_len}`, and
`RateLimiter::check_and_record`. Still `unimplemented!()`: `BatchRepository::{
record_prepared_submission, mark_submission_broadcast, mark_included, finalize, fail}` and all of
`AssignmentRepository::{assign_ready, assigned, assigned_many}`. So the admission and sealing half
is real code and the submission and wallet-assignment half is an interface — including the wallet
pool assignment, which is what #937 was really an attempt to build.

---

## 3. Findings that drive the rework

| ID | Sev | Problem | Resolved by |
|---|---|---|---|
| F1 | high | Releasing a wallet on a 1-confirmation receipt is not "wait until finalized"; the code carries a TODO admitting it. | §5.3, §5.10 |
| F2 | high | The timeout path marks requests `Failed` **and** frees the wallet, though the tx may still be in the mempool. | §5.5 |
| F3 | high | Deleting the orphan sweeper drops `Queued`/`Batching` recovery; a request admitted by a replica that dies before submitting is stuck, and its pending-set ID leaks forever. | §5.6 |
| F4 | high | `set_status_batch` only logs failures, and the lease is then deleted unconditionally (TODO in `f3cb9834`). | §5.1 R2, §5.7 |
| F5 | med | An RPC error is indistinguishable from "no receipt yet", and near the deadline it fails valid requests and frees the wallet. | §5.4 step 1 |
| F6 | med | `RESERVATION_TTL=60s` frees a reserved-but-unsigned wallet, while the submitted record becomes immortal. Neither lifetime is deliberate. | §5.1 |
| F7 | med | The record stores only the tx hash, not the signed bytes, so a crash between persist and broadcast can only be resolved by timing out. | §5.4 |
| F8 | med | `gateway:inflight:*` TTL (300s) is shorter than the submission lifetime, so duplicate detection expires while the request is still in flight. | §5.9 |
| F9 | med | `acquire()` is a spin-wait with a process-local `Notify`, a ~1s latency floor, and up to N Redis round trips. | §5.7 |
| F10 | med | The tracker polls all wallets sequentially, so one slow RPC delays every other wallet. | §5.8 |
| F11 | low | No pool observability: no in-flight/parked gauges, no acquire wait, no saturation counter. | §7 |
| F12 | low | The `AWS_KMS_KEY_IDS` format change is not rolling-upgrade safe: an old pod splits on commas and uses `key-a1;key-a2` as a key id. | §4.2, §8 |
| F13 | low | `http()` returning `Vec<DynProvider>` forces edits in `services/indexer`, `services/common` tests and `crates/authenticator/tests` for a gateway-only feature. | §4.1 |
| F14 | low | The author's own benchmark (PR #937 review comment: "main ~18s vs branch ~22s at 10 wallets, batch 10") suggests the pool is slower. | §5.3, §9 |

---

## 4. Decision: rework, not patch

Keep #937's `BatchType` and the durable per-wallet record idea, and #949's supervised tasks.
Discard #937's scope, lease lifetimes, release conditions and provider-config blast radius. Do
not land #937 as-is or "fix it in review": it conflicts with `main`, is 36 commits behind, and
several open issues are design-level.

### 4.1 PR breakdown

**P1 — `refactor(gateway): supervise background tasks and centralise app construction`**
(stripped of wallet work). Independently mergeable **and deployable**.
- `app.rs` `Gateway` container; all background tasks in a `JoinSet`; a failing task terminates the
  process with a named error so the orchestrator restarts the replica (fail-fast, matching #949's
  actual `supervise`).
- Request handling and transaction submission are unchanged. Supervision is not: a background-task
  death today is silent and leaves the feature disabled (e.g. the base-fee sampler); after P1 it
  restarts the replica. That is the point, and it is the only behaviour change in P1.
- Config: move the wallet knobs onto flat `GatewayConfig` fields rather than adding another
  sub-struct; do not rename env vars.
- Keep bounded tokio `mpsc` channels; do not add `flume` (§2.3).

**P2 — `feat(gateway): durable, restart-safe transaction submission`.** Merges first; **not**
deployable without P3.
- The lease/resolver mechanism of §5, for any pool size; deployment is what is gated.
- `BatchType` from #937.
- Deletes the per-batch receipt task and the receipt-polling half of the orphan sweeper.
- Keeps a shrunk `orphan_sweeper` (§5.6), which requires restoring
  `RequestStore::remove_pending_request` from `main`.
- Adds `RequestStore::update_status_if` (compare-and-set status write, §5.7) and the additive
  `RequestRecord::wallet` field (§6.4).
- Restores `ProviderArgs::http()`/`http_wallet()` signatures; adds `http_wallets()` alongside. No
  indexer or relay edits.

**P3 — `feat(gateway): shared wallet pool configuration`.** Merges after P2; deploys with it.
- `AWS_KMS_WALLET_KEYS` / `WALLET_PRIVATE_KEYS` as additive fields on `SignerArgs` (a flattened
  field of `ProviderArgs`). New fields, no existing signature changes — that is the F13 claim.
- `N = count(AWS_KMS_WALLET_KEYS)`; fairness; saturation metrics; `tx_send_lock` removal.
- The §9 benchmark, run in staging before prod enablement.
- Depends on an **infra change** (outside this repo): provision a set of pool KMS keys, disjoint
  from the legacy per-ordinal keys, decoupled from `gateway_replica_count`.

### 4.2 Wallet allocation: shared pool, disjoint keys, new env vars

Replace "comma-separated per pod ordinal, semicolon-separated per wallet" with a **shared pool**:

- `AWS_KMS_WALLET_KEYS` — comma-separated KMS key ids usable by **every** replica.
- `WALLET_PRIVATE_KEYS` — separated private keys, for dev/Anvil parity.

The legacy vars keep their exact current meaning and are used when the new ones are unset. A
process configured with both forms **fails to start**; §8 makes the switch a single atomic config
change so no pod is ever in that state.

Why a shared pool beats per-pod slices: Redis already coordinates wallets, so a shared pool is
what the mechanism was always for; adding capacity is one env var with no ordinal arithmetic and
no "keep `gateway_replica_count` in sync with StatefulSet replicas" comment for a human to
honour; pods and wallets scale independently; and the semicolon-in-slot parsing that F12 lives in
disappears. The cost is that per-key KMS quota is shared, which at current volumes is not a
constraint.

### 4.3 Stage 3: adopting the closed batch/assignment design

An earlier draft of this plan wrote the closed stack off as the over-engineering we set out to
avoid. That was wrong on two counts, and this section corrects it.

**It is a better-organised design than what this plan sketches for the request lifecycle.** Its
`PreparedSubmission` (nonce, signed bytes, locally computed tx hash, `submitted_at`) is the same
write-ahead log §5.4 arrives at independently. `BatchState::Included { block_hash, block_number }`
plus a safe-head comparison is the *correct* answer to the reorg question §5.3 explicitly defers.
And its `fail()` interface documents the exact caller contract this plan's resolver implements:

> The caller must enforce the configured duration, verify no receipt exists, and verify the latest
> chain nonce has not advanced past the submitted nonce before invoking this transition.

That is §5.4 step 4. So §5 is not an alternative to the closed design; it is the missing half of it.

**It is also only half implemented**, as §2.3 records. There is nothing to resurrect: the admission
and sealing half is real code, the submission and assignment half is a documented interface, and the
wallet pool assignment — the actual feature — is in the stubbed half.

**Two things block it from being additive, and both are free to fix.**

- **The lock rename is cosmetic.** `ResourceLock::{Authenticator, Account}` maps to
  `gateway:resource:authenticator:{addr}` / `gateway:resource:account:{idx}`, replacing
  `gateway:inflight:create:{addr}` / `gateway:inflight:leaf:{idx}`. Across a rolling deploy the two
  builds would disagree about which key is the lock, so the same leaf could be operated on twice.
  Fix: **keep the existing key names.** `ResourceLock` stays a code-level concept that serialises to
  the legacy strings. The rename buys nothing.
- **`StoredRequest` replaces `RequestRecord` rather than extending it.** This is the real blocker,
  because old builds read that key: `update_status`'s Lua decodes it and mutates `status`, and
  `requests()` deserialises it into `RequestRecord`. Fix: **make the record a strict superset.**
  Keep `kind`, `status`, `updated_at`, `inflight_keys`; add `payload: Option<RequestPayload>` and
  `batch_id: Option<Uuid>` with `#[serde(default)]`. Old builds ignore the new fields; new builds
  treat `payload: None` as a legacy request that cannot be resealed, which is exactly today's
  behaviour for a request with no durable payload.

With those two fixes, every other key in the stack (`gateway:batch:{id}`, `gateway:requests:create|ops`,
the ready-batch index, `gateway:wallet-assignment:{address}`) is new and read only by new builds, and
every shared key has exactly one writer per request — the lock owner — so there is no cross-version
write race. Mixed-version is then safe by the argument in §6.1, with no mirror, shadow mode or
fleet-version marker.

**It also improves §5.** Its assignment principle is "Redis never enumerates or introduces wallets
to the gateway; disabled wallets are retained in local config for draining." That is better than
this plan's `gateway:wallets` index set: it removes a new key, makes pool shrink an explicit
operational act rather than an inference, and keeps Redis out of wallet discovery. §5.1, §5.8 and
§6.4 have been revised to follow it, keeping the `Submitted`-request reconciliation as the backstop
for a wallet that leaves configuration by mistake.

**Decomposition, if we do it.**

- **R1 — durable payloads, no behaviour change.** Superset the request record with `payload` and
  `batch_id`; write the `gateway:requests:create|ops` ordered mirrors at admission alongside the
  pending set. Nothing reads them yet. Payloads are small: `CreateAccountRequest` is an optional
  address, a vector of addresses, a vector of `U256` and one `U256`, and operations are encoded
  multicall calldata — hundreds of bytes, not proofs. Rollback is a plain image revert.
- **R2 — durable batches become authoritative for new builds.** Sealing, the batch record, the
  write-ahead `PreparedSubmission`, `Included`/`Finalized` with safe-head confirmation, and the
  atomic batch-wide `finalize`/`fail` that also releases locks and the wallet assignment. Old builds
  keep the in-memory path; both serialise on the same lock keys, and both sweeper implementations
  already agree on the `Batching` threshold, so a request a new build holds is not failed by an old
  build's sweeper.
- **R3 — recovery, then retirement.** Startup recovery from the durable queues is the stack's main
  behavioural gain: a pod restart recovers unsent work instead of failing it. Only then remove the
  sweeper's `Queued` fail path and the in-memory queue as the source of truth.
- **Never do the lock rename**, or do it later, when no build that reads the old names can still be
  running.

**Cost, honestly.** Roughly 1.5–2.5k lines of storage and lifecycle work plus a batcher rewire:
three PRs, and a larger blast radius on the hottest path than P2/P3. Two scale notes: the atomic
batch-wide `finalize` spans a batch record, every member request, every resource lock and the
assignment key — at a 100-request batch that is a several-hundred-key Lua script, which needs
measuring and probably chunking; and payload persistence adds a durable copy of calldata that
currently lives only in memory. The gain is durability and maintainability plus a correct reorg
answer, not throughput.

**Ordering.** Land P1 → P2/P3 first. The wallet pool is the feature; the durable lifecycle is an
improvement to how work is stored, and running the refactor first is how this work got lost the
first time. The overlap with `AssignmentRepository` is small and is not duplicated work: which wallet
a batch uses is orthogonal to whether batches are durable, and P2's wallet record is the natural
substrate for it.

---

## 5. The mechanism

### 5.1 Per-wallet state machine

Two keys. The record, `gateway:wallet:{address}` (lowercase `0x` hex):

```json
{
  "v": 1,
  "state": "signing" | "in_flight" | "parked",
  "lease_id": "<uuid>",
  "nonce": 42,
  "tx_hash": "0x…",
  "raw_tx": "0x…",
  "request_ids": ["…"],
  "batch_type": "create" | "ops",
  "submitted_at": 1737000000,
  "last_attempt_at": 1737000030,
  "attempts": 0
}
```

- `nonce`, `tx_hash`, `raw_tx`, `request_ids`, `batch_type`, `submitted_at` are written at the
  `signing → in_flight` transition; `attempts` starts at 0; `last_attempt_at` is written on each
  broadcast attempt and is what rate-limits re-broadcasts.
- `raw_tx` is the EIP-2718 signed bytes. It is absent only on a record reconstructed by §6.4,
  which therefore cannot re-broadcast.

Transitions, all atomic single-key operations. "CAS" means a Lua script that writes only if the
named field still holds the value the caller read.

| From | To | Trigger | Guard / value written |
|---|---|---|---|
| absent | `signing` | batcher acquires the wallet | `SET NX PX WALLET_SIGN_LEASE_SECS`; value carries `lease_id` |
| `signing` | `in_flight` | signed and persisted, immediately before broadcast | CAS on `lease_id`; writes `WALLET_STATE_TTL_SECS` |
| `signing` | absent | signing failed, or process died | resolver deletes a `signing` record older than `WALLET_SIGN_LEASE_SECS`, CAS on `lease_id`; nothing was broadcast |
| `in_flight` | `in_flight` | resolver re-broadcasts `raw_tx` | CAS on `last_attempt_at`; `attempts += 1`; refresh TTL |
| `in_flight` | absent | resolver has a definitive outcome **and** all requests terminal | CAS on `lease_id` |
| `in_flight` | absent | batcher abandons before broadcast, still holding `lease_id` | CAS on `lease_id`; never re-broadcast |
| `in_flight` | `parked` | resolution timeout, outcome still undecidable | CAS on `lease_id`; refresh TTL |
| `parked` | absent | probe becomes decisive, or operator clears it | CAS on `lease_id` |

TTL: the resolver refreshes the record to `WALLET_STATE_TTL_SECS` (24h) on every pass for
`in_flight` and `parked` records only. A `signing` record keeps its short lease. Records therefore
live as long as a resolver is visiting them; 24h after a rollback or a permanently dead resolver
they expire. The TTL is a rollback backstop, **not** a mechanism for freeing stuck wallets.

Two rules make this safe:

- **R1 — never broadcast without a live lease.** If the `signing → in_flight` CAS fails (lease
  expired or replaced), the signed transaction is **discarded** and the requests fail. Without R1
  a KMS signing stall past `WALLET_SIGN_LEASE_SECS` produces two transactions sharing a nonce.
- **R2 — delete the lease only after the requests are terminal.** If a status write fails, leave
  the record and retry next pass. A request record that has already expired (24h) counts as
  terminal. This needs a fallible batch status write, which does not exist today: both
  `RequestTracker::set_status_batch` and #937's replacement only log.

`WALLET_SIGN_LEASE_SECS` bounds only the signing phase and must comfortably exceed worst-case KMS
sign latency plus the Redis write.

The resolver's wallet list comes from local configuration, following the closed stack's principle
that Redis never enumerates or introduces wallets (§4.3). A wallet that must stop receiving new
batches but still has a live record is marked **draining** in configuration: it is excluded from
`acquire()` but kept in the resolver's list until its record clears. That is why this plan adds no
index key — pool shrink is an explicit operational act, and §6.4 keeps a reconciliation backstop
for a wallet that leaves configuration by mistake.

### 5.2 What replaces the deleted pieces

| Today | After |
|---|---|
| `RequestTracker::set_status*` | same shape, but a **fallible** batch write returning per-ID results, plus `update_status_if` for guarded transitions (§5.7) |
| `RequestTracker::queued_backlog_stats_for_scope` | `Queued`-only counting unchanged; a new pending count gates the `NoBacklog` resync (§5.6) |
| `RequestTracker::check_rate_limit` | unchanged, `RequestStore::check_rate_limit` |
| `RequestTracker::spawn_receipt_tracker` | gone; one supervised resolver over leased wallets |
| `OrphanSweeper` receipt polling for `Submitted` | gone; the resolver owns `Submitted` records that carry a wallet. The sweeper keeps a self-eliminating path for legacy `Submitted` records that do not (§5.6) |
| `OrphanSweeper` `Queued`/`Batching` cleanup + pending-set prune | kept, with two thresholds (§5.6); `remove_pending_request` restored from `main` |

The split is deliberate: a `Submitted` request that knows its wallet has an owner (the lease) and
a durable record; `Queued`/`Batching` requests, and legacy `Submitted` requests, have no owner.
Two non-overlapping resolvers beat one sweeper that guesses.

### 5.3 Release condition: what "confirmed" has to mean

Throughput is `N_wallets / release_latency`, so the release condition sets the pool's ceiling:

| Release on | Typical latency, OP-stack L2 (assumption — §10 Q1) | Wallet throughput | Reorg exposure |
|---|---|---|---|
| receipt present (1 conf) | ~2s | `N / 2s` | reorgs shallower than 1 block |
| `safe` head ≥ receipt block | ~6–7 min | `N / 6min` | negligible |
| `finalized` head ≥ receipt block | ~12–13 min | `N / 13min` | none |

**Recommendation.** Release when a receipt exists, is canonical, and
`saturating_sub(head, receipt.block_number) >= WALLET_RELEASE_CONFIRMATIONS`. Default 1 — one
block on top of inclusion, the minimum the validation permits. Set it to the chain's practical
reorg depth + 1 to satisfy I1 strictly; §10 Q1 fixes the value. Record
`wallet.confirmations_at_release` so the choice is evidence-based rather than asserted.

**Residual risk, stated plainly.** Releasing on `k` confirmations means a reorg deeper than `k`
can remove a transaction whose wallet has already been reused, creating a nonce gap. Detecting
that requires keeping every released receipt under observation, or inspecting nonce contiguity —
the chain-watching machinery we are deliberately not building. The gap is not silent: it
manifests as a later transaction that never resolves, which parks a wallet and alerts (§5.5).

**Throughput.** The pool only helps when `N / release_latency` exceeds what `main` already
achieves with one pipelined wallet (sends serialised by `tx_send_lock`, roughly 5–20 batches/s at
50–200ms RPC latency, with no per-wallet confirmation wait). §9 requires a benchmark comparing
`main`, N=1 leased, and N=k leased at the same offered load. **If N=k does not beat `main`,
revert to `main` and keep only P1.**

### 5.4 Resolver decision procedure

Rules for the whole procedure:

- **Pin the pass to one endpoint.** The provider is a fallback layer over several RPC URLs that
  fans a request out to all of them in parallel and keeps the first success, so `head`, the
  receipt, `get_transaction_by_hash` and the nonce counts can otherwise be answered by different
  nodes. The resolver therefore builds one `DynProvider` per configured RPC URL (a
  single-URL `ProviderArgs`) and uses one provider for a whole pass; on failure it retries the
  pass on the next provider. Re-broadcasts use the same pinned provider. Never mix endpoints
  within a pass.
- **Delay the first probe by `WALLET_FIRST_PROBE_DELAY_SECS`** (default 2, the tracker interval)
  so the resolver does not race the batcher's own broadcast. This is short because the race is
  benign: a re-broadcast ships byte-identical `raw_tx`, so the worst case is a redundant
  `already known`.
- All RPC calls have bounded timeouts. `head` is fetched once per wallet, and a receipt's block
  number is never assumed to be ≤ `head`.

For a wallet in `in_flight`:

1. `receipt = get_transaction_receipt(tx_hash)`. **`Err(_)` → wait**; not being able to ask is not
   evidence of anything. Increment `wallet.tracker_errors`. (This is F5; #937 conflates the two.)
2. `Ok(Some(receipt))`:
   - `receipt.block_number` is `None` → wait.
   - canonical check: `get_block_by_number(receipt.block_number)` returns a block whose hash
     equals `receipt.block_hash`. A mismatch means the transaction was reorged out → go to 4. A
     fetch error → wait.
   - `saturating_sub(head, block_number) >= WALLET_RELEASE_CONFIRMATIONS` → **resolve** with
     `success = receipt.status()`.
   - otherwise → **wait**. Do not fall through to the nonce probe: a receipt with insufficient
     confirmations proves the nonce *is* consumed by us, and reaching the probe would misclassify
     our own mined transaction as `replaced`.
3. `Ok(Some(receipt))` and the block is no longer canonical → go to 4.
4. `Ok(None)` → then, on the same pinned provider:
   - `get_transaction_by_hash(tx_hash)` is `Some(_)` → in a mempool → **wait**;
   - else `latest > nonce` → **re-read the receipt for `tx_hash` before concluding anything**.
     A block containing our transaction can be imported between step 1 and here, which would
     otherwise fail a healthy transaction. Only if the receipt is still absent and
     `get_transaction_by_hash` is still `None` do we resolve as `success = false,
     reason = "replaced"`; the wallet is free because the nonce is mined either way;
   - else `pending > nonce` → the nonce is occupied in a mempool → **wait**;
   - else → the nonce is untouched, so `raw_tx` is still valid → **re-broadcast** it and wait.

Endpoint pinning is what makes the `latest > nonce` inference sound: if the pinned node reports
`latest > nonce`, that same node has the block, so an absent receipt plus an absent hash means the
occupant is not ours.

Re-broadcast is rate-limited to one attempt per `WALLET_REBROADCAST_INTERVAL_SECS` (default 30).
The attempt is claimed — under the same compare-and-set that guards the `attempts` counter — before
the send, so two resolver passes cannot both issue one or lose an increment. `already known` is
treated as liveness rather than as a failure: it does not stop the wallet from resolving. At
`WALLET_REBROADCAST_MAX_ATTEMPTS` (default 10) the resolver stops re-broadcasting and lets the
resolution timeout park the wallet, so parking has exactly one trigger. Without the backoff and the classification, an underpriced transaction is re-sent every
pass for 900s against the same node (a self-inflicted retry storm).

Provider caveat: `pending` reflects the mempool of the node answering. On an L2 whose sequencer is
separate, a transaction accepted by a non-sequencer endpoint can sit in that node's mempool
indefinitely. The resolution timeout and parking handle that (§5.5), and it is another reason to
broadcast to the sequencer endpoint.

### 5.5 Stuck wallets: park, and keep re-probing

If `now - submitted_at` exceeds `WALLET_RESOLUTION_TIMEOUT_SECS` (default 900) with an undecidable
outcome:

- Mark the batch's requests `Failed` with error code `ConfirmationError`. Clients must get a
  bounded answer; this matches today's 600s sweeper behaviour and preserves the
  `TransactionReverted`/`ConfirmationError` distinction clients already see.
- Transition the record to `parked`: excluded from `acquire()`, still present, still probed.
- Emit the `wallet.parked` gauge and an ERROR log with `wallet`, `tx_hash`, `nonce` and `attempts`.

**A parked wallet resolves only on a receipt or on `latest > nonce`.** It never resolves because a
single node's mempool no longer lists the transaction, and it is **not** re-broadcast — its
requests were already reported `Failed`, so re-broadcasting could execute an operation the client
was told failed. A parked wallet is therefore resolved by on-chain evidence or cleared by an
operator. That is the deliberate trade: park is a capacity loss, not a correctness risk.

Two residual risks are accepted here and are why parking pages:

- Marking the batch `Failed` also deletes its in-flight locks, so a client retry can duplicate the
  operation if the transaction later lands. `WALLET_RESOLUTION_TIMEOUT_SECS` bounds that window,
  which is why it is generous and why `wallet.parked > 0` is a page.
- A wallet parked by a condition that never resolves stays parked indefinitely: its TTL is
  refreshed every pass. The operator procedure is to verify the nonce on chain and delete the
  record.

Parking is a capacity loss, so when no wallet is acquirable the batcher stops attempting dispatch
and leaves the batch `Batching` (§5.6, §5.7). Requests are then failed by the sweeper's long
`Batching` threshold rather than held forever.

### 5.6 Orphan sweeper, shrunk

Keep a sweeper, scoped to requests that have no owner:

- `Queued` and `age > STALE_QUEUED_THRESHOLD_SECS` → `Failed`. This is the F3 window: the request
  never reached a batcher, or the batcher died before taking ownership. Safe because the batcher
  marks ownership with a guarded `Queued → Batching` write the first time it dequeues a request
  (§5.7), so anything a live batcher holds is not `Queued`.
- `Batching` and `age > STALE_SUBMITTED_THRESHOLD_SECS` → `Failed`. Covers a batcher that died
  holding a batch, and a batch that could not acquire a wallet. The env var name is legacy: it now
  governs the stale-in-progress threshold for `Batching` as well as `Submitted`.
- `Submitted` **and `wallet` is `None`** and `age > STALE_SUBMITTED_THRESHOLD_SECS` → `Failed`.
  This is the pre-P2 compatibility path: records written by the old build carry no wallet and were
  the old sweeper's responsibility. It disappears as those records expire.
- Never touches `Submitted` records that carry a wallet (the resolver owns those).
- Prunes terminal IDs from `gateway:pending_requests` via the restored
  `remove_pending_request`.
- Interval stays `ORPHAN_SWEEPER_INTERVAL_SECS`.
- Its terminal writes are guarded (§5.7): it may only move `Queued`/`Batching` to `Failed`, never
  overwrite `Submitted` or `Finalized`.

**Backlog interaction.** `age` is derived from `updated_at`, so it must not be rewritten while a
request merely waits. The batcher therefore sets `Batching` once, on first dequeue, and never
rewrites it when it requeues a batch that could not acquire a wallet. Backlog urgency keeps
counting `Queued` only, so a batch waiting for a wallet cannot inflate `oldest_age_secs` and
defeat gas-cost deferral; separately, the `NoBacklog` resync must require that the scope has no
`Batching` request either, or a batcher holding dispatched requests would conclude its own Redis
state was lost and drop its local queue.

### 5.7 Acquire, ordering and backpressure

Dispatch sequence, per batch. The guarded writes are single Lua scripts so they are atomic; the
batch-level transition is one script over the whole batch so it is all-or-nothing.

```
1. drain the channel into the local queue            (no status write)
2. on first dequeue of an envelope:
     guarded Queued -> Batching
       mismatch (the sweeper already failed it) -> drop the envelope
       ambiguous error -> re-read; if terminal, drop; else proceed
3. form a batch from the local queue (policy)
4. acquire a lease:
     from a rotating start index, SET NX each candidate
     none free -> wait for a release notification, bounded, then retry
     WALLET_ACQUIRE_TIMEOUT_SECS elapsed -> push the batch to the BACK of the local queue
       and continue the loop; the status stays Batching and updated_at is not rewritten
5. sign
6. persist in_flight (CAS signing -> in_flight)
     on CAS failure -> discard the signature; the lease is already gone or expiring
7. guarded Batching -> Submitted{tx_hash, wallet}, all-or-nothing over the batch
     all ids transitioned -> broadcast
     any id in a different state -> do NOT broadcast; abandon the transaction
     ambiguous error -> re-read the batch; if any id is terminal, abandon; else broadcast
8. broadcast on the pinned provider; write last_attempt_at
```

- Abandoning in step 7 means: CAS `in_flight → absent` (the "abandon before broadcast" row, so the
  resolver will never re-broadcast it), then fail the batch's remaining requests with the guarded
  terminal write. Broadcast is all-or-nothing because a partially-transitioned batch would
  otherwise strand `Submitted` requests with no wallet record.
- The all-or-nothing guard is what closes the sweeper race in both directions: the transaction is
  broadcast only if the requests were still `Batching` at that instant, and once they are
  `Submitted` the sweeper cannot touch them.
- Acquire is a sequence of `SET NX` attempts, deliberately **not** one multi-key script. Each
  `SET NX` is already atomic, so first-success needs no script, and N is small. (Batch-level
  status transitions do use multi-key Lua, which is already how `create_request` and
  `update_status` work, and is why §10 Q6 assumes a non-clustered Redis.)
- Backpressure lives here, not inside submission: when no wallet is free the batch returns to the
  local queue, the queue fills, the local-capacity limit pauses intake, and the bounded channel
  throttles upstream.
- The residual latency floor is real: a release notification is process-local, so it cannot report
  a wallet freed by another replica. `acquire` therefore rechecks every
  `WALLET_TRACKER_INTERVAL_SECS` as well as waiting for a notification, bounding the delay to one
  tracker interval rather than the whole acquire timeout. A cross-replica signal is not worth the
  complexity at this scale.
- `update_status_if` is a new Lua compare-and-set in `RequestStore`: apply the new status only if
  the stored status is in the expected set, and (for `Submitted`) write `tx_hash` and `wallet`.
  This fixes a pre-existing race: `update_status` is today a blind read-modify-write, so the
  sweeper and the receipt tracker can already clobber each other. It adds no new Redis key and no
  new field beyond the additive one of §6.4.
- Record acquire wait in a histogram and count `wallet.acquire_empty`. Saturation must be visible
  (F11), and it is not an error, so it must not look like one.

### 5.8 Resolver loop and supervision

- One supervised task (P1's `JoinSet`), tick every `WALLET_TRACKER_INTERVAL_SECS` (default 2).
- Iterate the configured wallet list, including wallets marked draining, and poll each record with
  bounded concurrency (`buffered(4)`) and per-call timeouts, so one bad RPC cannot stall the pool
  (F10). Every replica runs this loop; concurrent passes are safe because every mutating write is a
  CAS.
- Every pass also refreshes `in_flight`/`parked` TTLs, deletes expired `signing` records (§5.1), and
  runs the §6.4 reconciliation on a slower cadence
  (`WALLET_REBROADCAST_INTERVAL_SECS`).
- **The loop never returns an error.** Per-wallet and per-pass failures are logged and counted and
  the pass ends normally. #949's `supervise` is fail-fast, so an `Err` escaping the loop would
  restart every replica on a Redis blip; the existing sweeper's log-and-continue behaviour
  (`orphan_sweeper.rs`) is the model.
- Startup must not panic on an empty pool (`build_gateway` currently indexes `wallets[0]`); an
  empty pool is a configuration error with a clear message and a `wallet.pool_size = 0` gauge.
- Volume: every replica polls every wallet, so RPC volume scales as replicas × wallets × passes,
  bounded at roughly 5 calls per wallet per pass. At 2 replicas and tens of wallets this is
  negligible; if the pool grows much larger, shard wallets across replicas by address.

### 5.9 In-flight lock lifetime

`INFLIGHT_TTL` (300s) must outlive the submission it protects, otherwise duplicate detection
expires while a request is still `Submitted` (F8). Derive it instead of hardcoding:
`inflight_ttl = WALLET_RESOLUTION_TIMEOUT_SECS + 60` (default 960), plumbed into the `RequestStore`
constructor (the constant is module-private today and `connect` takes only a URL). Locks are
installed at admission, so the useful bound is the longest legitimate admitted-to-terminal time:
a `Queued` request older than `STALE_QUEUED_THRESHOLD_SECS` is failed, and a `Batching` request
older than `STALE_SUBMITTED_THRESHOLD_SECS` is failed, so the admission-to-terminal path is
bounded well below `inflight_ttl`. Existing `gateway:inflight:*` keys keep their meaning and the
legacy-owner tolerance (`owner == request_id or owner == '1'`) is unaffected.

### 5.10 What we are deliberately not building (P2/P3)

Scope note: this is the anti-scope list for the mechanism as it ships first. Stage 3 (§4.3)
revisits two of these deliberately — durable batch records and the safe-head reorg answer.

- No durable batch records, no `gateway:batch:*`, no `gateway:requests:*` queues.
- No post-release reorg observation. Stage 3's `Included` state replaces this deferral; until then
  a post-release reorg is detected only indirectly, via the parked-wallet alert (§5.3).
- No custom distributed nonce manager. With one in-flight transaction per wallet, the node's
  pending count for a leased wallet is unambiguous; `SimpleNonceManager` is sufficient. (This is
  what closed PR #916 tried to build instead.)
- No fee bumping or transaction replacement. Park and alert (§5.5).
- No per-wallet scheduling state beyond the rotating start index.

### 5.11 Configuration

New knobs follow the existing `config.rs` pattern: a `defaults` const, a clap/env field, and a
`validate()` floor. Env names are the SCREAMING_SNAKE form of the field, as
`STALE_QUEUED_THRESHOLD_SECS` maps to `stale_queued_threshold_secs`. The fields live in a
`WalletArgs` sub-struct flattened into `GatewayConfig`, so they are flat on the CLI and in the
environment while staying grouped in the Rust type.

| Env var | Field | Default | Validation |
|---|---|---|---|
| `WALLET_RELEASE_CONFIRMATIONS` | `wallet_release_confirmations` | 1 | `>= 1` |
| `WALLET_RESOLUTION_TIMEOUT_SECS` | `wallet_resolution_timeout_secs` | 900 | `>= 60` |
| `WALLET_TRACKER_INTERVAL_SECS` | `wallet_tracker_interval_secs` | 2 | `>= 1` |
| `WALLET_FIRST_PROBE_DELAY_SECS` | `wallet_first_probe_delay_secs` | 2 | `>= WALLET_TRACKER_INTERVAL_SECS` |
| `WALLET_SIGN_LEASE_SECS` | `wallet_sign_lease_secs` | 30 | `>= 5` |
| `WALLET_ACQUIRE_TIMEOUT_SECS` | `wallet_acquire_timeout_secs` | 20 | `>= 1`, `< STALE_QUEUED_THRESHOLD_SECS` |
| `WALLET_REBROADCAST_INTERVAL_SECS` | `wallet_rebroadcast_interval_secs` | 30 | `>= WALLET_TRACKER_INTERVAL_SECS` |
| `WALLET_REBROADCAST_MAX_ATTEMPTS` | `wallet_rebroadcast_max_attempts` | 10 | `>= 1` |
| `WALLET_STATE_TTL_SECS` | `wallet_state_ttl_secs` | 86400 | `> WALLET_RESOLUTION_TIMEOUT_SECS` |
| `AWS_KMS_WALLET_KEYS` | `SignerArgs` (P3) | unset | mutually exclusive with legacy signer vars; `N` is its element count |
| `WALLET_DRAINING_ADDRESSES` | `wallet_draining_addresses` (P3) | unset | comma-separated; excluded from `acquire()`, still resolved (§5.1) |
| `WALLET_PRIVATE_KEYS` | `SignerArgs` (P3) | unset | as above |

Reused unchanged: `ORPHAN_SWEEPER_INTERVAL_SECS`, `STALE_QUEUED_THRESHOLD_SECS`,
`STALE_SUBMITTED_THRESHOLD_SECS` (widened, §5.6). Derived, not configurable: `inflight_ttl`.

---

## 6. Redis schema and compatibility

### 6.1 The rule

1. **Add, never repurpose.** Never change or remove an existing field of a stored value. New code must decode
   old values, and old code must be able to ignore what it does not understand. The closed
   batch/assignment stack renamed `gateway:inflight:*` → `gateway:resource:*`; during a rolling
   deploy old pods would keep writing locks new pods never consult, letting the same leaf or
   authenticator be operated on twice on chain. Additive changes are the difference between a
   deploy and an incident; the semicolon-formatted `AWS_KMS_KEY_IDS` (F12) is the same mistake in
   a different medium.
2. **New key names for new shapes.** If a shape must change, use a new key name and read both for
   one release; do not version the key name unless you must.
3. **Tolerate, don't migrate.** No migration scripts, no rename jobs, no deletion of keys we no
   longer use. Old keys expire on their own TTLs or are simply never read again.
4. **Additive fields only**, with `#[serde(default)]`. `RequestRecord` has no
   `deny_unknown_fields`, so old records decode into new structs and new records are readable by
   old structs. Do not add `deny_unknown_fields` to a persisted type.
5. **Config formats are a compatibility surface too** (F12): see §4.2 and §8.

### 6.2 Key inventory after this change

| Key | Status | Notes |
|---|---|---|
| `gateway:request:{id}` | unchanged shape, one additive field | JSON `RequestRecord`, TTL 24h; gains `wallet` (§6.4) |
| `gateway:pending_requests` | unchanged | set, no TTL; pruned by the shrunk sweeper |
| `gateway:inflight:{create\|leaf}:{value}` | unchanged shape, longer TTL | legacy `'1'` owner tolerated |
| `gateway:ratelimit:leaf:{index}` | unchanged | zset, TTL = window |
| `gateway:wallet:{address}` | **new** | JSON, TTL `WALLET_STATE_TTL_SECS`, refreshed by the resolver |

One new key family, one member. Nothing renamed, nothing deleted, and no index key: the resolver
iterates local configuration (§5.1, §4.3).

### 6.3 Mixed-version behaviour of the new keys

Old builds never read or write `gateway:wallet*`, so leftover keys are inert and expire. New builds
treat `gateway:wallet*` as the sole authority for "is this wallet in use". The forward path is safe
because the pool keys are provisioned disjoint from the legacy per-ordinal keys (§8). This does
**not** make an image rollback safe on its own — see §8.

### 6.4 Recovery if a wallet record is lost

Redis is the system of record for leases, so the production instance must not evict these keys.
Note that `allkeys-lru`, `volatile-lru` and `volatile-ttl` all evict TTL-bearing keys, so the
requirement is that wallet keys are effectively non-evictable; verify at the infra layer (§10 Q6).

**Status: specified but not implemented in this stack.** The reconciliation below was not built
alongside the rest of P2, and neither were its metrics. The primary control is therefore the
non-evictable Redis configuration. Until it exists, a wallet that leaves configuration while in
flight — or a wallet record that is lost — leaves its requests non-terminal and ownerless, with no
metric to say so. Implementing it is the first follow-up.

The resolver iterates local configuration, so losing a record is otherwise invisible. P2 adds one
additive field to `RequestRecord`:

- `wallet: Option<Address>`, written by the guarded `Batching → Submitted` script (§5.7). The
  transaction hash is not duplicated: it already appears in `GatewayRequestState::Submitted`.

Old records decode with `None`. The reconciliation pass (slow cadence) would scan
`gateway:pending_requests` for `Submitted` records whose `wallet` is set, and:

- if that wallet has a record but is neither configured nor draining, increments
  `wallet.unconfigured` so the stranded lease is visible to an operator;
- if that wallet has no record at all, recreates it as `parked` carrying `tx_hash` and
  `raw_tx: None`, and increments `wallet.orphaned_submitted` and logs at ERROR.

A reconstructed record has no `nonce`, so it can only resolve on a receipt; if the transaction
never mined, it stays parked and requires an operator. This path is a **backstop, not prevention**:
`acquire` checks only the record, so a lost record lets the wallet be reused immediately, and the
reconciliation notices afterwards. The mitigation is the non-evictable Redis configuration.

### 6.5 Migrating to the Stage 3 schema

**There is no data migration, and the design's job is to keep it that way.** Everything that must
survive a release boundary keeps its key name and its existing field shapes; everything new is an
addition. That is not a happy accident — it is why §4.3 keeps the lock key names and supersets the
request record instead of adopting the closed stack's rename and record replacement.

The consequence is that the dual-shape window is bounded by TTLs rather than by a cutover date:

| Data | Compatibility window |
|---|---|
| `gateway:request:{id}` | 24h (`REQUESTS_TTL`) |
| `gateway:inflight:*` | ≤ `inflight_ttl` (§5.9) |
| `gateway:ratelimit:leaf:*` | one rate-limit window |
| new keys (`gateway:batch:*`, `gateway:requests:*`, `gateway:wallet*`) | never read by old builds; inert |

So the whole migration is: **read both shapes for one TTL period, then stop.** No backfill job, no
cutover, no downtime, nothing to clean up — old records expire on their own.

#### Three monotone phases

Each phase is a release. Phases 1 and 2 are safe with *any* mix of pod versions, which is what makes
the sequence work; only phase 3 is gated.

**Phase 1 — expand (safe with any version mix).**
- Superset `RequestRecord` with `payload`, `batch_id`, `wallet` and `tx_hash`, all `#[serde(default)]`.
- Add the new keys. New builds write them for the requests they own; old builds never see them.
- Both builds keep using their own admission and submission paths, serialising on the same,
  unrenamed lock keys. Nothing is removed, and nothing new is read that an old build does not
  already write.
- Old builds must **preserve** the new fields when they update a record they own. `update_status`
  does a full `cjson.decode` → mutate → `cjson.encode`, so it does today — but only by accident of
  using a whole-object round trip. Pin that with a test (§9), and have new builds write through
  field-level Lua (`update_status_if`) so they never depend on the accident.

**Phase 2 — switch authority (safe with any version mix).**
- New builds treat their batch record and the wallet lease as authoritative for the requests they
  own; `RequestRecord::status` becomes a **mirror**, maintained for old builds' `/status` responses
  and for the legacy fallback.
- Compatibility holds because ownership is exclusive via the lock and both builds agree on the lock
  keys and the statuses they read. An old build's sweeper can still blind-write `status`; because the
  new build resolves from the batch record rather than from `status`, that clobbers only the mirror.
  The existing 600s `Batching` threshold keeps the two in agreement in practice, since a request a
  new build is actively resolving never reaches it.
- Requests admitted by an old build have no payload and cannot be resealed, so new builds fail them
  on the existing thresholds, exactly as today. The class disappears as old records expire.

**Phase 3 — contract (gated).**
- Delete the legacy paths: the in-memory queue as source of truth, the sweeper's wallet-less
  `Submitted` path, the legacy admission path.
- This is the only phase unsafe with a mixed fleet, and it is pure code deletion — it introduces no
  new state.
- It does not need a fleet-version marker. Because phases 1–2 removed nothing, "is every pod new?"
  is answered by ordinary release ordering: phase 3 ships in a release after phase 2's rollout has
  completed, and a rollback that reintroduces old builds still works, because phase 2's state is
  additive and phase 3 deleted only code that reads nothing new.

#### Rollback

Rollback safety is one rule: **an old build must be able to ignore everything a new build wrote.**
It can for batch records, queues, assignments and additive fields — they are inert. It cannot for the
wallet lease: ignoring `gateway:wallet:{address}` means reusing a wallet whose transaction may still
be outstanding, which is the I1 violation §8 already calls out. So the only operator check before a
rollback is "no live `in_flight`/`parked` record on a wallet this build is about to use".

#### The one case that would force a real migration

A rename, or a change to an existing field's name or type, cannot be made compatible: old builds
read the old location, and you cannot know which location they read. If one is ever unavoidable, the
recipe is expand/contract:

1. add the new key, keeping the old one authoritative;
2. write both in the same atomic script, so a crash cannot leave them divergent;
3. read both with a documented precedence (new, then old) and a counter on the fallback path;
4. backfill lazily on read rather than with a batch job, so a key is never absent from both places;
5. delete the old key a release after the last reader is gone — and prefer letting its TTL do it,
   which for the request records costs exactly 24h.

This plan insists on keeping the lock names and supersetting the record precisely because this
recipe is expensive and its failure mode is duplicate on-chain operations. Avoiding it once is
cheaper than doing it correctly.

#### Gaps to fix before Stage 3 ships

- **Durable queue members leak.** `oldest_queued` skips members whose request record is missing
  without `ZREM`ing them, and `queue_len` is a `ZCARD`. A record that expires (24h TTL) while still
  queued therefore leaves a permanent member that inflates the length forever — and that length
  feeds the batch policy's backlog signal, so it becomes a slow-burn control bug. `fail_queued`
  cannot repair it either, since it errors when the record is missing. Fix in R1: `ZREM` on the
  missing-record path, and reconcile the queues against `gateway:pending_requests` on a slow cadence.
- **New keys need TTLs or explicit cleanup**, or the migration creates permanent garbage. The
  existing `gateway:pending_requests` set (no TTL) is the cautionary example. Batch records and
  assignments should carry a TTL beyond any possible resolution window; the ready-batch index needs
  the same treatment as the queues.
- **`gateway:wallet-assignment:{address}` has no TTL** in the closed design and is deleted only by
  `finalize`/`fail`. A batch that reaches neither — a crashed resolver, a lost key — leaves a
  permanent assignment. Give it a TTL longer than `WALLET_RESOLUTION_TIMEOUT_SECS` so the failure is
  bounded.

---

## 7. Observability

Metric names follow the existing flat convention (`batch.submitted`, `batch.size`,
`batch.success`, `batch.failure`, `batch.send_failed` in `metrics.rs`). There is no `gateway.`
prefix and none should be introduced. Declare each with `metrics::describe_*`.

| Metric | Type | Purpose / alert |
|---|---|---|
| `wallet.pool_size` | gauge | configured wallets; `0` ⇒ misconfiguration, alert |
| `wallet.in_flight` | gauge | pool utilisation; equal to pool size ⇒ saturated, scale wallets |
| `wallet.parked` | gauge | **> 0 ⇒ page**: wallets are out of service and requests were failed |
| `wallet.unconfigured` | gauge | **not implemented** — §6.4 backstop deferred (§6.4) |
| `wallet.orphaned_submitted` | counter | **not implemented** — §6.4 backstop deferred (§6.4) |
| `wallet.acquire_wait_ms` | histogram | queueing delay caused by the pool |
| `wallet.acquire_empty` | counter | saturation signal, **not** an error; alert on sustained growth |
| `wallet.outcome{outcome}` | counter | `confirmed` / `reverted` / `replaced` / `parked` — includes park, which is not a release |
| `wallet.time_in_flight_ms` | histogram | per-wallet turnaround |
| `wallet.confirmations_at_release` | histogram | evidence for `WALLET_RELEASE_CONFIRMATIONS` |
| `wallet.rebroadcast` | counter | ambiguous broadcast, crash, or mempool eviction |
| `wallet.tracker_error` | counter | RPC failures in the resolver; sustained ⇒ RPC/Redis problem |
| `batch.success`, `batch.failure`, `batch.latency_ms` | existing | keep; measure latency from `submitted_at` |

Logging: DEBUG on lease acquire and release (these happen at batch rate); INFO on park, on the
first re-broadcast of a transaction, and on the §6.4 reconciliation; never per-poll success logs.
Do not log private keys. Signed bytes are public once broadcast, but keeping them out of logs
avoids a needless secret-scanning fight.

Health probes: keep liveness independent of Redis and RPC. Readiness must not go false merely
because some wallets are parked — all replicas would leave rotation at once and amplify the outage.
A parked pool is an alerting condition, not a probe condition.

---

## 8. Rollout

The pool KMS keys must be provisioned **disjoint** from the legacy per-ordinal keys. That is what
makes a rolling config change safe: an updated pod uses pool keys, an un-updated pod uses its
ordinal key, and no wallet is ever driven by two processes (I4).

**Phase A — P1.** Deploy the supervision/app-container refactor. Request handling and transaction
submission are unchanged; supervision becomes fail-fast.

**Phase B — staging.** Deploy P2 + P3 with `AWS_KMS_WALLET_KEYS` on staging (one replica, several
wallets). Run the §9 benchmark against the real chain and soak. **Go/no-go: if the leased pool does
not beat `main`, stop; revert to `main` and keep only P1.**

**Phase C — prod.** In **one** template change, set `AWS_KMS_WALLET_KEYS` to the disjoint pool keys
and remove the legacy signer vars. Because the swap is atomic per template, no pod ever carries
both forms, so the §4.2 fail-closed check never fires and no pod is in the overlap state. Pods
that have not restarted yet keep running on their legacy ordinal keys, which is safe because the
key sets are disjoint. Retire the legacy keys after every replica reports the new build and a pool
size > 0.

Do not enable the pool on a wallet set that overlaps the legacy keys, and do not skip Phase B.

**Rollback.** Before reverting the image on any wallet that may hold a live `in_flight` or `parked`
record, confirm no such record exists (drain, or let the resolver resolve them). The TTL backstop
makes the key expire, but an old build that does not read the key reuses the wallet immediately —
that is an I1 violation, not a protected path. Reverting only the configuration, keeping the new
build, is safe: it collapses to one wallet per pod, which is slower but correct.

**Capacity.** After the infra change of §4.1, adding wallets is a config edit. Watch
`wallet.acquire_empty` and `wallet.in_flight` before and after; do not raise the pool without
watching the RPC node's error rate.

---

## 9. Test plan

Harness: testcontainers Redis + hermetic anvil (#956, #961), plus a mock provider for deterministic
RPC failure injection and a two-endpoint provider for pinning.

**Unit / Redis-only**

- Lease exclusivity: two concurrent acquires over one wallet yield one lease.
- Expired `signing` lease: reclaimable by the resolver, and nothing was broadcast if the
  `signing → in_flight` CAS fails (R1).
- Resolver matrix, on a pinned provider:
  - receipt `Ok(Some)`, canonical, success, enough confirmations → `Finalized`, released;
  - receipt `Ok(Some)`, confirmations below threshold → waits, wallet retained;
  - receipt `Ok(Some)`, `block_number` ahead of `head` → waits, no underflow;
  - receipt `Ok(Some)`, block no longer canonical → falls through to the probe;
  - receipt `Ok(Some)`, reverted → `Failed`, released;
  - receipt `Err` → unchanged, `wallet.tracker_error` incremented, **never** resolves;
  - receipt `Ok(None)`, `get_transaction_by_hash` `Some` → waits;
  - receipt `Ok(None)` then `latest > nonce`, but a re-read finds the receipt → resolves as
    success, does **not** report `replaced` (the step-1/step-4 TOCTOU);
  - receipt `Ok(None)`, `latest > nonce`, still absent on re-read → `Failed(replaced)`, released;
  - receipt `Ok(None)`, `pending > nonce` → waits;
  - receipt `Ok(None)`, nonce free → re-broadcasts, honours the interval, retains the lease,
    increments `attempts`;
  - send error `already known` → waits; the attempt is already claimed before the send;
  - end-to-end endpoint disagreement: a second URL one block behind must not fail a successful
    transaction.
- Crash between `in_flight` persist and the guarded transition: the resolver writes the request
  statuses from the record and resolves them; they are not left `Batching` until the sweeper.
- Guarded transitions: the sweeper cannot turn `Submitted`/`Finalized` into `Failed`; the batcher's
  all-or-nothing `Batching → Submitted` either transitions the whole batch or none of it; a
  partially-failed guard abandons without broadcasting.
- Abandon-before-broadcast: the `in_flight → absent` CAS holds, and the resolver never re-broadcasts
  that transaction.
- Parked wallet: resolves on `latest > nonce` and on a late receipt; does **not** resolve or
  re-broadcast on mempool absence alone.
- R2: a failing status write keeps the record; the next pass releases once it succeeds. An expired
  request record counts as terminal.
- Concurrent resolver passes over one `in_flight` record produce one re-broadcast and one `attempts`
  increment (`last_attempt_at` CAS).
- Requeue does not rewrite `updated_at`, so a wallet-starved batch still ages into the sweeper
  threshold.
- Legacy records: no `wallet` field, legacy `'1'` in-flight owner → decoded, and the sweeper fails
  a legacy `Submitted` after the long threshold.
- **Field preservation across versions** (§6.5 phase 1): a record written by a new build with all
  additive fields set, then updated by the legacy `update_status` path, retains every additive field.
  This pins the accident the whole migration rests on; if that Lua is ever changed to a partial
  write, the migration silently starts dropping data.
- **Durable queue reconciliation** (§6.5): a request record that expires while still a queue member
  is removed from the queue by `oldest_queued`; `queue_len` does not drift upward across expiries.
- §6.4: delete a wallet record under a live `Submitted` request; assert the reconciliation recreates
  it as parked, re-adds the index entry, and increments `wallet.orphaned_submitted`.
- Sweeper: fails stale `Queued` and stale `Batching`, leaves wallet-bearing `Submitted` untouched,
  prunes the pending set, and does not fire for a request a live batcher holds.
- Backlog: urgency counts `Queued` only; the `NoBacklog` resync does not fire while a `Batching`
  request exists for the scope.

**Integration (Redis + anvil)**

- N wallets, N concurrent batches: every wallet has at most one hash in flight at any observed
  instant, and per-wallet nonces are consecutive from a common base.
- Crash recovery: drop the submitter mid-flight, rebuild it, assert the lease is found, the
  transaction resolves, and the wallet is reused.
- Never lands: broadcast to a node that drops it; assert re-broadcast fires and the wallet is not
  freed before resolution.
- Stuck: force the resolution timeout with an undecidable nonce; assert `ConfirmationError`, the
  wallet parks, is excluded from acquire, and resolves once the nonce is provably mined.
- Pool starved: park every wallet; assert the batcher stops dispatching, does not spin, returns
  batches to the local queue, does not refresh their age, and that they are failed by the long
  `Batching` threshold.
- Pool shrink: remove a wallet from local config while in flight; assert the resolver still resolves
  it and `wallet.unconfigured` fires.
- Reorg: if the pinned anvil supports `anvil_reorg`, reorg out a released transaction and assert the
  downstream wallet parks and alerts (detection, not repair — §5.3, §5.10). Verify anvil support
  first; otherwise use the mock provider.

**Benchmark (Phase B gate)**

Same offered load against `main`, N=1 leased, and N=k leased; publish throughput and p99 latency.
This replaces the current bench, which compares unlike configurations, and is the evidence for §5.3.

---

## 10. Open questions

1. **What chain, and what are its safe/finalized latencies and practical reorg depth?** The
   production RPC URL is in Secrets Manager (`prod/world-id-gateway/rpc`), so this could not be
   confirmed from the repo. It fixes `WALLET_RELEASE_CONFIRMATIONS` (§5.3). Owner: gateway
   maintainer.
2. **What peak transaction rate must the gateway sustain?** Determines `N`: with release on receipt
   at ~2s, `N ≈ 2 × batches/s`. Owner: gateway maintainer.
3. **Does the pool beat `main` at all?** §9's benchmark decides. Answer in Phase B.
4. **Infra: provision pool KMS keys disjoint from the legacy per-ordinal keys**, decoupled from
   `gateway_replica_count`. Owner: platform; `world-id-protocol-deploy`.
5. **Who receives the `wallet.parked` alert?** Assumed Datadog; confirm the monitor owner.
6. **What is production Redis's topology, eviction policy and persistence mode?** Wallet keys must
   be non-evictable (§6.4). Note that the existing `create_request`/`update_status` Lua scripts
   already span `gateway:request:*` and `gateway:pending_requests`, so the gateway already assumes
   a non-clustered Redis; this plan does not change that assumption.
7. **Does the StatefulSet use an ordered update policy?** The "pod N is replaced only after pod N-1"
   argument behind the disjoint-key rollout holds under `OrderedReady`; confirm it. Even under
   `Parallel`, disjoint key sets make the rollout safe.
8. **Is Stage 3 (§4.3) worth doing at all?** Its behavioural gain over P2/P3 is recovering unsent
   work after a pod restart, which a client retry already covers today; the rest is durability,
   maintainability and a correct reorg answer. Decide after P2/P3 are stable and the pool's
   throughput is proven, not before. Owner: gateway maintainer.

---

## 11. Refinement log

**Post-refinement revision (v4 → v5), not part of the three rounds.** The author challenged the
disposition "keep the closed batch/assignment stack abandoned" (§2.5, §4) on the grounds that it is
a reasonable refactor. Re-reading the stack, the challenge was right about its quality and its
compatibility, and the earlier disposition is revised in §4.3 and §2.5:

- adopted as the Stage 3 target architecture, because its write-ahead `PreparedSubmission` is what
  §5.4 re-derives, its `Included`/safe-head state answers the reorg question §5.3 defers, and its
  documented `fail()` caller contract is exactly §5.4 step 4;
- recorded that it is only about half implemented — `record_prepared_submission`,
  `mark_submission_broadcast`, `mark_included`, `finalize`, `fail` and all of `AssignmentRepository`
  are `unimplemented!()`, so Stage 3 is new work rather than a revert of the closure;
- identified the two compatibility blockers that made it non-additive (the cosmetic lock rename and
  the `StoredRequest`/`RequestRecord` shape replacement) and the free fix for each;
- adopted its "Redis never enumerates or introduces wallets" principle, which **removed** the
  proposed `gateway:wallets` index key and replaced it with config-derived iteration plus a draining
  list (`WALLET_DRAINING_ADDRESSES`), keeping the `Submitted`-request reconciliation as the backstop.
  This is a net simplification: one new key family, one member.

Also carried over from that revision: §5.10 is now explicitly scoped as the anti-scope list for
P2/P3, since Stage 3 revisits two of its items deliberately.

**Migration procedure added (§6.5).** The revision left the schema question unanswered — §6.1 had the
rules and §8 had the rollout, but nothing stated the procedure for moving between them. §6.5 now
records that there is no data migration by construction, that the dual-shape window is bounded by
the existing TTLs (24h for request records) rather than by a cutover, the three monotone
expand/switch/contract phases with the compatibility argument for each, the single rollback
exception, the general expand/contract recipe for the rename case this design avoids, and three gaps
to fix before Stage 3 ships (durable queue members leaking on record expiry, missing TTLs on new
keys, and the assignment key having no TTL at all).

This section is an author revision of an unreviewed document, not a reviewed change; the three
rounds below predate it and do not cover it.

Three adversarial rounds were run, each with three independent reviewers (correctness against the
stated mechanism, robustness of failure paths, readability/operability) against a frozen snapshot,
followed by triage and targeted edits by the coordinator. Reviewers were read-only; no other review
of this document has taken place.

**Round 1 — v1 → v2.** Blocking correctness findings: the resolver's nonce probe misclassified a
mined-but-not-yet-observed transaction as `replaced` and freed a live wallet; an RPC error was
indistinguishable from an absent receipt, making a transient failure fatal; releasing on one
confirmation could not be protected by a post-release canonicality check. Blocking spec gaps: the
`parked` state was used but not defined; the `in_flight` TTL was unspecified; the 24h backstop
contradicted "park, don't free". Also accepted: the sweeper could fail requests legitimately waiting
for a wallet; finalization failures were swallowed; the lost-record recovery was unimplementable;
mixed-version config was unsafe; the sweep happened after the production regression; pool shrink and
Redis loss orphaned leases; the rebroadcast path had no backoff; the multi-key acquire script broke
on Redis Cluster. Readability findings accepted: config knobs had no single table; metric names
invented a `gateway.` prefix; infra citations did not name the other repo; `flume` was unjustified.
Applied in v2. Rejected/deferred: `flume` kept out (accepted), the acquire latency floor could not
be eliminated without a cross-replica signal and is documented as a known cost, and the document
location (`services/gateway/`) was kept deliberately rather than moved to `docs/WIPs/`.

**Round 2 — v2 → v3.** Blocking: §5.6 and §5.7 contradicted each other on whether `Batching` is set
before or after `acquire`, reopening the sweeper race from round 1; and Phase B still deployed the
serialised single-wallet path before the benchmark gate. Also accepted: `head - block_number` could
underflow and panic a fail-fast supervisor; cross-endpoint disagreement could fail a healthy
transaction; `already known` was misclassified as a permanent rejection; parked-wallet resolution
rules contradicted the probe; the index set could desynchronise; the guarded transition did not
close the sweeper race in both directions; §6.4 was unimplementable because a request record carries
no wallet; "independently mergeable" was false for P2/P3; the rebroadcast interval had no persisted
state. Applied in v3. Rejected: renaming `STALE_SUBMITTED_THRESHOLD_SECS` (avoid churn; a note
marks the name as legacy) and relocating the document.

**Round 3 — v3 → v4.** Blocking: a crash between the `in_flight` persist and the guarded
`Batching → Submitted` transition left requests un-finalizable, because the resolver was not
allowed to own that transition; the dequeue-time `Batching` write was unguarded, so a `Failed`
request could be revived and broadcast; Phase C could not execute under the fail-closed check
because the pod template would briefly carry both signer forms; and the first P2 deploy orphaned
pre-existing `Submitted` records, which the old sweeper used to handle. Also accepted: the
endpoint-pinning TOCTOU between the receipt lookup and the nonce probe; `already known` consuming
rebroadcast attempts and parking a live transaction; the requeue loop refreshing `updated_at` so
the sweeper threshold never fired; §6.4 having no executor and no recoverable nonce; the resolver
being able to return `Err` into fail-fast supervision; the resolver's blanket TTL refresh
extending a dead `signing` lease to 24h and the `signing → absent` transition have no actor; the
first-probe delay of 30s contradicting the 2s throughput model; front-pushing a starved batch
starving later ones; the index-set prune race (resolved by removing the prune entirely); and
several precision fixes (where the signer vars live, `inflight_ttl` plumbing, `update_status_if`
atomicity, INFO vs DEBUG volume, metric semantics, stale metric naming). Applied in v4.

**Deferred with residual risk stated in the document.** Releasing on `k` confirmations cannot
guarantee I1 against a reorg deeper than `k` without chain-watching, so §5.3 states the assumption
and §10 Q1 fixes the value. Marking a parked batch `Failed` releases its in-flight locks, so a
client retry can duplicate an operation if the transaction later lands; §5.5 states this and bounds
it with a generous resolution timeout plus a page on `wallet.parked`. A parked wallet resolved by
nothing requires an operator; §5.5 gives the procedure. §6.4 is a detection backstop, not
prevention, and says so.

**Quality gate: passed, with one qualification.** Three rounds completed, all three roles in each
round against a frozen snapshot, every round-1 and round-2 accepted fix re-reviewed in the
following round, and no supported blocking finding left unresolved. The user's budget of three
rounds means the round-3 edits were **not** re-reviewed adversarially; instead they received a
bounded consistency pass by the coordinator (stale-term grep, section-reference resolution, and a
cross-check of the schema, metric and config tables against the prose), which found and fixed two
wording contradictions: `update_status_if` was described as "changing no value shape" while also
adding two fields, and the additivity rule read as forbidding the field additions that rule 4
permits. Residual risk: an unreviewed final-round edit is the exact condition the refinement
protocol warns about, so treat the round-3 fixes as reviewed-by-author. Executable verification is
not applicable to a plan; code-level claims were checked against `main` and the #937/#949 branches
by file and line, but no test or build was run, and the production facts in §10 remain unverified
from this repository.
