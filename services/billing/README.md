# world-id-billing

Off-chain operator service for [WIP-107](../../docs) experimental transactional
fees. It operates against the on-chain Billing Contract on World Chain.

The service is a **modular monolith** with two independently-deployable workers,
selected via `--role`:

- **`finalizer`** — the permissionless keeper that drives epoch finalization.
  Finalization is keeper-driven in the contract: `finalizeEpochs` is the only
  call that advances the finalization cursor, and an epoch becomes finalizable
  purely by wall-clock time (once its voting window closes) — no event signals
  it, and vote-less epochs emit no events at all but still need the cursor
  advanced past them. Rather than polling on a fixed interval, the worker
  computes the exact moment the current cursor's voting window closes
  (`epochEnd` + `votingWindow`, both exposed by the contract) and sleeps to
  it; after waking it briefly confirms the chain reflects the close (bridging
  RPC lag / clock drift) before draining via bounded `finalizeEpochs`
  transactions. (Vote submission is out of scope: OPRF nodes' EIP-712 signed
  votes are relayable by anyone via `submitBillingVotes`.)
- **`payer`** — settles finalized epoch fees in WLD on behalf of relying parties
  before the payment deadline (a permissionless paymaster), batching across RPs
  with a per-RP slippage guard. *Not yet implemented.*

Running the workers as separate processes from the same image keeps their
signing keys and blast radius isolated (the payer holds a WLD spending key; the
finalizer only needs a gas key).

## Run

```sh
world-id-billing --role finalizer
world-id-billing --role payer
```

Configuration is read from the environment (see `.env.example`). The finalizer
requires a funded signer (`WALLET_PRIVATE_KEY` or AWS KMS) — `finalizeEpochs`
is permissionless, so any gas-funded key works.

## Failure behavior

- Failed cycles (a cursor/deadline read, or a `finalizeEpochs` drain) are
  logged and counted, then retried next cycle from fresh on-chain state — the
  confirm-retry interval is the backoff, so there is no retry storm.
  `finalizeEpochs` is idempotent: re-driving it after a partial failure is
  always safe.
- After waking at a computed deadline, the worker confirms the chain reflects
  the close by retrying every `FINALIZER_CONFIRM_RETRY_INTERVAL_SECS` up to
  `FINALIZER_CONFIRM_MAX_ATTEMPTS`. Exhausting that bound is treated as fatal
  — the worker exits with an error rather than degrading to a silent poll
  loop, since it signals either persistent RPC degradation or a
  systematically wrong deadline. Kubernetes' restart policy takes it from
  there, the same self-healing property RPC reconnects already rely on.
- Work per transaction is bounded (`FINALIZER_MAX_STEPS_PER_TX`) so a large
  epoch cannot produce an unminable transaction; a single drain always fully
  catches up the backlog (or errors), since each transaction is guaranteed
  forward progress by the contract while backlog remains.
- RPC reads and transaction submissions are bounded by the provider layer's
  per-request timeout and retry budget (with fallback across endpoints).
  Receipt waits additionally carry a worker-level deadline
  (`FINALIZER_RECEIPT_TIMEOUT_SECS`), since a transaction that never mines
  would otherwise block the worker forever.

## Observability

Emitted via `telemetry-batteries` (Datadog-compatible):

- `billing.finalizer.epoch_lag` (gauge) — closed-but-unfinalized epochs.
  0 = caught up; sustained growth means finalization is falling behind (e.g.
  RPC outage or the gas key ran dry) and RP debt / blocking state is going
  stale. Alert on this.
- `billing.finalizer.finalize_attempts` (counter, `outcome` label) —
  `finalizeEpochs` transaction attempts: `success`, `revert_on_chain`,
  `rpc_error`, `timeout`.
- `billing.finalizer.tick_failures` (counter) — failed finalizer cycles
  (cursor/deadline read or a `finalizeEpochs` drain).
- `billing.finalizer.confirm_retries` (counter) — confirm-loop retry attempts
  after waking at a computed deadline. Occasional retries are expected; a
  sustained rate signals persistent RPC lag and precedes a fatal
  confirm-timeout (worker crash) if it doesn't clear.
