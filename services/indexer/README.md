# World ID Indexer

The World ID Indexer indexes Account Registry events from the World ID Protocol into a PostgreSQL database and maintains an in-memory Merkle tree used to serve inclusion proofs.

## Architecture

### Run Modes

The indexer supports three run modes, selected via the `RUN_MODE` environment variable:

- **`both`** (default) — runs the indexer and HTTP server in the same process, sharing the same DB and tree
- **`indexer`** / **`indexer-only`** — only streams and indexes chain events, no HTTP server
- **`http`** / **`http-only`** — only serves the HTTP API; relies on a separate indexer process writing to DB and polls DB periodically to sync the tree

### Event Processing

The indexer connects to the chain via HTTP + WebSocket RPC. On startup it backfills from the last indexed block (or `START_BLOCK` if the DB is empty), then transitions to live WebSocket streaming.

Events are processed through `EventsCommitter`, which:

1. Buffers incoming `AccountCreated`, `AccountUpdated`, `AuthenticatorInserted`, `AuthenticatorRemoved`, and `AccountRecovered` events in memory.
2. On each `RootRecorded` event, simulates the resulting Merkle root and verifies it matches the on-chain value, then commits the buffered batch atomically to PostgreSQL, and finally applies the leaf changes to the in-memory Merkle tree.
3. The tree is only mutated after a successful DB commit; a root mismatch aborts without touching the tree.

### In-Memory Merkle Tree

The Merkle tree is a `CascadingMerkleTree` using the Poseidon2 hash function backed by a memory-mapped file (`TREE_CACHE_FILE`). The mmap backing means the tree persists across restarts without a full DB replay.

On startup:

- If the mmap file exists, the tree is restored from it. The restored root is validated against the DB: if no matching `RootRecorded` event is found in the DB the cache is considered stale and deleted, and the process exits. If valid, DB events from genesis are replayed on top of the restored tree to bring it up to date.
- If no mmap file exists, the tree is built from scratch from the accounts table and all DB events are replayed.

During normal indexing, the tree is wrapped in a `VersionedTreeState` that records a per-leaf change history bounded by `TREE_MAX_BLOCK_AGE` blocks. This history is used for in-memory rollbacks on reorg.

In `HttpOnly` mode the tree is not versioned; instead a background loop polls the DB at `DB_POLL_INTERVAL_SECS` and incrementally syncs new events into the tree.

### HTTP API

The HTTP server serves inclusion proofs for public keys. It is backed by the shared DB and in-memory tree. An optional periodic sanity check (`SANITY_CHECK_INTERVAL_SECS`) calls `isValidRoot` on the registry contract to verify the in-memory root is still valid on-chain.

### Reorg Handling

Reorgs are detected during batch commit in two ways:

1. **Block hash conflict** — an event with the same `(block_number, log_index)` already exists in the DB but with a different `block_hash` or `tx_hash`.
2. **Root mismatch** — the simulated root for the batch does not match the `RootRecorded` value in that batch (checked before commit; the tree is not modified).

When either condition is detected, `rollback_to_last_valid_root` is called. It walks backwards through `RootRecorded` events in the DB (newest first) and for each one queries the chain to verify that a log at the same block and log index still exists with the same root value. The first event that passes this check becomes the rollback target. The rollback then:

1. Deletes all DB events after the target event.
2. Re-applies the remaining events for any affected leaves to restore the `accounts` table to a consistent state.
3. Rolls back the in-memory `VersionedTreeState` by replaying per-leaf history in reverse.

After a successful rollback, `process_registry_events` returns a `ReorgDetected` error, which propagates up and terminates the process. **A restart is required.** On restart the indexer follows the normal startup procedure:

1. The tree is re-initialized from the mmap cache (which reflects the rolled-back state, since tree writes flush through to the mmap immediately). DB events are replayed from first event to bring the tree fully up to date with the rolled-back DB.
2. The indexer backfills from the last DB block forward, re-fetching the blocks that were removed by the rollback.

This restart-on-reorg pattern — detect, rollback state, exit cleanly, re-initialize on restart — has been used across multiple World ID Protocol services in the past. The alternative of recovering in-process adds significant complexity and is error-prone when in-flight state (buffered events, stream cursors, tree snapshots) is partially corrupted by the reorg. Also reorgs on World Chain are quite rare.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | required | PostgreSQL connection string |
| `RPC_URL` | required | HTTP RPC endpoint |
| `WS_URL` | required | WebSocket RPC endpoint |
| `REGISTRY_ADDRESS` | required | `AccountRegistry` contract address |
| `TREE_CACHE_FILE` | required | Path to mmap-backed tree cache file |
| `RUN_MODE` | `both` | `both`, `indexer`, or `http` |
| `START_BLOCK` | `0` | Block to start indexing from if DB is empty |
| `BATCH_SIZE` | `64` | Blocks per RPC batch during backfill |
| `TREE_DEPTH` | `30` | Merkle tree depth |
| `TREE_MAX_BLOCK_AGE` | `1000` | Blocks of per-leaf history kept for rollback |
| `HTTP_ADDR` | `0.0.0.0:8080` | Address for the HTTP server |
| `DB_POLL_INTERVAL_SECS` | `1` | DB poll interval in `HttpOnly` mode |
| `REQUEST_TIMEOUT_SECS` | `10` | HTTP request timeout |
| `SANITY_CHECK_INTERVAL_SECS` | unset | Interval for root sanity check; disabled if unset or `0` |
| `ENVIRONMENT` | `development` | `production`, `staging`, or `development` |

## Developing Locally

1. Set up your environment variables:

```
cp .env.example .env
```

2. Run Postgres (e.g. through Docker):

```
docker compose -f services/docker-compose.yml up
```
