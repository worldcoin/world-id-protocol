# Tree Cache Architecture

This document describes how the indexer manages the memory-mapped (mmap) merkle tree cache, including operational modes, file operations, and synchronization behavior.

## Table of Contents

- [Operational Modes](#operational-modes)
- [Mmap Tree Files](#mmap-tree-files)
- [Tree Initialization](#tree-initialization)
- [Tree Updates](#tree-updates)
- [Cache Synchronization](#cache-synchronization)
- [Memory and Disk Operations](#memory-and-disk-operations)
- [Performance Characteristics](#performance-characteristics)

---

## Operational Modes

The indexer supports three operational modes configured via `RUN_MODE` environment variable:

### IndexerOnly Mode

**Purpose**: Sync blockchain events to the database without maintaining an in-memory tree.

**Behavior**:
- Listens to blockchain events via WebSocket or batched HTTP requests
- Writes events to `commitment_update_events` table
- Updates `accounts` table with latest state
- **Does not** initialize or maintain the merkle tree
- **Does not** create or update mmap cache files
- **Does not** serve HTTP API requests

### HttpOnly Mode

**Purpose**: Serve API requests using a cached tree, periodically syncing with database updates.

**Behavior**:
- Initializes tree from mmap cache on startup (or builds from DB if cache missing)
- Loads entire tree into memory for fast proof generation
- Periodically checks database for new events
- Syncs tree with new events when detected
- Serves `/inclusion-proof` and other API endpoints
- **Does not** listen to blockchain events

### Both Mode (Default)

**Purpose**: Combined indexer and API server in a single process.

**Behavior**:
- Performs all IndexerOnly operations (event indexing)
- Performs all HttpOnly operations (API serving)
- Updates tree in real-time as events are indexed
- Writes metadata after each batch of events
- Most efficient for single-node deployments

---

## Mmap Tree Files

The tree cache consists of two files:

### 1. Tree Cache File (`.mmap`)

**Location**: Configured via `TREE_CACHE_FILE` environment variable (e.g., `/data/tree.mmap`)

**Contents**:
- Binary representation of the merkle tree structure
- Organized as a dense prefix (default depth: 26) followed by sparse storage
- Size: Depends on tree depth and number of active leaves (typically several GB)
- Format: Platform-specific, memory-mapped directly into process address space

**Structure**:
```
┌─────────────────────────────────────┐
│ Dense Prefix (depth 0-26)           │  ← Contiguous node storage
│ - Fast access, cache-friendly       │
├─────────────────────────────────────┤
│ Sparse Storage (depth 27-30)        │  ← On-demand node allocation
│ - Only allocated nodes stored       │
└─────────────────────────────────────┘
```

### 2. Metadata File (`.mmap.meta`)

**Location**: Same directory as tree file, with `.mmap.meta` extension

**Contents**: JSON file with synchronization metadata
```json
{
  "root_hash": "0x1234...",
  "last_block_number": 12345678,
  "last_event_id": 98765,
  "active_leaf_count": 50000,
  "tree_depth": 30,
  "dense_prefix_depth": 26,
  "created_at": 1234567890,
  "cache_version": 1
}
```

**Key Fields**:
- `root_hash`: Tree root at time of last cache write (for validation)
- `last_block_number`: Last blockchain block processed (informational)
- `last_event_id`: **Primary sync cursor** - auto-incrementing ID from `commitment_update_events` table
- `active_leaf_count`: Number of non-zero leaves (accounts created)
- `tree_depth`: Tree configuration (default: 30)
- `dense_prefix_depth`: Dense storage optimization depth (default: 26)
- `cache_version`: Format version for future compatibility

**Why Event ID as Cursor?**

The `last_event_id` field uses the auto-incrementing primary key from the `commitment_update_events` table rather than `block_number`. This handles blockchain reorganizations correctly:

- During a reorg, events may be inserted with older block numbers after newer ones
- Event IDs always increase monotonically regardless of block_number
- Replaying from `last_event_id` ensures all events are captured

---

## Tree Initialization

### Startup Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Check Cache Files                                        │
│    - Does .mmap file exist?                                 │
│    - Does .mmap.meta file exist?                            │
└──────────┬──────────────────────────────────────────────────┘
           │
           ├─ Both Missing ────────┐
           │                       ▼
           │              ┌──────────────────────┐
           │              │ Full Rebuild         │
           │              │ - Fetch all accounts │
           │              │ - Create new tree    │
           │              │ - Write both files   │
           │              └──────────────────────┘
           │
           ├─ One Missing ─────────┐
           │                       │
           │                       ▼
           │              ┌──────────────────────┐
           │              │ Full Rebuild         │
           │              │ (cache corrupted)    │
           │              └──────────────────────┘
           │
           └─ Both Present ────────┐
                                   ▼
                          ┌──────────────────────┐
                          │ Restore & Replay     │
                          │ - Restore from mmap  │
                          │ - Verify root hash   │
                          │ - Replay new events  │
                          └──────────────────────┘
```

### Restore & Replay Process

1. **Read Metadata**
   - Parse `.mmap.meta` JSON file
   - Extract `last_event_id` and `root_hash`

2. **Restore Tree from Mmap**
   - Memory-map the tree file into process address space
   - OS loads pages on-demand
   - Most pages already in OS page cache if recently used

3. **Verify Root Hash**
   - Compute tree root from restored tree
   - Compare with `root_hash` from metadata
   - If mismatch: fall back to full rebuild

4. **Check for New Events**
   - Query: `SELECT MAX(id) FROM commitment_update_events`
   - Compare with `last_event_id` from metadata
   - If equal: tree is up-to-date

5. **Replay Events**
   - Fetch events in batches: `SELECT * FROM commitment_update_events WHERE id > $1 ORDER BY id LIMIT 10000`
   - Deduplicate in memory (multiple updates to same leaf → keep final state)
   - Apply updates to tree: `tree.update_with_mutation(leaf_index, value)`
   - Update metadata with new `last_event_id`

### Full Rebuild Process

1. **Fetch All Accounts**
   - Query: `SELECT leaf_index, offchain_signer_commitment FROM accounts ORDER BY leaf_index`
   - Load all account data into memory

2. **Create New Mmap Tree**
   - Allocate/create `.mmap` file
   - Initialize with dense prefix optimization
   - Insert all account commitments at their leaf indices

3. **Write Metadata**
   - Create `.mmap.meta.tmp` with current state
   - Atomic rename to `.mmap.meta` (prevents torn writes)

---

## Tree Updates

### Real-Time Updates (Both Mode)

When blockchain events are indexed in Both mode:

```
Event Received → Decode → Update DB → Update Tree → Write Metadata
```

**Step-by-Step**:

1. **Event Received**
   - WebSocket: immediate notification
   - HTTP Batch: polled at regular intervals

2. **Decode Event**
   - Parse `AccountCreated`, `AccountUpdated`, etc.
   - Extract leaf index and new commitment value

3. **Update Database** (single transaction)
   - Insert into `commitment_update_events` (append-only)
   - Upsert into `accounts` (current state)

4. **Update Tree in Memory**
   - Acquire write lock on `GLOBAL_TREE`
   - Call `tree.update_with_mutation(leaf_index, value)`
   - Release write lock
   - **Mmap pages are marked dirty by OS**

5. **Write Metadata** (after batch)
   - Create temporary file with updated state
   - Atomic rename to `.mmap.meta`

**What Gets Written to Disk**:
- Modified tree nodes (OS writes dirty mmap pages automatically)
- New metadata file (after each batch)

**When It Gets Written**:
- Tree data: OS decides based on memory pressure and sync intervals
- Metadata: Immediately after each batch completes

### Periodic Sync (HttpOnly Mode)

HttpOnly nodes check for updates every `TREE_HTTP_CACHE_REFRESH_INTERVAL_SECS`:

```
Timer Tick → Check Metadata → Compare DB State → Sync If Needed
```

**Step-by-Step**:

1. **Check Cache Metadata**
   - Read `.mmap.meta` file
   - Extract `last_event_id`

2. **Query Database State**
   - Get current max event ID: `SELECT MAX(id) FROM commitment_update_events`
   - Calculate events behind: `current_id - last_event_id`

3. **If Behind**:
   - Restore tree from mmap (separate instance)
   - Replay missing events
   - Replace `GLOBAL_TREE` with updated tree
   - Write new metadata

4. **If Up-to-Date**:
   - No action taken
   - Next check scheduled

---

## Cache Synchronization

### sync_with_db() Method

The `sync_with_db()` method provides efficient incremental updates without full reinitialization:

```rust
pub async fn sync_with_db(&self, pool: &PgPool) -> Result<u64>
```

**Returns**: Number of events applied

**Process**:

1. **Read Current State**
   - Read `.mmap.meta` to get `last_event_id`
   - Query DB for current max event ID

2. **Early Exit If Current**
   - If `events_behind == 0`, return immediately
   - No disk I/O, no tree operations

3. **Restore Separate Tree Instance**
   - Restore from mmap into new tree object
   - **GLOBAL_TREE continues serving requests**
   - No interruption to API availability

4. **Replay Events**
   - Fetch events in batches (10,000 per batch)
   - Deduplicate in memory (HashMap of final leaf states)
   - Apply to restored tree

5. **Atomic Replacement**
   - Acquire write lock on `GLOBAL_TREE`
   - Assign updated tree: `*tree = updated_tree`
   - Release write lock

6. **Update Metadata**
   - Write new `.mmap.meta` with updated cursor

**Concurrency Guarantees**:
- `GLOBAL_TREE` is always in valid state
- API requests never see incomplete updates
- Write lock held only during pointer swap
- No torn reads possible

---

## Memory and Disk Operations

### What Lives in Memory

1. **Tree Structure** (~100 bytes per tree object)
   - Pointer to mmap region
   - Tree configuration (depth, dense prefix depth)
   - Metadata fields

2. **Mmap Mapping** (Virtual Memory)
   - Tree file mapped into process address space
   - OS loads pages into RAM on-demand (page faults)
   - Hot pages stay in RAM (page cache)
   - Cold pages evicted when memory pressure increases

3. **Deduplication Buffer** (During Replay)
   - HashMap of leaf updates: `HashMap<usize, U256>`
   - Size: O(unique leaves updated)
   - Cleared after batch applied

### What Gets Written to Disk

1. **Tree Updates** (Automatic)
   - Modified tree nodes written by OS
   - Dirty mmap pages flushed periodically
   - No explicit `write()` calls needed
   - Happens asynchronously in background

2. **Metadata** (Explicit)
   - Written after each event batch (Both mode)
   - Written after sync operation (HttpOnly mode)
   - Atomic write via temp file + rename
   - ~1KB JSON file

### Disk I/O Patterns

**Startup (Cold Cache)**:
- Mmap restore: OS loads pages on first access (page faults)
- Sequential read pattern for full tree traversal
- ~100MB/s typical read speed

**Startup (Warm Cache)**:
- Most pages already in OS page cache
- Minimal disk I/O (just metadata read)
- ~100ms restore time

**Runtime (Both Mode)**:
- Tree updates: dirty pages written by OS kernel
- Write pattern: scattered updates (tree structure)
- Metadata: small sequential writes (~1KB)

**Runtime (HttpOnly Mode)**:
- Sync operation: restore from mmap (uses page cache)
- Replay: tree updates similar to Both mode
- Metadata: written after sync

---

## Configuration Reference

### Environment Variables

```bash
# Required
TREE_CACHE_FILE=/data/tree.mmap

# Optional (with defaults)
TREE_DEPTH=30                              # Maximum tree capacity: 2^30 = ~1 billion
TREE_DENSE_PREFIX_DEPTH=26                 # Dense storage up to 2^26 = ~67 million
TREE_HTTP_CACHE_REFRESH_INTERVAL_SECS=30   # HttpOnly mode sync interval
```

---

## Implementation Notes

### Thread Safety

- `GLOBAL_TREE` protected by async `RwLock`
- Multiple concurrent readers allowed
- Exclusive writer access during updates
- No internal mutability beyond RwLock

### Error Handling

- Metadata read failures trigger full rebuild
- Mmap restore failures trigger full rebuild
- Root hash mismatch triggers full rebuild
- Event replay errors propagate to caller
