# Tree Cache Architecture

This document describes how the indexer manages the memory-mapped (mmap) merkle tree cache, including operational modes, file operations, and synchronization behavior.

## Table of Contents

- [Operational Modes](#operational-modes)
- [Mmap Tree File](#mmap-tree-file)
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
- Writes events to `world_tree_events` table
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
- Most efficient for single-node deployments

---

## Mmap Tree File

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

---

## Tree Initialization

### Startup Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Check if .mmap cache file exists                         │
└──────────┬──────────────────────────────────────────────────┘
           │
           ├─ Missing ──────────────┐
           │                        ▼
           │               ┌──────────────────────┐
           │               │ Full Rebuild         │
           │               │ - Fetch all accounts │
           │               │ - Create new tree    │
           │               └──────────────────────┘
           │
           └─ Present ──────────────┐
                                    ▼
                           ┌──────────────────────┐
                           │ Restore & Replay     │
                           │ - Restore from mmap  │
                           │ - Validate root in DB│
                           │ - Replay new events  │
                           │                      │
                           │ On failure → Full    │
                           │ Rebuild (fallback)   │
                           └──────────────────────┘
```

### Restore & Replay Process

1. **Restore Tree from Mmap**
   - Memory-map the tree file into process address space
   - OS loads pages on-demand
   - Most pages already in OS page cache if recently used

2. **Validate Root Against DB**
   - Compute tree root from restored tree
   - Look up the root in `world_tree_roots` table
   - If root not found: cache is stale, fall back to full rebuild

3. **Replay Events**
   - Fetch events after the root's position: `SELECT * FROM world_tree_events WHERE (block_number, log_index) > ($1, $2) ORDER BY block_number, log_index LIMIT 10000`
   - Deduplicate in memory (multiple updates to same leaf → keep final state)
   - Apply updates to tree: `tree.update_with_mutation(leaf_index, value)`

### Full Rebuild Process

1. **Fetch All Accounts**
   - Query: `SELECT leaf_index, offchain_signer_commitment FROM accounts ORDER BY leaf_index`
   - Process in batches of 100,000

2. **Two-Pass Tree Construction**
   - Pass 1: Build dense prefix from leaves within dense prefix range
   - Pass 2: Apply sparse leaves (beyond dense prefix) incrementally

3. **Create Mmap File**
   - Allocate/create `.mmap` file
   - Initialize with dense prefix optimization

---

## Tree Updates

### Real-Time Updates (Both Mode)

When blockchain events are indexed in Both mode:

```
Event Received → Decode → Buffer → RootRecorded? → Commit to DB → Sync Tree from DB
```

**Step-by-Step**:

1. **Event Received**
   - WebSocket: immediate notification
   - HTTP Batch: polled at regular intervals

2. **Decode & Buffer Event**
   - Parse `AccountCreated`, `AccountUpdated`, etc.
   - Buffer events until `RootRecorded` event is seen

3. **Commit to Database** (single serializable transaction)
   - Insert into `world_tree_events` (append-only)
   - Upsert into `accounts` (current state)
   - Insert root into `world_tree_roots`

4. **Sync Tree from DB**
   - Fetch new events since last sync cursor
   - Deduplicate (keep final state per leaf)
   - Acquire write lock on tree
   - Apply all updates under single lock
   - Advance sync cursor

**What Gets Written to Disk**:
- Modified tree nodes (OS writes dirty mmap pages automatically)

**When It Gets Written**:
- Tree data: OS decides based on memory pressure and sync intervals

### Periodic Sync (HttpOnly Mode)

HttpOnly nodes check for updates every `TREE_HTTP_CACHE_REFRESH_INTERVAL_SECS`:

```
Timer Tick → Query DB for new events → Apply to tree if needed
```

**Step-by-Step**:

1. **Read sync cursor** from tree state (last synced event ID)

2. **Query Database** for events after cursor

3. **If new events exist**:
   - Deduplicate to final leaf states
   - Apply under write lock
   - Advance cursor

4. **If no new events**:
   - No action taken
   - Next check scheduled

---

## Cache Synchronization

### sync_from_db() Function

The `sync_from_db()` function provides efficient incremental updates:

**Returns**: Number of events processed

**Process**:

1. **Read sync cursor** from `TreeState.last_synced_event_id`

2. **Batch-fetch pending events** from `world_tree_events` table (10,000 per batch)

3. **Deduplicate in memory** using HashMap (keeps final state per leaf)

4. **Apply all updates** under a single write lock

5. **Advance cursor** to latest event ID

**Concurrency Guarantees**:
- Tree is always in a valid state
- API requests never see incomplete updates
- Write lock held only during batch application
- Multiple concurrent readers allowed

---

## Memory and Disk Operations

### What Lives in Memory

1. **Tree Structure** (~100 bytes per tree object)
   - Pointer to mmap region
   - Tree configuration (depth, dense prefix depth)

2. **Mmap Mapping** (Virtual Memory)
   - Tree file mapped into process address space
   - OS loads pages into RAM on-demand (page faults)
   - Hot pages stay in RAM (page cache)
   - Cold pages evicted when memory pressure increases

3. **Deduplication Buffer** (During Replay/Sync)
   - HashMap of leaf updates: `HashMap<U256, U256>`
   - Size: O(unique leaves updated)
   - Cleared after batch applied

### What Gets Written to Disk

1. **Tree Updates** (Automatic)
   - Modified tree nodes written by OS
   - Dirty mmap pages flushed periodically
   - No explicit `write()` calls needed
   - Happens asynchronously in background

### Disk I/O Patterns

**Startup (Cold Cache)**:
- Mmap restore: OS loads pages on first access (page faults)
- Sequential read pattern for full tree traversal
- ~100MB/s typical read speed

**Startup (Warm Cache)**:
- Most pages already in OS page cache
- Minimal disk I/O
- ~100ms restore time

**Runtime (Both Mode)**:
- Tree updates: dirty pages written by OS kernel
- Write pattern: scattered updates (tree structure)

**Runtime (HttpOnly Mode)**:
- Sync operation: fetches events from DB, applies to tree
- Tree updates similar to Both mode

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

- Tree protected by async `RwLock` in `TreeState`
- Multiple concurrent readers allowed
- Exclusive writer access during updates
- No internal mutability beyond RwLock

### Error Handling & Cache Corruption Recovery

**Validation on Restore:**
- Tree root hash is validated against the `world_tree_roots` DB table after mmap restore
- Detects stale cache from disk errors, partial writes, or process crashes

**Automatic Recovery:**
- `init_tree()`: Falls back to full rebuild on validation failure
- Mmap restore failure → full rebuild
- Root not found in DB → full rebuild (stale cache)
- Event replay errors → propagate to caller

**Recovery Flow:**
```
Root Not In DB → Log Warning → Full Rebuild from DB → Return new TreeState
```
