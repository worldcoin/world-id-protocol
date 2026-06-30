# Slow Query Benchmark Script

Benchmark script for measuring query performance on the `world_id_registry_events` table.
This is a companion to [PR #800](https://github.com/worldcoin/world-id-protocol/pull/800)
which introduces index and query changes to improve paginated event fetches.

## Queries benchmarked

| # | Description |
|---|-------------|
| 1 | **Root existence check** — filters by `event_type` and JSON `event_data->>'root'` |
| 2 | **Paginated event fetch (original OR)** — the current `get_after` query using `OR` |
| 3 | **Paginated event fetch (UNION ALL)** — the optimised `get_after` query from PR #800 |

Queries 2 and 3 are the before/after versions of the same logical query, so their results
can be directly compared.

## Full benchmark workflow

### 1. Start Postgres and run migrations

```bash
docker compose -f docker-compose.benchmark.yml up --abort-on-container-exit migrate
```

This starts a fresh Postgres container, waits for it to be healthy, and applies every
SQL file under `services/indexer/migrations/` in order. No `sqlx-cli` or Rust toolchain
required.

### 2. Seed the database

```bash
DATABASE_URL=postgres://postgres:postgres@localhost:5432/indexer_tests \
  ./scripts/seed_benchmark_db.sh
```

The seed script inserts ~10,000 realistic rows (a mix of `root_recorded` and
`identity_updated` events with deterministic hashes and JSONB payloads).
If the table already contains data the script will ask whether to truncate first.
Re-running is safe — it uses `ON CONFLICT DO NOTHING`.

### 3. Run the benchmark (on main branch first)

```bash
git checkout main
DATABASE_URL=postgres://postgres:postgres@localhost:5432/indexer_tests \
  ./scripts/benchmark_slow_queries.sh
```

### 4. Run the benchmark on the PR branch

```bash
git checkout fix/slow-queries-world-id-registry-events
DATABASE_URL=postgres://postgres:postgres@localhost:5432/indexer_tests \
  ./scripts/benchmark_slow_queries.sh
```

### 5. Compare results

```bash
diff benchmarks/results_<main_ts>.txt benchmarks/results_<pr_ts>.txt
```

Or compare the summary lines at the bottom of each file for a quick glance.

### Teardown

```bash
docker compose -f docker-compose.benchmark.yml down -v
```

## Prerequisites

- Docker (with Compose v2)
- `psql` installed and on `$PATH` (for the seed and benchmark scripts)
