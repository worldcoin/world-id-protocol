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

## Prerequisites

- `psql` installed and on `$PATH`
- Access to a Postgres database with a populated `world_id_registry_events` table
  (local or staging)

## Usage

```bash
DATABASE_URL='postgres://user:pass@host:5432/dbname' ./scripts/benchmark_slow_queries.sh
```

Each query is run 5 times with `EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)`.
Results are written to `benchmarks/results_<ISO_TIMESTAMP>.txt`.

## Comparing branches

1. Checkout `main`, run the script, note the output file path.
2. Checkout the PR branch (or apply the index/query changes), run the script again.
3. Diff the two result files:

```bash
diff benchmarks/results_<main_timestamp>.txt benchmarks/results_<pr_timestamp>.txt
```

Or compare the summary lines at the bottom of each file for a quick glance.
