#!/usr/bin/env bash
#
# Benchmark slow queries on the world_id_registry_events table.
#
# Performs a full before/after comparison in a single run:
#   Phase 1 — Drop perf indexes, run "slow" queries (baseline)
#   Phase 2 — Create perf indexes (from 0002_perf_indexes.sql)
#   Phase 3 — Run "fast" queries (optimized)
#   Phase 4 — Print side-by-side comparison
#
# Queries benchmarked (both phases):
#   Query 1 — Root existence check  (benefits from partial expression index)
#   Query 3 — Insert                (shows index maintenance overhead)
#
# NOTE — Query 2 (paginated fetch with OR) was benchmarked during development
# and found to already be fast (≈0.066 ms) via the primary key on
# (block_number, log_index).  A UNION ALL rewrite was tested but turned out
# to be ~6000x SLOWER because it prevents PostgreSQL from doing early
# termination with LIMIT.  The rewrite was therefore dropped from PR #800 and
# Query 2 is excluded from this script.
#
# Usage: DATABASE_URL=postgres://... ./scripts/benchmark_slow_queries.sh
#
set -euo pipefail

RUNS=5

# ---------------------------------------------------------------------------
# 1. Resolve DATABASE_URL
# ---------------------------------------------------------------------------
DB_URL="${1:-${DATABASE_URL:-}}"
if [[ -z "$DB_URL" ]]; then
  echo "ERROR: DATABASE_URL env var (or first argument) is required." >&2
  echo "Usage: DATABASE_URL=postgres://... $0" >&2
  exit 1
fi

# Redact password for display: postgres://user:PASS@host -> postgres://user:***@host
REDACTED_URL=$(echo "$DB_URL" | sed -E 's|(://[^:]+:)[^@]+(@)|\1***\2|')

# ---------------------------------------------------------------------------
# 2. Prepare output directory & file
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BENCH_DIR="$REPO_DIR/benchmarks"
mkdir -p "$BENCH_DIR"

TIMESTAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
OUTFILE="$BENCH_DIR/results_${TIMESTAMP}.txt"

GIT_BRANCH="$(git -C "$REPO_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
GIT_COMMIT="$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"

# ---------------------------------------------------------------------------
# 3. Define queries
#
#  Only the two queries that are directly affected by the indexes added in
#  0002_perf_indexes.sql are included:
#
#   Query 1 — root_exists()
#     Partial expression index idx_world_id_registry_events_root turns a full
#     table seq scan into an index scan on root_recorded rows only.
#
#   Query 3 — INSERT
#     Included for completeness: shows the index maintenance overhead added by
#     the two new indexes on every insert.
# ---------------------------------------------------------------------------

QUERY_LABELS=(
  "Query 1 — Root existence check"
  "Query 3 — Insert"
)

BEFORE_LABELS=(
  "BEFORE (seq scan)"
  "BEFORE"
)

AFTER_LABELS=(
  "AFTER  (idx scan)"
  "AFTER"
)

# --- BEFORE queries (no indexes) ---
BEFORE_SQL=(
  "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT 1
FROM world_id_registry_events
WHERE event_type = 'root_recorded'
  AND event_data->>'root' = 'BENCH_ROOT_PLACEHOLDER'
LIMIT 1;"

  "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
INSERT INTO world_id_registry_events (block_number, log_index, block_hash, tx_hash, event_type, leaf_index, event_data)
VALUES (0, 0, '0xBENCH', '0xBENCH', 'bench_noop', 0, '{}')
ON CONFLICT (block_number, log_index) DO NOTHING;"
)

# --- AFTER queries (with indexes) ---
# Query 1 and Query 3 are identical in both phases; the difference is whether
# the indexes exist, which the planner picks up automatically.
AFTER_SQL=(
  "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT 1
FROM world_id_registry_events
WHERE event_type = 'root_recorded'
  AND event_data->>'root' = 'BENCH_ROOT_PLACEHOLDER'
LIMIT 1;"

  "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
INSERT INTO world_id_registry_events (block_number, log_index, block_hash, tx_hash, event_type, leaf_index, event_data)
VALUES (0, 0, '0xBENCH', '0xBENCH', 'bench_noop', 0, '{}')
ON CONFLICT (block_number, log_index) DO NOTHING;"
)

QUERY_COUNT="${#QUERY_LABELS[@]}"

# ---------------------------------------------------------------------------
# 4. Helper: extract "Execution Time: XX.XXX ms" from EXPLAIN output
# ---------------------------------------------------------------------------
extract_exec_time() {
  # Returns the numeric ms value from the last "Execution Time:" line.
  # Uses awk for cross-platform compatibility (BSD awk on macOS).
  printf '%s\n' "$1" | awk '/Execution Time:/ {val = $3} END {if (val != "") printf "%.3f", val}'
}

# ---------------------------------------------------------------------------
# 5. Helper: compute min / max / avg from a space-separated list of times
# ---------------------------------------------------------------------------
compute_stats() {
  # Usage: compute_stats "1.234 2.345 3.456"
  # Prints: avg min max   (space-separated, 3 decimal places)
  local times="$1"
  echo "$times" | awk '{
    n = split($0, a, " ")
    if (n == 0) { printf "N/A N/A N/A"; exit }
    sum = 0; mn = a[1]+0; mx = a[1]+0; cnt = 0
    for (i = 1; i <= n; i++) {
      if (a[i] == "N/A") continue
      v = a[i] + 0
      sum += v; cnt++
      if (v < mn) mn = v
      if (v > mx) mx = v
    }
    if (cnt > 0)
      printf "%.3f %.3f %.3f", sum/cnt, mn, mx
    else
      printf "N/A N/A N/A"
  }'
}

# ---------------------------------------------------------------------------
# 6. Helper: run a query set and collect times
# ---------------------------------------------------------------------------
run_phase() {
  local phase_name="$1"
  local sql_var_prefix="$2"   # "BEFORE" or "AFTER"

  {
    echo ""
    echo "========================================================================"
    echo "  $phase_name"
    echo "========================================================================"
  } | tee -a "$OUTFILE"

  for i in $(seq 0 $((QUERY_COUNT - 1))); do
    eval "local sql=\"\${${sql_var_prefix}_SQL[$i]}\""
    local label="${QUERY_LABELS[$i]}"
    local times=""

    {
      echo ""
      echo "------------------------------------------------------------------------"
      echo "  $label"
      echo "------------------------------------------------------------------------"
      echo ""
      echo "SQL:"
      echo "$sql"
      echo ""
    } | tee -a "$OUTFILE"

    for run in $(seq 1 $RUNS); do
      echo "  Running $label — iteration $run/$RUNS ..."
      OUTPUT=$(psql "$DB_URL" -X -A -c "$sql" 2>&1) || true

      {
        echo "--- Run $run ---"
        echo "$OUTPUT"
        echo ""
      } >> "$OUTFILE"

      EXEC_MS=$(extract_exec_time "$OUTPUT")
      if [[ -n "$EXEC_MS" ]]; then
        times="${times:+$times }$EXEC_MS"
      else
        times="${times:+$times }N/A"
      fi
    done

    # Store times in a global variable indexed by phase prefix and query number
    eval "TIMES_${sql_var_prefix}_${i}=\"\$times\""

    local stats
    stats=$(compute_stats "$times")
    local avg min max
    avg=$(echo "$stats" | awk '{print $1}')
    min=$(echo "$stats" | awk '{print $2}')
    max=$(echo "$stats" | awk '{print $3}')

    {
      echo "  Times (ms): $times"
      echo "  avg=$avg ms  min=$min ms  max=$max ms"
      echo ""
    } | tee -a "$OUTFILE"
  done
}

# ---------------------------------------------------------------------------
# 7. Write header
# ---------------------------------------------------------------------------
{
  echo "========================================================================"
  echo "  Slow Query Benchmark — world_id_registry_events"
  echo "========================================================================"
  echo ""
  echo "  Timestamp : $TIMESTAMP"
  echo "  Database  : $REDACTED_URL"
  echo "  Branch    : $GIT_BRANCH"
  echo "  Commit    : $GIT_COMMIT"
  echo "  Runs/query: $RUNS"
  echo ""
  echo "  Queries   : Query 1 (root existence check), Query 3 (insert)"
  echo "  Note      : Query 2 (paginated fetch / OR) excluded — already fast"
  echo "              via primary key; UNION ALL rewrite was ~6000x slower."
  echo ""
} | tee "$OUTFILE"

# ---------------------------------------------------------------------------
# 8. Phase 1 — BEFORE (drop indexes, run slow queries)
# ---------------------------------------------------------------------------
echo "" | tee -a "$OUTFILE"
echo ">>> Phase 1: Dropping perf indexes for clean baseline ..." | tee -a "$OUTFILE"
echo "" | tee -a "$OUTFILE"

psql "$DB_URL" -X -c "DROP INDEX IF EXISTS idx_world_id_registry_events_root;" 2>&1 | tee -a "$OUTFILE"
psql "$DB_URL" -X -c "DROP INDEX IF EXISTS idx_world_id_registry_events_block_number_hash;" 2>&1 | tee -a "$OUTFILE"

echo "  Indexes dropped." | tee -a "$OUTFILE"

run_phase "Phase 1 — BEFORE (no indexes)" "BEFORE"

# ---------------------------------------------------------------------------
# 9. Phase 2 — Create indexes (mirrors 0002_perf_indexes.sql exactly)
# ---------------------------------------------------------------------------
echo "" | tee -a "$OUTFILE"
echo ">>> Phase 2: Creating perf indexes (0002_perf_indexes.sql) ..." | tee -a "$OUTFILE"
echo "" | tee -a "$OUTFILE"

# Index 1: partial expression index for root_exists()
psql "$DB_URL" -X -c "
CREATE INDEX IF NOT EXISTS idx_world_id_registry_events_root
    ON world_id_registry_events ((event_data->>'root'))
    WHERE event_type = 'root_recorded';
" 2>&1 | tee -a "$OUTFILE"

# Index 2: compound index for get_blocks_with_conflicting_hashes()
psql "$DB_URL" -X -c "
CREATE INDEX IF NOT EXISTS idx_world_id_registry_events_block_number_hash
    ON world_id_registry_events (block_number, block_hash);
" 2>&1 | tee -a "$OUTFILE"

echo "  Indexes created." | tee -a "$OUTFILE"

# ---------------------------------------------------------------------------
# 10. Phase 3 — AFTER (with indexes)
# ---------------------------------------------------------------------------
run_phase "Phase 3 — AFTER (with indexes)" "AFTER"

# ---------------------------------------------------------------------------
# 11. Phase 4 — Comparison output
# ---------------------------------------------------------------------------
{
  echo ""
  echo "========================================================================"
  echo " RESULTS COMPARISON"
  echo "========================================================================"

  for i in $(seq 0 $((QUERY_COUNT - 1))); do
    eval "local_before_times=\"\$TIMES_BEFORE_${i}\""
    eval "local_after_times=\"\$TIMES_AFTER_${i}\""

    b_stats=$(compute_stats "$local_before_times")
    a_stats=$(compute_stats "$local_after_times")

    b_avg=$(echo "$b_stats" | awk '{print $1}')
    b_min=$(echo "$b_stats" | awk '{print $2}')
    b_max=$(echo "$b_stats" | awk '{print $3}')

    a_avg=$(echo "$a_stats" | awk '{print $1}')
    a_min=$(echo "$a_stats" | awk '{print $2}')
    a_max=$(echo "$a_stats" | awk '{print $3}')

    echo ""
    echo " ${QUERY_LABELS[$i]}"

    if [[ "$b_avg" == "N/A" ]] || [[ "$a_avg" == "N/A" ]]; then
      echo "   ${BEFORE_LABELS[$i]}:  avg=${b_avg} ms  min=${b_min} ms  max=${b_max} ms"
      echo "   ${AFTER_LABELS[$i]}:  avg=${a_avg} ms  min=${a_min} ms  max=${a_max} ms"
      echo "   Speedup: N/A"
    else
      printf "   %-28s avg=%s ms  min=%s ms  max=%s ms\n" "${BEFORE_LABELS[$i]}:" "$b_avg" "$b_min" "$b_max"
      printf "   %-28s avg=%s ms  min=%s ms  max=%s ms\n" "${AFTER_LABELS[$i]}:" "$a_avg" "$a_min" "$a_max"

      speedup=$(awk "BEGIN {
        if ($a_avg > 0)
          printf \"%.0f\", $b_avg / $a_avg
        else
          printf \"inf\"
      }")

      if [[ "$speedup" == "inf" ]]; then
        echo "   Change: inf (after avg is 0)"
      elif [[ "$speedup" -ge 2 ]]; then
        echo "   Speedup: ${speedup}x"
      else
        change=$(awk "BEGIN { printf \"%.1f\", $b_avg / $a_avg }")
        echo "   Change: ${change}x"
      fi
    fi
  done

  echo ""
  echo "========================================================================"
  echo " All results saved to: $OUTFILE"
  echo "========================================================================"
} | tee -a "$OUTFILE"
