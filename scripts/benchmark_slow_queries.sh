#!/usr/bin/env bash
#
# Benchmark slow queries on the world_id_registry_events table.
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
# ---------------------------------------------------------------------------
QUERY_NAMES=(
  "Query 1 — Root existence check"
  "Query 2 — Paginated event fetch (get_after) — original OR version"
  "Query 3 — Paginated event fetch (get_after) — new UNION ALL version"
)

QUERY_SQL=(
  "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT 1
FROM world_id_registry_events
WHERE event_type = 'root_recorded'
  AND event_data->>'root' = 'BENCH_ROOT_PLACEHOLDER'
LIMIT 1;"

  "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT block_number, log_index, block_hash, tx_hash, event_type, leaf_index, event_data
FROM world_id_registry_events
WHERE (block_number = 1000000 AND log_index > 0)
   OR block_number > 1000000
ORDER BY block_number ASC, log_index ASC
LIMIT 100;"

  "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT block_number, log_index, block_hash, tx_hash, event_type, leaf_index, event_data
FROM (
    SELECT block_number, log_index, block_hash, tx_hash, event_type, leaf_index, event_data
    FROM world_id_registry_events
    WHERE block_number = 1000000 AND log_index > 0
    UNION ALL
    SELECT block_number, log_index, block_hash, tx_hash, event_type, leaf_index, event_data
    FROM world_id_registry_events
    WHERE block_number > 1000000
) sub
ORDER BY block_number ASC, log_index ASC
LIMIT 100;"
)

# ---------------------------------------------------------------------------
# 4. Helper: extract "Execution Time: XX.XXX ms" from EXPLAIN output
# ---------------------------------------------------------------------------
extract_exec_time() {
  # Returns the numeric ms value from the last "Execution Time:" line
  grep -i 'Execution Time:' <<< "$1" | tail -1 | sed -E 's/.*Execution Time:\s*([0-9.]+)\s*ms.*/\1/'
}

# ---------------------------------------------------------------------------
# 5. Write header
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
  echo "========================================================================"
} | tee "$OUTFILE"

# ---------------------------------------------------------------------------
# 6. Run benchmarks
# ---------------------------------------------------------------------------
declare -a AVG_TIMES=()

for i in "${!QUERY_NAMES[@]}"; do
  NAME="${QUERY_NAMES[$i]}"
  SQL="${QUERY_SQL[$i]}"
  TOTAL_MS=0
  TIMES=()

  {
    echo ""
    echo "------------------------------------------------------------------------"
    echo "  $NAME"
    echo "------------------------------------------------------------------------"
    echo ""
    echo "SQL:"
    echo "$SQL"
    echo ""
  } | tee -a "$OUTFILE"

  for run in $(seq 1 $RUNS); do
    echo "  Running $NAME — iteration $run/$RUNS ..."
    OUTPUT=$(psql "$DB_URL" -X -A -c "$SQL" 2>&1) || true

    {
      echo "--- Run $run ---"
      echo "$OUTPUT"
      echo ""
    } >> "$OUTFILE"

    EXEC_MS=$(extract_exec_time "$OUTPUT")
    if [[ -n "$EXEC_MS" ]]; then
      TIMES+=("$EXEC_MS")
      TOTAL_MS=$(awk "BEGIN {printf \"%.3f\", $TOTAL_MS + $EXEC_MS}")
    else
      TIMES+=("N/A")
    fi
  done

  # Compute average
  VALID_COUNT=0
  for t in "${TIMES[@]}"; do
    [[ "$t" != "N/A" ]] && ((VALID_COUNT++)) || true
  done

  if [[ $VALID_COUNT -gt 0 ]]; then
    AVG=$(awk "BEGIN {printf \"%.3f\", $TOTAL_MS / $VALID_COUNT}")
  else
    AVG="N/A"
  fi
  AVG_TIMES+=("$AVG")

  {
    echo "  Individual times (ms): ${TIMES[*]}"
    echo "  Average (ms): $AVG"
    echo ""
  } | tee -a "$OUTFILE"
done

# ---------------------------------------------------------------------------
# 7. Summary
# ---------------------------------------------------------------------------
{
  echo ""
  echo "========================================================================"
  echo "  Summary"
  echo "========================================================================"
  echo ""
  for i in "${!QUERY_NAMES[@]}"; do
    printf "  %-65s  avg: %s ms\n" "${QUERY_NAMES[$i]}" "${AVG_TIMES[$i]}"
  done
  echo ""
  echo "========================================================================"
} | tee -a "$OUTFILE"

echo ""
echo "Results saved to: $OUTFILE"
