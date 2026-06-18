#!/usr/bin/env bash
#
# Seed the world_id_registry_events table with realistic benchmark data.
# Generates ~10,000,000 rows using 80 batched SQL statements with generate_series.
#
# Usage: DATABASE_URL=postgres://... ./scripts/seed_benchmark_db.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# 1. Resolve DATABASE_URL
# ---------------------------------------------------------------------------
DB_URL="${1:-${DATABASE_URL:-}}"
if [[ -z "$DB_URL" ]]; then
  echo "ERROR: DATABASE_URL env var (or first argument) is required." >&2
  echo "Usage: DATABASE_URL=postgres://... $0" >&2
  exit 1
fi

REDACTED_URL=$(echo "$DB_URL" | sed -E 's|(://[^:]+:)[^@]+(@)|\1***\2|')
echo "Database: $REDACTED_URL"

# ---------------------------------------------------------------------------
# 2. Check for existing data
# ---------------------------------------------------------------------------
EXISTING=$(psql "$DB_URL" -X -A -t -c \
  "SELECT count(*) FROM world_id_registry_events;" 2>/dev/null || echo "0")

if [[ "$EXISTING" -gt 0 ]]; then
  echo ""
  echo "WARNING: world_id_registry_events already contains $EXISTING rows."
  read -rp "Truncate the table before seeding? [y/N] " ANSWER
  if [[ "$ANSWER" =~ ^[Yy]$ ]]; then
    echo "Truncating world_id_registry_events..."
    psql "$DB_URL" -X -c "TRUNCATE world_id_registry_events;"
  else
    echo "Keeping existing data. New rows will use ON CONFLICT DO NOTHING."
  fi
fi

# ---------------------------------------------------------------------------
# 3. Seed data  (80 batches of ~125,000 rows each ≈ 10,000,000 rows total)
# ---------------------------------------------------------------------------
# We generate ~10,000,000 rows spread across 80 batches:
#   - ~4,000,000 blocks in range [1_000_000 .. 5_799_999]
#   - ~2.5 log entries per block on average (1..4 via deterministic hash)
#   - ~40% root_recorded, ~60% identity_updated
#
# Each batch covers 60,000 values in generate_series → ~50,000 blocks kept
# (~83% pass the hashtext % 6 <> 0 filter) → ~125,000 rows per batch.
# Batching avoids materialising the full result set in one shot.

# Total series length: 80 × 60,000 = 4,800,000 → ~4,000,000 blocks → ~10,000,000 rows
TOTAL_BATCHES=80
BATCH_SIZE=60000

echo ""
echo "Inserting benchmark rows in ${TOTAL_BATCHES} batches of ~${BATCH_SIZE} series values each..."

for (( BATCH=0; BATCH<TOTAL_BATCHES; BATCH++ )); do
  SERIES_START=$(( BATCH * BATCH_SIZE ))
  SERIES_END=$(( SERIES_START + BATCH_SIZE - 1 ))
  echo "  Batch $((BATCH + 1))/${TOTAL_BATCHES}: series ${SERIES_START}..${SERIES_END}"

  psql "$DB_URL" -X -e <<SEED_SQL
-- Batch $((BATCH + 1)) of ${TOTAL_BATCHES}: series ${SERIES_START}..${SERIES_END}
INSERT INTO world_id_registry_events
  (block_number, log_index, block_hash, tx_hash, event_type, leaf_index, event_data)
SELECT
  b.block_number,
  l.log_index,
  -- block_hash: 32 random bytes
  decode(lpad(md5(b.block_number::text || l.log_index::text || 'bh'), 32, '0') ||
         lpad(md5(l.log_index::text || b.block_number::text || 'bh2'), 32, '0'), 'hex'),
  -- tx_hash: 32 random bytes (different seed)
  decode(lpad(md5(b.block_number::text || l.log_index::text || 'tx'), 32, '0') ||
         lpad(md5(l.log_index::text || b.block_number::text || 'tx2'), 32, '0'), 'hex'),
  -- event_type: ~40% root_recorded, ~60% identity_updated
  CASE
    WHEN hashtext(b.block_number::text || ':' || l.log_index::text) % 5 < 2
      THEN 'root_recorded'
    ELSE 'identity_updated'
  END,
  -- leaf_index: NULL for root_recorded, sequential otherwise
  CASE
    WHEN hashtext(b.block_number::text || ':' || l.log_index::text) % 5 < 2
      THEN NULL
    ELSE row_number() OVER (
           ORDER BY b.block_number, l.log_index
         ) - 1  -- 0-based sequential within batch
  END,
  -- event_data: root_recorded gets a root field; others get {}
  CASE
    WHEN hashtext(b.block_number::text || ':' || l.log_index::text) % 5 < 2
      THEN jsonb_build_object(
             'root', '0x' || md5(b.block_number::text || l.log_index::text || 'root') ||
                             md5(l.log_index::text || b.block_number::text || 'root2')
           )
    ELSE '{}'::jsonb
  END
FROM
  -- ~50,000 blocks per batch (skip some to create gaps)
  (SELECT 1000000 + s AS block_number
   FROM generate_series(${SERIES_START}, ${SERIES_END}) s
   WHERE hashtext(s::text) % 6 <> 0   -- ~83% of blocks kept ≈ 50,000 per batch
  ) b
  CROSS JOIN LATERAL (
    -- 1–4 log entries per block (deterministic based on block)
    SELECT li AS log_index
    FROM generate_series(0, abs(hashtext(b.block_number::text)) % 4) li
  ) l
ON CONFLICT (block_number, log_index) DO NOTHING;
SEED_SQL
done

# ---------------------------------------------------------------------------
# 4. Report
# ---------------------------------------------------------------------------
FINAL_COUNT=$(psql "$DB_URL" -X -A -t -c \
  "SELECT count(*) FROM world_id_registry_events;")

ROOT_COUNT=$(psql "$DB_URL" -X -A -t -c \
  "SELECT count(*) FROM world_id_registry_events WHERE event_type = 'root_recorded';")

echo ""
echo "========================================================================"
echo "  Seeding complete"
echo "========================================================================"
echo "  Total rows : $FINAL_COUNT"
echo "  root_recorded : $ROOT_COUNT"
echo "  identity_updated : $((FINAL_COUNT - ROOT_COUNT))"
echo "========================================================================"
echo ""
echo "You can now run the benchmark:"
echo "  DATABASE_URL='...' ./scripts/benchmark_slow_queries.sh"
