#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER_NAME="world-id-indexer-postgres"

ENVIRONMENT="${ENVIRONMENT:-production}"
RUN_MODE="${RUN_MODE:-both}"
REGISTRY_ADDRESS="${REGISTRY_ADDRESS:-0x969947cFED008bFb5e3F32a25A1A2CDdf64d46fe}"
BATCH_SIZE="${BATCH_SIZE:-512}"
START_BLOCK="${START_BLOCK:-22827118}"
RPC_URL="${RPC_URL:-https://worldchain-mainnet.g.alchemy.com/public}"
WS_URL="${WS_URL:-wss://worldchain-mainnet.g.alchemy.com/public}"
DATABASE_URL="${DATABASE_URL:-postgres://postgres:postgres@localhost:5433/indexer_stage}"
TREE_CACHE_FILE="${TREE_CACHE_FILE:-$ROOT_DIR/tree-cache-stage.mmap}"
DB_NAME="${DB_NAME:-indexer_stage}"
DB_USER="${DB_USER:-postgres}"

cleanup() {
  echo ""
  echo "stopping postgres container..."
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1; then
  echo "missing required command: docker" >&2
  exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "missing required command: cargo" >&2
  exit 1
fi

# Remove any leftover container from a previous run.
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

# Clean tree cache so it matches the fresh DB.
rm -f "$TREE_CACHE_FILE" "$TREE_CACHE_FILE.meta"

# Start postgres.
docker run -d \
  --name "$CONTAINER_NAME" \
  -e POSTGRES_USER="$DB_USER" \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB="$DB_NAME" \
  -p 5433:5432 \
  postgres:16 >/dev/null

echo "waiting for postgres..."
for ((i = 1; i <= 60; i++)); do
  if docker exec "$CONTAINER_NAME" pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
    echo "postgres is ready"
    break
  fi
  if ((i == 60)); then
    echo "postgres did not become ready in time" >&2
    exit 1
  fi
  sleep 1
done

# Run the indexer in the foreground.
cd "$ROOT_DIR"
env \
  ENVIRONMENT="$ENVIRONMENT" \
  RUN_MODE="$RUN_MODE" \
  DATABASE_URL="$DATABASE_URL" \
  RPC_URL="$RPC_URL" \
  WS_URL="$WS_URL" \
  REGISTRY_ADDRESS="$REGISTRY_ADDRESS" \
  START_BLOCK="$START_BLOCK" \
  BATCH_SIZE="$BATCH_SIZE" \
  TREE_CACHE_FILE="$TREE_CACHE_FILE" \
  cargo run --release -p world-id-indexer
