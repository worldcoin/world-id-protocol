#!/usr/bin/env bash
# Usage: get-block-field.sh <block_number> <field> <rpc_url>
# Returns: hex-encoded field value (e.g. stateRoot, hash)
#
# Example: ./get-block-field.sh 25497398 stateRoot https://worldchain-mainnet.g.alchemy.com/public
set -euo pipefail

BLOCK_NUMBER="$1"
FIELD="$2"
RPC_URL="$3"

cast block "$BLOCK_NUMBER" -f "$FIELD" --rpc-url="$RPC_URL"
