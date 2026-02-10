#!/usr/bin/env bash
# Usage: get-proof.sh <address> <slots_json_array> <block_hex> <rpc_url>
# Returns: raw JSON from eth_getProof
#
# slots_json_array is a JSON array of storage keys, e.g.:
#   []                                  — no storage keys (just account proof)
#   ["0x11"]                            — single slot
#   ["0x11","0x12"]                     — two slots
#
# Example:
#   ./get-proof.sh 0x969947...fe '["0x11"]' 0x1850f36 https://worldchain-mainnet.g.alchemy.com/public
set -euo pipefail

ADDRESS="$1"
SLOTS="$2"
BLOCK_HEX="$3"
RPC_URL="$4"

cast rpc eth_getProof "$ADDRESS" "$SLOTS" "$BLOCK_HEX" --rpc-url="$RPC_URL"
