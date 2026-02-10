#!/usr/bin/env bash
# Usage: get-proof-encoded.sh <address> <slot> <block_hex> <rpc_url>
# Returns: 0x-prefixed ABI-encoded (bytes[] accountProof, bytes[] storageProof, uint256 storageValue)
#
# Uses cast + python3 to fetch eth_getProof and ABI-encode the result for Foundry consumption.
set -euo pipefail

ADDRESS="$1"
SLOT="$2"
BLOCK_HEX="$3"
RPC_URL="$4"

TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

cast rpc eth_getProof "$ADDRESS" "[\"$SLOT\"]" "$BLOCK_HEX" --rpc-url="$RPC_URL" > "$TMPFILE"

python3 - "$TMPFILE" <<'PYEOF'
import json, sys, struct

def to_bytes(hex_str):
    if hex_str is None or hex_str in ('0x', '0x0', '0x00'):
        return b''
    h = hex_str[2:] if hex_str.startswith('0x') else hex_str
    if len(h) % 2:
        h = '0' + h
    return bytes.fromhex(h)

def pad32(n):
    return n.to_bytes(32, 'big')

def encode_bytes(b):
    """ABI-encode a single bytes value (length-prefixed, 32-byte padded)."""
    length = len(b)
    padded_len = ((length + 31) // 32) * 32
    return pad32(length) + b + b'\x00' * (padded_len - length)

def encode_bytes_array(arr):
    """ABI-encode bytes[] — array of dynamic bytes."""
    n = len(arr)
    # Header: count
    result = pad32(n)
    # Offsets to each element (relative to start of data area)
    # Data area starts after n * 32 bytes of offsets
    offsets = []
    data_parts = []
    current_offset = n * 32
    for item in arr:
        offsets.append(pad32(current_offset))
        encoded = encode_bytes(item)
        data_parts.append(encoded)
        current_offset += len(encoded)
    result += b''.join(offsets) + b''.join(data_parts)
    return result

with open(sys.argv[1]) as f:
    data = json.load(f)

account_proof = [to_bytes(p) for p in data['accountProof']]
sp = data['storageProof'][0]
storage_proof = [to_bytes(p) for p in sp['proof']]
storage_value = int(sp['value'], 16) if sp['value'] not in ('0x', '0x0') else 0

# ABI-encode as (bytes[] accountProof, bytes[] storageProof, uint256 storageValue)
# Top-level tuple with 3 dynamic/static fields:
#   offset to accountProof (dynamic)
#   offset to storageProof (dynamic)
#   storageValue (static uint256)

encoded_ap = encode_bytes_array(account_proof)
encoded_sp = encode_bytes_array(storage_proof)
storage_val_bytes = pad32(storage_value)

# Offsets: 3 slots (3 * 32 = 96 bytes header)
offset_ap = 96  # 3 * 32
offset_sp = offset_ap + len(encoded_ap)

header = pad32(offset_ap) + pad32(offset_sp) + storage_val_bytes
payload = header + encoded_ap + encoded_sp

print('0x' + payload.hex())
PYEOF
