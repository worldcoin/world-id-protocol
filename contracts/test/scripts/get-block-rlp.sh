#!/usr/bin/env bash
# Usage: get-block-rlp.sh <block_hex> <rpc_url>
# Returns: 0x-prefixed RLP-encoded block header
#
# Example: ./get-block-rlp.sh 0x1749b78 https://ethereum-rpc.publicnode.com
set -euo pipefail

BLOCK_HEX="$1"
RPC_URL="$2"

TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

cast rpc eth_getBlockByNumber "$BLOCK_HEX" false --rpc-url="$RPC_URL" > "$TMPFILE"

python3 - "$TMPFILE" <<'PYEOF'
import json, sys

def encode_int(v):
    if v == 0:
        return b''
    h = hex(v)[2:]
    if len(h) % 2:
        h = '0' + h
    return bytes.fromhex(h)

def rlp_item(data):
    if isinstance(data, int):
        data = encode_int(data)
    n = len(data)
    if n == 0:
        return b'\x80'
    if n == 1 and data[0] < 0x80:
        return data
    if n < 56:
        return bytes([0x80 + n]) + data
    lb = encode_int(n)
    return bytes([0xb7 + len(lb)]) + lb + data

def rlp_list(items):
    payload = b''.join(items)
    n = len(payload)
    if n < 56:
        return bytes([0xc0 + n]) + payload
    lb = encode_int(n)
    return bytes([0xf7 + len(lb)]) + lb + payload

def hx(s):
    if s is None or s == '0x' or s == '0x0':
        return b''
    h = s[2:] if s.startswith('0x') else s
    if len(h) % 2:
        h = '0' + h
    return bytes.fromhex(h)

def hx32(s):
    raw = hx(s)
    return raw.rjust(32, b'\x00') if raw else b'\x00' * 32

with open(sys.argv[1]) as f:
    b = json.load(f)

fields = [
    rlp_item(hx32(b['parentHash'])),
    rlp_item(hx32(b['sha3Uncles'])),
    rlp_item(hx(b['miner'])),
    rlp_item(hx32(b['stateRoot'])),
    rlp_item(hx32(b['transactionsRoot'])),
    rlp_item(hx32(b['receiptsRoot'])),
    rlp_item(hx(b['logsBloom'])),
    rlp_item(hx(b['difficulty'])),
    rlp_item(hx(b['number'])),
    rlp_item(hx(b['gasLimit'])),
    rlp_item(hx(b['gasUsed'])),
    rlp_item(hx(b['timestamp'])),
    rlp_item(hx(b['extraData'])),
    rlp_item(hx32(b['mixHash'])),
    rlp_item(hx(b['nonce'])),
]

if b.get('baseFeePerGas') is not None:
    fields.append(rlp_item(hx(b['baseFeePerGas'])))
if b.get('withdrawalsRoot') is not None:
    fields.append(rlp_item(hx32(b['withdrawalsRoot'])))
if b.get('blobGasUsed') is not None:
    fields.append(rlp_item(hx(b['blobGasUsed'])))
if b.get('excessBlobGas') is not None:
    fields.append(rlp_item(hx(b['excessBlobGas'])))
if b.get('parentBeaconBlockRoot') is not None:
    fields.append(rlp_item(hx32(b['parentBeaconBlockRoot'])))
if b.get('requestsHash') is not None:
    fields.append(rlp_item(hx32(b['requestsHash'])))

print('0x' + rlp_list(fields).hex())
PYEOF
