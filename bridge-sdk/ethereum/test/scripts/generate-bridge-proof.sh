#!/usr/bin/env bash
# Usage:
#   generate-bridge-proof.sh l1-to-dest <fork_rpc> <bridge_addr> <chain_head>
#   generate-bridge-proof.sh wc-to-l1  <fork_rpc> <bridge_addr> <chain_head>
#
# Starts an ephemeral anvil instance, plants keccakChain.head=chainHead at slot 0 of
# the given bridge address, mines a block, and returns ABI-encoded MPT proofs.
#
# l1-to-dest returns: abi.encode(bytes mptProof, bytes32 blockHash)
#   where mptProof = abi.encode(bytes headerRlp, bytes[] accountProof, bytes[] storageProof)
#
# wc-to-l1 returns: abi.encode(bytes mptProof, bytes32 rootClaim)
#   where mptProof = abi.encode(bytes[] outputRootProof, bytes[] accountProof, bytes[] storageProof)
set -euo pipefail

MODE="$1"
FORK_RPC="$2"
BRIDGE_ADDR="$3"
CHAIN_HEAD="$4"

# keccakChain.head lives at slot 0 in BridgeState
CHAIN_HEAD_SLOT="0x0000000000000000000000000000000000000000000000000000000000000000"

# ── Start anvil ──────────────────────────────────────────────────
PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
anvil --fork-url "$FORK_RPC" --port "$PORT" --silent &
ANVIL_PID=$!

PROOF_TMP=$(mktemp)
BLOCK_TMP=$(mktemp)
MSGP_TMP=$(mktemp)

cleanup() {
    kill "$ANVIL_PID" 2>/dev/null || true
    wait "$ANVIL_PID" 2>/dev/null || true
    rm -f "$PROOF_TMP" "$BLOCK_TMP" "$MSGP_TMP"
}
trap cleanup EXIT

RPC="http://localhost:$PORT"
for _ in $(seq 1 60); do
    cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break
    sleep 0.1
done

# ── Plant storage ────────────────────────────────────────────────
# Set keccakChain.head (slot 0) to the expected chain head value
cast rpc anvil_setCode "$BRIDGE_ADDR" "0x00" --rpc-url "$RPC" > /dev/null
cast rpc anvil_setStorageAt "$BRIDGE_ADDR" "$CHAIN_HEAD_SLOT" \
    "$CHAIN_HEAD" \
    --rpc-url "$RPC" > /dev/null

# ── Mine a block to commit trie ──────────────────────────────────
cast rpc anvil_mine "0x1" --rpc-url "$RPC" > /dev/null

BLOCK_NUM=$(cast block-number --rpc-url "$RPC")
BLOCK_HEX=$(python3 -c "print(hex($BLOCK_NUM))")

# ── Fetch proofs + block ─────────────────────────────────────────
cast rpc eth_getProof "$BRIDGE_ADDR" "[\"$CHAIN_HEAD_SLOT\"]" "$BLOCK_HEX" --rpc-url "$RPC" > "$PROOF_TMP"
cast rpc eth_getBlockByNumber "$BLOCK_HEX" false --rpc-url "$RPC" > "$BLOCK_TMP"

# ── Compute real state root ──────────────────────────────────────
# Anvil doesn't compute correct stateRoot in mined block headers when forking.
# Recover the real state root from keccak256 of the account proof's root trie node.
ACCT_ROOT_NODE=$(python3 -c "import json; print(json.load(open('$PROOF_TMP'))['accountProof'][0])")
REAL_STATE_ROOT=$(cast keccak "$ACCT_ROOT_NODE")

# ── Mode: l1-to-dest ─────────────────────────────────────────────
if [ "$MODE" = "l1-to-dest" ]; then
    python3 - "$PROOF_TMP" "$BLOCK_TMP" "$REAL_STATE_ROOT" <<'PYEOF'
import json, sys, subprocess

# ── Helpers ──
def hx(s):
    if s is None or s in ('0x', '0x0'):
        return b''
    h = s[2:] if s.startswith('0x') else s
    if len(h) % 2:
        h = '0' + h
    return bytes.fromhex(h)

def hx32(s):
    raw = hx(s)
    return raw.rjust(32, b'\x00') if raw else b'\x00' * 32

def pad32(n):
    return n.to_bytes(32, 'big')

def encode_bytes(b):
    length = len(b)
    padded_len = ((length + 31) // 32) * 32
    return pad32(length) + b + b'\x00' * (padded_len - length)

def encode_bytes_array(arr):
    n = len(arr)
    result = pad32(n)
    offsets, data_parts = [], []
    current_offset = n * 32
    for item in arr:
        offsets.append(pad32(current_offset))
        encoded = encode_bytes(item)
        data_parts.append(encoded)
        current_offset += len(encoded)
    return result + b''.join(offsets) + b''.join(data_parts)

# ── RLP encoding (from get-block-rlp.sh) ──
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

def build_header_rlp(b):
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
    return rlp_list(fields)

def keccak256(hex_data):
    """Compute keccak256 via cast keccak."""
    r = subprocess.run(['cast', 'keccak', hex_data], capture_output=True, text=True, check=True)
    return r.stdout.strip()

# ── Parse inputs ──
with open(sys.argv[1]) as f:
    proof = json.load(f)
with open(sys.argv[2]) as f:
    block = json.load(f)

# Override stateRoot with real value from proof (anvil writes zeros in fork mode)
block['stateRoot'] = sys.argv[3]

account_proof = [hx(p) for p in proof['accountProof']]
sp = proof['storageProof'][0]
storage_proof = [hx(p) for p in sp['proof']]

header_rlp = build_header_rlp(block)
block_hash = hx32(keccak256('0x' + header_rlp.hex()))

# ── Build mptProof = abi.encode(bytes, bytes[], bytes[]) ──
enc_h = encode_bytes(header_rlp)
enc_a = encode_bytes_array(account_proof)
enc_s = encode_bytes_array(storage_proof)

off_h = 3 * 32
off_a = off_h + len(enc_h)
off_s = off_a + len(enc_a)
mpt_proof = pad32(off_h) + pad32(off_a) + pad32(off_s) + enc_h + enc_a + enc_s

# ── Return abi.encode(bytes mptProof, bytes32 blockHash) ──
enc_mpt = encode_bytes(mpt_proof)
off_mpt = 2 * 32  # 2 head slots: offset + bytes32
result = pad32(off_mpt) + block_hash + enc_mpt

print('0x' + result.hex())
PYEOF

# ── Mode: wc-to-l1 ───────────────────────────────────────────────
elif [ "$MODE" = "wc-to-l1" ]; then
    # Fetch message passer account proof (for its storage root)
    MSG_PASSER="0x4200000000000000000000000000000000000016"
    cast rpc eth_getProof "$MSG_PASSER" "[]" "$BLOCK_HEX" --rpc-url "$RPC" > "$MSGP_TMP"

    # Compute outputRoot via cast (avoids needing keccak256 in Python)
    STATE_ROOT="$REAL_STATE_ROOT"
    BLOCK_HASH=$(python3 -c "import json; print(json.load(open('$BLOCK_TMP'))['hash'])")
    MSGP_ROOT=$(python3 -c "import json; print(json.load(open('$MSGP_TMP'))['storageHash'])")

    ENCODED=$(cast abi-encode "f(bytes32,bytes32,bytes32,bytes32)" \
        "0x0000000000000000000000000000000000000000000000000000000000000000" \
        "$STATE_ROOT" "$MSGP_ROOT" "$BLOCK_HASH")
    OUTPUT_ROOT=$(cast keccak "$ENCODED")

    python3 - "$PROOF_TMP" "$STATE_ROOT" "$MSGP_ROOT" "$BLOCK_HASH" "$OUTPUT_ROOT" <<'PYEOF'
import json, sys

def hx(s):
    if s is None or s in ('0x', '0x0'):
        return b''
    h = s[2:] if s.startswith('0x') else s
    if len(h) % 2:
        h = '0' + h
    return bytes.fromhex(h)

def hx32(s):
    raw = hx(s)
    return raw.rjust(32, b'\x00') if raw else b'\x00' * 32

def pad32(n):
    return n.to_bytes(32, 'big')

def encode_bytes(b):
    length = len(b)
    padded_len = ((length + 31) // 32) * 32
    return pad32(length) + b + b'\x00' * (padded_len - length)

def encode_bytes_array(arr):
    n = len(arr)
    result = pad32(n)
    offsets, data_parts = [], []
    current_offset = n * 32
    for item in arr:
        offsets.append(pad32(current_offset))
        encoded = encode_bytes(item)
        data_parts.append(encoded)
        current_offset += len(encoded)
    return result + b''.join(offsets) + b''.join(data_parts)

# ── Parse inputs ──
with open(sys.argv[1]) as f:
    proof = json.load(f)

state_root = hx32(sys.argv[2])
msgp_root = hx32(sys.argv[3])
block_hash = hx32(sys.argv[4])
output_root = hx32(sys.argv[5])

account_proof = [hx(p) for p in proof['accountProof']]
sp = proof['storageProof'][0]
storage_proof = [hx(p) for p in sp['proof']]

# ── outputRootProof: bytes[] with 4 elements (each 32 raw bytes) ──
version = b'\x00' * 32
output_root_proof = [version, state_root, msgp_root, block_hash]

# ── mptProof = abi.encode(bytes[], bytes[], bytes[]) ──
enc_o = encode_bytes_array(output_root_proof)
enc_a = encode_bytes_array(account_proof)
enc_s = encode_bytes_array(storage_proof)

off_o = 3 * 32
off_a = off_o + len(enc_o)
off_s = off_a + len(enc_a)
mpt_proof = pad32(off_o) + pad32(off_a) + pad32(off_s) + enc_o + enc_a + enc_s

# ── Return abi.encode(bytes mptProof, bytes32 rootClaim) ──
enc_mpt = encode_bytes(mpt_proof)
off_mpt = 2 * 32
result = pad32(off_mpt) + output_root + enc_mpt

print('0x' + result.hex())
PYEOF

else
    echo "Unknown mode: $MODE (expected l1-to-dest or wc-to-l1)" >&2
    exit 1
fi
