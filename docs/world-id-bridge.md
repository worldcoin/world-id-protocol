# World ID Cross-Chain Bridge Implementation Plan

## Overview

Two bridge types for different trust/complexity tradeoffs:

| Route | Mechanism | Trust Model |
|-------|-----------|-------------|
| World Chain → L1 | L2CrossDomainMessenger | Native OP Stack (optimistic) |
| World Chain → Optimism | Storage proofs via L1Block | Fully trustless |

---

## Architecture

```
World Chain                 Ethereum L1                      Optimism
┌──────────────┐           ┌─────────────────────┐          ┌──────────────────────┐
│ WorldID      │           │  L2OutputOracle     │          │  L1Block predeploy   │
│ Registry     │           │  (WC outputs)       │          │  (has L1 block hash) │
│ + Registries │           │                     │          │                      │
└──────┬───────┘           │  WorldIDStateBridge │          │  WorldIDStateBridge  │
       │                   │  (receives msg)     │          │  (verifies proofs)   │
       │                   └─────────────────────┘          └──────────────────────┘
       │                          ▲                                ▲
       │                          │                                │
       │    ┌─────────────────────┴────────────────────────────────┘
       │    │
       ▼    │
┌──────────────────┐
│ world-id-bridge  │
│ service          │
│ - monitors WC    │
│ - sends messages │
│ - sends proofs   │
└──────────────────┘
```

---

## What Needs to Be Bridged

The WorldIDVerifier requires these inputs to construct the 15 public signals for Groth16 verification:

| Data | Source Contract | Bridge Strategy |
|------|-----------------|-----------------|
| `_latestRoot` | WorldIDRegistry | Bridge ~hourly (changes frequently) |
| `_rootToTimestamp[root]` | WorldIDRegistry | Bridge with root |
| `_treeDepth` | WorldIDRegistry | Hardcode (never changes) |
| `_rootValidityWindow` | WorldIDRegistry | Hardcode (rarely changes) |
| Credential issuer pubkey (x, y) | CredentialSchemaIssuerRegistry | Bridge when changed |
| OPRF pubkey (x, y) | OprfKeyRegistry | Bridge when changed |

**Bridging frequency**: ~hourly by `world-id-bridge` service. Users verify against already-bridged state (no proofs needed from users).

**What gets bridged**: Root + timestamp always. Registry pubkeys only when changed.

---

## Bridge Type 1: World Chain → L1 (Messenger)

### Contracts

**WorldIDStateSender** (World Chain)
- Reads `WorldIDRegistry` root/timestamp and registry pubkeys
- Sends state update via `L2CrossDomainMessenger` to L1

**WorldIDStateBridgeL1** (L1)
- Receives messages from `L1CrossDomainMessenger`
- Stores roots and registry data
- Validates sender via `xDomainMessageSender()`

**WorldIDVerifierL1** (L1)
- User-facing verification contract
- Reads roots and registry data from WorldIDStateBridgeL1
- `verify()` checks proof against stored roots, verifies Groth16

### Flow

1. `world-id-bridge` service calls `WorldIDStateSender.bridgeState()` on World Chain (~hourly)
2. Message relayed to L1 (optimistically or after finalization)
3. `WorldIDStateBridgeL1.receiveState()` stores root + registry data
4. Users call `WorldIDVerifierL1.verify()` with their ZK proof
5. Verifier checks `proof.root` against stored roots, verifies Groth16

### Files

```
contracts/src/bridge/
├── WorldIDStateSender.sol         # World Chain
├── WorldIDStateBridgeL1.sol       # L1 receiver + state storage
└── WorldIDVerifierL1.sol          # L1 verifier
```

---

## Bridge Type 2: World Chain → Optimism (Storage Proofs)

### Contracts

**WorldIDStateBridge** (Optimism)
- Receives bridge updates from `world-id-bridge` service
- Verifies storage proofs against L1 state (via L1Block predeploy)
- Stores proven roots and registry data
- Single `updateState()` function handles all state updates

Bridge update flow (called by `world-id-bridge` service ~hourly):
1. Get L1 block hash from `L1Block` predeploy
2. Verify provided L1 block header matches hash, extract L1 state root
3. Verify storage proof: `L2OutputOracle.outputRoots[index]` → World Chain output root
4. Extract World Chain state root from output root
5. Verify storage proofs for all needed slots (`_latestRoot`, registry pubkeys if changed)
6. Store proven values

**WorldIDVerifierBridge** (Optimism)
- User-facing verification contract
- Reads roots and registry data from WorldIDStateBridge
- `verify()` checks proof against stored roots, verifies Groth16

### Proof Data (submitted by world-id-bridge service)

```solidity
struct BridgeProofData {
    bytes l1BlockHeader;
    uint256 l2OutputIndex;
    bytes[] l1AccountProof;
    bytes[] l1StorageProof;
    bytes[] wcAccountProof;
    bytes[] wcStorageProofs;       // Multiple slots: root, registry data
}
```

### Files

```
contracts/src/bridge/
├── WorldIDStateBridge.sol         # Receives and verifies storage proofs
├── WorldIDVerifierBridge.sol      # User-facing verifier
└── libraries/
    ├── RLPReader.sol
    ├── MerklePatriciaProof.sol
    └── OutputRootLib.sol
```

1. Check if World Chain state has changed (root, registry pubkeys)
2. For Type 1 (L1): Call `WorldIDStateSender.bridgeState()` on World Chain
3. For Type 2 (Optimism): Generate storage proofs, call `WorldIDStateBridge.updateState()`

