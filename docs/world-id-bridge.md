# World ID Cross-Chain Bridge Implementation Plan

## Overview

Unified storage proof approach for bridging World ID state to other chains:

| Route | Mechanism | Trust Model |
|-------|-----------|-------------|
| World Chain → L1 | Storage proofs via L2OutputOracle | Optimistic (OP Stack) |
| World Chain → Optimism | Storage proofs via L1Block | Optimistic (OP Stack) |

Both bridges use the same pattern: verify World Chain storage proofs against the L2OutputOracle output root. The difference is how they access the L2OutputOracle - L1 reads it directly, Optimism proves it via L1Block.

---

## Architecture

```
World Chain        Ethereum L1                      Optimism
┌──────────────┐  ┌─────────────────────────────┐  ┌───────────────────────────┐
│ WorldID      │  │  L2OutputOracle             │  │  L1Block predeploy        │
│ Registry     │  │  (WC outputs)               │  │  (has L1 block hash)      │
│ + Registries │  │         │ read directly     │  │         │                 │
└──────────────┘  │         ▼                   │  │         ▼                 │
       │          │  WorldIDStateBridge         │  │  WorldIDStateBridge       │
       │          │  (verifies WC proofs)       │  │  (verifies L1 + WC proofs)│
       │          │         │                   │  │         │                 │
       │          │         ▼                   │  │         ▼                 │
       │          │  WorldIDVerifier            │  │  WorldIDVerifier          │
       │          └─────────────────────────────┘  └───────────────────────────┘
       │                 ▲                                ▲
       │                 │                                │
       │    ┌────────────┴────────────────────────────────┘
       │    │
       ▼    │
┌──────────────────┐
│ world-id-bridge  │
│ service          │
│ - monitors WC    │
│ - generates      │
│   storage proofs │
│ - submits to L1  │
│   and Optimism   │
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

**What gets bridged**: Root + timestamp always. Registry pubkeys only when changed (detected via events).

---

## Bridge: World Chain → L1

### Verification Flow

1. Read `L2OutputOracle.outputRoots[index]` directly on L1
2. Extract World Chain state root from output root
3. Verify World Chain storage proofs against that state root
4. Store proven values

### Contracts

**WorldIDStateBridge** (L1)
- Receives bridge updates from `world-id-bridge` service
- Reads L2OutputOracle directly to get World Chain output root
- Verifies World Chain storage proofs
- Stores proven roots and registry data

**WorldIDVerifier** (L1)
- User-facing verification contract
- Reads roots and registry data from WorldIDStateBridge
- `verify()` checks proof against stored roots, verifies Groth16

### Proof Data

```solidity
struct L1BridgeProofData {
    uint256 l2OutputIndex;
    bytes[] wcAccountProof;        // WorldIDRegistry account proof
    bytes[] wcStorageProofs;       // Multiple slots: root, timestamp, registry data
}
```

---

## Bridge: World Chain → Optimism

### Verification Flow

1. Get L1 block hash from `L1Block` predeploy
2. Verify provided L1 block header matches hash, extract L1 state root
3. Verify storage proof: `L2OutputOracle.outputRoots[index]` → World Chain output root
4. Extract World Chain state root from output root
5. Verify World Chain storage proofs against that state root
6. Store proven values

### Contracts

**WorldIDStateBridge** (Optimism)
- Receives bridge updates from `world-id-bridge` service
- Verifies L1 state via L1Block predeploy
- Verifies L2OutputOracle storage proof to get World Chain output root
- Verifies World Chain storage proofs
- Stores proven roots and registry data

**WorldIDVerifier** (Optimism)
- User-facing verification contract
- Reads roots and registry data from WorldIDStateBridge
- `verify()` checks proof against stored roots, verifies Groth16

### Proof Data

```solidity
struct OptimismBridgeProofData {
    bytes l1BlockHeader;
    uint256 l2OutputIndex;
    bytes[] l1AccountProof;        // L2OutputOracle account proof
    bytes[] l1StorageProof;        // L2OutputOracle.outputRoots[index]
    bytes[] wcAccountProof;        // WorldIDRegistry account proof
    bytes[] wcStorageProofs;       // Multiple slots: root, timestamp, registry data
}
```

```

### Bridge Update Flow (~hourly)

1. Check if World Chain state has changed (root, registry pubkeys via events)
2. Generate World Chain storage proofs
3. For L1: Submit `L1BridgeProofData` to `WorldIDStateBridgeL1.updateState()`
4. For Optimism: Generate L1 proofs, submit `OptimismBridgeProofData` to `WorldIDStateBridgeOP.updateState()`

