# World ID 4.0 State Bridge

> [!CAUTION]
> This is work in progress and unaudited. DO NOT USE IN PRODUCTION. Releases may contain breaking changes at any time.

Cross-chain state bridge for World ID 4.0. Propagates identity state (Merkle roots, issuer public keys, OPRF keys) from World Chain to any EVM destination chain, enabling World ID proof verification everywhere.

## Architecture

```
World Chain                          Destination Chain
┌──────────────┐                     ┌──────────────────┐
│ WorldIDSource │ ── keccak chain ──▸│ WorldIDSatellite  │
│ (registries)  │    commitment      │ (proof verifier)  │
└──────────────┘                     └────────▲─────────┘
                                              │ ERC-7786
                                     ┌────────┴─────────┐
                                     │  Gateway Adapter  │
                                     │ (verify + relay)  │
                                     └──────────────────┘
```

### Core Contracts

**`WorldIDSource`** — Deployed on World Chain. Reads state from the on-chain registries (`WorldIDRegistry`, `CredentialSchemaIssuerRegistry`, `OprfKeyRegistry`) and accumulates changes into a keccak hash chain. Anyone can call `propagateState()` to snapshot current registry state into the chain.

**`WorldIDSatellite`** — Deployed on each destination chain. Receives bridged state via [ERC-7786](https://eips.ethereum.org/EIPS/eip-7786) gateways, verifies that the committed chain head matches, and applies the state updates. Exposes `verify()` for Groth16 proof verification against the bridged Merkle root.

**`StateBridge`** — Abstract UUPS-upgradeable base shared by Source and Satellite. Manages the keccak hash chain accumulator, proven root/pubkey storage, and gateway authorization.

### Keccak Hash Chain

State changes are batched into `Commitment[]` arrays. Each commitment is hashed into a running keccak chain:

```
head_{n+1} = keccak256(head_n ‖ blockHash ‖ commitmentData)
```

The chain head is a single `bytes32` stored on-chain. Destination chains verify that a relayed set of commitments hashes to the proven chain head, ensuring integrity without replaying every historical state change.

### Gateway Adapters

Gateways are ERC-7786 source contracts that verify cross-chain state and deliver it to the Satellite. Each adapter implements a different trust model:

| Adapter | Trust Model | Where | Status |
|---------|------------|-------|--------|
| **PermissionedGatewayAdapter** | Owner-attested — the adapter owner signs off on the chain head | Any chain (fallback) | ✅ |
| **EthereumMPTGatewayAdapter** | Trustless — verifies World Chain state via OP Stack DisputeGame + MPT storage proofs against L1 | Ethereum L1 / OP Stack | ✅ |
| **LightClientGatewayAdapter** | Trustless — verifies L1 consensus via SP1 Helios ZK proof, then MPT-proves the L1 StateBridge's chain head | L2s and non-Ethereum chains | WIP |

Every destination chain gets a **PermissionedGateway** as a temporary fallback until the light client adapter is production-ready, plus a trustless adapter appropriate for that chain's position in the trust hierarchy.

### Bridging Flow

1. **World Chain**: `propagateState()` reads registries, diffs against stored state, and extends the keccak chain with new commitments.
2. **Relayer**: Calls `gateway.sendMessage(recipient, payload, attributes)` on the destination chain, providing the commitment payload and chain-specific proof data as ERC-7786 attributes.
3. **Gateway**: Verifies the proof (owner signature, DisputeGame+MPT, or ZK+MPT) and extracts the proven chain head.
4. **Satellite**: Receives the message via `receiveMessage()`, verifies the commitments hash to the proven chain head, and applies the state updates.

### State Types

The bridge propagates three types of state, each identified by a commitment selector:

- **`updateRoot`** — The World ID Merkle tree root and its timestamp
- **`setIssuerPubkey`** — Credential issuer public keys (BabyJubJub points)
- **`setOprfKey`** — OPRF public keys (BabyJubJub points)

## Directory Structure

```
bridge/contracts/
├── src/
│   ├── Core.sol                          # Top-level re-exports
│   ├── interfaces/Common.sol             # Shared interface imports
│   └── core/
│       ├── Source.sol                     # WorldIDSource (World Chain)
│       ├── Satellite.sol                 # WorldIDSatellite (destinations)
│       ├── Error.sol                     # Custom errors
│       ├── interfaces/
│       │   ├── IStateBridge.sol          # Bridge storage and events
│       │   ├── IGateway.sol              # Gateway interface
│       │   └── IWorldID.sol              # Verification interface
│       └── lib/
│           ├── Lib.sol                   # MPT proofs, hash chain, codec
│           ├── StateBridge.sol           # Abstract upgradeable base
│           ├── Gateway.sol               # Abstract ERC-7786 gateway
│           └── adapters/
│               ├── PermissionedGatewayAdapter.sol
│               ├── EthereumMPTGatewayAdapter.sol
│               └── LightClientGatewayAdapter.sol
├── test/
│   ├── Gateway.t.sol                     # Gateway adapter tests
│   └── Attributes.t.sol                 # Attribute encoding tests
├── script/
│   ├── Deploy.s.sol                      # Multi-chain deployment script
│   └── config/
│       ├── local.json                    # Local dev config
│       └── staging.json                  # Staging config (10 chains)
├── Justfile                              # Deployment and dev recipes
└── foundry.toml
```

## Usage

```bash
# Build
just build

# Test
just bridge-test

# Print resolved deployment env
ALCHEMY_API_KEY=... just bridge-print-env staging

# Dry-run deployment
ALCHEMY_API_KEY=... PRIVATE_KEY=... just bridge-dry-run staging

# Deploy
ALCHEMY_API_KEY=... PRIVATE_KEY=... just bridge-deploy-all staging
```

See the [Justfile](contracts/Justfile) header for full recipe documentation.
