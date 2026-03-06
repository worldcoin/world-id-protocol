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

### Keccak Hash Chain

State changes are batched into `Commitment[]` arrays. Each commitment is hashed into a running keccak chain:

```
head_{n+1} = keccak256(head_n ‖ blockHash ‖ commitmentData)
```

The chain head is a single `bytes32` stored on-chain. Destination chains verify that a relayed set of commitments hashes to the proven chain head, ensuring integrity without replaying every historical state change.

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
contracts/
├── src/
│   ├── WorldIDSource.sol                         # WorldIDSource (World Chain)
│   ├── WorldIDSatellite.sol                      # WorldIDSatellite (destination)
│   ├── Error.sol                          # Custom errors
│   ├── types/
│   │   ├── Common.sol                     # Shared types & imports
│   │   ├── IStateBridge.sol               # Bridge storage and events
│   │   ├── IGateway.sol                   # Gateway interface
│   │   └── IWorldID.sol                   # Verification interface
│   ├── lib/
│   │   ├── Lib.sol                        # MPT proofs, hash chain, codec
│   │   ├── StateBridge.sol                # Abstract upgradeable base
│   │   └── Gateway.sol                    # Abstract ERC-7786 gateway
│   └── adapters/
│       ├── PermissionedGatewayAdapter.sol # Owner-attested
│       ├── EthereumMPTGatewayAdapter.sol  # DisputeGame + MPT (trustless)
│       └── LightClientGatewayAdapter.sol  # SP1 Helios ZK + MPT (trustless)
├── script/
│   ├── Deploy.s.sol                       # Multi-chain deployment script
│   ├── E2E_MPT.s.sol                      # E2E integration test script
│   └── config/
│       ├── staging.json                   # Staging deployment config
│       └── local.json                     # Local anvil config
├── test/
│   ├── Gateway.t.sol                      # Gateway unit tests
│   ├── E2E.t.sol                          # E2E bridge tests
│   └── Attributes.t.sol                   # ERC-7786 attribute tests
├── deployments/
│   └── {env}.json                         # Deployment artifacts
└── foundry.toml
```

### Quick Start

```bash
# 1. Copy and fill in .env (only PRIVATE_KEY + ALCHEMY_API_KEY needed)
cp contracts/script/crosschain/.env.example contracts/script/crosschain/.env

# 2. Simulate deployment (no broadcast, no gas spent)
just contracts::crosschain-deploy-dry-run staging

# 3. Deploy for real
just contracts::crosschain-deploy staging

# 4. Check what was deployed
just contracts::crosschain-status staging
```

### Environment Variables

Only three env vars exist. Everything else lives in the config JSON.

| Variable | Required | Description |
|----------|----------|-------------|
| `PRIVATE_KEY` | Yes | Deployer key (must be funded on all target chains) |
| `ALCHEMY_API_KEY` | Yes* | Resolves per-chain RPCs via `alchemySlug` in config |
| `DEPLOY_CHAINS` | No | Comma-separated filter, e.g. `ethereum,base` |

\*Not required if every chain has an explicit `"rpc"` field in config.

### Configuration

Config files live in `contracts/script/crosschain/config/{env}.json`. The default environment is `staging`.

**Global parameters** apply to all chains:

```jsonc
{
  "owner": "0x...",                      // contract owner (receives ownership after deploy)
  "bridgeName": "WorldID Bridge",       // EIP-712 domain name
  "bridgeVersion": "1.0.0",             // EIP-712 domain version
  "rootValidityWindow": 3600,           // seconds a root stays valid
  "treeDepth": 30,                      // Semaphore Merkle tree depth
  "minExpirationThreshold": 18000,      // minimum proof expiration (seconds)
  "salts": {                            // CREATE2 salts for deterministic addresses
    "worldIDSource": "0x...",
    "worldIDSatellite": "0x...",
    "ownedGateway": "0x...",
    "l1Gateway": "0x...",
    "zkGateway": "0x...",
    "verifier": "0x..."
  }
}
```

**World Chain** (source of truth):

```jsonc
{
  "worldchain": {
    "chainId": 480,
    "alchemySlug": "worldchain-mainnet",  // or "rpc": "https://..."
    "registry": "0x...",                  // WorldIDRegistry address
    "issuerRegistry": "0x...",            // CredentialSchemaIssuerRegistry
    "oprfRegistry": "0x..."               // OprfKeyRegistry
  }
}
```

**Destination networks** — listed in the `"networks"` array, each with its own config block:

```jsonc
{
  "networks": ["ethereum", "base"],

  "ethereum": {
    "chainId": 1,
    "alchemySlug": "eth-mainnet",
    "verifier": "0x000...000",            // zero address = deploy fresh Verifier
    "ownedGateway": {},                   // presence = deploy PermissionedGatewayAdapter
    "l1Gateway": {                        // presence = deploy EthereumMPTGatewayAdapter
      "disputeGameFactory": "0x...",
      "requireFinalized": false
    }
  },

  "base": {
    "chainId": 8453,
    "alchemySlug": "base-mainnet",
    "verifier": "0x000...000",
    "ownedGateway": {},
    "zkGateway": {                        // presence = deploy LightClientGatewayAdapter
      "sp1Verifier": "0x...",
      "programVKey": "0x...",
      "initialHead": 0,
      "initialHeader": "0x...",
      "initialSyncCommitteeHash": "0x..."
    }
  }
}
```

### Just Recipes

All commands run from the repo root. Default env is `staging`.

```bash
# ── Deploy ────────────────────────────────────────────────────
just contracts::crosschain-deploy                                 # deploy all networks
just contracts::crosschain-deploy staging                         # deploy to staging env
DEPLOY_CHAINS=ethereum just contracts::crosschain-deploy          # deploy only ethereum

# ── Simulate ──────────────────────────────────────────────────
just contracts::crosschain-deploy-dry-run                         # simulate without broadcasting

# ── Inspect ───────────────────────────────────────────────────
just contracts::crosschain-status                                 # print deployment artifact JSON

# ── Admin ─────────────────────────────────────────────────────
just contracts::crosschain-gateway-add ethereum 0xGATEWAY         # authorize a gateway
just contracts::crosschain-gateway-remove ethereum 0xGATEWAY      # revoke a gateway
just contracts::crosschain-transfer-ownership-world-id-source worldchain 0xNEW
just contracts::crosschain-transfer-ownership-world-id-satellite ethereum 0xNEW

# ── Testing ───────────────────────────────────────────────────
just test                            # all tests (core + bridge + e2e)
just crosschain                      # bridge unit tests only
just it                              # full multi-anvil E2E MPT test
just it 50                           # E2E with batch size 50
just it-all                          # E2E at batch sizes 1, 50, 100
```

### Adding a New Chain

1. Add the chain config to `contracts/script/crosschain/config/{env}.json`:
   ```json
   {
     "networks": ["ethereum", "base", "mynewchain"],
     "mynewchain": {
       "chainId": 12345,
       "alchemySlug": "mynewchain-mainnet",
       "verifier": "0x0000000000000000000000000000000000000000",
       "ownedGateway": {}
     }
   }
   ```
2. Ensure the deployer key is funded on the new chain.
3. Deploy: `just contracts::crosschain-deploy` (or `DEPLOY_CHAINS=mynewchain just contracts::crosschain-deploy` to deploy only it).

### Re-deploying

The deployment is idempotent — re-running `just contracts::crosschain-deploy` skips contracts that already exist in the artifact file. To force a fresh deploy:

1. Remove the chain's entry from `contracts/deployments/crosschain/{env}.json`
2. Run `just contracts::crosschain-deploy` again

To redeploy everything, delete the entire artifact file.