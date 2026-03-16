# World ID Relay

Off-chain service that bridges World ID state from **World Chain** (chain 480, the source of truth) to satellite chains (Ethereum L1, L2 rollups, Alt L1s).

## Bridged Data

The relay bridges the following World ID state from World Chain to each satellite chain:

- **Merkle roots** -- Identity tree roots recorded by the `WorldIDRegistry`. Each `RootRecorded` event captures a new root and its timestamp, which satellites use to validate inclusion proofs (`updateRoot`).
- **Credential issuer public keys** -- BN254 affine points associated with issuer schema IDs from the `CredentialSchemaIssuerRegistry`. The relay tracks `IssuerSchemaRegistered`, `IssuerSchemaPubkeyUpdated`, and `IssuerSchemaRemoved` events and bridges the latest key for each schema (`setIssuerPubkey`).
- **OPRF public keys** -- BN254 affine points keyed by OPRF key ID from the `OprfKeyRegistry`. The relay tracks `SecretGenFinalize` events and bridges the resulting keys (`setOprfPubkey`).

Root updates, issuer key changes, and OPRF key changes are collected as pending state. Periodically the engine calls `propagateState(issuerSchemaIds, oprfKeyIds)` on `WorldIDSource`, which batches them into a `ChainCommitted` event containing ABI-encoded `Commitment[]` entries. Satellites then relay these chained commitments to the destination chain via ERC-7786 gateways.

## Architecture

The relay follows a **source -> log -> fan-out** pipeline:

1. **Stream** -- Watches World Chain registry contracts for events (`RootRecorded`, `ChainCommitted`, issuer/OPRF key updates) and back-fills historical events on startup.
2. **CommitmentLog** -- Append-only, hash-chain-verified log of all observed commitments. Each `ChainCommitted` event is verified against a local keccak chain replica before acceptance.
3. **Engine** -- Top-level coordinator. Consumes the event stream, feeds the log, periodically calls `propagateState()` on `WorldIDSource`, and manages satellite task lifecycles.
4. **Satellite** -- Destination-chain relayers that subscribe to the log, merge un-relayed commitments, build chain-specific proofs, and submit relay transactions through ERC-7786 gateways.

### Satellite types

- **Permissioned** -- Owner-attested chain head relayed from World Chain (no proofs required).
- **Ethereum MPT** -- OP Stack dispute game + Merkle Patricia Trie storage proofs for bridging to L1.

## Configuration

The relay is configured via a single JSON string passed through the `RELAY_CONFIG` environment variable (or `--config` CLI flag). RPC endpoints and the wallet key are passed as separate environment variables.

| Variable | Required | Description |
|---|---|---|
| `RELAY_CONFIG` | yes | JSON configuration string (see schema below) |
| `WALLET_PRIVATE_KEY` | yes | Private key for signing relay transactions |
| `WORLDCHAIN_RPC_URL` | yes | World Chain RPC endpoint |
| `{NAME}_RPC_URL` | per satellite | Satellite chain RPC endpoint, where `{NAME}` matches the satellite's `name` field in upper case (e.g. `ETHEREUM_RPC_URL`, `BASE_RPC_URL`) |

### Config schema

```json
{
  "source": {
    "chain_id": 480,
    "world_id_source": "0x...",
    "world_id_registry": "0x...",
    "oprf_key_registry": "0x...",
    "issuer_schema_registry": "0x...",
    "bridge_interval_secs": 3600
  },
  "ethereum_mpt_gateways": [
    {
      "name": "ETHEREUM",
      "destination_chain_id": 1,
      "gateway": "0x...",
      "satellite": "0x...",
      "dispute_game_factory": "0x...",
      "game_type": 0,
      "require_finalized": false
    }
  ],
  "permissioned_gateways": [
    {
      "name": "BASE",
      "destination_chain_id": 8453,
      "gateway": "0x...",
      "satellite": "0x..."
    }
  ]
}
```

| Field | Default | Description |
|---|---|---|
| `source.chain_id` | `480` | Source chain ID (World Chain) |
| `source.world_id_source` | required | `WorldIDSource` proxy address |
| `source.world_id_registry` | required | `WorldIDRegistry` proxy address |
| `source.oprf_key_registry` | required | `OprfKeyRegistry` proxy address |
| `source.issuer_schema_registry` | required | `CredentialSchemaIssuerRegistry` proxy address |
| `source.bridge_interval_secs` | `3600` | Seconds between periodic `propagateState()` calls |
| `permissioned_gateways[].name` | required | Satellite name (also derives `{NAME}_RPC_URL` env var) |
| `permissioned_gateways[].destination_chain_id` | required | Destination chain ID |
| `permissioned_gateways[].gateway` | required | ERC-7786 gateway address on destination chain |
| `permissioned_gateways[].satellite` | required | `WorldIDSatellite` proxy address on destination chain |
| `ethereum_mpt_gateways[].name` | required | Satellite name (also derives `{NAME}_RPC_URL` env var) |
| `ethereum_mpt_gateways[].destination_chain_id` | required | Destination chain ID |
| `ethereum_mpt_gateways[].gateway` | required | ERC-7786 gateway address on destination chain |
| `ethereum_mpt_gateways[].satellite` | required | `WorldIDSatellite` proxy address on destination chain |
| `ethereum_mpt_gateways[].dispute_game_factory` | required | OP Stack `DisputeGameFactory` address |
| `ethereum_mpt_gateways[].game_type` | `0` | Dispute game type (`0` = CANNON) |
| `ethereum_mpt_gateways[].require_finalized` | `false` | Require dispute games to be finalized (`DEFENDER_WINS`) |

## Running

1. Set up your environment variables:

```
cp .env.example .env
# Edit .env with your RPC URLs, wallet key, and contract addresses
```

2. Build and run **from the `services/relay/` directory** (dotenvy loads `.env` from the current working directory):

```bash
cd services/relay
cargo run -p world-id-relay
```

The service loads `.env` automatically via `dotenvy`. Send `SIGINT` (Ctrl+C) for graceful shutdown.

> **Note:** The `RELAY_CONFIG` value in `.env` must be wrapped in single quotes (`'...'`) because dotenvy interprets double quotes as delimiters, which would strip the JSON's `"` characters.

## Scripts

Helper scripts for testing the relay. Located in `scripts/` and run as cargo examples. All scripts read from the `.env` file and must be run from `services/relay/`.

### Create Account

Registers a new World ID account directly on the `WorldIDRegistry` contract. Generates a random authenticator seed, derives key pairs, and submits a `createAccount` transaction. If the registry has a registration fee, it will automatically approve the fee token first. Logs the transaction hash and the new `RootRecorded` root that the relay should bridge.

```bash
cd services/relay
cargo run --example create_account
```

### Register Issuer Schema

Registers a new issuer schema on the `CredentialSchemaIssuerRegistry` contract. Generates a random schema ID and EdDSA key pair, and submits a `register` transaction. Also triggers OPRF key generation for the new schema. Logs the `IssuerSchemaRegistered` event.

```bash
cd services/relay
cargo run --example register_issuer_schema
```
