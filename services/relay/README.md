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

- **Permissioned** -- Owner-attested chain head relayed from World Chain (no proofs required). Supports multiple blockchain types via `chain_type`:
  - `"default"` (or omitted) -- Standard EVM chains (Base, Optimism, etc.)
  - `"tempo"` -- Tempo blockchain, uses `TempoNetwork` provider with 2D random nonces and pays gas in TIP-20 USDC.
- **Ethereum MPT** -- OP Stack dispute game + Merkle Patricia Trie storage proofs for bridging to L1.

## How It Works

The relay service runs a continuous loop with the following phases:

### 1. Backfill (startup)

On every startup the engine replays **all** historical events from block 0 to the current block. Four contract log filters are issued in parallel:

- `WorldIDRegistry` -- `RootRecorded`
- `CredentialSchemaIssuerRegistry` -- `IssuerSchemaRegistered`, `IssuerSchemaPubkeyUpdated`, `IssuerSchemaRemoved`
- `OprfKeyRegistry` -- `SecretGenFinalize`
- `WorldIDSource` -- `ChainCommitted`

All logs are sorted by `(block_number, log_index)` and replayed sequentially. **Only `ChainCommitted` events are committed** to the in-memory log during backfill; pubkey and root updates are skipped because handling their pending/finalized semantics during replay would add unnecessary complexity -- they will arrive via the live stream instead.

Each replayed `ChainCommitted` event is verified against the local keccak chain replica (`KeccakChain`), so by the end of backfill the local chain head matches the on-chain head. There is **no checkpoint persistence** -- every restart does a full backfill, which is safe because the replay is idempotent.

Once backfill completes the engine calls `log.mark_ready()`, which unblocks any waiting satellite tasks.

### 2. Live event streaming

After backfill the engine opens a polling-based event stream (`poll_events`) that queries all four contracts every 2 seconds for new logs. Each decoded `StateCommitment` is dispatched into the `CommitmentLog`:

| Variant | Storage | Purpose |
|---|---|---|
| `ChainCommitted` | append-only `entries` deque + keccak chain | Verified chain commitments that satellites relay |
| `RootCommitment` | `pending_roots` map | Merkle root updates waiting to be propagated |
| `IssuerPubKey` | `pending_issuers` map | Issuer key changes waiting to be propagated |
| `OprfPubKey` | `pending_oprfs` map | OPRF key changes waiting to be propagated |

Pending entries use an `insert_if_newer` strategy -- only the latest update per key is kept, and updates older than the most recent chain entry timestamp are dropped.

### 3. State propagation (`propagateState`)

On a configurable tick (default 1 hour, set via `bridge_interval_secs`) the engine checks if there are any pending issuer or OPRF key updates. If so, it calls `WorldIDSource.propagateState(issuerSchemaIds, oprfKeyIds)` on World Chain. The relay only passes issuer schema IDs and OPRF key IDs -- the `WorldIDSource` contract itself queries the `WorldIDRegistry` for the latest merkle root, so root updates are handled entirely on-chain without the relay needing to pass them in. This on-chain call batches all the updates (root + issuer keys + OPRF keys) into a new `ChainCommitted` event, which the live stream picks up and commits to the log.

If the call reverts with `NothingChanged()` (state was already propagated), the pending maps are cleared silently. Pending state is **always cleared after each attempt** to avoid retrying the same data indefinitely.

### 4. Commitment log

The `CommitmentLog` is the central data structure -- an append-only, hash-chain-verified log that all satellites read from:

- **Keccak chain replica** -- every `ChainCommitted` entry is verified by computing `keccak256(prev_head || blockHash || data)` and checking it matches the event's `keccakChain` field. Invalid entries are rejected.
- **Head index** -- a `DashMap<B256, usize>` maps each chain head to its position in the deque, enabling O(1) delta queries via `log.since(cursor)`.
- **Watch channel** -- a `tokio::sync::watch` broadcasts each new chain head to all subscribed satellites.
- **Deduplication** -- duplicate chain heads are silently skipped (idempotent).
- **Monotonicity** -- chain ID must stay constant and block numbers must be non-decreasing.

### 5. Satellite relay (source-to-destination sync)

Each satellite runs as an independent async task that:

1. **Waits for backfill** via `log.wait_ready()`.
2. **Queries the destination chain's current chain head** by calling `satellite.KECCAK_CHAIN()` on the destination contract. This becomes its `local_head` cursor.
3. **Computes the delta** via `log.since(local_head)` -- all entries the destination hasn't received yet.
4. **Merges the delta** using `reduce()`, which concatenates all `Commitment[]` payloads into a single `ChainCommitment` that advances from `local_head` to the log's current head in one transaction.
5. **Builds a proof** and **sends a relay transaction** through an ERC-7786 gateway on the destination chain.
6. **Subscribes to future updates** via the watch channel and repeats from step 3 whenever a new `ChainCommitted` event is emitted by the `WorldIDSource` contract.

### 6. Out-of-sync recovery

If a satellite's `local_head` is not found in the log (e.g. another relay instance or manual tx advanced the destination), the satellite:

1. Re-queries the destination chain's current head via `remote_chain_head()`.
2. If the remote head exists in the log, adopts it as the new `local_head` and continues.
3. If the remote head equals the log's head, there's nothing to relay -- it updates `local_head` and waits.
4. If the remote head is not in the log either, it logs a warning and waits for the next chain head update to try again.

Relay failures (transaction reverts, timeouts up to 10 minutes) are logged but non-fatal -- the satellite retries on the next chain head change.

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
    "bridge_interval_secs": 3600,
    "deployment_block": 27182479
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
    },
    {
      "name": "TEMPO",
      "destination_chain_id": 4217,
      "gateway": "0x9384f9Ae863674953666aAC1027488d3a9CbE3f9",
      "satellite": "0x1dD638cF594Cba6F3192e62029f6e0E2266B3716",
      "chain_type": "tempo"
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
| `source.deployment_block` | `0` | Block number at which `WorldIDSource` was deployed; backfill starts here |
| `permissioned_gateways[].name` | required | Satellite name (also derives `{NAME}_RPC_URL` env var) |
| `permissioned_gateways[].destination_chain_id` | required | Destination chain ID |
| `permissioned_gateways[].gateway` | required | ERC-7786 gateway address on destination chain |
| `permissioned_gateways[].satellite` | required | `WorldIDSatellite` proxy address on destination chain |
| `permissioned_gateways[].chain_type` | `"default"` | Blockchain type: `"default"` for standard EVM, `"tempo"` for Tempo |
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
RUST_LOG=world_id_relay=debug cargo run -p world-id-relay
```

The service loads `.env` automatically via `dotenvy`. Send `SIGINT` (Ctrl+C) for graceful shutdown.

Set `RUST_LOG` to control log verbosity:
- `RUST_LOG=world_id_relay=info` — default, major state changes only
- `RUST_LOG=world_id_relay=debug` — includes event processing, backfill progress, propagation ticks, and satellite relay details
- `RUST_LOG=world_id_relay=trace` — full detail including duplicate skips and hash chain verification

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
