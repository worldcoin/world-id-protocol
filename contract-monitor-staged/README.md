# contract-monitor

On-chain event watcher service that subscribes to smart contract events via WebSocket and logs decoded event data. It auto-fetches ABIs from block explorer APIs (Etherscan V2), resolves proxy implementations, and emits structured logs for every matched event — ready for ingestion by Datadog or any log aggregator.

## How it works

1. On startup the service reads a TOML config listing contracts and (optionally) specific event names to watch.
2. For each contract it fetches the ABI from the configured block explorer, resolving proxy → implementation if needed.
3. It opens a WebSocket subscription to the RPC node, filtering by contract address and topic0.
4. Every matching log is decoded using the fetched ABI and emitted as a structured `tracing::info!` log line.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `WATCHER_CONFIG` | yes | Path to a TOML file listing contracts (see below) |
| `WATCHER_CHAIN_NAME` | yes | Human-readable chain name (e.g. `worldchain`) |
| `WATCHER_CHAIN_ID` | yes | Numeric chain ID (e.g. `480`) |
| `WATCHER_WS_RPC_URL` | yes | WebSocket RPC endpoint |
| `WATCHER_EXPLORER_URL` | yes | Etherscan-compatible API URL (e.g. `https://api.etherscan.io/v2/api`) |
| `WATCHER_EXPLORER_API_KEY` | no | API key for the block explorer |
| `HTTP_ADDR` | no | Health server listen address (default `0.0.0.0:8080`) |
| `TELEMETRY_PRESET` | no | Telemetry preset (`datadog`) |
| `TELEMETRY_SERVICE_NAME` | no | Service name for telemetry (default `contract-monitor`) |
| `TELEMETRY_METRICS_BACKEND` | no | Metrics backend (`statsd`) |
| `TELEMETRY_STATSD_HOST` | no | StatsD host |
| `TELEMETRY_STATSD_PORT` | no | StatsD port |

## Config file format

The config file is a TOML file listing contracts to watch:

```toml
[[contracts]]
name = "RpRegistry"
contract_address = "0x37d2462fE7B4a07987263AAd062C6593C4f567b9"
# Optional: if omitted, ALL events are subscribed and logged.
# If present, only these event names are watched.
# event_names = ["RpRegistered", "RpUpdated"]

[[contracts]]
name = "IssuerSchemaRegistry"
contract_address = "0x9037125Ae10e9E89fDbe7001228289462EFA3eF3"
```

See [`config/example.toml`](config/example.toml) for a full example.

## Running locally

```bash
# Copy and edit the example env file
cp .env.example .env
# Edit .env — at minimum set WATCHER_WS_RPC_URL to a real WebSocket RPC endpoint

# Run
cargo run
```

## Running with Docker

```bash
docker build -t contract-monitor .
docker run --env-file .env -p 8080:8080 contract-monitor
```

## Health check

```
GET /health → {"status": "ok"}
```

## Deploy

Helm values files for the `crypto-stage` and `crypto-prod` clusters are in [`deploy/`](deploy/):

- `deploy/values-contract-monitor-stage.yaml` — staging on `crypto-stage`
- `deploy/prod/values-contract-monitor-prod.yaml` — production on `crypto-prod`

Secrets (`WATCHER_WS_RPC_URL`, `WATCHER_EXPLORER_API_KEY`) are loaded from AWS Secrets Manager via the common-app chart.

## Tests

```bash
# Unit + integration tests (requires Anvil from Foundry)
cargo test --all-features
```

## CI

- **`ci.yml`** — runs `cargo fmt`, `cargo clippy`, and `cargo test` on every PR and push to `main`.
- **`build-and-push.yml`** — builds the Docker image and pushes to GHCR on merge to `main`.
