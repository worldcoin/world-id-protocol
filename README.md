# 🚧 WIP: world-id-protocol

> This project is work in progress and unaudited. DO NOT USE IN PRODUCTION.

Monorepo containing:

- `services/registry-gateway`: HTTP API service to interact with onchain `AuthenticatorRegistry` 
- `services/authtree-indexer`: Indexer for `AccountCreated` events serving inclusion proofs
- `crates/common`: Shared Rust library
- `contracts/`: Onchain contracts

## Prerequisites

- Rust toolchain (`rustup`, `cargo`) – pinned via `rust-toolchain.toml`
- Foundry (forge/cast/anvil): `curl -L https://foundry.paradigm.xyz | bash` then `foundryup`
- Postgres (for the indexer) if you run `authtree-indexer`

Optional:
- `direnv` or `.env` files via `dotenvy` for service env vars

## Make targets

Use the provided Makefile:

- `make help`: Show all available targets with descriptions
- `make build`: Build Rust workspace and Solidity contracts
- `make fmt`: Format Rust and Solidity
- `make lint`: Run Rust clippy (fails on warnings)
- `make test`: Run both Rust and Solidity tests
- `make rust-build`: `cargo build --workspace`
- `make rust-test`: `cargo test --workspace`
- `make rust-fmt`: `cargo fmt --all`
- `make rust-clippy`: `cargo clippy --workspace --all-targets -D warnings`
- `make run-indexer`: Run `authtree-indexer`
- `make run-gateway`: Run `registry-gateway` (defaults to 127.0.0.1:4000)
- `make sol-build`: `forge build` in `contracts/`
- `make sol-test`: `forge test -vvv` in `contracts/`
- `make sol-fmt`: `forge fmt` in `contracts/`

## Running services

### registry-gateway

Environment variables:

- `RPC_URL` (required): HTTP RPC endpoint
- `WALLET_KEY` (required): Hex private key for sending txs
- `REGISTRY_ADDRESS` (required): `AuthenticatorRegistry` address (0x…)
- `RG_BATCH_MS` (optional, default 1000): Batch window
- `RG_PORT` or `PORT` (optional, default 4000): Listen port
- `RUST_LOG` (optional): e.g. `registry_gateway=debug,axum=info`

Run:

```
make run-gateway
```

Endpoints:

- `GET /health`
- `POST /create-account` (batched)
- `POST /update-authenticator`
- `POST /insert-authenticator`
- `POST /remove-authenticator`
- `POST /recover-account`
- `GET /is-valid-root?root=<u256>`

### authtree-indexer

Environment variables:

- `RPC_URL` (required): HTTP RPC endpoint
- `REGISTRY_ADDRESS` (optional, default 0x0…0): Contract address
- `DATABASE_URL` or `PG_URL` (required): Postgres connection string
- `START_BLOCK` (optional, default 0): Initial block to backfill from
- `BATCH_SIZE` (optional, default 5000): Backfill chunk size
- `WS_URL` (optional): Websocket RPC; when provided, follows new logs live after backfill
- `RUST_LOG` (optional): e.g. `authtree_indexer=info`

Run:

```
make run-indexer
```

The indexer will backfill `AccountCreated` events into Postgres tables defined under `services/authtree-indexer/migrations`, then optionally follow live via WS if `WS_URL` is set.

## Solidity contracts

Foundry project under `contracts/`.

Common commands:

```
cd contracts
forge build
forge test -vvv
forge fmt
```

## Development

- Build everything: `make build`
- Test Rust: `make rust-test`; Test Solidity: `make sol-test`; Both: `make test`
- Format: `make fmt`
- Lint: `make lint`

## Notes

- This codebase is unaudited. Do not use in production.
- Ensure RPC and Postgres credentials are correct before running services.
