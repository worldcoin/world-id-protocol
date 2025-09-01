# 🚧 WIP: world-id-protocol

> This project is work in progress and unaudited. DO NOT USE IN PRODUCTION.

This repo is a minimal monorepo scaffolding that contains:

- Multiple Rust services (`service-a`, `registry-gateway`)
- A shared Rust library crate (`common`)
- A Foundry (forge) Solidity project (`contracts`)

## Layout

```
crates/
  common/            # shared Rust library
services/
  service-a/         # axum web service
  registry-gateway/  # AuthenticatorRegistry HTTP gateway (Axum + Alloy)
contracts/           # Foundry project (forge)
```

## Prerequisites

- Rust toolchain (`rustup`, `cargo`) – uses stable toolchain via `rust-toolchain.toml`
- Foundry (for Solidity): `curl -L https://foundry.paradigm.xyz | bash` then `foundryup`

## Commands

Use the provided Makefile targets:

- `make rust-build`: Build all Rust crates
- `make rust-test`: Run all Rust tests
- `make rust-fmt`: Format Rust code
- `make rust-clippy`: Lint with clippy (fails on warnings)
- `make run-a`: Run `service-a` (default at 127.0.0.1:3000)
- `make run-gateway`: Run `registry-gateway` (default at 127.0.0.1:4000)
- `make sol-build`: Build contracts with forge
- `make sol-test`: Test contracts with forge
- `make sol-fmt`: Format Solidity code

## Rust services

Both services are simple `axum` servers:

- `service-a`
  - `GET /health` → `{ "status": "ok" }`
  - `GET /hello/:name` → `{ "message": "Hello, <name>!" }` (uses `common::greeting`)
  - Port via `SERVICE_A_PORT` or `PORT` (default 3000)

- `registry-gateway`
  - `GET /health` → `{ "status": "ok" }`
  - AuthenticatorRegistry APIs (selected):
    - `POST /create-account` (batched → `createManyAccounts`)
    - `POST /update-authenticator`
    - `POST /insert-authenticator`
    - `POST /remove-authenticator`
    - `POST /recover-account`
  - Env: `RPC_URL`, `WALLET_KEY`, `REGISTRY_ADDRESS`, optional `RG_BATCH_MS`, `RG_PORT`/`PORT`

## Solidity contracts

Foundry layout under `contracts/` with an example `Counter` contract, test, and script.

Common commands:

```
cd contracts
forge build
forge test -vvv
forge fmt
```

## Next steps

- Add CI (GitHub Actions) for Rust and Foundry
- Add Dockerfiles and/or docker-compose for services
- Extend `common` crate for shared types, config, and error handling
- Wire services together or add DB/queues as needed
