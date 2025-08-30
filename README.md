# Monorepo: Rust Services + Library + Solidity Contracts

This repo is a minimal monorepo scaffolding that contains:

- Multiple Rust services (`service-a`, `service-b`)
- A shared Rust library crate (`common`)
- A Foundry (forge) Solidity project (`contracts`)

## Layout

```
crates/
  common/            # shared Rust library
services/
  service-a/         # axum web service
  service-b/         # axum web service
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
- `make run-b`: Run `service-b` (default at 127.0.0.1:4000)
- `make sol-build`: Build contracts with forge
- `make sol-test`: Test contracts with forge
- `make sol-fmt`: Format Solidity code

## Rust services

Both services are simple `axum` servers:

- `service-a`
  - `GET /health` → `{ "status": "ok" }`
  - `GET /hello/:name` → `{ "message": "Hello, <name>!" }` (uses `common::greeting`)
  - Port via `SERVICE_A_PORT` or `PORT` (default 3000)

- `service-b`
  - `GET /health` → `{ "status": "ok" }`
  - `GET /sum?a=<i64>&b=<i64>` → `{ a, b, sum, message }`
  - Port via `SERVICE_B_PORT` or `PORT` (default 4000)

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

