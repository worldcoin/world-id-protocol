# 🚧 WIP: world-id-protocol

> This project is work in progress and unaudited. DO NOT USE IN PRODUCTION.

Monorepo containing:

- `services/registry-gateway`: HTTP API service to interact with onchain `AccountRegistry`
- `services/world-id-indexer`: Indexer for `AccountCreated` events serving inclusion proofs
- `crates/world-id-core`: The core library of the World ID Protocol
- `contracts/`: Onchain contracts

## Prerequisites

- Rust toolchain (`rustup`, `cargo`) – pinned via `rust-toolchain.toml`
- Foundry (forge/cast/anvil): `curl -L https://foundry.paradigm.xyz | bash` then `foundryup`
- For running the Rust services look at the specific READMEs of each service.

## 🗃️ Addressbook

### Staging (World Chain Mainnet)

> [!WARNING]  
> These deployments are the current most up-to-date version, but this project is still WIP and deployments may change at any time.

- Deployed by `world-id-gateway`'s wallet address: `0x777DF5A6ab04B47995f0750D5Ff188879DC60Ac7`
- Deployed to World Chain Mainnet (Chain ID: `480`)

| Contract / Service               | Address                                               |
| -------------------------------- | ----------------------------------------------------- |
| `AccountRegistry`                | `0xd66aFbf92d684B4404B1ed3e9aDA85353c178dE2`          |
| `CredentialSchemaIssuerRegistry` | `0xCd987d2C973B099FD291Bf5AF332031Dc980a96B`          |
| `world-id-indexer`               | `https://world-id-indexer.stage-crypto.worldcoin.org` |

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
- `make run-indexer`: Run `world-id-indexer`
- `make run-gateway`: Run `registry-gateway` (defaults to 127.0.0.1:4000)
- `make sol-build`: `forge build` in `contracts/`
- `make sol-test`: `forge test -vvv` in `contracts/`
- `make sol-fmt`: `forge fmt` in `contracts/`

## Running services

### registry-gateway

Environment variables:

- `RPC_URL` (required): HTTP RPC endpoint
- `WALLET_KEY` (required): Hex private key for sending txs
- `REGISTRY_ADDRESS` (required): `AccountRegistry` address (0x…)
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
