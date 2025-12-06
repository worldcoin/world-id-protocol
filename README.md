# 🚧 WIP: world-id-protocol

> This project is work in progress and unaudited. DO NOT USE IN PRODUCTION.

Monorepo containing:

- `services/gateway`: HTTP API service to interact with onchain `AccountRegistry`
- `services/indexer`: Indexer for `AccountCreated` events serving inclusion proofs
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
| `world-id-gateway`               | `https://world-id-gateway.stage-crypto.worldcoin.org` |

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
- `make run-gateway`: Run `world-id-gateway` (defaults to 127.0.0.1:4000)
- `make sol-build`: `forge build` in `contracts/`
- `make sol-test`: `forge test -vvv` in `contracts/`
- `make sol-fmt`: `forge fmt` in `contracts/`

## Releasing

Versioning and releases are managed separately for crates and services.

### Crates

Crate releases (`world-id-core`, `world-id-primitives`) are automated using `release-plz`.

**How it works:**

1. Commits to `main` follow [conventional commits](https://www.conventionalcommits.org/). To override the version, simply update the PR.
2. release-plz creates/updates a release PR with:
   - Version bumps in `Cargo.toml` files
   - Updated `CHANGELOG.md` for each crate
3. When the release PR is merged:
   - Crates are published to [crates.io](https://crates.io) using trusted publishing
   - GitHub releases are created for each updated crate (e.g., `world-id-core-v0.2.0`)

### Services

Information coming soon.
