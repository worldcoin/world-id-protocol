# world-id-protocol

> [!WARNING]
> This project is unaudited. Releases may contain breaking changes at any time.

## Prerequisites

- Rust toolchain (`rustup`, `cargo`) – pinned via `rust-toolchain.toml`
- Foundry (forge/cast/anvil): `curl -L https://foundry.paradigm.xyz | bash` then `foundryup`
- For running the Rust services look at the specific READMEs of each service.

## 🗃️ Deployments

Deployments are tracked in [`contracts/deployments/`](contracts/deployments/)

### Core Contracts

| Environment | Chain              | Config                                                          |
| ----------- | ------------------ | --------------------------------------------------------------- |
| Production  | World Chain (`480`) | [`contracts/deployments/core/production.json`](contracts/deployments/core/production.json) |
| Staging     | World Chain (`480`) | [`contracts/deployments/core/staging.json`](contracts/deployments/core/staging.json) |

### OPRF Key Registry

| Environment | Chain              | Config                                                          |
| ----------- | ------------------ | --------------------------------------------------------------- |
| Production  | World Chain (`480`) | [`contracts/deployments/oprf-key-registry/prod.json`](contracts/deployments/oprf-key-registry/prod.json) |
| Staging     | World Chain (`480`) | [`contracts/deployments/oprf-key-registry/staging.json`](contracts/deployments/oprf-key-registry/staging.json) |

### Crosschain Contracts

| Environment | Chains             | Config                                                          |
| ----------- | ------------------ | --------------------------------------------------------------- |
| Staging     | World Chain (`480`), Ethereum (`1`), Base (`8453`) | [`contracts/deployments/crosschain/staging.json`](contracts/deployments/crosschain/staging.json) |

### Services

| Service            | Environment | URL                                                   |
| ------------------ | ----------- | ----------------------------------------------------- |
| `world-id-indexer` | Production  | `https://indexer.us.id-infra.worldcoin.dev`<br />`https://indexer.eu.id-infra.worldcoin.dev`<br />`https://indexer.ap.id-infra.worldcoin.dev` |
| `world-id-gateway` | Staging     | `https://world-id-gateway.stage-crypto.worldcoin.org` |

## 🏗️ Project Structure

This repo is organized into the following top-level components:

- **`circom/`**: Circom circuits for zero-knowledge proofs
- **`contracts/`**: Solidity smart contracts (see [contracts/README.md](contracts/README.md))
- **`crates/`**: Rust libraries providing protocol functionality
- **`services/`**: Deployable services (gateway, indexer, oprf-node)
- **`docs/`**: Protocol documentation (see [docs/README.md](docs/README.md))

### 📦 Crates Organization

The Rust crates are logically separated to ensure proper integration without feature flag conflicts:

```
world-id-primitives
└── functionality-specific crates
    └── world-id-core
```

- `world-id-primitives`: Foundation layer containing only raw types with **minimal implementation logic** except for hashing mechanisms. Has an optional `openapi` feature for OpenAPI schema derives.
- Functionality-specific crates: Providing focused use cases for authenticator, issuer, and RP operations.
- `world-id-core`: Top-level integration layer which exposes all functionality.


## 🚀 Releasing

Versioning and releases are managed separately for crates and services.

### Crates

Crate releases are automated using `release-plz`.

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
