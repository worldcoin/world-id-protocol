# 🚧 WIP: world-id-protocol

> [!CAUTION]
> This project is work in progress and unaudited. DO NOT USE IN PRODUCTION. Releases may contain breaking changes at any time.

Monorepo containing:

- `services/gateway`: HTTP API service to interact with onchain `WorldIDRegistry`
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
| `WorldIDRegistry`                | `0xb64a1F443C9a18Cd3865C3c9Be871946617C0d75`          |
| `CredentialSchemaIssuerRegistry` | `0xCd987d2C973B099FD291Bf5AF332031Dc980a96B`          |
| `RpRegistry`                     | `0x27ee9a7a64e445737e43cF5338584556b061e031`          |
| `OprfKeyRegistry`                |`0xD5dD99e7c11DaD43CF3D7AB0E708b2309738A618`           |
| `world-id-indexer`               | `https://world-id-indexer.stage-crypto.worldcoin.org` |
| `world-id-gateway`               | `https://world-id-gateway.stage-crypto.worldcoin.org` |

## 🚀 Releasing

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
