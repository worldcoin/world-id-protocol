![](docs/header.jpg)

# World ID

World ID is a protocol built to enable anonymous proof of human (PoH) at global scale and to complement existing identity systems. World ID allows individuals to prove things about themselves — like they are a real and unique human, not a bot — without revealing any personal information. [Read more about World ID][website].

This repository contains the **core components of the World ID Protocol**, including the smart contracts, Rust libraries, and services that power the protocol.

## 📝 Documentation

- **Learn more about World ID**: To learn more about World ID in general, see the [World ID Website][website].
- **Integrating World ID**: The best place to start for integrating World ID is the [Developer Docs](https://docs.world.org/world-id/overview).
- **Protocol Specs**: For an a high level overview of the latest major version of the Protocol (World ID 4.0), see the [World ID 4.0 Product & Technical Specs](docs/README.md).
- **In-depth technical documentation**: The primary source of technical documentation for the Protocol is directly in the codebase, particularly the foundational crates. See the [`world-id-primitives`](https://docs.rs/world-id-primitives) and [`world-id-core`](https://docs.rs/world-id-core) documentation for more details.
- **Contributing**: If you're interested in contributing to the Protocol, see the [Contributing Guide](CONTRIBUTING.md) for more information on how to get involved.

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
| Production  | World Chain (`480`) | [`contracts/deployments/oprf-key-registry/production.json`](contracts/deployments/oprf-key-registry/production.json) |
| Staging     | World Chain (`480`) | [`contracts/deployments/oprf-key-registry/staging.json`](contracts/deployments/oprf-key-registry/staging.json) |

### Services

The [World Foundation](https://foundation.world.org/) maintains a set of reference services (indexer & gateway) for interacting with the World ID Protocol. Use of these services is not required to work with World ID. You may choose to do direct on-chain interactions, host your own services or use third-party services as you see fit.

| Service            | Environment | URL                                                   |
| ------------------ | ----------- | ----------------------------------------------------- |
| `world-id-indexer` | Production  | `https://indexer.us.id-infra.worldcoin.dev`<br />`https://indexer.eu.id-infra.worldcoin.dev`<br />`https://indexer.ap.id-infra.worldcoin.dev` |
| `world-id-gateway` | Staging     | `https://gateway.id-infra.worldcoin.dev` |

## 🏗️ Project Structure

This repo is organized into the following top-level components:

- **`circom/`**: Circom circuits for zero-knowledge proofs
- **`contracts/`**: Solidity smart contracts (see [contracts/README.md](contracts/README.md))
- **`crates/`**: Rust libraries providing protocol functionality
- **`services/`**: Deployable services (gateway, indexer, oprf-node)
- **`docs/`**: Protocol documentation (see [docs/README.md](docs/README.md))


## 🛡️Audits
The Protocol undergoes continuous audits and security reviews to the different components, especially the core infrastructure which includes smart contracts and zero-knowledge circuits. Information about audits can be found in the [audits](./audits) folder.

[website]: https://world.org/world-id
