# AGENTS.md

## Repo Overview
- This repo is a Rust workspace plus Solidity contracts, Circom circuits, and deployable services.
- The protocol is WIP and unaudited. Check `README.md` for global status and prerequisites.
- Primary documentation sources: `docs/README.md`, crate READMEs under `crates/`, and service-specific README files where present.

## Core World ID Protocol 4.0
- Protocol logic lives in Rust crates under `crates/`, with `world-id-core` as the top-level integration layer and `world-id-primitives` as the raw types layer.
- Supporting specs for the 4.0 upgrade are in `docs/world-id-4-specs/`.
- Circom circuits used for proofs are in `circom/`.

## Gateway Service
- Code: `services/gateway/`
- Binary: `world-id-gateway` (see `services/gateway/src/main.rs`).
- This service is the gateway API for protocol requests. Look here first for HTTP routes, request/response types, and integration tests.

## Indexer Service
- Code: `services/indexer/`
- Binary: `world-id-indexer` (see `services/indexer/src/main.rs`).
- Indexes Account Registry events into a database and serves inclusion proofs and account info.
- Read `services/indexer/README.md` and `services/indexer/TREE_CACHE.md` for operational details.

## OPRF Node
- Code: `services/oprf-node/`
- Binary: `world-id-oprf-node` (see `services/oprf-node/src/bin/world-id-oprf-node.rs`).
- Implements the OPRF service used by the protocol. Look in `services/oprf-node/src/` for request auth and service wiring.

## Smart Contracts
- All contracts must follow the guidelines set out in contracts/README.md.
- Key contract rules from `contracts/README.md`:
- Contracts are upgradeable via a proxy and use explicit versioned implementations (`V{number}` suffix).
- Functions less restrictive than `private` should be `virtual`.
- Non-`private` state should be `internal`, with proxy-safe getters where needed.
- Any non-`pure` function must use `onlyProxy` and `onlyInitialized`.
- New functionality must be access controlled (e.g., `onlyOwner` or finer-grained).
- No contract-level variable initialization unless `constant`.

## Crates
- `crates/authenticator/`: Authenticator functionality for World ID.
- `crates/core/`: Core integration layer that exposes full protocol functionality.
- `crates/credential/`: Credential functionality for World ID.
- `crates/issuer/`: Issuer functionality for World ID.
- `crates/primitives/`: Foundational raw types and primitives with minimal dependencies.
- `crates/proof/`: Proof generation/verification logic, with optional `embed-zkeys`/`compress-zkeys` features.
- `crates/registry/`: Registry functionality for World ID.
- `crates/request/`: Request types and helpers for World ID flows.
- `crates/signer/`: Signer functionality for World ID.
- `crates/test-utils/`: Shared test helpers for integration/e2e tests across crates and services.
- `crates/types/`: Shared types for World ID.
