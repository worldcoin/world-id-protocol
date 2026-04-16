# AGENTS.md

## Repo Overview
- Rust workspace + Solidity contracts + Circom circuits + deployable services.
- See `README.md` for global status and prerequisites.
- Primary docs: `docs/README.md`, per-crate READMEs under `crates/`, per-service READMEs under `services/`.

## Core World ID Protocol 4.0
- Protocol logic lives in Rust crates under `crates/`, with `world-id-core` as the top-level integration layer and `world-id-primitives` as the raw types layer.
- Specs for the 4.0 upgrade: `docs/world-id-4-specs/`.
- ZK circuits: `circom/`.

## Gateway Service
- Code: `services/gateway/`
- Binary: `world-id-gateway` (see `services/gateway/src/main.rs`).
- HTTP gateway API for protocol requests. Look here first for routes, request/response types, and integration tests.

## Indexer Service
- Code: `services/indexer/`
- Binary: `world-id-indexer` (see `services/indexer/src/main.rs`).
- Indexes Account Registry events; serves inclusion proofs and account info.
- See `services/indexer/README.md` and `services/indexer/TREE_CACHE.md` for operational details.

## OPRF Node
- Code: `services/oprf-node/`
- Binary: `world-id-oprf-node` (see `services/oprf-node/src/bin/world-id-oprf-node.rs`).
- OPRF service used by the protocol. See `services/oprf-node/src/` for request auth and service wiring.

## Relay Service
- Code: `services/relay/`
- Binary: `world-id-relay` (see `services/relay/src/bin/main.rs`).
- See `services/relay/README.md`.

## Other Services
- `services/common/`: Shared middleware, server layers, and provider utilities used across services.
- `services/faux-issuer/`: Fake issuer for local development/testing (see `services/faux-issuer/src/main.rs`).
- `services/oprf-dev-client/`: Dev-only CLI clients for OPRF flows (see `services/oprf-dev-client/src/bin/`).

## Smart Contracts
- See `contracts/README.md` for all contract rules and upgrade patterns.

## Crates
- `crates/authenticator/`: Authenticator functionality for World ID.
- `crates/core/`: Top-level integration layer that exposes full protocol functionality.
- `crates/issuer/`: Issuer functionality for World ID.
- `crates/primitives/`: Foundational raw types with minimal dependencies.
- `crates/proof/`: Proof generation/verification; optional `embed-zkeys`/`compress-zkeys` features.
- `crates/test-utils/`: Shared test helpers for integration/e2e tests across crates and services.
