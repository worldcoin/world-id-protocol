# AGENTS.md

## You are the owner of this codebase

Treat every change as code you will maintain and debug later:

- Optimize for the next reader over quick local patches.
- Read and understand the surrounding code before changing it.
- Fix root causes instead of papering over symptoms.
- Keep changes small. When you find work outside the task's scope, leave a `TODO` and mention it in your summary instead of expanding the change.
- Push back when a request is wrong or a better approach exists.

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
- See `services/indexer/README.md` for details

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
- `crates/flamingo/`: WIP-201 Flamingo Verifier types (Flamingo Token, Engine configuration hash).
- `crates/issuer/`: Issuer functionality for World ID.
- `crates/primitives/`: Foundational raw types with minimal dependencies.
- `crates/proof/`: Proof generation/verification; ZK artifacts provided at runtime via `ZkArtifactSource`, with opt-in embed features (`embed-zkeys`, `embed-ownership-prover`/`-verifier`, the unaudited `embed-embedding-similarity-prover`/`-verifier`, umbrella `embed-zk-artifacts`); nothing is embedded by default.
- `crates/rp/`: RP verification of proofs checked off-chain (WIP-202 Proof of Embedding Similarity).
- `crates/test-utils/`: Shared test helpers for integration/e2e tests across crates and services.
- `crates/zk-mobile-bench/`: Mobile benchmarks for World ID ZK proof generation, used by CI via mobench.

## Rust formatting & lints

Full set of lints can be ran with: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Formatting relies on nightly options: `cargo +nightly fmt --all -- --check`

## Code style

Write readable, self-explanatory code.

### Comments

Keep non-doc comments to a minimum. Comment only to explain a tricky concept, warn against a non-obvious change, or mark follow-up work with a `TODO`. Link the issue or PR when one exists:

```rust
// TODO: Temporary workaround, remove once https://github.com/org/repo/pull/123 is merged
```

Describe only the current state of the code. Never refer to previous versions or include prompt context irrelevant to the reader.

### The Boy Scout rule

Leave touched code better than you found it, within the scope of the task. Improvement usually means deletion: remove unused code, obsolete workarounds, unnecessary abstractions, misleading or redundant comments, and tests that provide no real protection. Bad code does not deserve to survive just because it exists. Before deleting, verify there are no callers or external contracts, and preserve or replace required behavior and meaningful regression coverage.

### Stepdown rule

Order definitions so files read top to bottom, with callers before callees:

```rust
// BAD
fn bar() {}
fn foo() { bar(); }

// GOOD
fn foo() { bar(); }
fn bar() {}
```
