# Contributing Guidelines

Thank you for your interest in contributing to our project! This document provides guidelines and steps for contributing.

## General Guidelines

1. Create a Pull Request for any contribution. Pull requests should include clear descriptions.
2. Pull requests titles should follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/#summary) specifications. Pull requests may contain any number of commits. Commit messages do not need to follow Conventional Commits.
3. Everything must be documented following Rust conventions.
4. All new functionality must include relevant unit and integration tests.
5. Please disclose AI use in your contributions.


## Prerequisites

- Rust toolchain (`rustup`, `cargo`) – pinned via `rust-toolchain.toml`
- Foundry (forge/cast/anvil): `curl -L https://foundry.paradigm.xyz | bash` then `foundryup`
- Noir Lang: ([`noirup`](https://github.com/noir-lang/noirup) recommended): 
  ```bash
  curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
  noirup --version v1.0.0-beta.11 # this specific Noir Lang version is needed
  ```
- [ProveKit CLI](https://github.com/worldfnd/provekit): `cargo +nightly install --git https://github.com/worldfnd/provekit --locked provekit-cli`
- For running the Rust services look at the specific READMEs of each service.

## Crates Organization

The Rust crates are logically separated to ensure proper integration without feature flag conflicts:

```
world-id-primitives
└── functionality-specific crates
    └── world-id-core
```

- `world-id-primitives`: Foundation layer containing only raw types with **minimal implementation logic** except for hashing mechanisms. Has an optional `openapi` feature for OpenAPI schema derives.
- Functionality-specific crates: Providing focused use cases for authenticator, issuer, and RP operations.
- `world-id-core`: Top-level integration layer which exposes all functionality.

## Releasing

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


## Code of Conduct

Please note that this project is released with a Code of Conduct. By participating in this project, you agree to abide by its terms.

## Questions?

Feel free to reach out to the maintainers if you have any questions.

Thank you for contributing!
