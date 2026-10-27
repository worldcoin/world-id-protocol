# Changelog

All notable changes to `world-id-oprf-node` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1](https://github.com/worldcoin/world-id-protocol/compare/world-id-oprf-node-v1.2.0...world-id-oprf-node-v1.2.1) (2026-06-17)


### Bug Fixes

* **node:** fixes a test-cases ([#787](https://github.com/worldcoin/world-id-protocol/issues/787)) ([ab243a3](https://github.com/worldcoin/world-id-protocol/commit/ab243a3e0eadb3d786c12106758239c50ed9ff49))
* oprf release process ([#782](https://github.com/worldcoin/world-id-protocol/issues/782)) ([a0c1cba](https://github.com/worldcoin/world-id-protocol/commit/a0c1cba06b0005f3e6f52cb6535984ca0e9b927d))

## [Unreleased]

## [1.2.0](https://github.com/worldcoin/world-id-protocol/releases/tag/v1.2.0) - 2026-06-09

### Added

- *(node)* differentiate between unknown/invalid merkle root ([#768](https://github.com/worldcoin/world-id-protocol/pull/768))
- *(oprf-node)* add tti for watchers + add auth_error event to logs ([#741](https://github.com/worldcoin/world-id-protocol/pull/741))
- *(oprf-node)* use jemalloc as global allocator ([#723](https://github.com/worldcoin/world-id-protocol/pull/723))
- support session proof generation ([#712](https://github.com/worldcoin/world-id-protocol/pull/712))
- *(oprf-nodes)* added WIP101 support at the nodes ([#634](https://github.com/worldcoin/world-id-protocol/pull/634))
- improve docs for OPRF errors ([#606](https://github.com/worldcoin/world-id-protocol/pull/606))
- *(oprf-node)* add session route for OPRF ([#596](https://github.com/worldcoin/world-id-protocol/pull/596))
- [**breaking**] session proofs & rp signature ([#547](https://github.com/worldcoin/world-id-protocol/pull/547))
- Rust Proof Input verification with nicer errors ([#338](https://github.com/worldcoin/world-id-protocol/pull/338))
- remove circuits feature flags on primitives crate ([#425](https://github.com/worldcoin/world-id-protocol/pull/425))
- make world-id-signer wasm compatible ([#383](https://github.com/worldcoin/world-id-protocol/pull/383))
- add OPRF request authentication tests ([#350](https://github.com/worldcoin/world-id-protocol/pull/350))
- [**breaking**] update taceo crates ([#333](https://github.com/worldcoin/world-id-protocol/pull/333))
- [**breaking**] update names of OPRF node auth modules and types for new OprfModule names ([#332](https://github.com/worldcoin/world-id-protocol/pull/332))
- [**breaking**] add OPRF module for credential blinding factor generation, rename old one to nullifier, integrate into authenticator ([#293](https://github.com/worldcoin/world-id-protocol/pull/293))
- [**breaking**] update taceo crates ([#302](https://github.com/worldcoin/world-id-protocol/pull/302))
- align MerkleWatcher with WorldIdRegistry contract root valid validity check ([#282](https://github.com/worldcoin/world-id-protocol/pull/282))
- [**breaking**] split nullifier & proof generation ([#278](https://github.com/worldcoin/world-id-protocol/pull/278))
- update taceo deps ([#276](https://github.com/worldcoin/world-id-protocol/pull/276))
- add metrics for world-id-oprf-node ([#259](https://github.com/worldcoin/world-id-protocol/pull/259))
- [**breaking**] New rp_signature module and include action ([#243](https://github.com/worldcoin/world-id-protocol/pull/243))
- [**breaking**] contract interface updates ([#208](https://github.com/worldcoin/world-id-protocol/pull/208))
- use moka cache ([#217](https://github.com/worldcoin/world-id-protocol/pull/217))
- integrate and update RpRegistry to load and verifiy ecdsa signature in oprf-node ([#197](https://github.com/worldcoin/world-id-protocol/pull/197))
- *(api)* standardize success/error responses ([#204](https://github.com/worldcoin/world-id-protocol/pull/204))
- [**breaking**] update circuits, cred.id hashing & sub blinding factor ([#162](https://github.com/worldcoin/world-id-protocol/pull/162))
- update oprf client workflow in authenticator, add oprf node, add justfile with setup ([#129](https://github.com/worldcoin/world-id-protocol/pull/129))

### Fixed

- *(oprf-node)* add humantime serde for ttl/tti config ([#742](https://github.com/worldcoin/world-id-protocol/pull/742))
- *(oprf-nodes)* correctly constructs internal errors ([#672](https://github.com/worldcoin/world-id-protocol/pull/672))
- *(authenticator)* normalize sparse indexer pubkey slots before key set validation ([#447](https://github.com/worldcoin/world-id-protocol/pull/447))
- Temporarily remove decompressed zkey disk caching ([#431](https://github.com/worldcoin/world-id-protocol/pull/431))
- don't update oprf key id in RpRegistryWatcher ([#416](https://github.com/worldcoin/world-id-protocol/pull/416))
- oprfKeyId cannot be safely updated ([#414](https://github.com/worldcoin/world-id-protocol/pull/414))
- fix crates release workflow ([#381](https://github.com/worldcoin/world-id-protocol/pull/381))
- remove test contracts ([#378](https://github.com/worldcoin/world-id-protocol/pull/378))
- update MerkleWatcher after fix of infinite validity window ([#345](https://github.com/worldcoin/world-id-protocol/pull/345))
- add root validity window (time-to-live) to MerkleWatcher cache ([#232](https://github.com/worldcoin/world-id-protocol/pull/232))
- *(oprf-node)* don't cache invalid roots ([#169](https://github.com/worldcoin/world-id-protocol/pull/169))

### Other

- explicit oprf-node release ([#726](https://github.com/worldcoin/world-id-protocol/pull/726))
- *(oprf)* info for invalid merkle errors ([#769](https://github.com/worldcoin/world-id-protocol/pull/769))
- *(node)* add retry logic for RPC requests + bump oprf deps ([#764](https://github.com/worldcoin/world-id-protocol/pull/764))
- clp + recursion ([#746](https://github.com/worldcoin/world-id-protocol/pull/746))
- *(oprf-node)* [**breaking**] updated metrics call; use telemetry-batteries ([#724](https://github.com/worldcoin/world-id-protocol/pull/724))
- audit resutls oprf-node ([#658](https://github.com/worldcoin/world-id-protocol/pull/658))
- bump alloy to 2.0.1 ([#687](https://github.com/worldcoin/world-id-protocol/pull/687))
- *(node)* unset env variables on start ([#681](https://github.com/worldcoin/world-id-protocol/pull/681))
- Update docs & clarify around Authenticator management ([#673](https://github.com/worldcoin/world-id-protocol/pull/673))
- introduce registries crate ([#671](https://github.com/worldcoin/world-id-protocol/pull/671))
- *(primitives)* move circuit_inputs to world-id-proof ([#667](https://github.com/worldcoin/world-id-protocol/pull/667))
- *(oprf-node)* bump taceo crates ([#651](https://github.com/worldcoin/world-id-protocol/pull/651))
- *(oprf-nodes)* [**breaking**] uses the nodes_common rpc provider over ws provider everywhere + removes AWS deps ([#617](https://github.com/worldcoin/world-id-protocol/pull/617))
- *(oprf-node)* misc stuff for oprf-nodes (v1.1) ([#608](https://github.com/worldcoin/world-id-protocol/pull/608))
- *(nodes)* [**breaking**] add fine-grained error types for nodes ([#585](https://github.com/worldcoin/world-id-protocol/pull/585))
- store nonces instead of signatures in OPRF node ([#588](https://github.com/worldcoin/world-id-protocol/pull/588))
- use default to create empty AuthenticatorPublicKeySet ([#460](https://github.com/worldcoin/world-id-protocol/pull/460))
- *(deps)* update taceo crates and replace testcontainers with OPRF test secret_managers ([#407](https://github.com/worldcoin/world-id-protocol/pull/407))
- [**breaking**] removed auth counter metrics in OPRF ([#418](https://github.com/worldcoin/world-id-protocol/pull/418))
- add more tracing for world-oprf-node ([#409](https://github.com/worldcoin/world-id-protocol/pull/409))
- oprf-node main wraped into run function for tracing clarity ([#396](https://github.com/worldcoin/world-id-protocol/pull/396))
- *(deps)* bump taceo crates to latest version ([#384](https://github.com/worldcoin/world-id-protocol/pull/384))
- [**breaking**] updated taceo deps and restructured binary to get actual errors ([#359](https://github.com/worldcoin/world-id-protocol/pull/359))
- consolidate deps ([#354](https://github.com/worldcoin/world-id-protocol/pull/354))
- rust nits ([#211](https://github.com/worldcoin/world-id-protocol/pull/211))
- *(signature-history)* use lru cache ([#231](https://github.com/worldcoin/world-id-protocol/pull/231))
- *(merkle-watcher)* use lru cache to store merkle roots ([#230](https://github.com/worldcoin/world-id-protocol/pull/230))
- use a docker hub token for CI ([#207](https://github.com/worldcoin/world-id-protocol/pull/207))
- release 0.3.0 ([#147](https://github.com/worldcoin/world-id-protocol/pull/147))
- world-id-oprf-node ([#165](https://github.com/worldcoin/world-id-protocol/pull/165))
- cleanup build dependencies ([#170](https://github.com/worldcoin/world-id-protocol/pull/170))
- *(deps)* update deps to crates.io, add patches to stay compatible with git dev deps ([#161](https://github.com/worldcoin/world-id-protocol/pull/161))
