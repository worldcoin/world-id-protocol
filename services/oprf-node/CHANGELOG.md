# Changelog

All notable changes to `world-id-oprf-node` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.5](https://github.com/worldcoin/world-id-protocol/compare/world-id-oprf-node-v1.2.4...world-id-oprf-node-v1.2.5) (2026-11-02)

### Build

- Bump ark-serde-compat from 0.6.1 to 0.6.2 ([#1163](https://github.com/worldcoin/world-id-protocol/issues/1163))
- Bump uuid from 1.26.1 to 1.28.0 ([#1158](https://github.com/worldcoin/world-id-protocol/issues/1158))
- Bump tokio-util from 0.7.18 to 0.7.20 ([#1156](https://github.com/worldcoin/world-id-protocol/issues/1156))
- Bump moka from 0.12.13 to 0.12.16 ([#1155](https://github.com/worldcoin/world-id-protocol/issues/1155))
- Bump rustls-webpki and webpki-roots ([#1121](https://github.com/worldcoin/world-id-protocol/issues/1121))
- Fix cargo deny advisories (crypto-bigint, ctutils, tokio) ([#1137](https://github.com/worldcoin/world-id-protocol/issues/1137))

## [1.2.4](https://github.com/worldcoin/world-id-protocol/compare/world-id-oprf-node-v1.2.3...world-id-oprf-node-v1.2.4) (2026-10-19)

### Build

- **breaking** Update taceo crates to newer versions, update arkworks to 0.6 everywhere ([#1038](https://github.com/worldcoin/world-id-protocol/issues/1038))
- Consolidate dependabot bumps (alloy 2.0.4 among others) ([#1055](https://github.com/worldcoin/world-id-protocol/issues/1055))
- Bump uuid from 1.24.1 to 1.26.1 ([#1048](https://github.com/worldcoin/world-id-protocol/issues/1048))
- Bump anyhow from 1.0.103 to 1.0.104 ([#1049](https://github.com/worldcoin/world-id-protocol/issues/1049))
- Bump http from 1.4.0 to 1.5.0 ([#1047](https://github.com/worldcoin/world-id-protocol/issues/1047))
- Consolidate compatible dependency updates ([#962](https://github.com/worldcoin/world-id-protocol/issues/962))
- Bump h2 to fix RUSTSEC-2026-0258 ([#945](https://github.com/worldcoin/world-id-protocol/issues/945))
- Bump rustls to 0.23.46 for RUSTSEC-2026-0346 to 0349 ([#1101](https://github.com/worldcoin/world-id-protocol/issues/1101))
- Bump rustls past RUSTSEC-2026-0285 ([#1008](https://github.com/worldcoin/world-id-protocol/issues/1008))

## [1.2.3](https://github.com/worldcoin/world-id-protocol/compare/world-id-oprf-node-v1.2.2...world-id-oprf-node-v1.2.3) (2026-08-17)

### Build

- Bump cmov, quinn, serde_with, spin ([#893](https://github.com/worldcoin/world-id-protocol/issues/893))
- Bump ruint and event-listener to clear cargo-deny advisories ([#879](https://github.com/worldcoin/world-id-protocol/issues/879))
- Bump rand to 0.8.6/0.9.3 to patch RUSTSEC-2026-0097 ([#854](https://github.com/worldcoin/world-id-protocol/issues/854))
- Update crossbeam-epoch to 0.9.20 (RUSTSEC-2026-0204) ([#838](https://github.com/worldcoin/world-id-protocol/issues/838))

### Features

- Create an abstraction layer for poseidon hashing ([#915](https://github.com/worldcoin/world-id-protocol/issues/915))
- Add metrics and query with id to batcher ([#857](https://github.com/worldcoin/world-id-protocol/issues/857))
- Check expires_at max difference ([#853](https://github.com/worldcoin/world-id-protocol/issues/853))
- Add is_blocked at node ([#848](https://github.com/worldcoin/world-id-protocol/issues/848))
- Add worker that sends requests to accountant ([#843](https://github.com/worldcoin/world-id-protocol/issues/843))

### Bug Fixes

- **breaking** Don't expose fe with modulo reduction ([#932](https://github.com/worldcoin/world-id-protocol/issues/932))

### Refactoring

- Remove is_blocked and billing contract ([#939](https://github.com/worldcoin/world-id-protocol/issues/939))
- Bump to oprf version 0.18.1. Also remove test-utils and use alloy mock asserter over compiled solidity mocks ([#913](https://github.com/worldcoin/world-id-protocol/issues/913))
- **breaking** Unify field element domain prefixes into FePrefix ([#912](https://github.com/worldcoin/world-id-protocol/issues/912))
- **breaking** Collapse create_session proof type into session x create ([#866](https://github.com/worldcoin/world-id-protocol/issues/866))
- **breaking** Remove oprf-accountant ([#894](https://github.com/worldcoin/world-id-protocol/issues/894))
- Cleanup auth modules ([#850](https://github.com/worldcoin/world-id-protocol/issues/850))
- Introduce ZkArtifactSource abstraction ([#831](https://github.com/worldcoin/world-id-protocol/issues/831))

## [1.2.2](https://github.com/worldcoin/world-id-protocol/compare/world-id-oprf-node-v1.2.1...world-id-oprf-node-v1.2.2) (2026-07-03)

### Build

- Bump oprf to version 0.17.2 ([#826](https://github.com/worldcoin/world-id-protocol/issues/826))
- Update telemetry batteries ([#794](https://github.com/worldcoin/world-id-protocol/issues/794))

### Refactoring

- Remove run_pending_tasks + eviction listener ([#825](https://github.com/worldcoin/world-id-protocol/issues/825))
- Remove tokio::task for axum ([#802](https://github.com/worldcoin/world-id-protocol/issues/802))

## [1.2.1](https://github.com/worldcoin/world-id-protocol/compare/world-id-oprf-node-v1.2.0...world-id-oprf-node-v1.2.1) (2026-06-17)


### Bug Fixes

* **node:** fixes a test-cases ([#787](https://github.com/worldcoin/world-id-protocol/issues/787)) ([ab243a3](https://github.com/worldcoin/world-id-protocol/commit/ab243a3e0eadb3d786c12106758239c50ed9ff49))
* oprf release process ([#782](https://github.com/worldcoin/world-id-protocol/issues/782)) ([a0c1cba](https://github.com/worldcoin/world-id-protocol/commit/a0c1cba06b0005f3e6f52cb6535984ca0e9b927d))

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
