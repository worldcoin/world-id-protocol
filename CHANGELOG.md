# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.2](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.8.1...world-id-primitives-v0.8.2) - 2026-04-02

### Added

- generate session_id_r_seed through OPRF nodes ([#628](https://github.com/worldcoin/world-id-protocol/pull/628))
- rename sign_initiate_recovery_agent_update → danger_sign_initiate_recovery_agent_update (PROTO-4477) ([#631](https://github.com/worldcoin/world-id-protocol/pull/631))

### Other

- WIP-103 - Proof of Ownership ([#622](https://github.com/worldcoin/world-id-protocol/pull/622))

## [0.8.1](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.8.0...world-id-primitives-v0.8.1) - 2026-04-01

### Added

- expose sign_initiate_recovery_agent_update on CoreAuthenticator (PROTO-4477) ([#630](https://github.com/worldcoin/world-id-protocol/pull/630))

## [0.8.0](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.7.1...world-id-primitives-v0.8.0) - 2026-03-31

### Added

- expose from_be_bytes_mod_order ([#624](https://github.com/worldcoin/world-id-protocol/pull/624))

### Fixed

- use hex serde for all signature Vec<u8> fields in API types ([#619](https://github.com/worldcoin/world-id-protocol/pull/619))

### Other

- use hex_signature for signature parsing ([#626](https://github.com/worldcoin/world-id-protocol/pull/626))
- *(oprf-nodes)* [**breaking**] uses the nodes_common rpc provider over ws provider everywhere + removes AWS deps ([#617](https://github.com/worldcoin/world-id-protocol/pull/617))
- update Cargo.toml dependencies

## [0.7.1](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.7.0...world-id-primitives-v0.7.1) - 2026-03-26

### Added

- add recovery agent update methods to CoreAuthenticator ([#602](https://github.com/worldcoin/world-id-protocol/pull/602))

### Other

- *(oprf-node)* misc stuff for oprf-nodes (v1.1) ([#608](https://github.com/worldcoin/world-id-protocol/pull/608))
- update Cargo.toml dependencies

## [0.7.0](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.6.0...world-id-primitives-v0.7.0) - 2026-03-25

### Added

- GatewayRequestId newtype and Authenticator::poll_status ([#603](https://github.com/worldcoin/world-id-protocol/pull/603))
- improve docs for OPRF errors ([#606](https://github.com/worldcoin/world-id-protocol/pull/606))
- *(oprf-node)* add session route for OPRF ([#596](https://github.com/worldcoin/world-id-protocol/pull/596))
- rename to associated data commitment ([#586](https://github.com/worldcoin/world-id-protocol/pull/586))
- *(indexer)* expose offchain_signer_commitment ([#593](https://github.com/worldcoin/world-id-protocol/pull/593))
- recovery agent management gateway endpoints ([#589](https://github.com/worldcoin/world-id-protocol/pull/589))
- separate action prefix ([#581](https://github.com/worldcoin/world-id-protocol/pull/581))

### Fixed

- sign_recover_account with async processing ([#597](https://github.com/worldcoin/world-id-protocol/pull/597))

### Other

- lifecycle terminology ([#605](https://github.com/worldcoin/world-id-protocol/pull/605))
- *(nodes)* [**breaking**] add fine-grained error types for nodes ([#585](https://github.com/worldcoin/world-id-protocol/pull/585))
- improved documentation on main crate ([#600](https://github.com/worldcoin/world-id-protocol/pull/600))
- increase zstd compression level to 9 for circuit files ([#591](https://github.com/worldcoin/world-id-protocol/pull/591))

## [0.6.0](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.5.4...world-id-primitives-v0.6.0) - 2026-03-18

### Added

- [**breaking**] session proofs & rp signature ([#547](https://github.com/worldcoin/world-id-protocol/pull/547))
- lazy load proof materials when needed ([#568](https://github.com/worldcoin/world-id-protocol/pull/568))

### Other

- introduce cargo nextest and fix test port conflicts ([#567](https://github.com/worldcoin/world-id-protocol/pull/567))

## [0.5.4](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.5.3...world-id-primitives-v0.5.4) - 2026-03-17

### Fixed

- authenticator management methods no longer require &mut self ([#564](https://github.com/worldcoin/world-id-protocol/pull/564))

## [0.5.3](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.5.2...world-id-primitives-v0.5.3) - 2026-03-17

### Fixed

- signer doesn't need to be mutable ([#556](https://github.com/worldcoin/world-id-protocol/pull/556))

### Other

- remove unused error variant ([#562](https://github.com/worldcoin/world-id-protocol/pull/562))

## [0.5.2](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.5.1...world-id-primitives-v0.5.2) - 2026-03-13

### Added

- /get-recovery-agent endpoint ([#550](https://github.com/worldcoin/world-id-protocol/pull/550))
- *(authenticator,proof)* make dependencies WASM-compatible ([#512](https://github.com/worldcoin/world-id-protocol/pull/512))
- introduce sign for leaf index verification ([#551](https://github.com/worldcoin/world-id-protocol/pull/551))

### Fixed

- signal as raw bytes ([#548](https://github.com/worldcoin/world-id-protocol/pull/548))

### Other

- update Cargo.toml dependencies

## [0.5.1](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.5.0...world-id-primitives-v0.5.1) - 2026-03-07

### Added

- structured timeout errors ([#532](https://github.com/worldcoin/world-id-protocol/pull/532))
- in-flight locks for all gateway operations ([#519](https://github.com/worldcoin/world-id-protocol/pull/519))

### Fixed

- encode signature hex-nicely ([#500](https://github.com/worldcoin/world-id-protocol/pull/500))
- *(indexer)* prevent panics in inclusion-proof handler ([#529](https://github.com/worldcoin/world-id-protocol/pull/529))

## [0.5.0](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.4.4...world-id-primitives-v0.5.0) - 2026-03-03

### Added

- [**breaking**] explicit nullifier type ([#518](https://github.com/worldcoin/world-id-protocol/pull/518))
- Rust Proof Input verification with nicer errors ([#338](https://github.com/worldcoin/world-id-protocol/pull/338))
- *(gateway)* add a batch submit policy ([#505](https://github.com/worldcoin/world-id-protocol/pull/505))
- println -> tracing:: ([#474](https://github.com/worldcoin/world-id-protocol/pull/474))
- gateway orphan sweeper ([#494](https://github.com/worldcoin/world-id-protocol/pull/494))

### Other

- gateway config ([#506](https://github.com/worldcoin/world-id-protocol/pull/506))
- *(deps)* bumped oprf versions ([#522](https://github.com/worldcoin/world-id-protocol/pull/522))

## [0.4.4](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.4.3...world-id-primitives-v0.4.4) - 2026-02-24

### Other

- update Cargo.toml dependencies
- Finalize World ID 4 trusted setup docs, artifacts, and explainer video ([#468](https://github.com/worldcoin/world-id-protocol/pull/468))

## [0.4.3](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.4.2...world-id-primitives-v0.4.3) - 2026-02-23

### Added

- *(rp)* include version byte in rp signature message

### Other

- expose eddsa keys & sig ([#467](https://github.com/worldcoin/world-id-protocol/pull/467))

## [0.4.2](https://github.com/worldcoin/world-id-protocol/compare/world-id-proof-v0.4.1...world-id-proof-v0.4.2) - 2026-02-20

### Fixed

- bump circuit commit ([#463](https://github.com/worldcoin/world-id-protocol/pull/463))

## [0.4.1](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.4.0...world-id-primitives-v0.4.1) - 2026-02-20

### Added

- Compute random action for session proofs ([#377](https://github.com/worldcoin/world-id-protocol/pull/377))
- *(gateway)* Add rate limitting. ([#424](https://github.com/worldcoin/world-id-protocol/pull/424))
- remove circuits feature flags on primitives crate ([#425](https://github.com/worldcoin/world-id-protocol/pull/425))
- *(contract)* full tree in storage ([#402](https://github.com/worldcoin/world-id-protocol/pull/402))
- *(indexer)* add deserialization from 0x hex or decimal ([#419](https://github.com/worldcoin/world-id-protocol/pull/419))
- *(request)* add enumerate constraint ([#388](https://github.com/worldcoin/world-id-protocol/pull/388))

### Fixed

- field element encoding ([#461](https://github.com/worldcoin/world-id-protocol/pull/461))
- *(primitives)* reject unknown and duplicate response credentials ([#458](https://github.com/worldcoin/world-id-protocol/pull/458))
- *(authenticator)* normalize sparse indexer pubkey slots before key set validation ([#447](https://github.com/worldcoin/world-id-protocol/pull/447))
- Temporarily remove decompressed zkey disk caching ([#431](https://github.com/worldcoin/world-id-protocol/pull/431))
- filter credentials_to_prove by issuer_schema_id ([#410](https://github.com/worldcoin/world-id-protocol/pull/410))

### Other

- use default to create empty AuthenticatorPublicKeySet ([#460](https://github.com/worldcoin/world-id-protocol/pull/460))
- bump deps ([#435](https://github.com/worldcoin/world-id-protocol/pull/435))
- *(deps)* update taceo crates and replace testcontainers with OPRF test secret_managers ([#407](https://github.com/worldcoin/world-id-protocol/pull/407))

## [0.4.0](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.3.0...world-id-primitives-v0.4.0) - 2026-02-10

### Added

- add session_nullifier ([#367](https://github.com/worldcoin/world-id-protocol/pull/367))
- faux issuer ([#371](https://github.com/worldcoin/world-id-protocol/pull/371))
- [**breaking**] update names of OPRF node auth modules and types for new OprfModule names ([#332](https://github.com/worldcoin/world-id-protocol/pull/332))
- [**breaking**] add OPRF module for credential blinding factor generation, rename old one to nullifier, integrate into authenticator ([#293](https://github.com/worldcoin/world-id-protocol/pull/293))
- extract authenticator crate ([#313](https://github.com/worldcoin/world-id-protocol/pull/313))
- optionally compress embedded zkey files and cache to disk ([#264](https://github.com/worldcoin/world-id-protocol/pull/264))
- update poseidon2 ([#305](https://github.com/worldcoin/world-id-protocol/pull/305))
- [**breaking**] update taceo crates ([#302](https://github.com/worldcoin/world-id-protocol/pull/302))
- encoded proof output ([#300](https://github.com/worldcoin/world-id-protocol/pull/300))
- [**breaking**] split nullifier & proof generation ([#278](https://github.com/worldcoin/world-id-protocol/pull/278))
- [**breaking**] New rp_signature module and include action ([#243](https://github.com/worldcoin/world-id-protocol/pull/243))
- final circuit updates ([#235](https://github.com/worldcoin/world-id-protocol/pull/235))
- Make primitives crate wasm compatible ([#229](https://github.com/worldcoin/world-id-protocol/pull/229))
- [**breaking**] remove OprfPublicKey from ProofRequest, now is returned from oprf nodes during distributed_oprf ([#215](https://github.com/worldcoin/world-id-protocol/pull/215))
- integrate and update RpRegistry to load and verifiy ecdsa signature in oprf-node ([#197](https://github.com/worldcoin/world-id-protocol/pull/197))

### Other

- *(deps)* bump taceo crates to latest version ([#384](https://github.com/worldcoin/world-id-protocol/pull/384))
- compact signer and request into world-id-primitives ([#386](https://github.com/worldcoin/world-id-protocol/pull/386))
- move registry and types into the authenticator crate ([#368](https://github.com/worldcoin/world-id-protocol/pull/368))
- consolidate deps ([#354](https://github.com/worldcoin/world-id-protocol/pull/354))
- contracts housekeeping & final definitions ([#331](https://github.com/worldcoin/world-id-protocol/pull/331))
- document crate structure & drop credential crate ([#320](https://github.com/worldcoin/world-id-protocol/pull/320))
- rust nits ([#211](https://github.com/worldcoin/world-id-protocol/pull/211))

## [0.3.0](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.2.0...world-id-primitives-v0.3.0) - 2026-01-14

### Added

- [**breaking**] update circuits, cred.id hashing & sub blinding factor ([#162](https://github.com/worldcoin/world-id-protocol/pull/162))
- make claim method reflect associated_data method ([#163](https://github.com/worldcoin/world-id-protocol/pull/163))
- [**breaking**] improve documentation for associated data ([#160](https://github.com/worldcoin/world-id-protocol/pull/160))
- update oprf client workflow in authenticator, add oprf node, add justfile with setup ([#129](https://github.com/worldcoin/world-id-protocol/pull/129))
- [**breaking**] rename AccountRegistry to WorldIDRegistry ([#154](https://github.com/worldcoin/world-id-protocol/pull/154))
- poseidon2 hash sponge construction from raw bytes ([#150](https://github.com/worldcoin/world-id-protocol/pull/150))
- update serialization formats for hex strings ([#153](https://github.com/worldcoin/world-id-protocol/pull/153))
- unify API requests & responses ([#149](https://github.com/worldcoin/world-id-protocol/pull/149))
- proof requests & responses (take II) ([#141](https://github.com/worldcoin/world-id-protocol/pull/141))

### Fixed

- *(oprf-node)* don't cache invalid roots ([#169](https://github.com/worldcoin/world-id-protocol/pull/169))

### Other

- *(deps)* update deps to crates.io, add patches to stay compatible with git dev deps ([#161](https://github.com/worldcoin/world-id-protocol/pull/161))

## [0.2.0](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.1.3...world-id-primitives-v0.2.0) - 2025-12-05

### Added

- introduce release plz for crates publishing ([#137](https://github.com/worldcoin/world-id-protocol/pull/137))
- rename sub in credential ([#133](https://github.com/worldcoin/world-id-protocol/pull/133))
- rename account_id/account_index to leaf_index everywhere ([#132](https://github.com/worldcoin/world-id-protocol/pull/132))
