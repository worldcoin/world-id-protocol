# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
