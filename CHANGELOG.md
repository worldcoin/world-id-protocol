# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0](https://github.com/worldcoin/world-id-protocol/compare/world-id-primitives-v0.3.0...world-id-primitives-v0.4.0) - 2026-01-26

### Added

- [**breaking**] New rp_signature module and include action ([#243](https://github.com/worldcoin/world-id-protocol/pull/243))
- final circuit updates ([#235](https://github.com/worldcoin/world-id-protocol/pull/235))
- Make primitives crate wasm compatible ([#229](https://github.com/worldcoin/world-id-protocol/pull/229))
- [**breaking**] remove OprfPublicKey from ProofRequest, now is returned from oprf nodes during distributed_oprf ([#215](https://github.com/worldcoin/world-id-protocol/pull/215))
- integrate and update RpRegistry to load and verifiy ecdsa signature in oprf-node ([#197](https://github.com/worldcoin/world-id-protocol/pull/197))

### Other

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
