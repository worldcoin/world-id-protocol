# Changelog

All notable changes to `world-id-oprf-node` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0](https://github.com/worldcoin/world-id-protocol/compare/world-id-oprf-node-v1.2.1...world-id-oprf-node-v2.0.0) (2026-06-18)


### ⚠ BREAKING CHANGES

* **oprf-node:** updated metrics call; use telemetry-batteries ([#724](https://github.com/worldcoin/world-id-protocol/issues/724))
* **oprf-nodes:** uses the nodes_common rpc provider over ws provider everywhere + removes AWS deps ([#617](https://github.com/worldcoin/world-id-protocol/issues/617))
* **nodes:** add fine-grained error types for nodes ([#585](https://github.com/worldcoin/world-id-protocol/issues/585))
* session proofs & rp signature ([#547](https://github.com/worldcoin/world-id-protocol/issues/547))
* removed auth counter metrics in OPRF ([#418](https://github.com/worldcoin/world-id-protocol/issues/418))
* updated taceo deps and restructured binary to get actual errors ([#359](https://github.com/worldcoin/world-id-protocol/issues/359))
* update taceo crates ([#333](https://github.com/worldcoin/world-id-protocol/issues/333))
* update names of OPRF node auth modules and types for new OprfModule names ([#332](https://github.com/worldcoin/world-id-protocol/issues/332))
* add OPRF module for credential blinding factor generation, rename old one to nullifier, integrate into authenticator ([#293](https://github.com/worldcoin/world-id-protocol/issues/293))
* update taceo crates ([#302](https://github.com/worldcoin/world-id-protocol/issues/302))
* split nullifier & proof generation ([#278](https://github.com/worldcoin/world-id-protocol/issues/278))
* New rp_signature module and include action ([#243](https://github.com/worldcoin/world-id-protocol/issues/243))
* contract interface updates ([#208](https://github.com/worldcoin/world-id-protocol/issues/208))
* update circuits, cred.id hashing & sub blinding factor ([#162](https://github.com/worldcoin/world-id-protocol/issues/162))

### Features

* add metrics for world-id-oprf-node ([#259](https://github.com/worldcoin/world-id-protocol/issues/259)) ([a10f9e9](https://github.com/worldcoin/world-id-protocol/commit/a10f9e93f507c0664e05c3592dab4c1012e4a33d))
* add OPRF module for credential blinding factor generation, rename old one to nullifier, integrate into authenticator ([#293](https://github.com/worldcoin/world-id-protocol/issues/293)) ([a756fec](https://github.com/worldcoin/world-id-protocol/commit/a756fec64e8a48f806dda16e46ec416f024ff065))
* add OPRF request authentication tests ([#350](https://github.com/worldcoin/world-id-protocol/issues/350)) ([9613a74](https://github.com/worldcoin/world-id-protocol/commit/9613a74b6d69412acafe0234b4b74f96cf842855))
* align MerkleWatcher with WorldIdRegistry contract root valid validity check ([#282](https://github.com/worldcoin/world-id-protocol/issues/282)) ([af044a2](https://github.com/worldcoin/world-id-protocol/commit/af044a247d705ff9f8c6675898cbfd006985e46f))
* **api:** standardize success/error responses ([#204](https://github.com/worldcoin/world-id-protocol/issues/204)) ([1fd59fc](https://github.com/worldcoin/world-id-protocol/commit/1fd59fce02716fba46f39de24e681bf71cf3cf4c))
* contract interface updates ([#208](https://github.com/worldcoin/world-id-protocol/issues/208)) ([eb098f5](https://github.com/worldcoin/world-id-protocol/commit/eb098f599f7a0ba4da35367cba89d2ac336e00cf))
* improve docs for OPRF errors ([#606](https://github.com/worldcoin/world-id-protocol/issues/606)) ([195efcb](https://github.com/worldcoin/world-id-protocol/commit/195efcbbce1338550501348e5f622b043e41e194))
* integrate and update RpRegistry to load and verifiy ecdsa signature in oprf-node ([#197](https://github.com/worldcoin/world-id-protocol/issues/197)) ([13925fd](https://github.com/worldcoin/world-id-protocol/commit/13925fdddf1d9ec7618dd05b3cffe2daee0caa95))
* make world-id-signer wasm compatible ([#383](https://github.com/worldcoin/world-id-protocol/issues/383)) ([fefa01a](https://github.com/worldcoin/world-id-protocol/commit/fefa01a4de9cc867e35b16663fff62d3a4bb8bcf))
* New rp_signature module and include action ([#243](https://github.com/worldcoin/world-id-protocol/issues/243)) ([2ad2258](https://github.com/worldcoin/world-id-protocol/commit/2ad2258fdeace663bdcf10c7c735057d134416fb))
* **node:** differentiate between unknown/invalid merkle root ([#768](https://github.com/worldcoin/world-id-protocol/issues/768)) ([ac60010](https://github.com/worldcoin/world-id-protocol/commit/ac60010e9c9ebd186a74a5ca54fc6690021db904))
* **oprf-node:** add session route for OPRF ([#596](https://github.com/worldcoin/world-id-protocol/issues/596)) ([5a7c060](https://github.com/worldcoin/world-id-protocol/commit/5a7c060e0eb535a48a2d78872584bd416a3f0ef0))
* **oprf-node:** add tti for watchers + add auth_error event to logs ([#741](https://github.com/worldcoin/world-id-protocol/issues/741)) ([d20efd7](https://github.com/worldcoin/world-id-protocol/commit/d20efd79793063f5ddf8a5169631308feb475ccb))
* **oprf-nodes:** added WIP101 support at the nodes ([#634](https://github.com/worldcoin/world-id-protocol/issues/634)) ([0b0fc58](https://github.com/worldcoin/world-id-protocol/commit/0b0fc58b6ab88befc771994aea302833d4c860b4))
* **oprf-node:** use jemalloc as global allocator ([#723](https://github.com/worldcoin/world-id-protocol/issues/723)) ([22fd09e](https://github.com/worldcoin/world-id-protocol/commit/22fd09e7b0f842e284c19c4d939712efb150d716))
* remove circuits feature flags on primitives crate ([#425](https://github.com/worldcoin/world-id-protocol/issues/425)) ([14baf36](https://github.com/worldcoin/world-id-protocol/commit/14baf3605b89953c1c37fa6decd7e9afba6d937c))
* Rust Proof Input verification with nicer errors ([#338](https://github.com/worldcoin/world-id-protocol/issues/338)) ([93a5a34](https://github.com/worldcoin/world-id-protocol/commit/93a5a342988d359c9ded367f0d3a79279df75da4))
* session proofs & rp signature ([#547](https://github.com/worldcoin/world-id-protocol/issues/547)) ([545afc5](https://github.com/worldcoin/world-id-protocol/commit/545afc5d9fbdd3d5d69346971b4aa62b63257785))
* split nullifier & proof generation ([#278](https://github.com/worldcoin/world-id-protocol/issues/278)) ([0008eab](https://github.com/worldcoin/world-id-protocol/commit/0008eab1efe200e572f27258793f9be5cb32858b))
* support session proof generation ([#712](https://github.com/worldcoin/world-id-protocol/issues/712)) ([670a8e7](https://github.com/worldcoin/world-id-protocol/commit/670a8e717a5973fbd3ac720f9102dd3659a85e1b))
* update circuits, cred.id hashing & sub blinding factor ([#162](https://github.com/worldcoin/world-id-protocol/issues/162)) ([7d583f2](https://github.com/worldcoin/world-id-protocol/commit/7d583f290897e3e1aca7c87dfaa9c7af7188f9fc))
* update names of OPRF node auth modules and types for new OprfModule names ([#332](https://github.com/worldcoin/world-id-protocol/issues/332)) ([69d33fb](https://github.com/worldcoin/world-id-protocol/commit/69d33fbf701b4200f3d38901631365d97296e005))
* update oprf client workflow in authenticator, add oprf node, add justfile with setup ([#129](https://github.com/worldcoin/world-id-protocol/issues/129)) ([a49e345](https://github.com/worldcoin/world-id-protocol/commit/a49e34510d649423a9aad3d5d6b92d81932200ac))
* update taceo crates ([#302](https://github.com/worldcoin/world-id-protocol/issues/302)) ([5ad6b18](https://github.com/worldcoin/world-id-protocol/commit/5ad6b18afa942e33c13656dcaef74a0efc557306))
* update taceo crates ([#333](https://github.com/worldcoin/world-id-protocol/issues/333)) ([7e04ea5](https://github.com/worldcoin/world-id-protocol/commit/7e04ea5ac8229abd93429d5a8dc1973b93aab7c4))
* update taceo deps ([#276](https://github.com/worldcoin/world-id-protocol/issues/276)) ([90ad27d](https://github.com/worldcoin/world-id-protocol/commit/90ad27ddf3fbdbe7dd10a6e961927e79270cf55a))
* use moka cache ([#217](https://github.com/worldcoin/world-id-protocol/issues/217)) ([862bf5c](https://github.com/worldcoin/world-id-protocol/commit/862bf5c57edb86041deb94cde600158f40902afa))


### Bug Fixes

* add root validity window (time-to-live) to MerkleWatcher cache ([#232](https://github.com/worldcoin/world-id-protocol/issues/232)) ([72ca951](https://github.com/worldcoin/world-id-protocol/commit/72ca95146c5928dc903a30c33ec7818731236e50))
* **authenticator:** normalize sparse indexer pubkey slots before key set validation ([#447](https://github.com/worldcoin/world-id-protocol/issues/447)) ([e24d999](https://github.com/worldcoin/world-id-protocol/commit/e24d9999cdd3f49fe280701fa5b707e0173d9293))
* don't update oprf key id in RpRegistryWatcher ([#416](https://github.com/worldcoin/world-id-protocol/issues/416)) ([7c65bb2](https://github.com/worldcoin/world-id-protocol/commit/7c65bb260ddab64825e69dbf939cbc05a888d007))
* fix crates release workflow ([#381](https://github.com/worldcoin/world-id-protocol/issues/381)) ([bdb7065](https://github.com/worldcoin/world-id-protocol/commit/bdb706551a15911a4508cc1a520fe3f5a164cafa))
* **node:** fixes a test-cases ([#787](https://github.com/worldcoin/world-id-protocol/issues/787)) ([ab243a3](https://github.com/worldcoin/world-id-protocol/commit/ab243a3e0eadb3d786c12106758239c50ed9ff49))
* oprf release process ([#782](https://github.com/worldcoin/world-id-protocol/issues/782)) ([a0c1cba](https://github.com/worldcoin/world-id-protocol/commit/a0c1cba06b0005f3e6f52cb6535984ca0e9b927d))
* **oprf-node:** add humantime serde for ttl/tti config ([#742](https://github.com/worldcoin/world-id-protocol/issues/742)) ([f43b7db](https://github.com/worldcoin/world-id-protocol/commit/f43b7db678b4a253f95a6c11e298ea43279bf31b))
* **oprf-node:** don't cache invalid roots ([#169](https://github.com/worldcoin/world-id-protocol/issues/169)) ([0afee62](https://github.com/worldcoin/world-id-protocol/commit/0afee623c434191772af152653ab2372da544bf1))
* **oprf-nodes:** correctly constructs internal errors ([#672](https://github.com/worldcoin/world-id-protocol/issues/672)) ([acb2207](https://github.com/worldcoin/world-id-protocol/commit/acb2207526c19508f109a87fe0183efc6c52083c))
* oprfKeyId cannot be safely updated ([#414](https://github.com/worldcoin/world-id-protocol/issues/414)) ([f1bd233](https://github.com/worldcoin/world-id-protocol/commit/f1bd233e97ab77e884b776e36dc011be41deb52a))
* remove test contracts ([#378](https://github.com/worldcoin/world-id-protocol/issues/378)) ([16f07d1](https://github.com/worldcoin/world-id-protocol/commit/16f07d1f72fb7ff843dc0a69e253732784233c26))
* Temporarily remove decompressed zkey disk caching ([#431](https://github.com/worldcoin/world-id-protocol/issues/431)) ([4c973a8](https://github.com/worldcoin/world-id-protocol/commit/4c973a88cd003e4cd25be85666291a26c84c424f))
* update MerkleWatcher after fix of infinite validity window ([#345](https://github.com/worldcoin/world-id-protocol/issues/345)) ([7145918](https://github.com/worldcoin/world-id-protocol/commit/71459180d56f17b6e6201f4b30a375269857eeb9))


### Performance Improvements

* **merkle-watcher:** use lru cache to store merkle roots ([#230](https://github.com/worldcoin/world-id-protocol/issues/230)) ([bbeaf6c](https://github.com/worldcoin/world-id-protocol/commit/bbeaf6c6c913ff2fa079bf18f87a4e5532b062ca))
* **signature-history:** use lru cache ([#231](https://github.com/worldcoin/world-id-protocol/issues/231)) ([a865621](https://github.com/worldcoin/world-id-protocol/commit/a865621dffd44c0e8bb90eebb98411561fb98915))


### Code Refactoring

* **nodes:** add fine-grained error types for nodes ([#585](https://github.com/worldcoin/world-id-protocol/issues/585)) ([27144a4](https://github.com/worldcoin/world-id-protocol/commit/27144a43d37de755505111db45495e6afee4f0cd))
* **oprf-nodes:** uses the nodes_common rpc provider over ws provider everywhere + removes AWS deps ([#617](https://github.com/worldcoin/world-id-protocol/issues/617)) ([d3736c6](https://github.com/worldcoin/world-id-protocol/commit/d3736c623ade8487e63b90de2ccdcdefbddba6bd))
* **oprf-node:** updated metrics call; use telemetry-batteries ([#724](https://github.com/worldcoin/world-id-protocol/issues/724)) ([ea54961](https://github.com/worldcoin/world-id-protocol/commit/ea54961c145cc71565fd9dc23d7a0ee2fa9af1af))
* removed auth counter metrics in OPRF ([#418](https://github.com/worldcoin/world-id-protocol/issues/418)) ([9ce0965](https://github.com/worldcoin/world-id-protocol/commit/9ce09655ab401685b8ed16135c76dcbf5172fe36))
* updated taceo deps and restructured binary to get actual errors ([#359](https://github.com/worldcoin/world-id-protocol/issues/359)) ([4b5d79e](https://github.com/worldcoin/world-id-protocol/commit/4b5d79e6501ad5e0b0e720e6bb138630401fa6f4))

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
