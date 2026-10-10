# Documentation for World ID

1. The Protocol's primary source of documentation is directly in the codebase and particularly the foundational crates.
  - Primitives: https://docs.rs/world-id-primitives
  - Core: https://docs.rs/world-id-core
2. The developer documentation and generally how to use World ID can be found in: https://docs.world.org/world-id


## Supporting Documentation

This folder includes supporting documentation for World ID, particularly point-in-time product and technical specifications for discussion and reference. These docs differ from the primary sources (e.g. crates documentation) because they are static at the time of introduction.

- [World ID 4.0 product and technical specifications](world-id-4-specs/):
  High level product and technical specs of the World ID 4.0 Upgrade.
- [World ID 4.0 trusted setup](world-id-4-trusted-setup/): High level explanation of what a
  trusted setup is and how to contribute to it for World ID 4.0. After the trusted setup is done it
  will also contain a step by step guide to verify the provenance of the `.zkey` files used to power
  World ID ZK circuits.

## World ID Improvement Proposals

| Spec | Status | Description |
| --- | --- | --- |
| [WIP-100: Cryptographic Primitives for World ID Protocol](WIPs/wip-100.md) | 🌿 Living | Establishes the default cryptographic primitives used throughout the Protocol. |
| [WIP-101: RP Request Authorization Method for Smart Contracts](WIPs/wip-101.md) | 🟠 Last Call | Standard to verify a relying party proof request for a World ID Proof in Smart Contracts |
| [WIP-102: Simplified Optimistic Recovery Agent Update](WIPs/wip-102.md) | 🟠 Last Call | Replace the current Recovery Agent update mechanism with an immediate update and revert window, removing the need for a follow-up execute transaction. |
| [WIP-103: Proof of Ownership](WIPs/wip-103.md) | 🟠 Last Call | Mechanism to privately prove ownership of a registered leaf via a blinded leaf index commitment. |
| [WIP-104: Proving and Admin Authenticators with Fixed Permission Sets](WIPs/wip-104.md) | ✅ Final | Introduce two classes of authenticators where a Proving Authenticator is not allowed to perform any management operations on a World ID. |
| [WIP-105: Authenticator Message Format](https://github.com/worldcoin/world-id-protocol/pull/965) | 🟡 Draft | Standard format for messages exchanged between World ID authenticators. |
| [WIP-106: Authenticator Assertions](WIPs/wip-106.md) | 🟡 Draft | Mechanism for Authenticator Providers to attest the integrity of the environment in which a World ID Proof is generated. |
| [WIP-107: Experimental Transactional Fees](https://app.notion.com/p/worldcoin/YABS-3ab8614bdf8c80d9801ae9692f5ab7aa?source=copy_link#3e48614bdf8c80138098f2aa92d2f750) | 🟡 Draft | Prepaid per-World-ID-per-period billing, initially for Deep Face proofs. |
| [WIP-108: Authenticator State Sync](https://app.notion.com/p/worldcoin/WIP-108-Authenticator-State-Sync-3c28614bdf8c80a6a967cc9fce7ed4e8) | 🟡 Draft | Synchronize credential vaults across authenticators using continuous group key agreement. |
| [WIP-109: Authenticator Registration Protocol](https://github.com/worldcoin/world-id-protocol/pull/983) | 🟡 Draft | Protocol for securely confirming and authorizing the registration of a new World ID authenticator. |
| [WIP-110: Message Bridge](WIPs/wip-110.md) | 🚧 Planned | Generic encrypted messaging between protocol participants, with pairing and hybrid post-quantum key exchange. |
| [WIP-111: Passkey Ownership Proof](https://github.com/worldcoin/world-id-protocol/pull/872) | 🟡 Draft | Prove control of a World ID using a WebAuthn ES256 passkey registered as a proving authenticator, without a PRF-derived BabyJubJub secret. |
| [WIP-112: Authenticator Registration over iroh](https://github.com/worldcoin/world-id-protocol/pull/985) | 🗑️ Cancelled | Secure bidirectional transport for WIP-109 authenticator registration using iroh. |
| [WIP-115: Authenticator Vault Sync](WIPs/wip-115.md) | 🟡 Draft | Mechanism to copy the credential vault from one registered authenticator to another authenticator of the same World ID. |
| [WIP-201: Flamingo Verifier](https://github.com/worldcoin/world-id-protocol/pull/979) | 🟡 Draft | A TEE-backed service that compares images or embeddings under a requested match strictness and signs a Flamingo Token committing to its inputs. |
| [WIP-202: Proof of Embedding Similarity](https://github.com/worldcoin/world-id-protocol/pull/979) | 🟡 Draft | Mechanism to prove similarity between vector embeddings based on a World ID credential. |
