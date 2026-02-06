# Documentation for World ID

1. The Protocol's primary source of documentation is directly in the codebase and particularly the foundational crates.
  - Primitives: https://docs.rs/world-id-primitives
  - Core: https://docs.rs/world-id-core
2. The developer documentation and generally how to use World ID can be found in: https://docs.world.org/world-id


## Supporting Documentation

This folder includes supporting documentation for World ID, particularly point-in-time product and technical specifications for discussion and reference. These docs differ from the primary sources (e.g. crates documentation) because they are static at the time of introduction.

### Index

- `world-id-4-specs`: High level product and technical specs of the World ID 4.0 Upgrade.

## World ID 4.0 Trusted Setup

### How a trusted setup works

World ID 4.0 uses a Groth16 Phase 2 trusted setup ceremony for its zk-SNARK circuits. In this process, multiple participants each add their own randomness contribution (often called "toxic waste") to circuit-specific setup artifacts (`.zkey`),
and each contribution is publicly verifiable as part of a transcript. Security relies on at least one participant contributing honestly and permanently deleting their secret randomness.

### Why we are doing this for World ID 4.0

The World ID 4.0 ceremony is for the circuits used by the [`oprf-service`](https://github.com/TaceoLabs/oprf-service/) stack and the corresponding [Circom circuits](https://github.com/TaceoLabs/oprf-service/tree/main/circom/main):

- `OPRFQueryProof`
- `OPRFNullifierProof`
- `OPRFKeyGenProof13`
- `OPRFKeyGenProof25`
- `OPRFKeyGenProof37`

These circuits require Groth16 proving keys, which are produced via a Phase 2 setup. The trusted setup is therefore a required part of preparing production-grade proving artifacts for the World ID 4.0 protocol.

### How to contribute

The `@worldcoin/world-id-trusted-setup-cli` package was built as a fork of [PSE](https://pse.dev/)'s [p0tion](https://github.com/privacy-scaling-explorations/p0tion) for organizing a trusted setup ceremony with minimum work needed to
be done by the contributors. You can perform a contribution with the following 2 easy steps:

1. Authenticate with GitHub device-flow OAuth (used by the CLI and for ceremony identity/attestation flow):

```bash
npx @worldcoin/world-id-trusted-setup-cli auth
```

2. Run the contribution command to join an open ceremony and compute/upload your contribution (<10 min on average):

```bash
npx @worldcoin/world-id-trusted-setup-cli contribute
```

If you have any issues contributing to the ceremony, please contact our ceremony coordinator [dcbuilder on Telegram](https://t.me/dcbuilder).

