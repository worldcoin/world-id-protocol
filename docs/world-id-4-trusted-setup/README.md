# World ID 4.0 Trusted Setup

## How a trusted setup works

World ID 4.0 uses a Groth16 Phase 2 trusted setup ceremony for its zk-SNARK circuits. In this process, multiple participants each add their own randomness contribution (often called "toxic waste") to circuit-specific setup artifacts (`.zkey`), and each contribution is publicly verifiable as part of a transcript. Security relies on at least one participant contributing honestly and permanently deleting their secret randomness.

## Why we are doing this for World ID 4.0

The World ID 4.0 ceremony is for the [Circom circuits](https://github.com/TaceoLabs/oprf-service/tree/main/circom/main) part of the [`oprf-service`](https://github.com/TaceoLabs/oprf-service/) stack:

- `OPRFQueryProof`
- `OPRFNullifierProof`
- `OPRFKeyGenProof13`
- `OPRFKeyGenProof25`
- `OPRFKeyGenProof37`

These circuits require Groth16 proving keys, which are produced via a Phase 2 setup. The trusted setup is therefore a required part of preparing production-grade proving artifacts for the World ID 4.0 protocol.

## How to contribute

> [!NOTE]
> The World ID 4.0 trusted setup ceremony is closed. New contributions are no longer accepted.

The [`@worldcoin/world-id-trusted-setup-cli`](https://www.npmjs.com/package/@worldcoin/world-id-trusted-setup-cli) package was built as a fork of [PSE](https://pse.dev/)'s [p0tion](https://github.com/privacy-scaling-explorations/p0tion) for organizing a trusted setup ceremony with minimum work needed to be done by the contributors. During the active ceremony, contributors used the following flow:

1. Authenticate with GitHub device-flow OAuth (used by the CLI and for ceremony identity/attestation flow):

```bash
npx @worldcoin/world-id-trusted-setup-cli auth
```

2. Run the contribution command to join an open ceremony and compute/upload your contribution (<10 min on average):

```bash
npx @worldcoin/world-id-trusted-setup-cli contribute
```

If you had any issues contributing to the ceremony, please contact our ceremony coordinator [dcbuilder on Telegram](https://t.me/dcbuilder).

## How it was

> [!NOTE]
> If you want to learn more about the trusted setup, watch the rendered explainer video: [World Chain post](https://x.com/world_chain_/status/2023451971651596718?s=20).

- Trusted setup result files: [`circom/artifacts/`](../../circom/artifacts/)
- Verification guide: [`TRUSTED_SETUP.MD`](./TRUSTED_SETUP.MD)
- Verification artifacts: [`artifacts/`](./artifacts/)
- Canonical attestation gists: [`artifacts/hash_gists_primary.tsv`](./artifacts/hash_gists_primary.tsv) (requires file title `world-id-protocol_attestation.log`)
- Local rendered video file (Git LFS): [`World ID Trusted Setup.MP4`](./World%20ID%20Trusted%20Setup.MP4)
