# World ID 4.0 Trusted Setup Artifacts

This orphan branch contains the full trusted setup ceremony artifacts, verification transcripts,
video documentation, and deprecated circuit files.

These files are kept separate from the [`main`](https://github.com/worldcoin/world-id-protocol) branch to reduce repository size. Only the essential
runtime artifacts (`.arks.zkey` proving keys and `*Graph.bin` witness graphs) are kept on the main branch.

## Contents

- `circom/artifacts/` — Full ceremony outputs per circuit (zkeys, r1cs, wasm, verifier contracts, vkeys, transcripts)
- `circom/artifacts/deprecated/` — Previous generation artifacts
- `docs/world-id-4-trusted-setup/` — Trusted setup documentation, video, and manim source
  - [Verification guide](docs/world-id-4-trusted-setup/TRUSTED_SETUP.MD)
  - [Overview & contribution history](docs/world-id-4-trusted-setup/README.md)

## Git LFS

Many artifacts on this branch are stored using [Git LFS](https://git-lfs.com/). After checkout, run:

```bash
git lfs install
git lfs pull
```
