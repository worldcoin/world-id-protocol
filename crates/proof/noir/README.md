# Noir circuits

## Packages

- `ownership-proof/` — World ID ownership proof. Compiled by `crates/proof/build.rs` with the repo-standard nargo (`1.0.0-beta.11`), proven with the `provekit-*` crates from crates.io.
- `authenticator-attestation/` — WIP-106 Authenticator Attestation library (Trust Anchor Key Token + Authenticator Assertion Token verification). **🚧 Warning. This is extremely WIP and in active development, things may change significantly or even disappear altogether.**
- `embedding-similarity/` — WIP-111 Embedding Similarity proof (verifies a WIP-110 Verifier token, a WIP-106 attestation chain, and Credential validity). Fixtures (`Prover.toml`, `src/test_fixtures.nr`) are generated: `UPDATE_PROVER_TOML=1 cargo test -p world-id-proof embedding_similarity`, then `nargo fmt`. **🚧 Warning. This is extremely WIP and in active development, things may change significantly or even disappear altogether.**
- `embedding-similarity-no-attestation/` — WIP-111 variant without in-circuit WIP-106 attestation verification (the TEE Verifier checks the attestation instead). Same generated fixtures. One of the two variants will be dropped once the design decision lands, so the shared modules are duplicated rather than extracted. **🚧 Warning. See above.**

## Development workflow

```sh
nargo test      # runs all constraint tests, including cross-implementation KATs
nargo fmt       # CI runs `nargo fmt --check`
```
