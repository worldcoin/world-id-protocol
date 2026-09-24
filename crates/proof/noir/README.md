# Noir circuits

## Packages

- `ownership-proof/` — World ID ownership proof. Compiled by `crates/proof/build.rs` with the repo-standard nargo (`1.0.0-beta.11`), proven with the `provekit-*` crates from crates.io.
- `authenticator-attestation/` — WIP-106 Authenticator Attestation library (Trust Anchor Key Token + Authenticator Assertion Token verification). **🚧 Warning. This is extremely WIP and in active development, things may change significantly or even disappear altogether.**
- `embedding-similarity/` — WIP-111 Embedding Similarity proof (verifies a WIP-110 Verifier token, a WIP-106 attestation chain, and Credential validity). Fixtures (`Prover.toml`, `src/test_fixtures.nr`) are generated: `UPDATE_PROVER_TOML=1 cargo test -p world-id-proof embedding_similarity`, then `nargo fmt`. **🚧 Warning. This is extremely WIP and in active development, things may change significantly or even disappear altogether.**
- `embedding-similarity-no-attestation/` — WIP-111 variant without in-circuit WIP-106 attestation verification (the TEE Verifier checks the attestation instead). Same generated fixtures. **🚧 Warning. See above.**
- `embedding-similarity-registry-only/` — WIP-111 variant that keeps only the `WorldIDRegistry` inclusion in-circuit: the attestation *and* the Credential validation move to the TEE Verifier, which commits to the Credential it validated in a `delegation_commitment` token claim. Same generated fixtures. **🚧 Warning. See above.**

All but one of the three variants will be dropped once the design decision lands, so their shared modules are duplicated rather than extracted.

## Development workflow

```sh
nargo test      # runs all constraint tests, including cross-implementation KATs
nargo fmt       # CI runs `nargo fmt --check`
```
