# Noir circuits

## Packages

- `ownership-proof/` — World ID ownership proof. Compiled by `crates/proof/build.rs` with the repo-standard nargo (`1.0.0-beta.11`), proven with the `provekit-*` crates from crates.io.
- `authenticator-attestation/` — WIP-106 Authenticator Attestation library (Trust Anchor Key Token + Authenticator Assertion Token verification). **🚧 Warning. This is extremely WIP and in active development, things may change significantly or even disappear altogether.** 

## Development workflow

```sh
nargo test      # runs all constraint tests, including cross-implementation KATs
nargo fmt       # CI runs `nargo fmt --check`
```
