# Noir circuits

## Packages

- `ownership-proof/` — Proof of Ownership (WIP-103).
- `embedding-similarity/` — WIP-202 Proof of Embedding Similarity over a WIP-201 Flamingo Token. **🚧 Unaudited, in active development.**
- `authenticator-assertion/` — WIP-106 Authenticator Assertion Token verification. **🚧 Warning. This is WIP and in active development, things may change significantly.**

## Development workflow

```sh
nargo test      # runs all constraint tests, including cross-implementation KATs
nargo fmt       # CI runs `nargo fmt --check`
```
