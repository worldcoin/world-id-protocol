# Noir circuits

## Packages

- `ownership-proof/` — World ID ownership proof. Compiled by `crates/proof/build.rs`
  with the repo-standard nargo (`1.0.0-beta.11`), proven with the `provekit-*`
  crates from crates.io.
- `authenticator-attestation/` — WIP-106 Authenticator Attestation library
  (Trust Anchor Key Token + Authenticator Assertion Token verification).

  The TAKT is **not** nested in the AAT. It travels in the AAT's `COSE_Sign1`
  unprotected header, which never enters the `Sig_structure` (RFC 9052 §4.4), so
  the circuit never reserializes it. The two tokens are bound solely by the
  shared `assertion_key`: `verify_takt` authenticates the TAKT under the
  provider's `trust_anchor_key`, and `verify_aat` then verifies the ES256
  signature under the key that TAKT attests. That key equality is the *only*
  binding — if you touch either verification path, preserve it.

## Development workflow

Circuits are developed and tested with **nargo only** — no proving backend:

```sh
nargo test      # runs all constraint tests, including cross-implementation KATs
nargo fmt       # CI runs `nargo fmt --check`
```
