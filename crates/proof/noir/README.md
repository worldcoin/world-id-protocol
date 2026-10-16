# Noir circuits

## Packages

- `ownership-proof/` — Proof of Ownership (WIP-103).
- `authenticator-assertion/` — WIP-106 Authenticator Assertion Token verification. **🚧 Warning. This is WIP and in active development, things may change significantly.**

## Consuming `authenticator-assertion`

A circuit calling `verify_aat` MUST:

- expose every field of `AuthenticatorAssertionPublicInputs` as a public input. `now` is Unix **seconds**.
- constrain `cdh` to its own inputs (or to `0` where its spec allows nil), otherwise the AAT is not bound to its upstream use.

## Development workflow

```sh
nargo test      # runs all constraint tests, including cross-implementation KATs
nargo fmt       # CI runs `nargo fmt --check`
```
