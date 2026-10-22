# Noir circuits

## Packages

- `ownership-proof/` — Proof of Ownership (WIP-103).
- `authenticator-assertion/` — WIP-106 Trust Anchor Key Token (`BabyJubJub-EdDSA-Poseidon2`) and Authenticator Assertion Token (`ES256`) verification. **🚧 Warning. This is WIP and in active development, things may change significantly.**

## Consuming `authenticator-assertion`

A circuit calling `verify_assertion` MUST:

- expose every field of `AuthenticatorAssertionPublicInputs` as a public input. `now` is Unix **seconds**.
- compute `cdh` from its own inputs, as the consuming spec defines (or `0` where it allows nil); otherwise the AAT is not bound to its upstream use.

## Development workflow

```sh
nargo test      # runs all constraint tests, including cross-implementation KATs
nargo fmt       # CI runs `nargo fmt --check`
```
