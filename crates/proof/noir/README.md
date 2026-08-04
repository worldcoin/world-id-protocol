# Noir circuits

## Packages

- `ownership-proof/` — World ID ownership proof. Compiled by `crates/proof/build.rs`
  with the repo-standard nargo (`1.0.0-beta.11`), proven with the `provekit-*`
  crates from crates.io.
- `authenticator-attestation/` — WIP-106 Authenticator Attestation library
  (Trust Anchor Key Token + Authenticator Assertion Token verification).

## Toolchain

Every package here builds with **nargo `1.0.0-beta.11`**, the version pinned in
`nix/nargo.nix` and enforced by `crates/proof/build.rs`. This is not a
preference: the published `provekit-*` crates depend on the republished
`provekit_acir` / `provekit_noirc_abi` forks, which exist only at
`1.0.0-beta.11-alpha.x`. `world-id-proof` is `publish = true`, so it cannot take
git dependencies on provekit `main` (which does target beta.20). A package that
only builds on a newer nargo therefore cannot be proven.

Dependency pins follow from that, and must stay on the beta.11 generation:

| dependency | pin | note |
| --- | --- | --- |
| `noir_ecdsa` | `v0.2.9` | `v0.4.x` pins bigcurve `v0.14.0-1`, which needs beta.20 |
| `bigcurve` / `bignum` | `v0.11.0-1` / `v0.8.0-2` | pre-`#[derive_curve_impl]` |
| `poseidon2` | `v0.5.0-beta.0` | `perm::x5_8`; `v0.6.1` renames it `permutation::t8` and is beta.20-only |
| `babyjubjub`, `eddsa_poseidon2` | `taceo-oprf-v0.12.0` | matched pair; `oprf-nr` ships no eddsa, and its babyjubjub is beta.20-only |

`Field::to_le_bits` returns `[u1; N]` on beta.11 and `[bool; N]` on beta.20,
which is why the TACEO libraries cannot span both.

Two consequences worth knowing before changing pins:

- `noir_ecdsa v0.2.9` does not reject `r == 0`; `aat.nr` asserts it explicitly.
  Removing that assertion is only safe if the pin moves to `>= v0.4.1`.
- Bumping `poseidon2` changes nothing semantically today (round constants are
  byte-identical, KAT digests match), but nothing in CI pins that — add real KAT
  vectors before relying on it.

## Development workflow

Circuits are developed and tested with **nargo only** — no proving backend:

```sh
nargo test      # runs all constraint tests, including cross-implementation KATs
nargo fmt       # CI runs `nargo fmt --check`
```
