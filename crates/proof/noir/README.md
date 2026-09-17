# Noir circuits

## Packages

- `ownership-proof/` — World ID ownership proof. Compiled by `crates/proof/build.rs` with the repo-standard nargo (`1.0.0-beta.11`), proven with the `provekit-*` crates from crates.io.
- `authenticator-assertion/` — WIP-106 Authenticator Attestation library (Trust Anchor Key Token + Authenticator Assertion Token verification). **🚧 Warning. This is extremely WIP and in active development, things may change significantly or even disappear altogether.**

## Consuming `authenticator-assertion`

`verify_attestation` is the only entrypoint. `verify_takt` and `verify_aat` are crate-private by design: a TAKT alone attests a key without saying what it signed, and an AAT alone proves only that *some* key signed the claims.

The library cannot enforce the rest. A calling circuit MUST:

- expose `trust_anchor_key_x`/`_y` and `now` as **public inputs**. The trust anchor key is the RP's entire trust decision, taken from the provider's Authenticator Metadata; left private, a prover signs its own TAKT and the attestation proves nothing. A private `now` lets a prover pick a time at which any token is fresh. `now` is Unix **seconds** — each token is rejected unless it expires within its maximum remaining lifetime (`aat::MAX_AAT_LIFETIME_SECS`, 30 min; `takt::MAX_TAKT_LIFETIME_SECS`, 7 days), so passing milliseconds fails every proof.
- bind `aat.aud` to the request's RP id, `aat.nonce` to the `ProofRequest` nonce, and `aat.cdh` to the proof's own commitment (zero when nil). The token commits to all three, but only the consumer can anchor them to the statement being proven.
- expose whichever of `sec_flags` (via `takt::unpack_sec_flags`) and `aat.authenticator_meta` the RP needs for its business rules.

```rust
fn main(
    trust_anchor_key_x: pub Field,
    trust_anchor_key_y: pub Field,
    now: pub Field,
    aat: AuthenticatorAssertionToken,
    takt: TrustAnchorKeyToken,
) {
    verify_attestation(aat, takt, trust_anchor_key_x, trust_anchor_key_y, now);
}
```

## Development workflow

```sh
nargo test      # runs all constraint tests, including cross-implementation KATs
nargo fmt       # CI runs `nargo fmt --check`
```
