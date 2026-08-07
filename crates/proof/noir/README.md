# Noir circuits

## Packages

- `ownership-proof/` — World ID ownership proof. Compiled by `crates/proof/build.rs` with the repo-standard nargo (`1.0.0-beta.11`), proven with the `provekit-*` crates from crates.io.
- `authenticator-assertion/` — WIP-106 Authenticator Attestation library (Trust Anchor Key Token + Authenticator Assertion Token verification). **🚧 Warning. This is extremely WIP and in active development, things may change significantly or even disappear altogether.**

  The TAKT is **not** part of the AAT — not nested in its claims and not in its `COSE_Sign1` headers. The two are fully separate objects, so the circuit never reserializes the TAKT's CBOR. They are bound by the shared `assertion_key`: `verify_takt` authenticates the TAKT under the provider's `trust_anchor_key`, and `verify_aat` then verifies the ES256 signature under the key that TAKT attests. That key equality is the *only* binding.

  Because the binding is the key rather than the container, pairing the two on the wire is left to the carrying protocol. A verifier handed more than one candidate TAKT MUST use the one whose `cnf` key verifies the AAT — `verify_attestation` does this by construction, taking both tokens as independent inputs.

## Consuming `authenticator-assertion`

`verify_attestation` is the only entrypoint. `verify_takt` and `verify_aat` are crate-private by design: a TAKT alone attests a key without saying what it signed, and an AAT alone proves only that *some* key signed the claims. Going through the composite is what binds them — it feeds `verify_aat` the `assertion_key` read from the TAKT it just verified, so the two cannot be mismatched. If you find yourself wanting one half, verify both and ignore what you don't need.

The library cannot enforce the rest. A calling circuit MUST:

- expose `trust_anchor_key_x`/`_y` and `now` as **public inputs**. The trust anchor key is the RP's entire trust decision, taken from the provider's Authenticator Metadata; left private, a prover signs its own TAKT and the attestation proves nothing. A private `now` lets a prover pick a time at which any token is fresh.
- bind `aat.nonce` and `aat.cdh` to the surrounding proof.
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
