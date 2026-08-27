# Claims proof prototype

This is a proof-of-concept companion to the Circom `OPRFNullifier` proof. It
shows that public predicates hold over private credential claims without
revealing the credential's stable `claims_hash`.

The circuit proves that:

1. the private claims produce the `claims_hash` embedded in a valid issuer
   signature;
2. the public `salted_claims_hash` commits to that private `claims_hash`;
3. the public statements hold over the private claims; and
4. the issuer-attested credential subject and the public nullifier are derived
   from the same private World ID leaf index.

The RP verifies the Circom nullifier proof and this proof with the same public
`nullifier`, `issuer_schema_id`, `cred_pk`, `rp_id`, `action`, and time policy.
This circuit intentionally does not duplicate the Circom proof's authenticator
signature, Merkle inclusion, DLog equality, or OPRF unblinding constraints.

The salt must be fresh and unpredictable for each presentation. Freshness is a
protocol requirement and cannot be enforced by this circuit.

Run the POC with the repository-pinned Noir toolchain:

```sh
nix develop --command sh -c \
  'cd crates/proof/noir/claims-proof && nargo fmt --check && nargo test && nargo compile'
```

This directory is intentionally marked as a prototype and is not wired into
the Rust proof-generation interface or release artifacts.
