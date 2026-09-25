# World ID Authenticator

World ID is an anonymous proof of human for the age of AI.

This crate provides the functionality for a World ID Authenticator.

An RP can optionally attach sparse private-claim predicates to a credential request. On native
targets, `generate_proof` then returns the regular Circom nullifier proof and a Noir claims
co-proof in the same response item. The two proofs are bound through their shared nullifier,
credential issuer, RP/action, and credential time policy.

More information can be found in the [World ID Developer Documentation](https://docs.world.org/world-id).
