# World ID RP

World ID is an anonymous proof of human for the age of AI.

This crate provides RP-side verification of World ID proofs off-chain:

- Uniqueness and Session Proofs (`world_id_proof`), with the checks `WorldIDVerifier` runs on-chain, reading on-chain state through a `WorldIdState` the RP provides.
- The WIP-202 Proof of Embedding Similarity (`embedding_similarity`).

More information can be found in the [World ID Developer Documentation](https://docs.world.org/world-id).
