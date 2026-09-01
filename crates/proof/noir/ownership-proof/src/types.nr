/// An EdDSA public key over the BabyJubJub curve, represented as its coordinate points (x, y).
pub struct PublicKey {
    pub x: Field,
    pub y: Field,
}

/// An inclusion proof for a single leaf of the `WorldIDRegistry`'s Merkle tree.
pub struct MerkleProof<let MAX_DEPTH: u32> {
    /// The index of the user's World ID in the `WorldIDRegistry`, it is the
    /// position it holds in the Merkle tree. In other circuits this is called `mt_index`.
    pub leaf_index: Field,
    /// The sequence of all siblings from the `leaf_index` to the `merkle_root`.
    pub siblings: [Field; MAX_DEPTH],
}

/// The private inputs of the Ownership Proof (WIP-103).
pub struct OwnershipProofPrivateInputs<let MAX_DEPTH: u32, let NUM_KEYS: u32> {
    /// The list of authenticator public keys registered in the `WorldIDRegistry`.
    pub user_pk: [PublicKey; NUM_KEYS],
    /// The index in `user_pk` of the key used for the signature.
    pub pk_index: Field,
    /// The `s` component of the EdDSA signature on the message.
    pub query_s: Field,
    /// The `r` component of the EdDSA signature on the message.
    pub query_r: [Field; 2],
    /// The inclusion proof of the user's World ID in the `WorldIDRegistry`.
    pub merkle_proof: MerkleProof<MAX_DEPTH>,
    /// The blinding value that is hashed with the `leaf_index` to output the
    /// `expected_commitment`. Its provenance depends on the specific use case (see WIP-103).
    pub commitment_blinder: Field,
}
