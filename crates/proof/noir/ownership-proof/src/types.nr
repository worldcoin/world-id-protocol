pub struct PublicKey {
    pub x: Field,
    pub y: Field,
}

pub struct MerkleProof<let MAX_DEPTH: u32> {
    pub mt_index: Field,
    pub siblings: [Field; MAX_DEPTH],
}

pub struct OwnershipProofInputs<let MAX_DEPTH: u32, let NUM_KEYS: u32> {
    pub user_pk: [PublicKey; NUM_KEYS],
    pub pk_index: Field,
    pub query_s: Field,
    pub query_r: [Field; 2],

    pub merkle_proof: MerkleProof<MAX_DEPTH>,

    pub commitment_r: Field,
}

pub struct OwnershipProofOutputs {
    pub commitment: Field,
}
