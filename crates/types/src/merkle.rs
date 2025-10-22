use crate::FieldElement;

/// Artifact required to compute the Merkle inclusion proof.
///
/// This is generally used to prove inclusion into the set of World ID Accounts (`AccountRegistry`);
/// each authenticator public key is tied to a leaf in a Merkle tree, where each leaf represents
/// a unique World ID Account.
///
/// To prove validity, the user shows membership in the tree with a sibling path up to the root.
#[derive(Debug, Clone)]
pub struct MerkleInclusionProof<const TREE_DEPTH: usize> {
    /// The root hash of the Merkle tree.
    pub root: FieldElement,
    /// The logical index of the user's leaf in the Merkle tree.
    pub leaf_index: u64,
    /// The user's account ID which is represented by the leaf position in the Merkle tree.
    ///
    /// This is the `leaf_index` + 1 (because the `account_id` is initialized to `1`).
    pub account_id: u64,
    /// The sibling path up to the Merkle root.
    pub siblings: [FieldElement; TREE_DEPTH],
}
