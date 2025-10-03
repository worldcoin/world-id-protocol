use ruint::aliases::U256;

/// The response from an inclusion proof request.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct InclusionProofResponse {
    /// TODO: Add proper documentation.
    pub account_index: u64,
    /// The index of the leaf in the tree.
    pub leaf_index: u64,
    /// The hash root of the tree.
    pub root: U256,
    /// The entire proof of inclusion for all the nodes in the path.
    pub proof: Vec<U256>,
}

impl InclusionProofResponse {
    /// Instantiates a new inclusion proof response.
    #[must_use]
    pub const fn new(account_index: u64, leaf_index: u64, root: U256, proof: Vec<U256>) -> Self {
        Self {
            account_index,
            leaf_index,
            root,
            proof,
        }
    }
}
