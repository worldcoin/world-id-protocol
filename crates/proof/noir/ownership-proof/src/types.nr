use world_id_components::types::AccountInputs;

/// The private inputs of the Ownership Proof (WIP-103).
pub struct OwnershipProofPrivateInputs {
    /// The World ID's `WorldIDRegistry` witness and its Authenticator's signature.
    pub account: AccountInputs,
    /// The blinding value that is hashed with the `leaf_index` to output the
    /// `expected_commitment`. Its provenance depends on the specific use case (see WIP-103).
    pub commitment_blinder: Field,
}
