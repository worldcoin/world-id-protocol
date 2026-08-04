pub struct PublicKey {
    pub x: Field,
    pub y: Field,
}

pub struct MerkleProof<let MAX_DEPTH: u32> {
    pub mt_index: Field,
    pub siblings: [Field; MAX_DEPTH],
}

/// The private part of a Proof of Human credential.
///
/// `claims_hash` is deliberately absent: it is the `pcp_hash` public input, because the
/// TEE has to compare it against the hash it derives from `hashes.json` itself.
pub struct CredentialWitness {
    /// The `associated_data_commitment`, i.e. `hashes[1]` of the credential.
    pub associated_data_hash: Field,
    pub genesis_issued_at: Field,
    pub expires_at: Field,
    /// The `s` part of the issuer's EdDSA signature over the credential.
    pub sig_s: Field,
    /// The `r` part of the issuer's EdDSA signature over the credential.
    pub sig_r: [Field; 2],
    /// Blinding factor of the credential subject commitment (`sub`).
    pub sub_blinding_factor: Field,
    /// Packed credential `id` and `issuer_version`.
    pub cred_id: Field,
}

pub struct DeepFaceQueryProofInputs<let BILLING_MAX_DEPTH: u32> {
    /// Position of the World ID in the `WorldIDRegistry` tree, i.e. `leafIndex`.
    ///
    /// Private: publishing it would identify the human to the TEE.
    pub mt_index: Field,
    /// The session secret `r = OPRF(pk_rp_id, DS_C || leafIndex || oprf_seed)`.
    ///
    /// Private: it is what makes the billing leaf unlinkable across periods.
    pub commitment_r: Field,
    /// Inclusion path of the session id commitment in the billing tree.
    pub billing_proof: MerkleProof<BILLING_MAX_DEPTH>,
    pub credential: CredentialWitness,
}
