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
/// The aggregate `claims_hash` is absent by design: it is recomputed in-circuit from the
/// `pcp_hash` public input plus `other_claims`, so the TEE checks the one claim it can
/// derive from `hashes.json` rather than an aggregate it cannot.
pub struct CredentialWitness {
    /// The claim slots other than `PCP_CLAIM_INDEX`, in ascending slot order.
    ///
    /// Private, so the PCP claim can be opened without revealing what else the issuer
    /// attested about this human.
    pub other_claims: [Field; 15],
    /// The `associated_data_commitment`, i.e. `hashes[1]` of the credential.
    ///
    /// Issuer-private operational data per the `Credential` docs, so it is a witness and
    /// deliberately not the PCP binding.
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
