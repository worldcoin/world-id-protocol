use super::constants::{MERKLE_DEPTH, NUM_KEYS};

/// An EdDSA public key over the BabyJubJub curve, represented as its affine coordinates (x, y).
pub struct PublicKey {
    pub x: Field,
    pub y: Field,
}

/// The `WorldIDRegistry` witness: the key set, its inclusion proof, and the
/// authenticator authorization signature (WIP-111 constraints 1-5, 10).
pub struct RegistryInputs {
    /// Authenticator public keys registered in the `WorldIDRegistry`, in slot
    /// order; inactive slots hold the identity (0, 1).
    pub user_pk: [PublicKey; NUM_KEYS],
    /// The index in `user_pk` of the key that signed the authorization message.
    pub pk_index: Field,
    /// The `s` component of the authorization signature (`sig_s` in WIP-111).
    pub sig_s: Field,
    /// The `r` component of the authorization signature (`sig_r` in WIP-111).
    pub sig_r: [Field; 2],
    /// Index of the user's World ID in the `WorldIDRegistry`.
    pub leaf_index: Field,
    /// Sibling nodes from `leaf_index` upwards.
    pub siblings: [Field; MERKLE_DEPTH],
}

/// The Credential fields this variant still reads.
///
/// The Issuer signature is verified by the WIP-110 Verifier, not here, so the
/// claims array, the associated data hash, `cred_id` and the signature itself
/// are no longer witnesses. What remains is the blinding factor that ties the
/// Issuer-signed subject to `leaf_index` (constraint 6) and the two timestamps
/// the validity window reads (constraint 9); both are covered by the
/// delegation commitment the Verifier signed.
pub struct CredentialInputs {
    /// Timestamp of first issuance, Unix seconds (`cred_genesis_issued_at`).
    pub genesis_issued_at: Field,
    /// Expiration timestamp, Unix seconds (`cred_expires_at`).
    pub expires_at: Field,
    /// Blinding factor of the credential subject (`cred_sub_blinding_factor`).
    pub sub_blinding_factor: Field,
}

/// The WIP-110 Verifier token (`cwt`) witness: the claims the circuit reads and
/// the EdDSA signature over their digest (WIP-111 constraint 14).
///
/// Neither `challenge_commitment` nor `delegation_commitment` is carried here:
/// both are bound by hashing the circuit's own value into the signed digest.
pub struct VerifierTokenInputs {
    /// Time of the comparison, seconds since the Unix epoch (`iat`).
    pub iat: Field,
    /// Commitment to the credential item the Verifier compared against. The
    /// Verifier checked it against `claims[claim_index]` of the Credential it
    /// validated, so this circuit reads it only to reproduce the token digest.
    pub credential_commitment: Field,
    /// Commitment to the live capture the Verifier compared.
    pub live_commitment: Field,
    /// Score for live against credential.
    pub similarity_live: Field,
    /// Score for challenge against credential; `0` in the 2-way flow.
    pub similarity_challenge: Field,
    /// The `s` component of the Verifier's EdDSA signature.
    pub sig_s: Field,
    /// The `r` component of the Verifier's EdDSA signature.
    pub sig_r: [Field; 2],
}

/// All private inputs of the Embedding Similarity Proof (registry-only variant).
pub struct PrivateInputs {
    pub registry: RegistryInputs,
    pub credential: CredentialInputs,
    pub cwt: VerifierTokenInputs,
    /// Blinding factor for the session commitment.
    pub session_id_r: Field,
}
