use super::constants::{CHUNK_SLOTS, MAX_CLAIMS, MERKLE_DEPTH, NUM_KEYS};
use authenticator_assertion::AuthenticatorAssertionToken;

/// An EdDSA public key over the BabyJubJub curve, as its affine coordinates (x, y).
pub struct PublicKey {
    pub x: Field,
    pub y: Field,
}

/// The `WorldIDRegistry` witness and the authenticator authorization signature.
pub struct RegistryInputs {
    /// Registered authenticator keys in slot order; inactive slots hold the identity (0, 1).
    pub user_pk: [PublicKey; NUM_KEYS],
    /// Index in `user_pk` of the key that signed the authorization message.
    pub pk_index: Field,
    pub sig_s: Field,
    pub sig_r: [Field; 2],
    /// Index of the user's World ID in the `WorldIDRegistry`.
    pub leaf_index: Field,
    /// Sibling nodes from `leaf_index` upwards.
    pub siblings: [Field; MERKLE_DEPTH],
}

/// The Credential fields covered by the Issuer signature.
pub struct CredentialInputs {
    pub claims: [Field; MAX_CLAIMS],
    pub associated_data_hash: Field,
    pub genesis_issued_at: Field,
    pub expires_at: Field,
    pub sub_blinding_factor: Field,
    /// Issuer-scoped credential identifier, `< 2^64`.
    pub id: Field,
    pub sig_s: Field,
    pub sig_r: [Field; 2],
}

/// The WIP-110 Verifier token claims and signature.
pub struct VerifierTokenInputs {
    pub iat: Field,
    pub method: Field,
    pub assurance_level: Field,
    pub request_hash: Field,
    /// `R(SHA-256(entries[compare[k]].data))`: credential, live, challenge, unused.
    pub compared_entry_hash: [Field; 4],
    pub sig_s: Field,
    pub sig_r: [Field; 2],
}

/// The PCP `hashes.json` the credential claim commits to, as the sponge absorbs it.
pub struct HashesJsonInputs {
    /// 31-byte big-endian chunks; the last is the integer of its remaining bytes, and
    /// every slot past the last chunk is `0`.
    pub chunks: [Field; CHUNK_SLOTS],
    /// Length in bytes.
    pub len: u32,
    /// Byte offset of the `"thumbnail.png":"<hex>"` entry.
    pub thumbnail_offset: u32,
}

/// All private inputs of the DeepFace Proof.
pub struct PrivateInputs {
    pub registry: RegistryInputs,
    pub credential: CredentialInputs,
    pub token: VerifierTokenInputs,
    pub aat: AuthenticatorAssertionToken,
    /// Blinding factor of the AAT request commitment.
    pub aat_blind: Field,
    pub hashes_json: HashesJsonInputs,
    /// Blinding factor of the session commitment.
    pub session_id_r: Field,
}
