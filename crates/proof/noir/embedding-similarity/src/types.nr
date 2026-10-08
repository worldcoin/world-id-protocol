use super::constants::{CHUNK_SLOTS, MAX_CLAIMS, MAX_COMPARED, MERKLE_DEPTH, NUM_KEYS};
use eddsa_poseidon2::{
    BabyJubJubPoint, BabyJubJubPointInSubgroup, BabyJubJubScalarFieldElement,
    verify_eddsa_poseidon2,
};

/// An EdDSA public key over the BabyJubJub curve, as its affine coordinates (x, y).
pub struct PublicKey {
    pub x: Field,
    pub y: Field,
}

/// A WIP-100 `BabyJubJub-EdDSA-Poseidon2` signature.
pub struct Signature {
    pub s: Field,
    pub r: [Field; 2],
}

impl Signature {
    /// Whether this is a valid signature by `pk` over `message`; rejects the identity key.
    pub fn verify(self, pk: PublicKey, message: Field) -> bool {
        verify_eddsa_poseidon2(
            BabyJubJubPointInSubgroup::new(pk.x, pk.y),
            BabyJubJubScalarFieldElement::new(self.s),
            BabyJubJubPoint::new(self.r[0], self.r[1]),
            message,
        )
    }
}

/// The WIP-201 Flamingo Token values that stay private.
pub struct FlamingoTokenInputs {
    /// `R(SHA-256(entries[compare[k]].data))`: credential, live, challenge, unused.
    pub compared_entry_hash: [Field; MAX_COMPARED],
    pub sig: Signature,
}

/// The account's `WorldIDRegistry` witness and its authorization signature.
pub struct AccountInputs {
    /// Registered authenticator keys in slot order; inactive slots hold the identity (0, 1).
    pub user_pk: [PublicKey; NUM_KEYS],
    /// Index in `user_pk` of the key that signed the authorization.
    pub pk_index: Field,
    pub auth: Signature,
    /// Index of the account in the `WorldIDRegistry`.
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
    pub sig: Signature,
}

/// The PCP `hashes.json` the Credential claim commits to, as the sponge absorbs it.
pub struct HashesJsonInputs {
    /// 31-byte big-endian chunks; the last is the integer of its remaining bytes, and
    /// every slot past the last chunk is `0`.
    pub chunks: [Field; CHUNK_SLOTS],
    /// Length in bytes.
    pub len: u32,
    /// Byte offset of the `"thumbnail.png":"<hex>"` entry.
    pub digest_offset: u32,
}

/// All private inputs of the Proof of Embedding Similarity.
pub struct PrivateInputs {
    pub token: FlamingoTokenInputs,
    pub account: AccountInputs,
    pub credential: CredentialInputs,
    pub hashes_json: HashesJsonInputs,
    /// Blinding factor of the session commitment.
    pub session_id_r: Field,
}
