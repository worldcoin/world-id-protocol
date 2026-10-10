use super::{
    components::types::{AccountInputs, CredentialInputs, Signature},
    constants::{CHUNK_SLOTS, MAX_COMPARED},
};

/// The WIP-201 Flamingo Token values that stay private.
pub struct FlamingoTokenInputs {
    /// `R(SHA-256(entries[compare[k]].data))`: credential, live, challenge, unused.
    pub compared_entry_hash: [Field; MAX_COMPARED],
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
