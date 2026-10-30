use super::constants::CHUNK_SLOTS;
use world_id_components::types::{AccountInputs, CredentialInputs, Signature};

/// The WIP-201 Flamingo Token values that stay private.
pub struct FlamingoTokenInputs {
    /// `compared_entry_hash_1`, the live capture; the circuit derives the other entries.
    pub live_capture_hash: Field,
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
