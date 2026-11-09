// Constants of the WIP-202 Proof of Embedding Similarity; shared ones are in `world_id_components`.
//
// Domain separators are the ASCII bytes of the quoted tag read as a big-endian
// integer (all tags are shorter than 31 bytes, so no reduction occurs).

/// `compare_sources` WIP-202 fixes: compared entry 1 is pipeline input 0, the others are references.
pub global COMPARE_SOURCES: u32 = 256;

/// Credential claim holding the PCP `hashes.json` commitment.
pub global CLAIM_INDEX: u32 = 0;

/// The `"thumbnail.png":"` key of the thumbnail entry.
pub global THUMBNAIL_KEY: [u8; 17] = "\"thumbnail.png\":\"".as_bytes();

/// Hex digits of a SHA-256 digest.
pub global DIGEST_HEX_LEN: u32 = 64;

/// Accepted `hashes.json` lengths. A v3 PCP `hashes.json` is about 4.3 KB and a v2 one
/// about 3.9 KB. The SAFE tag table costs about 3 R1CS constraints per accepted length.
pub global MIN_HASHES_JSON_BYTES: u32 = 3072;
pub global MAX_HASHES_JSON_BYTES: u32 = 5120;

/// Bytes per `H_var` chunk, from the shared library.
pub use world_id_components::var_hash::CHUNK_BYTES;

/// Sponge chunks of a maximum-length `hashes.json`.
pub global NUM_CHUNKS: u32 = (MAX_HASHES_JSON_BYTES + CHUNK_BYTES - 1) / CHUNK_BYTES;

/// Chunks spanned by the 83-byte thumbnail window (delimiter, key, digest, quote).
pub global WINDOW_CHUNKS: u32 = 4;

/// Chunk slots of `hashes_json`, `⌈MAX_HASHES_JSON_BYTES / 31⌉` as WIP-202 §4.5 specifies. The
/// thumbnail window needs no slack: `digest_offset + 64 < len` keeps its last chunk below
/// `NUM_CHUNKS`.
pub global CHUNK_SLOTS: u32 = NUM_CHUNKS;

/// Account authorization (`DS_WIP_202_AUTH`): b"WORLD-ID/WIP-202/AUTH".
pub global DS_WIP_202_AUTH: Field = 127603488023523044162070750169730750023380107613256;
