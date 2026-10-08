// Constants of the WIP-202 Proof of Embedding Similarity; shared ones are in `components`.
//
// Domain separators are the ASCII bytes of the quoted tag read as a big-endian
// integer (all tags are shorter than 31 bytes, so no reduction occurs).

/// Compared entries in a WIP-201 Flamingo Token.
pub global MAX_COMPARED: u32 = 4;

/// Credential claim holding the PCP `hashes.json` commitment.
pub global CLAIM_INDEX: u32 = 0;

/// Accepted `hashes.json` lengths. A v3 PCP `hashes.json` is about 4.3 KB and a v2 one
/// about 3.9 KB. The SAFE tag table costs about 3 R1CS constraints per accepted length.
pub global MIN_HASHES_JSON_BYTES: u32 = 3072;
pub global MAX_HASHES_JSON_BYTES: u32 = 5120;

/// Bytes per sponge chunk: 31 bytes stay below the BN254 modulus.
pub global CHUNK_BYTES: u32 = 31;

/// Sponge chunks of a maximum-length `hashes.json`.
pub global NUM_CHUNKS: u32 = (MAX_HASHES_JSON_BYTES + CHUNK_BYTES - 1) / CHUNK_BYTES;

/// Chunks spanned by the 83-byte thumbnail window (delimiter, key, digest, quote).
pub global WINDOW_CHUNKS: u32 = 4;

/// Chunk slots: `NUM_CHUNKS` plus zero slack so the window never indexes past the end.
pub global CHUNK_SLOTS: u32 = NUM_CHUNKS + WINDOW_CHUNKS - 1;

/// Flamingo Token digest (`DS_WIP_201`): b"WORLD-ID/WIP-201/SIGN".
pub global DS_WIP_201: Field = 127603488023523044162070750169730750022280897185614;

/// Account authorization (`DS_WIP_202_AUTH`): b"WORLD-ID/WIP-202/AUTH".
pub global DS_WIP_202_AUTH: Field = 127603488023523044162070750169730750023380107613256;
