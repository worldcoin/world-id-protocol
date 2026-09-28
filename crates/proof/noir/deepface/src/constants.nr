// Constants of the WIP-111 DeepFace Proof.
//
// Domain separators are the ASCII bytes of the quoted tag read as a big-endian
// integer (all tags are shorter than 31 bytes, so no reduction occurs).

/// Number of authenticator key slots in a `WorldIDRegistry` leaf.
pub global NUM_KEYS: u32 = 7;

/// Number of claim slots in a Credential.
pub global MAX_CLAIMS: u32 = 15;

/// Depth of the `WorldIDRegistry` Merkle tree, fixed by WIP-100.
pub global MERKLE_DEPTH: u32 = 30;

/// Credential claim holding the PCP `hashes.json` commitment.
pub global CLAIM_INDEX: u32 = 0;

/// Bound on the `hashes.json` input. A v3 PCP `hashes.json` is about 4.3 KB.
pub global MAX_HASHES_JSON_BYTES: u32 = 5120;

/// Bytes per sponge chunk: 31 bytes stay below the BN254 modulus.
pub global CHUNK_BYTES: u32 = 31;

/// Sponge chunks of a maximum-length `hashes.json`.
pub global NUM_CHUNKS: u32 = (MAX_HASHES_JSON_BYTES + CHUNK_BYTES - 1) / CHUNK_BYTES;

/// Chunks spanned by the 83-byte thumbnail window (delimiter, key, digest, quote).
pub global WINDOW_CHUNKS: u32 = 4;

/// Chunk slots: `NUM_CHUNKS` plus zero slack so the window never indexes past the end.
pub global CHUNK_SLOTS: u32 = NUM_CHUNKS + WINDOW_CHUNKS - 1;

/// Ceiling on the RP-supplied `comparison_age_max`, in seconds (24h).
pub global MAX_COMPARISON_AGE_SECS: u64 = 86400;

/// Authenticator authorization message: b"WORLD-ID/WIP-111/SIGN".
pub global DS_WIP_111: Field = 127603488023523044162070750169730678246161835968334;

/// WIP-110 Verifier token digest: b"WORLD_ID_EVT_V1".
pub global DS_EVT_V1: Field = 453338657364062333832270442605270577;

/// Credential hash (`ds::CREDENTIAL_V1`): b"POSEIDON2+EDDSA-BJJ".
pub global DS_CREDENTIAL_V1: Field = 1790969822004668215611014194230797064349043274;

/// Blinded credential subject (`ds::CREDENTIAL_SUB`): b"H_CS(id, r)".
pub global DS_CREDENTIAL_SUB: Field = 87492525752134038588518953;

/// Session commitment (`ds::SESSION_COMMITMENT`): b"H(id, r)".
pub global DS_SESSION_COMMITMENT: Field = 5199521648757207593;

/// Registry leaf hash (`ds::AUTHENTICATOR_KEY_SET`): b"World ID PK".
pub global MERKLE_LEAF_DS: Field = 105702839725298824521994315;
