// Constants shared by World ID circuits (WIP-113).
//
// Domain separators are the ASCII bytes of the quoted tag read as a big-endian
// integer (all tags are shorter than 31 bytes, so no reduction occurs).

/// Number of authenticator key slots in a `WorldIDRegistry` leaf.
pub global NUM_KEYS: u32 = 7;

/// Number of claim slots in a Credential.
pub global MAX_CLAIMS: u32 = 15;

/// Depth of the `WorldIDRegistry` Merkle tree, fixed by WIP-100.
pub global MERKLE_DEPTH: u32 = 30;

/// Registry leaf hash (`ds::AUTHENTICATOR_KEY_SET`): b"World ID PK".
pub global MERKLE_LEAF_DS: Field = 105702839725298824521994315;

/// Credential hash (`ds::CREDENTIAL_V1`): b"POSEIDON2+EDDSA-BJJ".
pub global DS_CREDENTIAL_V1: Field = 1790969822004668215611014194230797064349043274;

/// Blinded credential subject (`ds::CREDENTIAL_SUB`): b"H_CS(id, r)".
pub global DS_CREDENTIAL_SUB: Field = 87492525752134038588518953;

/// Session commitment (`ds::SESSION_COMMITMENT`): b"H(id, r)".
pub global DS_SESSION_COMMITMENT: Field = 5199521648757207593;
