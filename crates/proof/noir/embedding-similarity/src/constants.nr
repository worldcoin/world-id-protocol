// Constants of the WIP-111 Embedding Similarity Proof.
//
// The domain separators are the ASCII bytes of the quoted tag interpreted as a
// big-endian integer (all tags are shorter than 31 bytes, so no reduction occurs).

/// Number of authenticator key slots in a `WorldIDRegistry` leaf.
pub global NUM_KEYS: u32 = 7;

/// Number of claim slots in a Credential.
pub global MAX_CLAIMS: u32 = 15;

/// Depth of the `WorldIDRegistry` Merkle tree, fixed by WIP-100.
pub global MERKLE_DEPTH: u32 = 30;

/// Ceiling on the RP-supplied `comparison_age_max`, in seconds (24h).
pub global MAX_COMPARISON_AGE_SECS: u64 = 86400;

/// Ceiling on the remaining lifetime of an AAT (`exp - now`), in seconds (12h).
//
// WIP-111 sets 43200; the WIP-106 draft currently says 1800. The spec authors
// need to reconcile the two -- tracked in the WIP-111 PR.
pub global MAX_AAT_LIFETIME_SECS: u64 = 43200;

/// Domain separator for the authenticator authorization message: b"WORLD-ID/WIP-111/SIGN".
pub global DS_WIP_111: Field = 127603488023523044162070750169730678246161835968334;

/// Domain separator for the WIP-110 Verifier token digest: b"WORLD_ID_EVT_V1".
pub global DS_EVT_V1: Field = 453338657364062333832270442605270577;

/// Domain separator of the Credential hash (`ds::CREDENTIAL_V1`): b"POSEIDON2+EDDSA-BJJ".
pub global DS_CREDENTIAL_V1: Field = 1790969822004668215611014194230797064349043274;

/// Domain separator of the blinded credential subject (`ds::CREDENTIAL_SUB`): b"H_CS(id, r)".
pub global DS_CREDENTIAL_SUB: Field = 87492525752134038588518953;

/// Domain separator of the session commitment (`ds::SESSION_COMMITMENT`): b"H(id, r)".
pub global DS_SESSION_COMMITMENT: Field = 5199521648757207593;

/// Domain separator of the registry leaf hash (`ds::AUTHENTICATOR_KEY_SET`): b"World ID PK".
pub global MERKLE_LEAF_DS: Field = 105702839725298824521994315;
