// Constants shared by World ID circuits.
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

/// OPRF query digest (`ds::OPRF_QUERY`): b"World ID Query".
pub global DS_QUERY: Field = 1773399373884719043551600379785849;

/// Nullifier, the OPRF finalization hash (WIP-100 §3.8; `ds::OPRF_PROOF` in Rust): b"World ID Proof".
pub global DS_NULLIFIER: Field = 1773399373884719043551596035141478;

/// Commitment to a World ID's secret-shared blinding secret `s`: b"WORLD-ID/SHARES/S-COMMIT".
pub global DS_SECRET_COMMITMENT: Field = 2140831280924059192884579192232817354492141043481939102036;

/// Registry leaf binding the key set, `s` and the XMSS credential set: b"WORLD-ID/SHARES/LEAF".
pub global DS_REGISTRY_LEAF: Field = 498451125091886891258084027150836157261310935366;

/// OPRF query digest that includes `s`: b"WORLD-ID/SHARES/QUERY".
pub global DS_QUERY_V2: Field = 127603488023523044162069510950614056258917342990937;

/// Message authorizing a share fetch from the OPRF nodes: b"WORLD-ID/SHARES/FETCH".
pub global DS_SHARE_FETCH: Field = 127603488023523044162069510950614056258869830894408;

/// Commitment to a World ID's XMSS credential slots: b"WORLD-ID/SHARES/XMSS-SET".
pub global DS_XMSS_SET: Field = 2140831280924059192884579192232817354492510356260212917588;

/// XMSS hashes (`xmss.nr`). b"WORLD-ID/XMSS/CHAIN".
pub global DS_XMSS_CHAIN: Field = 1947074707390183168976914436421382366178658638;
/// b"WORLD-ID/XMSS/MSG".
pub global DS_XMSS_MSG: Field = 29710002248995714858656531317464941548359;
/// b"WORLD-ID/XMSS/PK".
pub global DS_XMSS_PK: Field = 116054696285139511166627075458847428683;
/// b"WORLD-ID/XMSS/NODE".
pub global DS_XMSS_NODE: Field = 7605760575742903003816072017271025052894277;
/// b"WORLD-ID/XMSS/COMMIT".
pub global DS_XMSS_COMMIT: Field = 498451125091886891258090095723873885772002969940;
/// b"WORLD-ID/XMSS/TAG".
pub global DS_XMSS_TAG: Field = 29710002248995714858656531317464942002503;
/// b"WORLD-ID/XMSS/TAG-KEY".
pub global DS_XMSS_TAG_KEY: Field = 127603488023523044162071064505311719527287895049561;

/// Number of XMSS credential slots per World ID, one per authenticator key slot.
pub global NUM_XMSS_SLOTS: u32 = 7;

/// Height of an authenticator's XMSS tree: 2^10 one-time keys.
pub global XMSS_HEIGHT: u32 = 10;

/// WOTS+ chains for w = 2: 254 message bits plus an 8-bit checksum.
pub global WOTS_MSG_CHAINS: u32 = 254;
pub global WOTS_CHECKSUM_CHAINS: u32 = 8;
pub global WOTS_CHAINS: u32 = 262;
