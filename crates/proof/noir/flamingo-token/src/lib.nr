//! WIP-201 Flamingo Token verification for circuits that keep the token private
//! (WIP-201 §4.7 Consuming Flamingo Tokens, checks 2 and 3). The consuming circuit binds
//! the claims its statement depends on, including check 8 for a nonzero `billing_nullifier`.
use poseidon2::bn254::permutation;
use world_id_components::types::{PublicKey, Signature};

mod tests;

/// Compared entries in a Flamingo Token.
pub global MAX_COMPARED: u32 = 4;

/// Flamingo Token digest (`DS_WIP_201`): b"WORLD-ID/WIP-201/SIGN".
pub global DS_WIP_201: Field = 127603488023523044162070750169730750022280897185614;

/// The token values a consuming circuit takes as public inputs.
pub struct FlamingoTokenPublic {
    pub verifier_key: PublicKey,
    pub now: u32,
    pub aud: Field,
    pub nonce: Field,
    pub has_aat: bool,
    pub trust_anchor_key_hash: Field,
    pub platform: u8,
    pub sec_level: u8,
    pub sec_meta: u8,
    pub authenticator_meta: u8,
    pub min_build_version: u32,
    pub engine_config_hash: Field,
}

/// The token values a consuming circuit keeps private or fixes itself.
pub struct FlamingoTokenClaims {
    /// `compared_entry_hash_k`, `0` past the last compared entry.
    pub compared_entry_hashes: [Field; MAX_COMPARED],
    pub compare_sources: u32,
    /// The WIP-107 billing nullifier, or `0` for an RP that is not billed.
    pub billing_nullifier: Field,
}

/// `aat_flags`: the TAKT's `sec_flags` layout with `min_build_version` in bits 16-47 and
/// `authenticator_meta` in bits 52-56. Range-checks the sub-fields (check 3).
pub fn aat_flags(public: FlamingoTokenPublic) -> Field {
    assert(public.sec_meta < 16, "sec_meta exceeds 4 bits");
    assert(public.authenticator_meta < 32, "authenticator_meta exceeds 5 bits");
    assert((public.authenticator_meta & 7) < 5, "user_presence values 5 to 7 are reserved");
    public.platform as Field
        + 0x100 * public.sec_level as Field
        + 0x10000 * public.min_build_version as Field
        + 0x1000000000000 * public.sec_meta as Field
        + 0x10000000000000 * public.authenticator_meta as Field
}

/// The signed digest (WIP-201 §4.5): `H_16(DS_WIP_201; ...)` over the 13 claims.
pub fn digest(public: FlamingoTokenPublic, claims: FlamingoTokenClaims) -> Field {
    let h = claims.compared_entry_hashes;
    permutation::t16([
        DS_WIP_201,
        public.now as Field,
        h[0],
        h[1],
        h[2],
        h[3],
        public.aud,
        public.nonce,
        public.trust_anchor_key_hash,
        aat_flags(public),
        public.has_aat as Field,
        claims.compare_sources as Field,
        public.engine_config_hash,
        claims.billing_nullifier,
        0,
        0,
    ])[1]
}

/// Checks 2 (signature) and 3 (well-formed values), and returns the signed digest.
pub fn verify(public: FlamingoTokenPublic, claims: FlamingoTokenClaims, sig: Signature) -> Field {
    if !public.has_aat {
        assert(
            (public.trust_anchor_key_hash == 0)
                & (public.platform == 0)
                & (public.sec_level == 0)
                & (public.sec_meta == 0)
                & (public.authenticator_meta == 0)
                & (public.min_build_version == 0),
            "AAT values must be zero without an AAT",
        );
    }
    let digest = digest(public, claims);
    assert(sig.verify(public.verifier_key, digest), "invalid flamingo token signature");
    digest
}
