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

/// The token values a consuming circuit takes as public inputs. The library range-checks every
/// value to its claim width itself, so callers may pass any field element.
pub struct FlamingoTokenPublic {
    pub verifier_key: PublicKey,
    /// 32-bit.
    pub now: Field,
    pub aud: Field,
    pub nonce: Field,
    /// `0` or `1`.
    pub has_aat: Field,
    pub trust_anchor_key_hash: Field,
    /// 8-bit.
    pub platform: Field,
    /// 8-bit.
    pub sec_level: Field,
    /// 4-bit.
    pub sec_meta: Field,
    /// 5-bit; its `user_presence` bits 0-2 are below 5.
    pub authenticator_meta: Field,
    /// 32-bit.
    pub min_build_version: Field,
    pub engine_config_hash: Field,
}

/// The token values a consuming circuit keeps private or fixes itself.
pub struct FlamingoTokenClaims {
    /// `compared_entry_hash_k`, `0` past the last compared entry.
    pub compared_entry_hashes: [Field; MAX_COMPARED],
    /// 32-bit.
    pub compare_sources: Field,
    /// The WIP-107 billing nullifier, or `0` for an RP that is not billed.
    pub billing_nullifier: Field,
}

/// Check 3 (Well-formed values) of WIP-201 §4.7. Range-checks every integer claim here,
/// not through the caller's types.
fn check_well_formed(public: FlamingoTokenPublic, claims: FlamingoTokenClaims) {
    public.now.assert_max_bit_size::<32>();
    assert(public.has_aat * (public.has_aat - 1) == 0, "has_aat must be 0 or 1");
    public.platform.assert_max_bit_size::<8>();
    public.sec_level.assert_max_bit_size::<8>();
    public.sec_meta.assert_max_bit_size::<4>();
    public.authenticator_meta.assert_max_bit_size::<5>();
    assert(((public.authenticator_meta as u8) & 7) < 5, "user_presence values 5 to 7 are reserved");
    public.min_build_version.assert_max_bit_size::<32>();
    claims.compare_sources.assert_max_bit_size::<32>();
    if public.has_aat == 0 {
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
}

/// `aat_flags`: the TAKT's `sec_flags` layout with `min_build_version` in bits 16-47 and
/// `authenticator_meta` in bits 52-56. Assumes the widths [`check_well_formed`] enforces.
fn aat_flags(public: FlamingoTokenPublic) -> Field {
    public.platform
        + 0x100 * public.sec_level
        + 0x10000 * public.min_build_version
        + 0x1000000000000 * public.sec_meta
        + 0x10000000000000 * public.authenticator_meta
}

/// The signed digest (WIP-201 §4.5): `H_16(DS_WIP_201; ...)` over the 13 claims.
pub fn digest(public: FlamingoTokenPublic, claims: FlamingoTokenClaims) -> Field {
    check_well_formed(public, claims);
    let h = claims.compared_entry_hashes;
    permutation::t16([
        DS_WIP_201,
        public.now,
        h[0],
        h[1],
        h[2],
        h[3],
        public.aud,
        public.nonce,
        public.trust_anchor_key_hash,
        aat_flags(public),
        public.has_aat,
        claims.compare_sources,
        public.engine_config_hash,
        claims.billing_nullifier,
        0,
        0,
    ])[1]
}

/// Checks 2 (signature) and 3 (well-formed values), and returns the signed digest.
pub fn verify(public: FlamingoTokenPublic, claims: FlamingoTokenClaims, sig: Signature) -> Field {
    let digest = digest(public, claims);
    assert(sig.verify(public.verifier_key, digest), "invalid flamingo token signature");
    digest
}
