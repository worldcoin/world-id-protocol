// WIP-201 Flamingo Token signature check (WIP-201 §4.7 Consuming Flamingo Tokens, check 2).
use super::constants::{COMPARE_SOURCES, DS_WIP_201, MAX_COMPARED};
use poseidon2::bn254::permutation;
use world_id_components::types::{PublicKey, Signature};

/// The public values a Flamingo Token is verified against.
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
    pub engine_config_hash: Field,
}

/// `aat_flags` with `min_build_version` 0 in bits 16-47, since WIP-202 fixes it to 0.
pub fn aat_flags(public: FlamingoTokenPublic) -> Field {
    assert(public.sec_meta < 16, "sec_meta exceeds 4 bits");
    assert(public.authenticator_meta < 32, "authenticator_meta exceeds 5 bits");
    assert((public.authenticator_meta & 7) < 5, "user_presence values 5 to 7 are reserved");
    public.platform as Field
        + 0x100 * public.sec_level as Field
        + 0x1000000000000 * public.sec_meta as Field
        + 0x10000000000000 * public.authenticator_meta as Field
}

/// The signed digest (WIP-201 §4.5): output element 1 of the Poseidon2 t=16 permutation.
/// Without an AAT, `trust_anchor_key_hash` and `aat_flags` enter as `0`.
pub fn digest(public: FlamingoTokenPublic, h: [Field; MAX_COMPARED]) -> Field {
    let has_aat = public.has_aat as Field;
    permutation::t16([
        DS_WIP_201,
        public.now as Field,
        h[0],
        h[1],
        h[2],
        h[3],
        public.aud,
        public.nonce,
        has_aat * public.trust_anchor_key_hash,
        has_aat * aat_flags(public),
        has_aat,
        COMPARE_SOURCES as Field,
        public.engine_config_hash,
        0,
        0,
        0,
    ])[1]
}

/// Verifies the Verifier's signature over `compared` and returns the signed digest.
pub fn verify(
    public: FlamingoTokenPublic,
    compared: [Field; MAX_COMPARED],
    sig: Signature,
) -> Field {
    // Check 2 requires the AAT values to be zero when no AAT was verified.
    if !public.has_aat {
        assert(
            (public.trust_anchor_key_hash == 0)
                & (public.platform == 0)
                & (public.sec_level == 0)
                & (public.sec_meta == 0)
                & (public.authenticator_meta == 0),
            "AAT values must be zero without an AAT",
        );
    }
    let digest = digest(public, compared);
    assert(sig.verify(public.verifier_key, digest), "invalid flamingo token signature");
    digest
}
