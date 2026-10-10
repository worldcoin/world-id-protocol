// WIP-201 Flamingo Token Verification (WIP-201 section 3.9).
use super::{components::types::PublicKey, constants::DS_WIP_201, types::FlamingoTokenInputs};
use poseidon2::bn254::permutation;

/// The public values a Flamingo Token is verified against.
pub struct FlamingoTokenPublic {
    pub verifier_key: PublicKey,
    pub now: u32,
    pub aud: Field,
    pub nonce: Field,
    pub has_aat: bool,
    pub authenticator_provider_key_hash: Field,
    pub platform: u8,
    pub sec_level: u8,
    pub sec_meta: u8,
    pub user_presence: u8,
    pub min_build_version: u32,
    pub engine_config_hash: Field,
}

/// `aat_flags`, the WIP-106 `sec_flags` layout with `min_build_version` in place of
/// `build_version`. `sec_meta` and `user_presence` are 3-bit; the types bound the rest.
pub fn aat_flags(public: FlamingoTokenPublic) -> Field {
    assert(public.sec_meta < 8, "sec_meta exceeds 3 bits");
    assert(public.user_presence < 5, "user_presence values 5 to 7 are reserved");
    public.platform as Field
        + 0x100 * public.sec_level as Field
        + 0x10000 * public.min_build_version as Field
        + 0x1000000000000 * public.sec_meta as Field
        + 0x8000000000000 * public.user_presence as Field
}

/// The signed digest: output element 1 of the Poseidon2 t=16 permutation. Without an
/// AAT, `now`, `authenticator_provider_key_hash` and `aat_flags` enter as `0`.
pub fn digest(public: FlamingoTokenPublic, token: FlamingoTokenInputs) -> Field {
    let has_aat = public.has_aat as Field;
    let h = token.compared_entry_hash;
    permutation::t16([
        DS_WIP_201,
        has_aat * public.now as Field,
        h[0],
        h[1],
        h[2],
        h[3],
        public.aud,
        public.nonce,
        has_aat * public.authenticator_provider_key_hash,
        has_aat * aat_flags(public),
        has_aat,
        public.engine_config_hash,
        0,
        0,
        0,
        0,
    ])[1]
}

/// Verifies the Verifier's signature and returns the signed digest.
pub fn verify(public: FlamingoTokenPublic, token: FlamingoTokenInputs) -> Field {
    // As in WIP-106, the AAT values are zero when no AAT was verified.
    if !public.has_aat {
        assert(
            (public.authenticator_provider_key_hash == 0)
                & (public.platform == 0)
                & (public.sec_level == 0)
                & (public.sec_meta == 0)
                & (public.user_presence == 0)
                & (public.min_build_version == 0),
            "AAT values must be zero without an AAT",
        );
    }
    let digest = digest(public, token);
    assert(token.sig.verify(public.verifier_key, digest), "invalid flamingo token signature");
    digest
}
