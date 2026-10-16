//! WARNING. This library as well as its defining spec (WIP-106) are in active development.
//!
//! Verifies an Authenticator Assertion Token (AAT): a token signed by an Authenticator
//! Provider's `authenticator_provider_key` over `H_4(DS_AAT; exp, aat_commitment, sec_flags)`,
//! bound to a request through `aat_commitment = H_8(DS_REQ; aud, nonce, cdh, blind)`.

use eddsa_poseidon2::{
    BabyJubJubPoint, BabyJubJubPointInSubgroup, BabyJubJubScalarFieldElement,
    verify_eddsa_poseidon2,
};
use poseidon2::bn254::permutation;

mod tests;

global DS_AAT: Field = 498451125091886891258088867850510460821031698772; // b"WORLD-ID/WIP-106/AAT"
global DS_REQ: Field = 498451125091886891258088867850510460821032813905; // b"WORLD-ID/WIP-106/REQ"
global DS_KEY: Field = 498451125091886891258088867850510460821032355161; // b"WORLD-ID/WIP-106/KEY"

/// Maximum remaining lifetime `exp - now` of an AAT, in seconds.
pub global MAX_AAT_LIFETIME: Field = 1800;

/// The public inputs of AAT verification (WIP-106 section 3.7). The caller MUST expose every
/// field as a public input of its circuit.
pub struct AuthenticatorAssertionPublicInputs {
    /// `H_3(DS_KEY; x, y)` of the Authenticator Provider's key; the RP checks it against its
    /// allowlist.
    pub authenticator_provider_key_hash: Field,
    /// Current time as seconds since the Unix epoch.
    pub now: Field,
    /// The `rpId` of the request.
    pub aud: Field,
    /// The nonce of the request.
    pub nonce: Field,
    /// Platform of the Authenticator.
    pub platform: u8,
    /// Class of integrity evidence verified for the request.
    pub sec_level: u8,
    /// Provider-defined 3-bit bitmask.
    pub sec_meta: u8,
    /// User presence signed by the Authenticator Provider.
    pub user_presence: u8,
    /// Minimum `build_version` the RP accepts.
    pub min_build_version: u32,
}

/// The private inputs of AAT verification (WIP-106 section 3.7): the signing key, the token
/// and the opening of its request commitment. `aat_commitment` is recomputed, not passed. How
/// `cdh` is bound to the surrounding proof is the caller's obligation.
pub struct AuthenticatorAssertionPrivateInputs {
    /// The key that signed the AAT (affine x, y).
    pub authenticator_provider_key: [Field; 2],
    /// Expiration as seconds since the Unix epoch.
    pub exp: Field,
    /// Packed security attributes.
    pub sec_flags: Field,
    /// EdDSA signature scalar component.
    pub sig_s: Field,
    /// EdDSA signature point component (affine x, y).
    pub sig_r: [Field; 2],
    /// Client data hash binding the AAT to its upstream use; `0` is nil.
    pub cdh: Field,
    /// Blinding factor of the request commitment.
    pub blind: Field,
}

/// Verifies an AAT against the public inputs.
pub fn verify_aat(
    public: AuthenticatorAssertionPublicInputs,
    private: AuthenticatorAssertionPrivateInputs,
) {
    assert(public.nonce != 0, "nonce must not be 0");

    let key = private.authenticator_provider_key;
    assert(
        permutation::t3([DS_KEY, key[0], key[1]])[1] == public.authenticator_provider_key_hash,
        "authenticator_provider_key does not match its hash",
    );

    let aat_commitment = request_commitment(public.aud, public.nonce, private.cdh, private.blind);
    let message = permutation::t4([DS_AAT, private.exp, aat_commitment, private.sec_flags])[1];
    let is_valid = verify_eddsa_poseidon2(
        BabyJubJubPointInSubgroup::new(key[0], key[1]),
        BabyJubJubScalarFieldElement::new(private.sig_s),
        BabyJubJubPoint::new(private.sig_r[0], private.sig_r[1]),
        message,
    );
    assert(is_valid, "invalid signature");

    assert_fresh(private.exp, public.now);
    let build_version = assert_sec_flags(
        private.sec_flags,
        public.platform,
        public.sec_level,
        public.sec_meta,
        public.user_presence,
    );
    assert(build_version >= public.min_build_version, "build_version below minimum");
}

fn request_commitment(aud: Field, nonce: Field, cdh: Field, blind: Field) -> Field {
    permutation::t8([DS_REQ, aud, nonce, cdh, blind, 0, 0, 0])[1]
}

/// Asserts `now < exp` and `exp - now <= MAX_AAT_LIFETIME`, with both below 2^32.
fn assert_fresh(exp: Field, now: Field) {
    exp.assert_max_bit_size::<32>();
    now.assert_max_bit_size::<32>();
    assert(std::field::bn254::lt(now, exp), "token is expired");
    // Both are below 2^32, so `now + MAX_AAT_LIFETIME + 1` can not wrap.
    assert(
        std::field::bn254::lt(exp, now + MAX_AAT_LIFETIME + 1),
        "token lifetime exceeds maximum",
    );
}

/// Asserts `sec_flags < 2^54` and that it packs LSB-first `platform` (bits 0-7), `sec_level`
/// (8-15), `build_version` (16-47), `sec_meta` (48-50) and `user_presence` (51-53), with
/// `user_presence < 5`. Returns `build_version`, which must stay private.
fn assert_sec_flags(
    sec_flags: Field,
    platform: u8,
    sec_level: u8,
    sec_meta: u8,
    user_presence: u8,
) -> u32 {
    // Constrains `sec_flags < 2^56`; `bytes[0]` holds bits 48-55.
    let bytes: [u8; 7] = sec_flags.to_be_bytes();
    assert(bytes[0] < 64, "sec_flags bits 54 and above are reserved and must be 0");
    assert(user_presence < 5, "user_presence values 5 to 7 are reserved");
    assert(
        (bytes[6] == platform)
            & (bytes[5] == sec_level)
            & ((bytes[0] & 7) == sec_meta)
            & ((bytes[0] >> 3) == user_presence),
        "sec_flags do not match the public security flags",
    );
    Field::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u32
}
