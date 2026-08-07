//! WARNING. This library as well as its defining spec are in active development,
//! and extremely WIP. Things may change significantly or even disappear altogether.

pub mod aat;
pub(crate) mod constants;
pub mod takt;
pub(crate) mod utils;

use crate::aat::{AuthenticatorAssertionToken, verify_aat};
use crate::takt::{TrustAnchorKeyToken, verify_takt};

/// Verifies a complete Authenticator Attestation:
/// 1. the TAKT is signed by the Authenticator Provider's `trust_anchor_key`
///    (`BabyJubJub-EdDSA-Poseidon2`), attesting an `assertion_key`, and
/// 2. that attested `assertion_key` signed the AAT (`ES256` over the COSE
///    `Sig_structure`).
///
/// Both tokens must be unexpired at `now`.
///
/// The two tokens are bound *solely* by the shared `assertion_key`.
///
/// # Public inputs
/// `trust_anchor_key_x` / `_y` and `now` are verifier-supplied and MUST be
/// public inputs of the calling circuit. `trust_anchor_key` carries the RP's
/// trust decision (allowlisted from the provider's Authenticator Metadata), and
/// a private `now` would let the prover pick a time at which any token is fresh.
/// Neither can be enforced from inside this library -- see
/// crates/proof/noir/README.md.
///
/// Callers are additionally responsible for binding `aat.nonce` and `aat.cdh`
/// to the surrounding proof, and for exposing whichever of `sec_flags` (via
/// `takt::unpack_sec_flags`) and `aat.authenticator_meta` their RP needs.
pub fn verify_attestation(
    aat: AuthenticatorAssertionToken,
    takt: TrustAnchorKeyToken,
    trust_anchor_key_x: Field,
    trust_anchor_key_y: Field,
    now: Field,
) {
    verify_takt(takt, trust_anchor_key_x, trust_anchor_key_y, now);
    verify_aat(aat, takt.assertion_key_x, takt.assertion_key_y, now);
}

#[test]
fn test_deterministic_attestation() {
    verify_attestation(
        aat::test_deterministic_aat(),
        takt::test_deterministic_takt(),
        takt::TEST_TRUST_ANCHOR_KEY_X,
        takt::TEST_TRUST_ANCHOR_KEY_Y,
        takt::TEST_NOW,
    );
}

#[test(should_fail_with = "invalid AAT signature")]
fn test_aat_key_not_attested() {
    verify_attestation(
        aat::test_deterministic_aat(),
        takt::test_deterministic_takt_unrelated_key(),
        takt::TEST_TRUST_ANCHOR_KEY_X,
        takt::TEST_TRUST_ANCHOR_KEY_Y,
        takt::TEST_NOW,
    );
}

#[test(should_fail_with = "invalid signature")]
fn test_untrusted_trust_anchor_key_rejected() {
    verify_attestation(
        aat::test_deterministic_aat(),
        takt::test_deterministic_takt(),
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203,
        takt::TEST_NOW,
    );
}
