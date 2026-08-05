// The WIP-106 Authenticator Attestation: the pair of tokens that together
// prove a World ID proof was produced in an environment the Authenticator
// Provider vouches for. This is the only entrypoint consumers can reach.
use super::aat::{AuthenticatorAssertionToken, verify_aat};
use super::takt::{TrustAnchorKeyToken, verify_takt};

/// Verifies a complete Authenticator Attestation:
/// 1. the TAKT is signed by the Authenticator Provider's `trust_anchor_key`
///    (`BabyJubJub-EdDSA-Poseidon2`), attesting an `assertion_key`, and
/// 2. that attested `assertion_key` signed the AAT (`ES256` over the COSE
///    `Sig_structure`).
///
/// Both tokens must be unexpired at `now`.
///
/// The two tokens are bound *solely* by the shared `assertion_key`: the TAKT
/// travels in the AAT's `COSE_Sign1` unprotected header and so is not covered by
/// the AAT signature. That binding is enforced here by construction -- the key
/// handed to `verify_aat` is read from the TAKT this function just verified, and
/// there is no other way to supply it. `verify_takt` and `verify_aat` are
/// crate-private for exactly this reason: neither half proves anything alone.
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
        super::aat::test_deterministic_aat(),
        super::takt::test_deterministic_takt(),
        super::takt::TEST_TRUST_ANCHOR_KEY_X,
        super::takt::TEST_TRUST_ANCHOR_KEY_Y,
        super::takt::TEST_NOW,
    );
}

#[test(should_fail_with = "invalid AAT signature")]
fn test_aat_key_not_attested() {
    // A TAKT that is itself valid, but attests an unrelated assertion key, must
    // not verify this AAT: the ES256 key comes from the TAKT, so swapping the
    // TAKT swaps the key the AAT is checked against.
    verify_attestation(
        super::aat::test_deterministic_aat(),
        super::takt::test_deterministic_takt_unrelated_key(),
        super::takt::TEST_TRUST_ANCHOR_KEY_X,
        super::takt::TEST_TRUST_ANCHOR_KEY_Y,
        super::takt::TEST_NOW,
    );
}

#[test(should_fail_with = "invalid signature")]
fn test_untrusted_trust_anchor_key_rejected() {
    // The verifier's key is what the whole chain rests on: a TAKT signed by
    // anyone else must not verify, even though every claim in it is well formed.
    // Checked against the BabyJubJub prime-order subgroup generator, so the
    // failure is the signature check and not a point validity assert.
    verify_attestation(
        super::aat::test_deterministic_aat(),
        super::takt::test_deterministic_takt(),
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203,
        super::takt::TEST_NOW,
    );
}
