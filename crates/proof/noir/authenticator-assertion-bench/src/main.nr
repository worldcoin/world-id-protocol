use authenticator_assertion::aat::AuthenticatorAssertionToken;
use authenticator_assertion::takt::TrustAnchorKeyToken;
use authenticator_assertion::verify_attestation;

/// Verifies a WIP-106 attestation, binding every caller obligation from
/// crates/proof/noir/README.md as a public input.
fn main(
    trust_anchor_key_x: pub Field,
    trust_anchor_key_y: pub Field,
    now: pub Field,
    aud: pub Field,
    nonce: pub Field,
    cdh: pub Field,
    authenticator_meta: pub Field,
    sec_flags: pub Field,
    aat: AuthenticatorAssertionToken,
    takt: TrustAnchorKeyToken,
) {
    assert_eq(aat.aud, aud, "aud mismatch");
    assert_eq(aat.nonce, nonce, "nonce mismatch");
    assert_eq(aat.cdh, cdh, "cdh mismatch");
    assert_eq(aat.authenticator_meta, authenticator_meta, "authenticator_meta mismatch");
    assert_eq(takt.sec_flags, sec_flags, "sec_flags mismatch");

    verify_attestation(aat, takt, trust_anchor_key_x, trust_anchor_key_y, now);
}
