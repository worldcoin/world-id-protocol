use authenticator_assertion::aat::AuthenticatorAssertionToken;
use authenticator_assertion::takt::TrustAnchorKeyToken;
use authenticator_assertion::verify_attestation;

/// Verifies a WIP-106 Authenticator Attestation (TAKT + AAT pair) and binds
/// every claim a consumer circuit is obliged to expose (see
/// crates/proof/noir/README.md).
///
/// `trust_anchor_key_x` / `_y` carry the RP's trust decision and `now` the
/// verifier-supplied Unix time; both MUST be public. The remaining public
/// inputs surface the token claims the library cannot enforce from inside:
/// `aud`, `nonce` and `cdh` bind the AAT to the surrounding request, and
/// `authenticator_meta` / `sec_flags` expose the integrity metadata for the
/// RP's own rules.
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
