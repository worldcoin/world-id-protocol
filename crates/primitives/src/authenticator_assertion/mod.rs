//! Authenticator Assertions (WIP-106).
//!
//! A Trust Anchor Key Token (TAKT) is signed by an Authenticator Provider's `trust_anchor_key`
//! (`BabyJubJub-EdDSA-Poseidon2`) and attests a device-bound `assertion_key`. An Authenticator
//! Assertion Token (AAT) is signed by that `assertion_key` (`ES256`) for a single request. Both are
//! CWTs in deterministic CBOR.
//!
//! `verify` performs every check of WIP-106 §3.8 on `AuthenticatorAssertionPublicInputs` and
//! `AuthenticatorAssertionPrivateInputs`, the same split as the Noir `verify_assertion`.

use crate::FieldElement;
use eddsa_babyjubjub::EdDSAPublicKey;

mod aat;
mod error;
mod takt;

pub use aat::*;
pub use error::*;
pub use takt::*;

/// Smallest `exp` whose deterministic CBOR encoding is a 4-byte uint.
const MIN_EXP: u32 = 1 << 16;

/// The public inputs of WIP-106 §3.8 verification. A verifier reveals only these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatorAssertionPublicInputs {
    /// Hash of the Authenticator Provider's key, see [`trust_anchor_key_hash`]; the RP checks it
    /// against its allowlist.
    pub trust_anchor_key_hash: FieldElement,
    /// Current time as seconds since the Unix epoch.
    pub now: u32,
    /// The `rpId` of the request.
    pub aud: u64,
    /// The nonce of the request.
    pub nonce: FieldElement,
    /// Platform of the Authenticator (see [`Platform`]).
    pub platform: u8,
    /// Class of integrity evidence verified at TAKT issuance (see [`SecLevel`]).
    pub sec_level: u8,
    /// Provider-defined 4-bit bitmask.
    pub sec_meta: u8,
    /// User presence and provider-defined bits the Authenticator reports.
    pub authenticator_meta: AuthenticatorMeta,
    /// Minimum `build_version` the RP accepts.
    pub min_build_version: u32,
}

/// The private inputs of WIP-106 §3.8 verification. A verifier MUST keep them confidential;
/// `Debug` prints none of them.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatorAssertionPrivateInputs {
    /// The key that signed the TAKT.
    pub trust_anchor_key: EdDSAPublicKey,
    /// The TAKT, decoded with [`TrustAnchorKeyToken::from_cwt`].
    pub takt: TrustAnchorKeyToken,
    /// The AAT, decoded with [`AuthenticatorAssertionToken::from_cwt`].
    pub aat: AuthenticatorAssertionToken,
    /// Client data hash, computed by the verifier as the consuming specification defines.
    pub cdh: FieldElement,
}

impl std::fmt::Debug for AuthenticatorAssertionPrivateInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatorAssertionPrivateInputs")
            .finish_non_exhaustive()
    }
}

impl AuthenticatorAssertionPrivateInputs {
    /// Derives the public inputs a verifier reports from the key and the tokens' claims, given
    /// the request values and the RP's minimum. Reads the claims unverified; run [`verify`] on
    /// the result.
    #[must_use]
    pub fn public_inputs(
        &self,
        now: u32,
        aud: u64,
        nonce: FieldElement,
        min_build_version: u32,
    ) -> AuthenticatorAssertionPublicInputs {
        let flags = self.takt.claims().sec_flags();
        AuthenticatorAssertionPublicInputs {
            trust_anchor_key_hash: trust_anchor_key_hash(&self.trust_anchor_key),
            now,
            aud,
            nonce,
            platform: flags.platform,
            sec_level: flags.sec_level,
            sec_meta: flags.sec_meta,
            authenticator_meta: self.aat.claims().authenticator_meta,
            min_build_version,
        }
    }
}

/// Verifies a TAKT and an AAT with every check of WIP-106 §3.8, in the order of the Noir
/// `verify_assertion`.
///
/// # Errors
/// [`AuthenticatorAssertionError`] for the first failing check.
pub fn verify(
    public: &AuthenticatorAssertionPublicInputs,
    private: &AuthenticatorAssertionPrivateInputs,
) -> Result<(), AuthenticatorAssertionError> {
    if public.nonce == FieldElement::ZERO {
        return Err(AuthenticatorAssertionError::InvalidField("nonce"));
    }
    if trust_anchor_key_hash(&private.trust_anchor_key) != public.trust_anchor_key_hash {
        return Err(AuthenticatorAssertionError::KeyMismatch);
    }
    let takt = private.takt.verify(&private.trust_anchor_key)?;
    let aat = private.aat.verify(takt.assertion_key())?;
    check_lifetime(public.now, takt.exp, MAX_TAKT_LIFETIME_SECS, Token::Takt)?;
    check_lifetime(public.now, aat.exp, MAX_AAT_LIFETIME_SECS, Token::Aat)?;
    if (aat.aud, aat.nonce, aat.cdh) != (public.aud, public.nonce, private.cdh) {
        return Err(AuthenticatorAssertionError::Mismatch("request"));
    }
    let flags = takt.sec_flags;
    if (flags.platform, flags.sec_level, flags.sec_meta)
        != (public.platform, public.sec_level, public.sec_meta)
    {
        return Err(AuthenticatorAssertionError::Mismatch("sec_flags"));
    }
    if aat.authenticator_meta != public.authenticator_meta {
        return Err(AuthenticatorAssertionError::Mismatch("authenticator_meta"));
    }
    if flags.build_version < public.min_build_version {
        return Err(AuthenticatorAssertionError::BuildVersionBelowMinimum);
    }
    Ok(())
}

/// Checks `now < exp <= now + max_lifetime` at issuance, and the fixed `exp` encoding.
const fn check_issuance(
    now: u32,
    exp: u32,
    max_lifetime: u32,
    token: Token,
) -> Result<(), AuthenticatorAssertionError> {
    if let Err(e) = check_lifetime(now, exp, max_lifetime, token) {
        return Err(e);
    }
    if exp < MIN_EXP {
        return Err(AuthenticatorAssertionError::InvalidField("exp"));
    }
    Ok(())
}

/// Checks `now < exp <= now + max_lifetime`.
const fn check_lifetime(
    now: u32,
    exp: u32,
    max_lifetime: u32,
    token: Token,
) -> Result<(), AuthenticatorAssertionError> {
    if now >= exp {
        return Err(AuthenticatorAssertionError::Expired(token));
    }
    if exp - now > max_lifetime {
        return Err(AuthenticatorAssertionError::LifetimeExceeded(token));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
