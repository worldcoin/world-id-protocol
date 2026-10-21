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
mod cose;
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
    /// The TAKT's CWT encoding.
    pub takt: Vec<u8>,
    /// The AAT's CWT encoding.
    pub aat: Vec<u8>,
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
    /// Decodes both tokens and verifies their signatures: the TAKT under `trust_anchor_key`, the
    /// AAT under the `assertion_key` it attests.
    fn verified_claims(&self) -> Result<(TaktClaims, AatClaims), VerificationError> {
        let takt = TrustAnchorKeyToken::from_cwt(&self.takt)
            .map_err(|e| VerificationError::Takt(e.into()))?;
        let takt = *takt
            .verify(&self.trust_anchor_key)
            .map_err(VerificationError::Takt)?;
        let aat = AuthenticatorAssertionToken::from_cwt(&self.aat)
            .map_err(|e| VerificationError::Aat(e.into()))?;
        let aat = *aat
            .verify(takt.assertion_key())
            .map_err(VerificationError::Aat)?;
        Ok((takt, aat))
    }

    /// Derives the public inputs a verifier reports from the key and tokens it holds, given the
    /// request values and the RP's minimum. Run [`verify`] on the result.
    ///
    /// # Errors
    /// [`VerificationError::Takt`] or [`VerificationError::Aat`] if a token fails to decode or
    /// verify.
    pub fn public_inputs(
        &self,
        now: u32,
        aud: u64,
        nonce: FieldElement,
        min_build_version: u32,
    ) -> Result<AuthenticatorAssertionPublicInputs, VerificationError> {
        let (takt, aat) = self.verified_claims()?;
        let flags = takt.sec_flags();
        Ok(AuthenticatorAssertionPublicInputs {
            trust_anchor_key_hash: trust_anchor_key_hash(&self.trust_anchor_key),
            now,
            aud,
            nonce,
            platform: flags.platform,
            sec_level: flags.sec_level,
            sec_meta: flags.sec_meta,
            authenticator_meta: aat.authenticator_meta,
            min_build_version,
        })
    }
}

/// Verifies a TAKT and an AAT with every check of WIP-106 §3.8, in the order of the Noir
/// `verify_assertion`.
///
/// # Errors
/// [`VerificationError`] for the first failing check.
pub fn verify(
    public: &AuthenticatorAssertionPublicInputs,
    private: &AuthenticatorAssertionPrivateInputs,
) -> Result<(), VerificationError> {
    if public.nonce == FieldElement::ZERO {
        return Err(VerificationError::ZeroNonce);
    }
    if trust_anchor_key_hash(&private.trust_anchor_key) != public.trust_anchor_key_hash {
        return Err(VerificationError::KeyHashMismatch);
    }
    let (takt, aat) = private.verified_claims()?;
    check_freshness(
        public.now,
        takt.exp,
        MAX_TAKT_LIFETIME_SECS,
        VerificationError::TaktExpired,
        VerificationError::TaktLifetimeExceeded,
    )?;
    check_freshness(
        public.now,
        aat.exp,
        MAX_AAT_LIFETIME_SECS,
        VerificationError::AatExpired,
        VerificationError::AatLifetimeExceeded,
    )?;
    if (aat.aud, aat.nonce, aat.cdh) != (public.aud, public.nonce, private.cdh) {
        return Err(VerificationError::RequestMismatch);
    }
    let flags = takt.sec_flags;
    if (flags.platform, flags.sec_level, flags.sec_meta)
        != (public.platform, public.sec_level, public.sec_meta)
    {
        return Err(VerificationError::SecFlagsMismatch);
    }
    if aat.authenticator_meta != public.authenticator_meta {
        return Err(VerificationError::AuthenticatorMetaMismatch);
    }
    if flags.build_version < public.min_build_version {
        return Err(VerificationError::BuildVersionBelowMinimum);
    }
    Ok(())
}

/// Checks `now < exp <= now + max_lifetime` at issuance, and the fixed `exp` encoding.
const fn check_issuance(now: u32, exp: u32, max_lifetime: u32) -> Result<(), AssertionError> {
    if exp <= now || exp - now > max_lifetime {
        return Err(AssertionError::LifetimeOutOfRange { now, exp });
    }
    if exp < MIN_EXP {
        return Err(AssertionError::ExpirationOutOfRange(exp));
    }
    Ok(())
}

/// Checks `now < exp` and `exp - now <= max_lifetime` at verification.
fn check_freshness(
    now: u32,
    exp: u32,
    max_lifetime: u32,
    expired: VerificationError,
    too_long: VerificationError,
) -> Result<(), VerificationError> {
    if now >= exp {
        return Err(expired);
    }
    if exp - now > max_lifetime {
        return Err(too_long);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
