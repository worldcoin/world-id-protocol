//! Errors of WIP-106 Authenticator Assertions, one type per stage:
//!
//! - [`AssertionError`]: building or decoding a TAKT or an AAT, without any key.
//! - [`TokenError`]: verifying one token's `kid` and signature.
//! - [`VerificationError`]: the full WIP-106 §3.8 check; wraps a [`TokenError`] per token and
//!   adds the checks across both tokens and the public inputs.

/// Errors when building or decoding a TAKT or an AAT.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AssertionError {
    /// `sec_meta` exceeds the 4-bit limit.
    #[error("sec_meta must carry at most 4 bits of data, got {0:#b}")]
    SecMetaTooLarge(u8),
    /// `exp` can not use the fixed 4-byte CBOR uint encoding.
    #[error("exp {0} must be in [2^16, 2^32) for its fixed-width encoding")]
    ExpirationOutOfRange(u32),
    /// `exp` is not in `(now, now + max_lifetime]` at issuance.
    #[error("exp {exp} must be in (now, now + max lifetime] at issuance, now is {now}")]
    LifetimeOutOfRange {
        /// Issuance time as seconds since the Unix epoch.
        now: u32,
        /// The requested expiration.
        exp: u32,
    },
    /// A TAKT's `exp` is later than the `not_after` of the `trust_anchor_key` that signs it.
    #[error("exp {exp} must not be later than the trust_anchor_key's not_after {not_after}")]
    ExpirationAfterKeyValidity {
        /// The requested expiration.
        exp: u32,
        /// End of the `trust_anchor_key`'s validity window.
        not_after: u32,
    },
    /// `sec_flags` has reserved bits set. Carries no value, as `sec_flags` holds the private
    /// `build_version`.
    #[error("sec_flags bits 52 and above are reserved")]
    InvalidSecFlags,
    /// `user_presence` is a reserved value.
    #[error("user_presence values 5 and above are reserved, got {0}")]
    ReservedPresence(u8),
    /// The provider bits of `authenticator_meta` exceed the 2-bit limit.
    #[error("authenticator_meta provider bits must carry at most 2 bits, got {0:#b}")]
    ProviderBitsTooLarge(u8),
    /// `authenticator_meta` has bits 5 and above set.
    #[error("authenticator_meta bits 5 and above are reserved")]
    InvalidAuthenticatorMeta,
    /// The bytes are not the canonical CWT encoding of the token.
    #[error("not a canonical encoding: {0}")]
    InvalidEncoding(&'static str),
    /// Key or signature material could not be encoded.
    #[error("invalid key material: {0}")]
    KeyEncoding(String),
}

/// Why a single token failed to verify.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    /// The TAKT's `kid` is not the key it is verified under.
    #[error("kid is not the verifying key")]
    KidMismatch,
    /// The signature does not verify.
    #[error("invalid signature")]
    Signature,
}

/// Why verification failed. One variant per WIP-106 §3.8 check; carries no private value.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerificationError {
    /// The request nonce is `0`.
    #[error("nonce must not be 0")]
    ZeroNonce,
    /// The `trust_anchor_key` does not hash to `trust_anchor_key_hash`.
    #[error("trust_anchor_key does not match its hash")]
    KeyHashMismatch,
    /// The TAKT is not canonical, or its signature does not verify under `trust_anchor_key`.
    #[error("invalid TAKT: {0}")]
    Takt(TokenError),
    /// The AAT is not canonical, or its signature does not verify under the attested key.
    #[error("invalid AAT: {0}")]
    Aat(TokenError),
    /// `now >= exp` for the TAKT.
    #[error("TAKT is expired")]
    TaktExpired,
    /// `exp - now > MAX_TAKT_LIFETIME_SECS` for the TAKT.
    #[error("TAKT lifetime exceeds maximum")]
    TaktLifetimeExceeded,
    /// `now >= exp` for the AAT.
    #[error("AAT is expired")]
    AatExpired,
    /// `exp - now > MAX_AAT_LIFETIME_SECS` for the AAT.
    #[error("AAT lifetime exceeds maximum")]
    AatLifetimeExceeded,
    /// The AAT's `aud`, `nonce` or `cdh` differs from the input.
    #[error("AAT is not bound to this request")]
    RequestMismatch,
    /// The TAKT's `platform`, `sec_level` or `sec_meta` differs from the public input.
    #[error("sec_flags do not match the public security flags")]
    SecFlagsMismatch,
    /// The AAT's `authenticator_meta` differs from the public input.
    #[error("authenticator_meta does not match the public input")]
    AuthenticatorMetaMismatch,
    /// `build_version < min_build_version`.
    #[error("build_version below minimum")]
    BuildVersionBelowMinimum,
}
