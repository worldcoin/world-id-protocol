//! The error of WIP-106 Authenticator Assertions. No variant carries a token value, as a verifier
//! MUST keep them confidential.

/// The token an error is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    /// The Trust Anchor Key Token.
    Takt,
    /// The Authenticator Assertion Token.
    Aat,
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Takt => "TAKT",
            Self::Aat => "AAT",
        })
    }
}

/// Why building, decoding or verifying a TAKT or an AAT failed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthenticatorAssertionError {
    /// Not the canonical CWT encoding, or unusable key material.
    #[error("invalid encoding: {0}")]
    InvalidEncoding(&'static str),
    /// A value is out of range or sets reserved bits.
    #[error("invalid {0}")]
    InvalidField(&'static str),
    /// The `trust_anchor_key` does not match `trust_anchor_key_hash` or the TAKT's `kid`.
    #[error("trust_anchor_key does not match its hash or the TAKT's kid")]
    KeyMismatch,
    /// The token's signature does not verify.
    #[error("invalid {0} signature")]
    InvalidSignature(Token),
    /// `now >= exp`.
    #[error("{0} is expired")]
    Expired(Token),
    /// `exp - now` exceeds the token's maximum lifetime, or a TAKT's `exp` is later than its
    /// key's `not_after`.
    #[error("{0} lifetime exceeds maximum")]
    LifetimeExceeded(Token),
    /// A public input differs from the signed claims: `request` (`aud`, `nonce`, `cdh`),
    /// `sec_flags` or `authenticator_meta`.
    #[error("{0} does not match the signed claims")]
    Mismatch(&'static str),
    /// `build_version < min_build_version`.
    #[error("build_version below minimum")]
    BuildVersionBelowMinimum,
}
