//! The Authenticator Assertion Token (AAT, WIP-106 §3.5): signed with `ES256` by the
//! `assertion_key` over the COSE `Sig_structure`, for a single request.

use super::{AuthenticatorAssertionError, MIN_EXP, Token, check_issuance};
use crate::{
    FieldElement,
    cbor::{self, Fields, Value},
};
use coset::{Header, HeaderBuilder, ProtectedHeader, SignatureContext, iana};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};

/// Maximum remaining lifetime `exp - now` of an AAT, in seconds.
pub const MAX_AAT_LIFETIME_SECS: u32 = 1800;

/// Maximum value of the provider-defined bits of `authenticator_meta` (2 bits).
pub const MAX_PROVIDER_BITS: u8 = 0x3;

/// `eat_profile` claim value (RFC 9711 §4.3.2) of an AAT.
pub const EAT_PROFILE_AAT: &str = "https://world.org/eat/aat/v1";

/// Length in bytes of an AAT's CWT encoding.
const AAT_CWT_LEN: usize = 237;

/// CWT claim keys of an AAT (RFC 8392, RFC 9711, WIP-106).
const CLAIM_AUD: i64 = 3;
const CLAIM_EXP: i64 = 4;
const CLAIM_NONCE: i64 = 10;
const CLAIM_EAT_PROFILE: i64 = 265;
const CLAIM_CDH: i64 = -80_000;
const CLAIM_AUTHENTICATOR_META: i64 = -80_001;

/// User presence the Authenticator reports in an AAT (`authenticator_meta` bits 0-2); values are
/// identifiers, not an order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UserPresence {
    /// Undetermined.
    Undetermined = 0,
    /// User is not present.
    NotPresent = 1,
    /// User is present, verified by a biometric check during this request.
    PresentVerified = 2,
    /// User was present within the last 30 days.
    PresentWithin30Days = 3,
    /// User was present within the last 7 days.
    PresentWithin7Days = 4,
}

impl From<UserPresence> for u8 {
    fn from(presence: UserPresence) -> Self {
        presence as Self
    }
}

impl TryFrom<u8> for UserPresence {
    type Error = AuthenticatorAssertionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Undetermined),
            1 => Ok(Self::NotPresent),
            2 => Ok(Self::PresentVerified),
            3 => Ok(Self::PresentWithin30Days),
            4 => Ok(Self::PresentWithin7Days),
            _ => Err(AuthenticatorAssertionError::InvalidField("user_presence")),
        }
    }
}

/// The AAT's `authenticator_meta`: user presence (bits 0-2) and two provider-defined bits
/// (3-4). Fields are private so every value packs into its own bit range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatorMeta {
    user_presence: UserPresence,
    provider_bits: u8,
}

impl AuthenticatorMeta {
    /// Creates `authenticator_meta`.
    ///
    /// # Errors
    /// [`AuthenticatorAssertionError::InvalidField`] if `provider_bits` carries more than 2 bits.
    pub const fn new(
        user_presence: UserPresence,
        provider_bits: u8,
    ) -> Result<Self, AuthenticatorAssertionError> {
        if provider_bits > MAX_PROVIDER_BITS {
            return Err(AuthenticatorAssertionError::InvalidField("provider_bits"));
        }
        Ok(Self {
            user_presence,
            provider_bits,
        })
    }

    /// User presence the Authenticator reports.
    #[must_use]
    pub const fn user_presence(&self) -> UserPresence {
        self.user_presence
    }

    /// Provider-defined bits; `0` is the nil value.
    #[must_use]
    pub const fn provider_bits(&self) -> u8 {
        self.provider_bits
    }

    /// Packs the sub-fields LSB-first: `user_presence` (bits 0-2), provider bits (3-4).
    #[must_use]
    pub fn pack(&self) -> u8 {
        u8::from(self.user_presence) | (self.provider_bits << 3)
    }

    /// Unpacks `authenticator_meta`.
    ///
    /// # Errors
    /// [`AuthenticatorAssertionError::InvalidField`] if bits 5 and above are set or `user_presence` is reserved.
    pub fn unpack(packed: u8) -> Result<Self, AuthenticatorAssertionError> {
        if packed >> 5 != 0 {
            return Err(AuthenticatorAssertionError::InvalidField(
                "authenticator_meta",
            ));
        }
        Ok(Self {
            user_presence: UserPresence::try_from(packed & 0x7)?,
            provider_bits: packed >> 3,
        })
    }
}

/// The claims of an Authenticator Assertion Token (AAT, WIP-106 §3.5). `Debug` prints none of its
/// values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AatClaims {
    pub(super) aud: u64,
    pub(super) exp: u32,
    pub(super) nonce: FieldElement,
    pub(super) cdh: FieldElement,
    pub(super) authenticator_meta: AuthenticatorMeta,
}

impl AatClaims {
    /// Creates AAT claims for issuance at `now`.
    ///
    /// # Errors
    /// [`AuthenticatorAssertionError::Expired`] if `exp <= now`, [`AuthenticatorAssertionError::LifetimeExceeded`] if
    /// `exp > now + MAX_AAT_LIFETIME_SECS`, and [`AuthenticatorAssertionError::InvalidField`] if `exp < 2^16`.
    pub fn new(
        now: u32,
        aud: u64,
        exp: u32,
        nonce: FieldElement,
        cdh: FieldElement,
        authenticator_meta: AuthenticatorMeta,
    ) -> Result<Self, AuthenticatorAssertionError> {
        check_issuance(now, exp, MAX_AAT_LIFETIME_SECS, Token::Aat)?;
        Ok(Self {
            aud,
            exp,
            nonce,
            cdh,
            authenticator_meta,
        })
    }

    /// The `rpId` of the request.
    #[must_use]
    pub const fn aud(&self) -> u64 {
        self.aud
    }

    /// Expiration as seconds since the Unix epoch.
    #[must_use]
    pub const fn exp(&self) -> u32 {
        self.exp
    }

    /// The nonce of the request.
    #[must_use]
    pub const fn nonce(&self) -> FieldElement {
        self.nonce
    }

    /// The client data hash.
    #[must_use]
    pub const fn cdh(&self) -> FieldElement {
        self.cdh
    }

    /// User presence and provider-defined bits.
    #[must_use]
    pub const fn authenticator_meta(&self) -> AuthenticatorMeta {
        self.authenticator_meta
    }

    /// The CWT claims set.
    fn to_value(self) -> Value {
        // A field element: the packed byte, big-endian.
        let mut meta = [0u8; 32];
        meta[31] = self.authenticator_meta.pack();
        cbor::map(vec![
            (
                CLAIM_AUD.into(),
                Value::Bytes(self.aud.to_be_bytes().to_vec()),
            ),
            (CLAIM_EXP.into(), Value::Integer(self.exp.into())),
            (
                CLAIM_NONCE.into(),
                Value::Bytes(self.nonce.to_be_bytes().to_vec()),
            ),
            (
                CLAIM_EAT_PROFILE.into(),
                Value::Text(EAT_PROFILE_AAT.into()),
            ),
            (
                CLAIM_CDH.into(),
                Value::Bytes(self.cdh.to_be_bytes().to_vec()),
            ),
            (CLAIM_AUTHENTICATOR_META.into(), Value::Bytes(meta.to_vec())),
        ])
    }

    /// The bytes the `assertion_key` signs: the COSE `Sig_structure` (RFC 9052 §4.4) with an
    /// empty `external_aad`.
    fn sig_structure(&self) -> Vec<u8> {
        coset::sig_structure_data(
            SignatureContext::CoseSign1,
            ProtectedHeader {
                original_data: None,
                header: protected(),
            },
            None,
            b"",
            &cbor::encode(&self.to_value()),
        )
    }

    /// Reads the CWT claims set.
    fn from_value(value: Value) -> Result<Self, AuthenticatorAssertionError> {
        let mut claims = Fields::of(value, "AAT claims")?;
        let aud = u64::from_be_bytes(claims.bytes(CLAIM_AUD)?);
        let exp: u32 = claims.uint(CLAIM_EXP)?;
        let nonce = field(&claims.bytes(CLAIM_NONCE)?, "non-canonical nonce")?;
        claims.text(CLAIM_EAT_PROFILE, EAT_PROFILE_AAT)?;
        let cdh = field(&claims.bytes(CLAIM_CDH)?, "non-canonical cdh")?;
        let meta: [u8; 32] = claims.bytes(CLAIM_AUTHENTICATOR_META)?;
        // A field element with bits 5 and above zero.
        if meta[..31].iter().any(|b| *b != 0) {
            return Err(AuthenticatorAssertionError::InvalidField(
                "authenticator_meta",
            ));
        }
        let authenticator_meta = AuthenticatorMeta::unpack(meta[31])?;
        if exp < MIN_EXP {
            return Err(AuthenticatorAssertionError::InvalidField("exp"));
        }
        Ok(Self {
            aud,
            exp,
            nonce,
            cdh,
            authenticator_meta,
        })
    }
}

impl std::fmt::Debug for AatClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AatClaims").finish_non_exhaustive()
    }
}

/// A signed Authenticator Assertion Token (AAT, WIP-106 §3.5). `Debug` prints none of its values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatorAssertionToken {
    claims: AatClaims,
    signature: Signature,
}

impl AuthenticatorAssertionToken {
    /// Signs `claims` with the `assertion_key` (`ES256` over the COSE `Sig_structure`).
    #[must_use]
    pub fn sign(claims: AatClaims, assertion_key: &SigningKey) -> Self {
        let signature = assertion_key.sign(&claims.sig_structure());
        Self { claims, signature }
    }

    /// The claims, unverified. Use [`Self::verify`] to check them.
    #[must_use]
    pub const fn claims(&self) -> &AatClaims {
        &self.claims
    }

    /// The CWT encoding: protected header `{1: -7}`, an empty unprotected header, the claims set
    /// and the `ES256` signature (`r || s`).
    #[must_use]
    pub fn to_cwt(&self) -> Vec<u8> {
        cbor::encode_sign1(
            protected(),
            cbor::encode(&self.claims.to_value()),
            self.signature.to_bytes().to_vec(),
        )
    }

    /// Decodes an AAT from its CWT encoding, rejecting anything but the canonical encoding. Does
    /// not verify the signature.
    ///
    /// # Errors
    /// [`AuthenticatorAssertionError::InvalidEncoding`] on any other encoding, and [`AuthenticatorAssertionError::InvalidField`] for an
    /// out-of-range claim.
    pub fn from_cwt(cwt: &[u8]) -> Result<Self, AuthenticatorAssertionError> {
        let (_, payload, signature) = cbor::decode_sign1(cwt, AAT_CWT_LEN..=AAT_CWT_LEN)?;
        let claims = AatClaims::from_value(payload)?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| AuthenticatorAssertionError::InvalidEncoding("signature"))?;
        let aat = Self { claims, signature };
        // Also covers the protected header, which must be exactly `{1: -7}`.
        if aat.to_cwt() != cwt {
            return Err(AuthenticatorAssertionError::InvalidEncoding(
                "non-canonical CBOR",
            ));
        }
        Ok(aat)
    }

    /// Verifies the AAT under `assertion_key` and returns its claims.
    ///
    /// # Errors
    /// [`AuthenticatorAssertionError::InvalidSignature`] if the signature does not verify.
    pub fn verify(
        &self,
        assertion_key: &VerifyingKey,
    ) -> Result<&AatClaims, AuthenticatorAssertionError> {
        assertion_key
            .verify(&self.claims.sig_structure(), &self.signature)
            .map_err(|_| AuthenticatorAssertionError::InvalidSignature(Token::Aat))?;
        Ok(&self.claims)
    }
}

impl std::fmt::Debug for AuthenticatorAssertionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatorAssertionToken")
            .finish_non_exhaustive()
    }
}

/// The protected header `{1: -7}` (`alg`: `ES256`).
fn protected() -> Header {
    HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .build()
}

/// Reads a canonical field element.
fn field(
    bytes: &[u8; 32],
    name: &'static str,
) -> Result<FieldElement, AuthenticatorAssertionError> {
    FieldElement::from_be_bytes(bytes)
        .map_err(|_| AuthenticatorAssertionError::InvalidEncoding(name))
}
