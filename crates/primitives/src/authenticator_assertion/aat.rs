//! The Authenticator Assertion Token (AAT, WIP-106 §3.5): signed with `ES256` by the
//! `assertion_key` over the COSE `Sig_structure`, for a single request.

use super::{
    AssertionError, MIN_EXP, TokenError, bstr_header, check_issuance, encode_sign1, open_sign1,
};
use crate::FieldElement;
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

/// Length in bytes of the AAT claims set.
const AAT_PAYLOAD_LEN: usize = 163;

/// AAT protected header `{1: -7}`.
const AAT_PROTECTED: [u8; 3] = [
    0xa1, // map(1)
    0x01, 0x26, // alg (1): -7
];

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
    type Error = AssertionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Undetermined),
            1 => Ok(Self::NotPresent),
            2 => Ok(Self::PresentVerified),
            3 => Ok(Self::PresentWithin30Days),
            4 => Ok(Self::PresentWithin7Days),
            _ => Err(AssertionError::ReservedPresence(value)),
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
    /// [`AssertionError::ProviderBitsTooLarge`] if `provider_bits` carries more than 2 bits.
    pub const fn new(
        user_presence: UserPresence,
        provider_bits: u8,
    ) -> Result<Self, AssertionError> {
        if provider_bits > MAX_PROVIDER_BITS {
            return Err(AssertionError::ProviderBitsTooLarge(provider_bits));
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
    /// [`AssertionError::InvalidAuthenticatorMeta`] if bits 5 and above are set, and
    /// [`AssertionError::ReservedPresence`] for a reserved user presence.
    pub fn unpack(packed: u8) -> Result<Self, AssertionError> {
        if packed >> 5 != 0 {
            return Err(AssertionError::InvalidAuthenticatorMeta);
        }
        Ok(Self {
            user_presence: UserPresence::try_from(packed & 0x7)?,
            provider_bits: packed >> 3,
        })
    }

    /// The claim value, a field element.
    fn to_field_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[31] = self.pack();
        out
    }
}

/// The COSE `Sig_structure` (RFC 9052 §4.4) with an empty `external_aad`.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    // array(4), context: text(10) "Signature1"
    let mut out = vec![0x84, 0x6a];
    out.extend_from_slice(b"Signature1");
    out.extend(bstr_header(protected.len()));
    out.extend_from_slice(protected);
    // external_aad: bstr(0)
    out.push(0x40);
    out.extend(bstr_header(payload.len()));
    out.extend_from_slice(payload);
    out
}

/// An Authenticator Assertion Token (AAT, WIP-106 §3.5), before signing. `Debug` prints none of
/// its values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatorAssertionToken {
    pub(super) aud: u64,
    pub(super) exp: u32,
    pub(super) nonce: FieldElement,
    pub(super) cdh: FieldElement,
    pub(super) authenticator_meta: AuthenticatorMeta,
}

impl AuthenticatorAssertionToken {
    /// Creates an AAT for issuance at `now`.
    ///
    /// # Errors
    /// [`AssertionError::LifetimeOutOfRange`] unless `now < exp <= now + MAX_AAT_LIFETIME_SECS`,
    /// and [`AssertionError::ExpirationOutOfRange`] if `exp < 2^16`.
    pub fn new(
        now: u32,
        aud: u64,
        exp: u32,
        nonce: FieldElement,
        cdh: FieldElement,
        authenticator_meta: AuthenticatorMeta,
    ) -> Result<Self, AssertionError> {
        check_issuance(now, exp, MAX_AAT_LIFETIME_SECS)?;
        Ok(Self {
            aud,
            exp,
            nonce,
            cdh,
            authenticator_meta,
        })
    }

    /// Expiration as seconds since the Unix epoch.
    #[must_use]
    pub const fn exp(&self) -> u32 {
        self.exp
    }

    /// User presence and provider-defined bits.
    #[must_use]
    pub const fn authenticator_meta(&self) -> AuthenticatorMeta {
        self.authenticator_meta
    }

    /// Signs the AAT with the `assertion_key` and returns its CWT encoding.
    #[must_use]
    pub fn sign(&self, assertion_key: &SigningKey) -> Vec<u8> {
        let payload = self.payload();
        let signature: Signature = assertion_key.sign(&sig_structure(&AAT_PROTECTED, &payload));
        encode_sign1(
            &AAT_PROTECTED,
            &[0xa0],
            &payload,
            &signature.to_bytes().into(),
        )
    }

    /// Decodes an AAT and verifies its signature under `assertion_key`.
    ///
    /// # Errors
    /// [`TokenError::Encoding`] on any encoding but the canonical one; [`TokenError::Signature`]
    /// if the signature does not verify.
    pub fn verify(cwt: &[u8], assertion_key: &VerifyingKey) -> Result<Self, TokenError> {
        let (payload, signature) = open_sign1(cwt, &AAT_PROTECTED, AAT_PAYLOAD_LEN)?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| AssertionError::InvalidEncoding("signature"))?;
        let field = |range: std::ops::Range<usize>, name| {
            FieldElement::from_be_bytes(payload[range].try_into().expect("32 bytes"))
                .map_err(|_| AssertionError::InvalidEncoding(name))
        };
        let aud = u64::from_be_bytes(payload[3..11].try_into().expect("8 bytes"));
        let exp = u32::from_be_bytes(payload[13..17].try_into().expect("4 bytes"));
        let nonce = field(20..52, "non-canonical nonce")?;
        let cdh = field(92..124, "non-canonical cdh")?;
        if payload[131..162].iter().any(|b| *b != 0) {
            return Err(AssertionError::InvalidAuthenticatorMeta.into());
        }
        let authenticator_meta = AuthenticatorMeta::unpack(payload[162])?;
        if exp < MIN_EXP {
            return Err(AssertionError::ExpirationOutOfRange(exp).into());
        }
        let aat = Self {
            aud,
            exp,
            nonce,
            cdh,
            authenticator_meta,
        };
        if aat.payload() != payload {
            return Err(AssertionError::InvalidEncoding("AAT claims").into());
        }
        assertion_key
            .verify(&sig_structure(&AAT_PROTECTED, payload), &signature)
            .map_err(|_| TokenError::Signature)?;
        Ok(aat)
    }

    /// The CWT claims set in deterministic CBOR.
    fn payload(&self) -> [u8; AAT_PAYLOAD_LEN] {
        let mut out = [0u8; AAT_PAYLOAD_LEN];
        // map(6), aud (3): bstr(8)
        out[..3].copy_from_slice(&[0xa6, 0x03, 0x48]);
        out[3..11].copy_from_slice(&self.aud.to_be_bytes());
        // exp (4): uint32
        out[11..13].copy_from_slice(&[0x04, 0x1a]);
        out[13..17].copy_from_slice(&self.exp.to_be_bytes());
        // nonce (10): bstr(32)
        out[17..20].copy_from_slice(&[0x0a, 0x58, 0x20]);
        out[20..52].copy_from_slice(&self.nonce.to_be_bytes());
        // eat_profile (265): text(28)
        out[52..57].copy_from_slice(&[0x19, 0x01, 0x09, 0x78, 0x1c]);
        out[57..85].copy_from_slice(EAT_PROFILE_AAT.as_bytes());
        // cdh (-80000): bstr(32)
        out[85..92].copy_from_slice(&[0x3a, 0x00, 0x01, 0x38, 0x7f, 0x58, 0x20]);
        out[92..124].copy_from_slice(&self.cdh.to_be_bytes());
        // authenticator_meta (-80001): bstr(32)
        out[124..131].copy_from_slice(&[0x3a, 0x00, 0x01, 0x38, 0x80, 0x58, 0x20]);
        out[131..].copy_from_slice(&self.authenticator_meta.to_field_bytes());
        out
    }
}

impl std::fmt::Debug for AuthenticatorAssertionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatorAssertionToken")
            .finish_non_exhaustive()
    }
}
