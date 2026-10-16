//! Authenticator Assertions (WIP-106).
//!
//! A Trust Anchor Key Token (TAKT) is signed by an Authenticator Provider's `trust_anchor_key`
//! (`BabyJubJub-EdDSA-Poseidon2`) and attests a device-bound `assertion_key`. An Authenticator
//! Assertion Token (AAT) is signed by that `assertion_key` (`ES256`) for a single request. Both are
//! CWTs in a fixed deterministic CBOR layout.
//!
//! `verify` performs every check of WIP-106 §3.8 on `AuthenticatorAssertionPublicInputs` and
//! `AuthenticatorAssertionPrivateInputs`, the same split as the Noir `verify_assertion`.

use crate::{
    FieldElement,
    poseidon::{self, ds},
};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};

/// Maximum remaining lifetime `exp - now` of a TAKT, in seconds.
pub const MAX_TAKT_LIFETIME_SECS: u32 = 2_592_000;

/// Maximum remaining lifetime `exp - now` of an AAT, in seconds.
pub const MAX_AAT_LIFETIME_SECS: u32 = 1800;

/// Maximum value of `sec_meta` (4-bit bitmask).
pub const MAX_SEC_META: u8 = 0xF;

/// Maximum value of the provider-defined bits of `authenticator_meta` (2 bits).
pub const MAX_PROVIDER_BITS: u8 = 0x3;

/// `eat_profile` claim value (RFC 9711 §4.3.2) of a TAKT.
pub const EAT_PROFILE_TAKT: &str = "https://world.org/eat/takt/v1";

/// `eat_profile` claim value (RFC 9711 §4.3.2) of an AAT.
pub const EAT_PROFILE_AAT: &str = "https://world.org/eat/aat/v1";

/// Smallest `exp` whose deterministic CBOR encoding is a 4-byte uint.
const MIN_EXP: u32 = 1 << 16;

/// Length in bytes of the TAKT claims set.
const TAKT_PAYLOAD_LEN: usize = 133;

/// Length in bytes of the AAT claims set.
const AAT_PAYLOAD_LEN: usize = 163;

/// COSE algorithm identifier for `BabyJubJub-EdDSA-Poseidon2` over a TAKT (WIP-106).
pub const COSE_ALG_TAKT: i64 = -65537;

/// Prefix of the TAKT protected header `{1: -65537, 4: kid}`, followed by the 32-byte `kid`.
const TAKT_PROTECTED_PREFIX: [u8; 10] =
    [0xa2, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x04, 0x58, 0x20];

/// AAT protected header `{1: -7}`.
const AAT_PROTECTED: [u8; 3] = [0xa1, 0x01, 0x26];

/// Platform of the Authenticator.
///
/// The known identifiers; `sec_flags` carries the raw byte so unknown values pass through to
/// the RP's allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Platform {
    /// Unspecified, cannot be determined.
    Unspecified = 0,
    /// iOS.
    Ios = 2,
    /// Android.
    Android = 4,
    /// Web browser.
    Web = 6,
}

impl From<Platform> for u8 {
    fn from(platform: Platform) -> Self {
        platform as Self
    }
}

/// Where the `assertion_key` is generated and stored.
///
/// The known identifiers, not a trust ranking; `sec_flags` carries the raw byte so unknown
/// values pass through to the RP's allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecLevel {
    /// Unspecified, cannot be determined.
    Unspecified = 0,
    /// Hardware-bound key attested by the platform manufacturer (e.g. App Attest).
    HardwareKey = 1,
    /// Non-extractable platform key with a platform integrity verdict (e.g. Play Integrity).
    PlatformKey = 3,
    /// Internally verified (only authorized parties, e.g. internal developers).
    InternallyVerified = 5,
    /// Software key, user-bound, without environment integrity (e.g. a browser-held key).
    Software = 10,
}

impl From<SecLevel> for u8 {
    fn from(sec_level: SecLevel) -> Self {
        sec_level as Self
    }
}

/// User presence the Authenticator reports in an AAT (`authenticator_meta` bits 0-2); values are
/// identifiers, not an order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UserPresence {
    /// Undetermined.
    Undetermined = 0,
    /// User is not present.
    NotPresent = 1,
    /// User is present, verified by a liveness or biometric check during this request.
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

/// Security attributes of an `assertion_key`, carried in the TAKT's `sec_flags`. Fields are
/// private so every value packs into its own bit range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecFlags {
    platform: u8,
    sec_level: u8,
    build_version: u32,
    sec_meta: u8,
}

impl SecFlags {
    /// Creates security flags. Unknown `platform` and `sec_level` identifiers are kept for the RP
    /// to allowlist.
    ///
    /// # Errors
    /// [`AssertionError::SecMetaTooLarge`] if `sec_meta` carries more than 4 bits.
    pub const fn new(
        platform: u8,
        sec_level: u8,
        build_version: u32,
        sec_meta: u8,
    ) -> Result<Self, AssertionError> {
        if sec_meta > MAX_SEC_META {
            return Err(AssertionError::SecMetaTooLarge(sec_meta));
        }
        Ok(Self {
            platform,
            sec_level,
            build_version,
            sec_meta,
        })
    }

    /// Platform of the Authenticator (see [`Platform`]).
    #[must_use]
    pub const fn platform(&self) -> u8 {
        self.platform
    }

    /// Where the `assertion_key` is generated and stored (see [`SecLevel`]).
    #[must_use]
    pub const fn sec_level(&self) -> u8 {
        self.sec_level
    }

    /// Monotonic version of the Authenticator build that requested the TAKT.
    #[must_use]
    pub const fn build_version(&self) -> u32 {
        self.build_version
    }

    /// Provider-defined 4-bit bitmask.
    #[must_use]
    pub const fn sec_meta(&self) -> u8 {
        self.sec_meta
    }

    /// Unpacks `sec_flags`.
    ///
    /// # Errors
    /// [`AssertionError::InvalidSecFlags`] if bits 52 and above are set.
    pub const fn unpack(packed: u64) -> Result<Self, AssertionError> {
        if packed >> 52 != 0 {
            return Err(AssertionError::InvalidSecFlags);
        }
        let [_, top, v3, v2, v1, v0, sec_level, platform] = packed.to_be_bytes();
        Ok(Self {
            platform,
            sec_level,
            build_version: u32::from_be_bytes([v3, v2, v1, v0]),
            sec_meta: top,
        })
    }

    /// Packs the sub-fields LSB-first: `platform` (bits 0-7), `sec_level` (8-15),
    /// `build_version` (16-47), `sec_meta` (48-51).
    #[must_use]
    pub fn pack(&self) -> u64 {
        u64::from(self.platform)
            | (u64::from(self.sec_level) << 8)
            | (u64::from(self.build_version) << 16)
            | (u64::from(self.sec_meta) << 48)
    }
}

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

/// Computes `trust_anchor_key_hash = H_3(DS_KEY; x, y)`, the value circuits and RPs identify a
/// `trust_anchor_key` by.
#[must_use]
pub fn trust_anchor_key_hash(key: &EdDSAPublicKey) -> FieldElement {
    poseidon::hash(
        ds::TRUST_ANCHOR_KEY,
        [FieldElement::from(key.pk.x), FieldElement::from(key.pk.y)],
    )
}

/// Splits a 32-byte big-endian P-256 coordinate into its high and low 128-bit limbs.
fn limbs(coordinate: &[u8]) -> [FieldElement; 2] {
    let half = |range: std::ops::Range<usize>| {
        FieldElement::from(u128::from_be_bytes(
            coordinate[range].try_into().expect("16 bytes"),
        ))
    };
    [half(0..16), half(16..32)]
}

/// Encodes a P-256 key as the EC2 `COSE_Key` `{1: 2, -1: 1, -2: x, -3: y}`.
fn cose_key(key: &VerifyingKey) -> [u8; 75] {
    let point = key.to_encoded_point(false);
    let mut out = [0u8; 75];
    out[..8].copy_from_slice(&[0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20]);
    out[8..40].copy_from_slice(point.x().expect("uncompressed point"));
    out[40..43].copy_from_slice(&[0x22, 0x58, 0x20]);
    out[43..].copy_from_slice(point.y().expect("uncompressed point"));
    out
}

/// Encodes a CBOR byte string header for `len` bytes, in its shortest form.
fn bstr_header(len: usize) -> Vec<u8> {
    match len {
        0..=23 => vec![0x40 | len as u8],
        24..=255 => vec![0x58, len as u8],
        _ => unreachable!("WIP-106 byte strings are shorter than 256 bytes"),
    }
}

/// The COSE `Sig_structure` (RFC 9052 §4.4) with an empty `external_aad`.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x84, 0x6a];
    out.extend_from_slice(b"Signature1");
    out.extend(bstr_header(protected.len()));
    out.extend_from_slice(protected);
    out.push(0x40);
    out.extend(bstr_header(payload.len()));
    out.extend_from_slice(payload);
    out
}

/// Encodes an untagged `COSE_Sign1`.
fn encode_sign1(
    protected: &[u8],
    unprotected: &[u8],
    payload: &[u8],
    signature: &[u8; 64],
) -> Vec<u8> {
    let mut out = vec![0x84];
    out.extend(bstr_header(protected.len()));
    out.extend_from_slice(protected);
    out.extend_from_slice(unprotected);
    out.extend(bstr_header(payload.len()));
    out.extend_from_slice(payload);
    out.extend_from_slice(&[0x58, 0x40]);
    out.extend_from_slice(signature);
    out
}

/// Splits an untagged `COSE_Sign1` into its payload and signature, rejecting any other protected
/// header than `protected` and any unprotected header but an empty one.
fn open_sign1<'a>(
    cwt: &'a [u8],
    protected: &[u8],
    payload_len: usize,
) -> Result<(&'a [u8], [u8; 64]), AssertionError> {
    let rest = cwt
        .strip_prefix(&[0x84])
        .and_then(|r| r.strip_prefix(bstr_header(protected.len()).as_slice()))
        .and_then(|r| r.strip_prefix(protected))
        .ok_or(AssertionError::InvalidEncoding("protected header"))?;
    let rest = rest
        .strip_prefix(&[0xa0])
        .ok_or(AssertionError::InvalidEncoding("unprotected header"))?;
    let rest = rest
        .strip_prefix(bstr_header(payload_len).as_slice())
        .ok_or(AssertionError::InvalidEncoding("payload"))?;
    let (payload, rest) = rest
        .split_at_checked(payload_len)
        .ok_or(AssertionError::InvalidEncoding("payload"))?;
    let signature = rest
        .strip_prefix(&[0x58, 0x40])
        .and_then(|r| <[u8; 64]>::try_from(r).ok())
        .ok_or(AssertionError::InvalidEncoding("signature"))?;
    Ok((payload, signature))
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

/// A Trust Anchor Key Token (TAKT, WIP-106 §3.4), before signing. `Debug` prints none of its
/// values, as a verifier MUST keep the `assertion_key` and `exp` confidential.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrustAnchorKeyToken {
    exp: u32,
    assertion_key: VerifyingKey,
    sec_flags: SecFlags,
}

impl TrustAnchorKeyToken {
    /// Creates a TAKT for issuance at `now`.
    ///
    /// # Errors
    /// [`AssertionError::LifetimeOutOfRange`] unless `now < exp <= now + MAX_TAKT_LIFETIME_SECS`,
    /// and [`AssertionError::ExpirationOutOfRange`] if `exp < 2^16`.
    pub fn new(
        now: u32,
        exp: u32,
        assertion_key: VerifyingKey,
        sec_flags: SecFlags,
    ) -> Result<Self, AssertionError> {
        check_issuance(now, exp, MAX_TAKT_LIFETIME_SECS)?;
        Ok(Self {
            exp,
            assertion_key,
            sec_flags,
        })
    }

    /// Expiration as seconds since the Unix epoch.
    #[must_use]
    pub const fn exp(&self) -> u32 {
        self.exp
    }

    /// The attested `assertion_key`.
    #[must_use]
    pub const fn assertion_key(&self) -> &VerifyingKey {
        &self.assertion_key
    }

    /// The security attributes of the `assertion_key`.
    #[must_use]
    pub const fn sec_flags(&self) -> SecFlags {
        self.sec_flags
    }

    /// Computes the signed message `H_8(DS_TAKT; exp, x_hi, x_lo, y_hi, y_lo, sec_flags)`, with
    /// the `assertion_key` coordinates split into 128-bit limbs.
    #[must_use]
    pub fn message_hash(&self) -> FieldElement {
        let point = self.assertion_key.to_encoded_point(false);
        let [x_hi, x_lo] = limbs(point.x().expect("uncompressed point"));
        let [y_hi, y_lo] = limbs(point.y().expect("uncompressed point"));
        poseidon::hash(
            ds::TRUST_ANCHOR_KEY_TOKEN,
            [
                u64::from(self.exp).into(),
                x_hi,
                x_lo,
                y_hi,
                y_lo,
                self.sec_flags.pack().into(),
            ],
        )
    }

    /// Signs the TAKT with the `trust_anchor_key` and returns its CWT encoding.
    ///
    /// # Errors
    /// [`AssertionError::KeyEncoding`] if the signature or key can not be compressed.
    pub fn sign(&self, trust_anchor_key: &EdDSAPrivateKey) -> Result<Vec<u8>, AssertionError> {
        let key_encoding = |e: eyre::Report| AssertionError::KeyEncoding(e.to_string());
        let signature = trust_anchor_key
            .sign(*self.message_hash())
            .to_compressed_bytes()
            .map_err(key_encoding)?;
        let kid = trust_anchor_key
            .public()
            .to_compressed_bytes()
            .map_err(key_encoding)?;
        Ok(encode_sign1(
            &Self::protected(&kid),
            &[0xa0],
            &self.payload(),
            &signature,
        ))
    }

    /// Decodes a TAKT and verifies its signature under `trust_anchor_key`.
    ///
    /// # Errors
    /// [`TokenError::Encoding`] on any encoding but the canonical one, including a protected
    /// header whose `kid` is not that of `trust_anchor_key`; [`TokenError::Signature`] if the
    /// signature does not verify.
    pub fn verify(cwt: &[u8], trust_anchor_key: &EdDSAPublicKey) -> Result<Self, TokenError> {
        let kid = trust_anchor_key
            .to_compressed_bytes()
            .map_err(|e| AssertionError::KeyEncoding(e.to_string()))?;
        let (payload, signature) = open_sign1(cwt, &Self::protected(&kid), TAKT_PAYLOAD_LEN)?;
        let exp = u32::from_be_bytes(payload[3..7].try_into().expect("4 bytes"));
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..33].copy_from_slice(&payload[18..50]);
        point[33..].copy_from_slice(&payload[53..85]);
        let assertion_key = VerifyingKey::from_sec1_bytes(&point)
            .map_err(|_| AssertionError::InvalidEncoding("assertion_key"))?;
        let sec_flags = SecFlags::unpack(u64::from_be_bytes(
            payload[125..133].try_into().expect("8 bytes"),
        ))?;
        if exp < MIN_EXP {
            return Err(AssertionError::ExpirationOutOfRange(exp).into());
        }
        let takt = Self {
            exp,
            assertion_key,
            sec_flags,
        };
        if takt.payload() != payload {
            return Err(AssertionError::InvalidEncoding("TAKT claims").into());
        }
        // Canonical `s` and `R` are enforced by deserialization and `verify`.
        let signature = EdDSASignature::from_compressed_bytes(signature)
            .map_err(|_| AssertionError::InvalidEncoding("signature"))?;
        if !trust_anchor_key.verify(*takt.message_hash(), &signature) {
            return Err(TokenError::Signature);
        }
        Ok(takt)
    }

    /// The protected header `{1: -65537, 4: kid}`. The EdDSA signature over `message` does not
    /// cover these bytes; they are authenticated implicitly, as `alg` is fixed and `kid` must be
    /// the key the signature verifies under.
    fn protected(kid: &[u8; 32]) -> [u8; 42] {
        let mut out = [0u8; 42];
        out[..10].copy_from_slice(&TAKT_PROTECTED_PREFIX);
        out[10..].copy_from_slice(kid);
        out
    }

    /// The CWT claims set in deterministic CBOR.
    fn payload(&self) -> [u8; TAKT_PAYLOAD_LEN] {
        let mut out = [0u8; TAKT_PAYLOAD_LEN];
        let key = cose_key(&self.assertion_key);
        out[..3].copy_from_slice(&[0xa4, 0x04, 0x1a]);
        out[3..7].copy_from_slice(&self.exp.to_be_bytes());
        out[7..10].copy_from_slice(&[0x08, 0xa1, 0x01]);
        out[10..85].copy_from_slice(&key);
        out[85..90].copy_from_slice(&[0x19, 0x01, 0x09, 0x78, 0x1d]);
        out[90..119].copy_from_slice(EAT_PROFILE_TAKT.as_bytes());
        out[119..125].copy_from_slice(&[0x3a, 0x00, 0x01, 0x11, 0x6f, 0x48]);
        out[125..].copy_from_slice(&self.sec_flags.pack().to_be_bytes());
        out
    }
}

impl std::fmt::Debug for TrustAnchorKeyToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustAnchorKeyToken")
            .finish_non_exhaustive()
    }
}

/// An Authenticator Assertion Token (AAT, WIP-106 §3.5), before signing. `Debug` prints none of
/// its values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatorAssertionToken {
    aud: u64,
    exp: u32,
    nonce: FieldElement,
    cdh: FieldElement,
    authenticator_meta: AuthenticatorMeta,
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
        out[..3].copy_from_slice(&[0xa6, 0x03, 0x48]);
        out[3..11].copy_from_slice(&self.aud.to_be_bytes());
        out[11..13].copy_from_slice(&[0x04, 0x1a]);
        out[13..17].copy_from_slice(&self.exp.to_be_bytes());
        out[17..20].copy_from_slice(&[0x0a, 0x58, 0x20]);
        out[20..52].copy_from_slice(&self.nonce.to_be_bytes());
        out[52..57].copy_from_slice(&[0x19, 0x01, 0x09, 0x78, 0x1c]);
        out[57..85].copy_from_slice(EAT_PROFILE_AAT.as_bytes());
        out[85..92].copy_from_slice(&[0x3a, 0x00, 0x01, 0x38, 0x7f, 0x58, 0x20]);
        out[92..124].copy_from_slice(&self.cdh.to_be_bytes());
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

/// Why a single token failed to decode or verify.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    /// The token is not encoded as WIP-106 requires.
    #[error(transparent)]
    Encoding(#[from] AssertionError),
    /// The signature does not verify.
    #[error("invalid signature")]
    Signature,
}

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
    /// Where the `assertion_key` is stored (see [`SecLevel`]).
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
        let takt = TrustAnchorKeyToken::verify(&self.takt, &self.trust_anchor_key)
            .map_err(VerificationError::Takt)?;
        let aat = AuthenticatorAssertionToken::verify(&self.aat, takt.assertion_key())
            .map_err(VerificationError::Aat)?;
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

/// Checks `now < exp` and `exp - now <= max_lifetime`.
const fn fresh(now: u32, exp: u32, max_lifetime: u32) -> Result<(), bool> {
    if now >= exp {
        return Err(true);
    }
    if exp - now > max_lifetime {
        return Err(false);
    }
    Ok(())
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
    let takt = TrustAnchorKeyToken::verify(&private.takt, &private.trust_anchor_key)
        .map_err(VerificationError::Takt)?;
    let aat = AuthenticatorAssertionToken::verify(&private.aat, takt.assertion_key())
        .map_err(VerificationError::Aat)?;
    fresh(public.now, takt.exp, MAX_TAKT_LIFETIME_SECS).map_err(|expired| {
        if expired {
            VerificationError::TaktExpired
        } else {
            VerificationError::TaktLifetimeExceeded
        }
    })?;
    fresh(public.now, aat.exp, MAX_AAT_LIFETIME_SECS).map_err(|expired| {
        if expired {
            VerificationError::AatExpired
        } else {
            VerificationError::AatLifetimeExceeded
        }
    })?;
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

#[cfg(test)]
mod tests;
