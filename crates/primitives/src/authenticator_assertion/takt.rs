//! The Trust Anchor Key Token (TAKT, WIP-106 §3.4): signed by the Authenticator Provider's
//! `trust_anchor_key` over a Poseidon2 digest of its claims, attesting an `assertion_key`.

use super::{AssertionError, MIN_EXP, TokenError, check_issuance, encode_sign1, open_sign1};
use crate::{
    FieldElement,
    poseidon::{self, ds},
};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use p256::ecdsa::VerifyingKey;

/// Maximum remaining lifetime `exp - now` of a TAKT, in seconds.
pub const MAX_TAKT_LIFETIME_SECS: u32 = 2_592_000;

/// Maximum value of `sec_meta` (4-bit bitmask).
pub const MAX_SEC_META: u8 = 0xF;

/// `eat_profile` claim value (RFC 9711 §4.3.2) of a TAKT.
pub const EAT_PROFILE_TAKT: &str = "https://world.org/eat/takt/v1";

/// Length in bytes of the TAKT claims set.
const TAKT_PAYLOAD_LEN: usize = 133;

/// COSE algorithm identifier for `BabyJubJub-EdDSA-Poseidon2` over a TAKT (WIP-106).
pub const COSE_ALG_TAKT: i64 = -65537;

/// Prefix of the TAKT protected header `{1: -65537, 4: kid}`, followed by the 32-byte `kid`.
const TAKT_PROTECTED_PREFIX: [u8; 10] = [
    0xa2, // map(2)
    0x01, 0x3a, 0x00, 0x01, 0x00, 0x00, // alg (1): -65537
    0x04, 0x58, 0x20, // kid (4): bstr(32)
];

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

/// Class of integrity evidence the Authenticator Provider verified when issuing the TAKT.
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
    /// Platform integrity verdict without a hardware-bound key (e.g. Play Integrity).
    PlatformKey = 3,
    /// Integrity implied by the Authenticator Provider's internal controls.
    InternallyVerified = 5,
    /// No environment integrity could be verified.
    Software = 10,
}

impl From<SecLevel> for u8 {
    fn from(sec_level: SecLevel) -> Self {
        sec_level as Self
    }
}

/// Security attributes of an `assertion_key`, carried in the TAKT's `sec_flags`. Fields are
/// private so every value packs into its own bit range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecFlags {
    pub(super) platform: u8,
    pub(super) sec_level: u8,
    pub(super) build_version: u32,
    pub(super) sec_meta: u8,
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

    /// Class of integrity evidence verified at TAKT issuance (see [`SecLevel`]).
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
    // map(4), kty (1): EC2 (2), crv (-1): P-256 (1), x (-2): bstr(32)
    out[..8].copy_from_slice(&[0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20]);
    out[8..40].copy_from_slice(point.x().expect("uncompressed point"));
    // y (-3): bstr(32)
    out[40..43].copy_from_slice(&[0x22, 0x58, 0x20]);
    out[43..].copy_from_slice(point.y().expect("uncompressed point"));
    out
}

/// A Trust Anchor Key Token (TAKT, WIP-106 §3.4), before signing. `Debug` prints none of its
/// values, as a verifier MUST keep the `assertion_key` and `exp` confidential.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrustAnchorKeyToken {
    pub(super) exp: u32,
    pub(super) assertion_key: VerifyingKey,
    pub(super) sec_flags: SecFlags,
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
        // SEC1 uncompressed point tag
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
        // map(4), exp (4): uint32
        out[..3].copy_from_slice(&[0xa4, 0x04, 0x1a]);
        out[3..7].copy_from_slice(&self.exp.to_be_bytes());
        // cnf (8): map(1), COSE_Key (1)
        out[7..10].copy_from_slice(&[0x08, 0xa1, 0x01]);
        out[10..85].copy_from_slice(&key);
        // eat_profile (265): text(29)
        out[85..90].copy_from_slice(&[0x19, 0x01, 0x09, 0x78, 0x1d]);
        out[90..119].copy_from_slice(EAT_PROFILE_TAKT.as_bytes());
        // sec_flags (-70000): bstr(8)
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
