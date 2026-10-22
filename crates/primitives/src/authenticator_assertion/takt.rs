//! The Trust Anchor Key Token (TAKT, WIP-106 §3.4): signed by the Authenticator Provider's
//! `trust_anchor_key` over a Poseidon2 digest of its claims, attesting an `assertion_key`.

use coset::{Algorithm, Header};

use super::{AuthenticatorAssertionError, MIN_EXP, Token, check_issuance};
use crate::{
    FieldElement,
    cbor::{self, CLAIM_EAT_PROFILE, Fields, Value},
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

/// Length in bytes of a TAKT's CWT encoding.
const TAKT_CWT_LEN: usize = 247;

/// CWT claim keys of a TAKT (RFC 8392, RFC 8747, RFC 9711, WIP-106).
const CLAIM_EXP: i64 = 4;
const CLAIM_CNF: i64 = 8;
const CLAIM_SEC_FLAGS: i64 = -70_000;

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
    /// [`AuthenticatorAssertionError::InvalidField`] if `sec_meta` carries more than 4 bits.
    pub const fn new(
        platform: u8,
        sec_level: u8,
        build_version: u32,
        sec_meta: u8,
    ) -> Result<Self, AuthenticatorAssertionError> {
        if sec_meta > MAX_SEC_META {
            return Err(AuthenticatorAssertionError::InvalidField("sec_meta"));
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
    /// [`AuthenticatorAssertionError::InvalidField`] if bits 52 and above are set.
    pub const fn unpack(packed: u64) -> Result<Self, AuthenticatorAssertionError> {
        if packed >> 52 != 0 {
            return Err(AuthenticatorAssertionError::InvalidField("sec_flags"));
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

/// The claims of a Trust Anchor Key Token (TAKT, WIP-106 §3.4). `Debug` prints none of its values,
/// as a verifier MUST keep the `assertion_key` and `exp` confidential.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TaktClaims {
    pub(super) exp: u32,
    pub(super) assertion_key: VerifyingKey,
    pub(super) sec_flags: SecFlags,
}

impl TaktClaims {
    /// Creates TAKT claims for issuance at `now` by a `trust_anchor_key` valid until `not_after`.
    /// The caller MUST NOT attest the same `assertion_key` with differing `sec_flags` (WIP-106
    /// §3.4).
    ///
    /// # Errors
    /// [`AuthenticatorAssertionError::Expired`] if `exp <= now`, [`AuthenticatorAssertionError::LifetimeExceeded`] if
    /// `exp > now + MAX_TAKT_LIFETIME_SECS` or `exp > not_after`, and [`AuthenticatorAssertionError::InvalidField`] if
    /// `exp < 2^16`.
    pub fn new(
        now: u32,
        exp: u32,
        not_after: u32,
        assertion_key: VerifyingKey,
        sec_flags: SecFlags,
    ) -> Result<Self, AuthenticatorAssertionError> {
        check_issuance(now, exp, MAX_TAKT_LIFETIME_SECS, Token::Takt)?;
        if exp > not_after {
            return Err(AuthenticatorAssertionError::LifetimeExceeded(Token::Takt));
        }
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

    /// The CWT claims set.
    fn to_value(self) -> Value {
        let point = self.assertion_key.to_encoded_point(false);
        // The EC2 P-256 `COSE_Key` `{1: 2, -1: 1, -2: x, -3: y}` (RFC 9053 §7.1).
        let cose_key = cbor::map(vec![
            (Value::from(1), Value::from(2)),
            (Value::from(-1), Value::from(1)),
            (
                Value::from(-2),
                Value::Bytes(point.x().expect("uncompressed point").to_vec()),
            ),
            (
                Value::from(-3),
                Value::Bytes(point.y().expect("uncompressed point").to_vec()),
            ),
        ]);
        cbor::map(vec![
            (CLAIM_EXP.into(), Value::Integer(self.exp.into())),
            (
                CLAIM_CNF.into(),
                cbor::map(vec![(Value::from(1), cose_key)]),
            ),
            (
                CLAIM_EAT_PROFILE.into(),
                Value::Text(EAT_PROFILE_TAKT.into()),
            ),
            (
                CLAIM_SEC_FLAGS.into(),
                Value::Bytes(self.sec_flags.pack().to_be_bytes().to_vec()),
            ),
        ])
    }

    /// Reads the CWT claims set.
    fn from_value(value: Value) -> Result<Self, AuthenticatorAssertionError> {
        let mut claims = Fields::of(value, "TAKT claims")?;
        let exp: u32 = claims.uint(CLAIM_EXP)?;
        let mut cnf = Fields::of(claims.take(CLAIM_CNF)?, "cnf")?;
        // The EC2 P-256 `COSE_Key` `{1: 2, -1: 1, -2: x, -3: y}`.
        let mut key = Fields::of(cnf.take(1)?, "assertion_key")?;
        if key.uint::<u8>(1)? != 2 || key.uint::<u8>(-1)? != 1 {
            return Err(AuthenticatorAssertionError::InvalidEncoding(
                "assertion_key",
            ));
        }
        let x: [u8; 32] = key.bytes(-2)?;
        let y: [u8; 32] = key.bytes(-3)?;
        let assertion_key = VerifyingKey::from_sec1_bytes(&[[0x04].as_slice(), &x, &y].concat())
            .map_err(|_| AuthenticatorAssertionError::InvalidEncoding("assertion_key"))?;
        claims.text(CLAIM_EAT_PROFILE, EAT_PROFILE_TAKT)?;
        let sec_flags = SecFlags::unpack(u64::from_be_bytes(claims.bytes(CLAIM_SEC_FLAGS)?))?;
        if exp < MIN_EXP {
            return Err(AuthenticatorAssertionError::InvalidField("exp"));
        }
        Ok(Self {
            exp,
            assertion_key,
            sec_flags,
        })
    }
}

impl std::fmt::Debug for TaktClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaktClaims").finish_non_exhaustive()
    }
}

/// A signed Trust Anchor Key Token (TAKT, WIP-106 §3.4). `Debug` prints none of its values.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustAnchorKeyToken {
    claims: TaktClaims,
    kid: [u8; 32],
    signature: [u8; 64],
}

impl TrustAnchorKeyToken {
    /// Signs `claims` with the `trust_anchor_key`.
    ///
    /// # Errors
    /// [`AuthenticatorAssertionError::InvalidEncoding`] if the signature or key can not be compressed.
    pub fn sign(
        claims: TaktClaims,
        trust_anchor_key: &EdDSAPrivateKey,
    ) -> Result<Self, AuthenticatorAssertionError> {
        Ok(Self {
            claims,
            kid: trust_anchor_key
                .public()
                .to_compressed_bytes()
                .map_err(|_| AuthenticatorAssertionError::InvalidEncoding("trust_anchor_key"))?,
            signature: trust_anchor_key
                .sign(*claims.message_hash())
                .to_compressed_bytes()
                .map_err(|_| AuthenticatorAssertionError::InvalidEncoding("signature"))?,
        })
    }

    /// The claims, unverified. Use [`Self::verify`] to check them.
    #[must_use]
    pub const fn claims(&self) -> &TaktClaims {
        &self.claims
    }

    /// The `kid` of the `trust_anchor_key` that signed the TAKT, for picking the key to verify
    /// under (e.g. during a key rotation).
    #[must_use]
    pub const fn kid(&self) -> [u8; 32] {
        self.kid
    }

    /// The CWT encoding: protected header `{1: -65537, 4: kid}`, an empty unprotected header, the
    /// claims set and the compressed EdDSA signature.
    #[must_use]
    pub fn to_cwt(&self) -> Vec<u8> {
        let protected = Header {
            alg: Some(Algorithm::PrivateUse(
                cbor::COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2,
            )),
            key_id: self.kid.to_vec(),
            ..Header::default()
        };
        cbor::encode_sign1(
            protected,
            cbor::encode(&self.claims.to_value()),
            self.signature.to_vec(),
        )
    }

    /// Decodes a TAKT from its CWT encoding, rejecting anything but the canonical encoding. Does
    /// not verify the signature.
    ///
    /// # Errors
    /// [`AuthenticatorAssertionError::InvalidEncoding`] on any other encoding, and [`AuthenticatorAssertionError::InvalidField`] for an
    /// out-of-range claim.
    pub fn from_cwt(cwt: &[u8]) -> Result<Self, AuthenticatorAssertionError> {
        let (protected, payload, signature) = cbor::decode_sign1(cwt, TAKT_CWT_LEN..=TAKT_CWT_LEN)?;
        if protected.alg
            != Some(Algorithm::PrivateUse(
                cbor::COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2,
            ))
        {
            return Err(AuthenticatorAssertionError::InvalidEncoding(
                "protected header",
            ));
        }
        // Other header parameters are rejected by the re-encoding check below.
        let kid: [u8; 32] = protected
            .key_id
            .try_into()
            .map_err(|_| AuthenticatorAssertionError::InvalidEncoding("protected header"))?;
        let claims = TaktClaims::from_value(payload)?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| AuthenticatorAssertionError::InvalidEncoding("signature"))?;
        // Canonical `s` and `R` are enforced by deserialization and `verify`.
        EdDSASignature::from_compressed_bytes(signature)
            .map_err(|_| AuthenticatorAssertionError::InvalidEncoding("signature"))?;
        let takt = Self {
            claims,
            kid,
            signature,
        };
        if takt.to_cwt() != cwt {
            return Err(AuthenticatorAssertionError::InvalidEncoding(
                "non-canonical CBOR",
            ));
        }
        Ok(takt)
    }

    /// Verifies the TAKT under `trust_anchor_key` and returns its claims. The protected header is
    /// authenticated implicitly (WIP-106 §3.4): `kid` must be the compressed `trust_anchor_key`.
    ///
    /// # Errors
    /// [`AuthenticatorAssertionError::KeyMismatch`] if `kid` is another key's; [`AuthenticatorAssertionError::InvalidSignature`] if the
    /// signature does not verify.
    pub fn verify(
        &self,
        trust_anchor_key: &EdDSAPublicKey,
    ) -> Result<&TaktClaims, AuthenticatorAssertionError> {
        if trust_anchor_key.to_compressed_bytes().ok() != Some(self.kid) {
            return Err(AuthenticatorAssertionError::KeyMismatch);
        }
        let signature = EdDSASignature::from_compressed_bytes(self.signature)
            .map_err(|_| AuthenticatorAssertionError::InvalidSignature(Token::Takt))?;
        if !trust_anchor_key.verify(*self.claims.message_hash(), &signature) {
            return Err(AuthenticatorAssertionError::InvalidSignature(Token::Takt));
        }
        Ok(&self.claims)
    }
}

impl std::fmt::Debug for TrustAnchorKeyToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustAnchorKeyToken")
            .finish_non_exhaustive()
    }
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
