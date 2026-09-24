//! Authenticator Assertions (WIP-106).
//!
//! An Authenticator Assertion Token (AAT) is signed by an Authenticator Provider's
//! `trust_anchor_key` after verifying platform integrity evidence for a single
//! request. The request is bound through a blinded commitment, see
//! [`request_commitment`].

use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSASignature};
use world_id_primitives::{
    FieldElement,
    poseidon::{self, ds},
};

/// Maximum remaining lifetime `exp - now` of an AAT, in seconds.
pub const MAX_AAT_LIFETIME_SECS: u32 = 1800;

/// Maximum value of `sec_meta` (4-bit bitmask).
pub const MAX_SEC_META: u8 = 0xF;

/// `eat_profile` claim value (RFC 9711 §4.3.2) of an AAT.
pub const EAT_PROFILE: &str = "https://world.org/eat/aat/v1";

/// COSE algorithm identifier for `BabyJubJub-EdDSA-Poseidon2` over an AAT (WIP-106).
pub const COSE_ALG_AAT: i64 = -65537;

/// Smallest `exp` whose deterministic CBOR encoding is a 4-byte uint.
const MIN_EXP: u32 = 1 << 16;

/// Protected header `{1: -65537}` as a CBOR byte string.
const PROTECTED: [u8; 8] = [0x47, 0xa1, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00];

/// `Sig_structure` array header and context string `"Signature1"`.
const SIG_STRUCTURE_PREFIX: [u8; 12] = [
    0x84, 0x6a, b'S', b'i', b'g', b'n', b'a', b't', b'u', b'r', b'e', b'1',
];

/// Length in bytes of the CWT claims set.
const PAYLOAD_LEN: usize = 85;

/// Platform of the Authenticator.
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

/// Class of integrity evidence the Authenticator Provider verified for a request.
///
/// Values are identifiers, not a trust ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecLevel {
    /// Unspecified, cannot be determined.
    Unspecified = 0,
    /// Hardware-bound key attested by the platform manufacturer (e.g. App Attest).
    HardwareKey = 1,
    /// Platform integrity verdict without a hardware-bound key (e.g. Play Integrity).
    PlatformVerdict = 3,
    /// Internally verified (only authorized parties, e.g. internal developers).
    InternallyVerified = 5,
    /// User-bound credential without environment integrity (e.g. a passkey).
    UserBound = 10,
}

/// Security attributes carried in `sec_flags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecFlags {
    /// Platform of the Authenticator.
    pub platform: Platform,
    /// Class of integrity evidence verified for the request.
    pub sec_level: SecLevel,
    /// Provider-defined 4-bit bitmask.
    pub sec_meta: u8,
}

impl SecFlags {
    /// Unpacks `sec_flags`.
    ///
    /// # Errors
    /// [`AssertionError::InvalidSecFlags`] on reserved bits or unknown enum values.
    pub fn unpack(packed: u32) -> Result<Self, AssertionError> {
        let [reserved, sec_meta, sec_level, platform] = packed.to_be_bytes();
        if reserved != 0 || sec_meta > MAX_SEC_META {
            return Err(AssertionError::InvalidSecFlags(packed));
        }
        let platform = match platform {
            0 => Platform::Unspecified,
            2 => Platform::Ios,
            4 => Platform::Android,
            6 => Platform::Web,
            _ => return Err(AssertionError::InvalidSecFlags(packed)),
        };
        let sec_level = match sec_level {
            0 => SecLevel::Unspecified,
            1 => SecLevel::HardwareKey,
            3 => SecLevel::PlatformVerdict,
            5 => SecLevel::InternallyVerified,
            10 => SecLevel::UserBound,
            _ => return Err(AssertionError::InvalidSecFlags(packed)),
        };
        Ok(Self {
            platform,
            sec_level,
            sec_meta,
        })
    }

    /// Packs the sub-fields LSB-first: `platform` (bits 0-7), `sec_level` (8-15), `sec_meta` (16-19).
    #[must_use]
    pub fn pack(&self) -> u32 {
        u32::from(self.platform as u8)
            | (u32::from(self.sec_level as u8) << 8)
            | (u32::from(self.sec_meta) << 16)
    }
}

/// Errors that can occur when building an Authenticator Assertion Token.
#[derive(Debug, thiserror::Error)]
pub enum AssertionError {
    /// `sec_meta` exceeds the 4-bit limit.
    #[error("sec_meta must carry at most 4 bits of data, got {0:#b}")]
    SecMetaTooLarge(u8),
    /// `exp` can not use the fixed 4-byte CBOR uint encoding.
    #[error("exp {0} must be in [2^16, 2^32) for its fixed-width encoding")]
    ExpirationOutOfRange(u32),
    /// `sec_flags` has reserved bits set or unknown enum values.
    #[error("invalid sec_flags {0:#x}")]
    InvalidSecFlags(u32),
    /// The bytes are not the canonical CWT encoding of an AAT.
    #[error("not a canonical AAT encoding: {0}")]
    InvalidEncoding(&'static str),
    /// Key or signature material could not be encoded or decoded.
    #[error("invalid key material: {0}")]
    KeyEncoding(String),
}

/// A signed AAT, as decoded from its CWT encoding.
#[derive(Debug, Clone)]
pub struct SignedAuthenticatorAssertionToken {
    /// The signed token values.
    pub token: AuthenticatorAssertionToken,
    /// The signature by the `trust_anchor_key`.
    pub signature: EdDSASignature,
    /// The `kid` hint from the unprotected header, if present. Untrusted.
    pub kid: Option<[u8; 32]>,
}

/// Computes the request commitment `req = H_8(DS_REQ; aud, nonce, cdh, blind)`.
///
/// Only `req` is sent to the Authenticator Provider; `blind` MUST be fresh and uniformly random.
#[must_use]
pub fn request_commitment(
    aud: FieldElement,
    nonce: FieldElement,
    cdh: FieldElement,
    blind: FieldElement,
) -> FieldElement {
    poseidon::hash(
        ds::AUTHENTICATOR_ASSERTION_REQUEST,
        [aud, nonce, cdh, blind],
    )
}

/// An Authenticator Assertion Token (AAT, WIP-106), before signing.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatorAssertionToken {
    exp: u32,
    req: FieldElement,
    sec_flags: SecFlags,
}

impl AuthenticatorAssertionToken {
    /// Creates an Authenticator Assertion Token from validated claims.
    ///
    /// # Errors
    /// - [`AssertionError::ExpirationOutOfRange`] if `exp < 2^16`.
    /// - [`AssertionError::SecMetaTooLarge`] if `sec_meta` carries more than 4 bits.
    pub fn new(exp: u32, req: FieldElement, sec_flags: SecFlags) -> Result<Self, AssertionError> {
        if exp < MIN_EXP {
            return Err(AssertionError::ExpirationOutOfRange(exp));
        }
        if sec_flags.sec_meta > MAX_SEC_META {
            return Err(AssertionError::SecMetaTooLarge(sec_flags.sec_meta));
        }
        Ok(Self {
            exp,
            req,
            sec_flags,
        })
    }

    /// Computes the signed message `H_4(DS_AAT; exp, req, sec_flags)`.
    #[must_use]
    pub fn message_hash(&self) -> FieldElement {
        poseidon::hash(
            ds::AUTHENTICATOR_ASSERTION_TOKEN,
            [
                FieldElement::from(u64::from(self.exp)),
                self.req,
                FieldElement::from(u64::from(self.sec_flags.pack())),
            ],
        )
    }

    /// Expiration as seconds since the Unix epoch.
    #[must_use]
    pub const fn exp(&self) -> u32 {
        self.exp
    }

    /// The request commitment.
    #[must_use]
    pub const fn req(&self) -> FieldElement {
        self.req
    }

    /// The security flags.
    #[must_use]
    pub const fn sec_flags(&self) -> SecFlags {
        self.sec_flags
    }

    /// Signs the token with the `trust_anchor_key` and returns its CWT encoding, with the `kid` hint.
    ///
    /// # Errors
    /// [`AssertionError::KeyEncoding`] if the signature or key can not be compressed.
    pub fn sign(&self, trust_anchor_key: &EdDSAPrivateKey) -> Result<Vec<u8>, AssertionError> {
        let signature = trust_anchor_key
            .sign(*self.message_hash())
            .to_compressed_bytes()
            .map_err(|e| AssertionError::KeyEncoding(e.to_string()))?;
        let kid = trust_anchor_key
            .public()
            .to_compressed_bytes()
            .map_err(|e| AssertionError::KeyEncoding(e.to_string()))?;

        let mut cwt = vec![0x84];
        cwt.extend_from_slice(&PROTECTED);
        cwt.extend_from_slice(&[0xa1, 0x04, 0x58, 0x20]);
        cwt.extend_from_slice(&kid);
        cwt.extend_from_slice(&[0x58, 0x55]);
        cwt.extend_from_slice(&self.payload());
        cwt.extend_from_slice(&[0x58, 0x40]);
        cwt.extend_from_slice(&signature);
        Ok(cwt)
    }

    /// The RFC 9052 `Sig_structure` of the token (empty `external_aad`).
    #[must_use]
    pub fn sig_structure(&self) -> Vec<u8> {
        let mut sig_structure = SIG_STRUCTURE_PREFIX.to_vec();
        sig_structure.extend_from_slice(&PROTECTED);
        sig_structure.extend_from_slice(&[0x40, 0x58, 0x55]);
        sig_structure.extend_from_slice(&self.payload());
        sig_structure
    }

    /// The CWT claims set in deterministic CBOR.
    fn payload(&self) -> [u8; PAYLOAD_LEN] {
        let mut payload = [0u8; PAYLOAD_LEN];
        let mut parts: Vec<&[u8]> = Vec::with_capacity(8);
        let exp = self.exp.to_be_bytes();
        let req = self.req.to_be_bytes();
        let sec_flags = self.sec_flags.pack().to_be_bytes();
        parts.push(&[0xa4, 0x04, 0x1a]);
        parts.push(&exp);
        parts.push(&[0x0a, 0x58, 0x20]);
        parts.push(&req);
        parts.push(&[0x19, 0x01, 0x09, 0x78, 0x1c]);
        parts.push(EAT_PROFILE.as_bytes());
        parts.push(&[0x3a, 0x00, 0x01, 0x11, 0x6f, 0x44]);
        parts.push(&sec_flags);
        let mut offset = 0;
        for part in parts {
            payload[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        }
        debug_assert_eq!(offset, PAYLOAD_LEN);
        payload
    }
}

impl SignedAuthenticatorAssertionToken {
    /// Decodes an AAT from its CWT encoding, rejecting anything but the canonical encoding.
    ///
    /// Does not verify the signature.
    ///
    /// # Errors
    /// [`AssertionError::InvalidEncoding`] on a non-canonical encoding, or the claim validation
    /// errors of [`AuthenticatorAssertionToken::new`] and [`SecFlags::unpack`].
    pub fn decode(cwt: &[u8]) -> Result<Self, AssertionError> {
        let rest = cwt
            .strip_prefix(&[0x84])
            .and_then(|r| r.strip_prefix(&PROTECTED))
            .ok_or(AssertionError::InvalidEncoding("header"))?;
        let (kid, rest) = if let Some(r) = rest.strip_prefix(&[0xa0]) {
            (None, r)
        } else {
            let r = rest
                .strip_prefix(&[0xa1, 0x04, 0x58, 0x20])
                .ok_or(AssertionError::InvalidEncoding("unprotected header"))?;
            let (kid, r) = r
                .split_at_checked(32)
                .ok_or(AssertionError::InvalidEncoding("kid"))?;
            (Some(<[u8; 32]>::try_from(kid).expect("split at 32")), r)
        };
        let rest = rest
            .strip_prefix(&[0x58, 0x55])
            .ok_or(AssertionError::InvalidEncoding("payload"))?;
        let (payload, rest) = rest
            .split_at_checked(PAYLOAD_LEN)
            .ok_or(AssertionError::InvalidEncoding("payload"))?;
        let signature = rest
            .strip_prefix(&[0x58, 0x40])
            .and_then(|r| <[u8; 64]>::try_from(r).ok())
            .ok_or(AssertionError::InvalidEncoding("signature"))?;

        let exp = u32::from_be_bytes(payload[3..7].try_into().expect("4 bytes"));
        let req = FieldElement::from_be_bytes(payload[10..42].try_into().expect("32 bytes"))
            .map_err(|_| AssertionError::InvalidEncoding("non-canonical nonce"))?;
        let sec_flags = SecFlags::unpack(u32::from_be_bytes(
            payload[81..85].try_into().expect("4 bytes"),
        ))?;
        let token = AuthenticatorAssertionToken::new(exp, req, sec_flags)?;
        if token.payload() != payload {
            return Err(AssertionError::InvalidEncoding("claims"));
        }
        let signature = EdDSASignature::from_compressed_bytes(signature)
            .map_err(|e| AssertionError::KeyEncoding(e.to_string()))?;
        Ok(Self {
            token,
            signature,
            kid,
        })
    }
}

#[cfg(test)]
mod tests;
