//! Authenticator Assertions (WIP-106).
//!
//! An Authenticator Assertion Token (AAT) is signed by an Authenticator Provider's
//! `trust_anchor_key` after verifying platform integrity evidence for a single
//! request. The request is bound through a blinded commitment, see
//! [`request_commitment`].
//!
//! [`SignedAuthenticatorAssertionToken`] is what the Authenticator receives from the
//! Authenticator Provider, as a CWT. A Rust verifier, e.g. inside a TEE, does not take the
//! token but [`AuthenticatorAssertionPublicInputs`] and
//! [`AuthenticatorAssertionPrivateInputs`], the same split as the Noir `verify_aat`. The
//! Authenticator derives the private inputs from the token with
//! [`SignedAuthenticatorAssertionToken::into_private_inputs`].

use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use serde::{Deserialize, Serialize};
use world_id_primitives::{
    FieldElement,
    poseidon::{self, ds},
};

/// Maximum remaining lifetime `exp - now` of an AAT, in seconds.
pub const MAX_AAT_LIFETIME_SECS: u32 = 1800;

/// Maximum value of `sec_meta` (3-bit bitmask).
pub const MAX_SEC_META: u8 = 0x7;

/// `eat_profile` claim value (RFC 9711 §4.3.2) of an AAT.
pub const EAT_PROFILE: &str = "https://world.org/eat/aat/v1";

/// COSE algorithm identifier for `BabyJubJub-EdDSA-Poseidon2` over an AAT (WIP-106).
pub const COSE_ALG_AAT: i64 = -65537;

/// Smallest `exp` whose deterministic CBOR encoding is a 4-byte uint.
const MIN_EXP: u32 = 1 << 16;

/// Protected header `{1: -65537}` as a CBOR byte string.
const PROTECTED: [u8; 8] = [0x47, 0xa1, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00];

/// Length in bytes of the CWT claims set.
const PAYLOAD_LEN: usize = 89;

/// Platform of the Authenticator.
///
/// The known identifiers; `sec_flags` carries the raw byte so unknown values pass through
/// to the RP's allowlist, as in the circuit.
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

/// Class of integrity evidence the Authenticator Provider verified for a request.
///
/// The known identifiers, not a trust ranking; `sec_flags` carries the raw byte so
/// unknown values pass through to the RP's allowlist, as in the circuit.
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

impl From<SecLevel> for u8 {
    fn from(sec_level: SecLevel) -> Self {
        sec_level as Self
    }
}

/// User presence asserted by the Authenticator; values are identifiers, not an order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
#[repr(u8)]
pub enum UserPresence {
    /// Undetermined.
    Undetermined = 0,
    /// User is not present.
    NotPresent = 1,
    /// User is present, verified by a liveness or biometric check during this request.
    PresentVerified = 2,
    /// User was present within the last 7 days.
    PresentWithin7Days = 3,
    /// User was present within the last 30 days.
    PresentWithin30Days = 4,
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
            3 => Ok(Self::PresentWithin7Days),
            4 => Ok(Self::PresentWithin30Days),
            _ => Err(AssertionError::ReservedPresence(value)),
        }
    }
}

/// Security attributes carried in `sec_flags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecFlags {
    /// Platform of the Authenticator (see [`Platform`]).
    pub platform: u8,
    /// Class of integrity evidence verified for the request (see [`SecLevel`]).
    pub sec_level: u8,
    /// Monotonic version of the Authenticator build that produced the evidence.
    pub build_version: u32,
    /// Provider-defined 3-bit bitmask.
    pub sec_meta: u8,
}

impl SecFlags {
    /// Unpacks `sec_flags`. Unknown `platform` and `sec_level` values are kept as is, for
    /// the RP to allowlist.
    ///
    /// # Errors
    /// [`AssertionError::InvalidSecFlags`] on reserved bits.
    pub fn unpack(packed: u64) -> Result<Self, AssertionError> {
        let [reserved, sec_meta, v3, v2, v1, v0, sec_level, platform] = packed.to_be_bytes();
        if reserved != 0 || sec_meta > MAX_SEC_META {
            return Err(AssertionError::InvalidSecFlags(packed));
        }
        Ok(Self {
            platform,
            sec_level,
            build_version: u32::from_be_bytes([v3, v2, v1, v0]),
            sec_meta,
        })
    }

    /// Packs the sub-fields LSB-first: `platform` (bits 0-7), `sec_level` (8-15),
    /// `build_version` (16-47), `sec_meta` (48-50).
    #[must_use]
    pub fn pack(&self) -> u64 {
        u64::from(self.platform)
            | (u64::from(self.sec_level) << 8)
            | (u64::from(self.build_version) << 16)
            | (u64::from(self.sec_meta) << 48)
    }
}

/// Errors that can occur when building an Authenticator Assertion Token.
#[derive(Debug, thiserror::Error)]
pub enum AssertionError {
    /// `sec_meta` exceeds the 3-bit limit.
    #[error("sec_meta must carry at most 3 bits of data, got {0:#b}")]
    SecMetaTooLarge(u8),
    /// `exp` can not use the fixed 4-byte CBOR uint encoding.
    #[error("exp {0} must be in [2^16, 2^32) for its fixed-width encoding")]
    ExpirationOutOfRange(u32),
    /// `sec_flags` has reserved bits set.
    #[error("invalid sec_flags {0:#x}")]
    InvalidSecFlags(u64),
    /// `presence` is a reserved value.
    #[error("presence values 5 and above are reserved, got {0}")]
    ReservedPresence(u8),
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

/// Computes the request commitment `req = H_8(DS_REQ; aud, nonce, cdh, presence, blind)`.
///
/// Only `req` is sent to the Authenticator Provider; `blind` MUST be fresh and uniformly random.
#[must_use]
pub fn request_commitment(
    aud: FieldElement,
    nonce: FieldElement,
    cdh: FieldElement,
    presence: UserPresence,
    blind: FieldElement,
) -> FieldElement {
    poseidon::hash(
        ds::AUTHENTICATOR_ASSERTION_REQUEST,
        [
            aud,
            nonce,
            cdh,
            FieldElement::from(u64::from(presence as u8)),
            blind,
        ],
    )
}

/// Computes the signed message `H_4(DS_AAT; exp, req, sec_flags)` from raw claims.
#[must_use]
pub fn message_hash(exp: u32, req: FieldElement, sec_flags: u64) -> FieldElement {
    poseidon::hash(
        ds::AUTHENTICATOR_ASSERTION_TOKEN,
        [
            FieldElement::from(u64::from(exp)),
            req,
            FieldElement::from(sec_flags),
        ],
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
    /// - [`AssertionError::SecMetaTooLarge`] if `sec_meta` carries more than 3 bits.
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
        message_hash(self.exp, self.req, self.sec_flags.pack())
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
        cwt.extend_from_slice(&[0x58, 0x59]);
        cwt.extend_from_slice(&self.payload());
        cwt.extend_from_slice(&[0x58, 0x40]);
        cwt.extend_from_slice(&signature);
        Ok(cwt)
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
        parts.push(&[0x3a, 0x00, 0x01, 0x11, 0x6f, 0x48]);
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
            .strip_prefix(&[0x58, 0x59])
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
        let sec_flags = SecFlags::unpack(u64::from_be_bytes(
            payload[81..89].try_into().expect("8 bytes"),
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

    /// Turns the token into the private inputs of a verifier, given the opening of its
    /// request commitment. The token's `req` is dropped: a verifier recomputes it.
    #[must_use]
    pub fn into_private_inputs(
        self,
        cdh: FieldElement,
        blind: FieldElement,
    ) -> AuthenticatorAssertionPrivateInputs {
        AuthenticatorAssertionPrivateInputs {
            exp: self.token.exp,
            sec_flags: self.token.sec_flags.pack(),
            sig: self.signature,
            cdh,
            blind,
        }
    }
}

/// The public inputs of AAT verification (WIP-106 section 3.7). Set by the RP and the
/// verifier; a verifier reports them alongside its output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatorAssertionPublicInputs {
    /// The Authenticator Provider's `trust_anchor_key`, chosen by the RP.
    pub trust_anchor_key: EdDSAPublicKey,
    /// Current time as seconds since the Unix epoch, from the verifier's clock.
    pub now: u32,
    /// The `rpId` of the request.
    pub aud: FieldElement,
    /// The nonce of the request.
    pub nonce: FieldElement,
    /// User presence asserted by the Authenticator.
    pub presence: UserPresence,
    /// Minimum `build_version` the RP accepts.
    pub min_build_version: u32,
}

/// The private inputs of AAT verification (WIP-106 section 3.7): the token's claims and
/// signature, and the opening of its request commitment. A verifier MUST keep them
/// confidential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatorAssertionPrivateInputs {
    /// Expiration as seconds since the Unix epoch.
    pub exp: u32,
    /// Packed security attributes (see [`SecFlags`]).
    pub sec_flags: u64,
    /// The signature by the `trust_anchor_key`.
    pub sig: EdDSASignature,
    /// Client data hash binding the AAT to its upstream use; `0` is nil.
    pub cdh: FieldElement,
    /// Blinding factor of the request commitment.
    pub blind: FieldElement,
}

/// The public output of a verified AAT: the disclosed `sec_flags` sub-fields.
/// `exp` and `build_version` stay private and are deliberately absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedAssertion {
    /// Platform of the Authenticator (see [`Platform`]).
    pub platform: u8,
    /// Class of integrity evidence verified for the request (see [`SecLevel`]).
    pub sec_level: u8,
    /// Provider-defined 3-bit bitmask.
    pub sec_meta: u8,
}

/// Why an AAT failed verification. One variant per WIP-106 section 3.7 constraint.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerificationError {
    /// The request nonce is `0`.
    #[error("nonce must not be 0")]
    ZeroNonce,
    /// The signature does not verify: forged, or the request inputs do not open `req`.
    #[error("invalid signature")]
    InvalidSignature,
    /// `now >= exp`.
    #[error("token is expired")]
    Expired,
    /// `exp - now > MAX_AAT_LIFETIME_SECS`.
    #[error("token lifetime exceeds maximum")]
    LifetimeExceeded,
    /// `sec_flags` has reserved bits set.
    #[error("invalid sec_flags {0:#x}")]
    InvalidSecFlags(u64),
    /// `build_version < min_build_version`.
    #[error("build_version below minimum")]
    BuildVersionBelowMinimum,
}

/// Verifies an AAT outside a circuit, e.g. inside a TEE, with the checks of WIP-106
/// section 3.7 in the order of the Noir `verify_aat`.
///
/// `presence < 5` is guaranteed by [`UserPresence`]; canonical `sig` scalars and points by
/// their types' deserialization.
///
/// # Errors
/// [`VerificationError`] for the first failing constraint.
pub fn verify_aat(
    public: &AuthenticatorAssertionPublicInputs,
    private: &AuthenticatorAssertionPrivateInputs,
) -> Result<VerifiedAssertion, VerificationError> {
    if public.nonce == FieldElement::ZERO {
        return Err(VerificationError::ZeroNonce);
    }
    let req = request_commitment(
        public.aud,
        public.nonce,
        private.cdh,
        public.presence,
        private.blind,
    );
    let message = message_hash(private.exp, req, private.sec_flags);
    if !public.trust_anchor_key.verify(*message, &private.sig) {
        return Err(VerificationError::InvalidSignature);
    }
    if public.now >= private.exp {
        return Err(VerificationError::Expired);
    }
    if private.exp - public.now > MAX_AAT_LIFETIME_SECS {
        return Err(VerificationError::LifetimeExceeded);
    }
    let flags = SecFlags::unpack(private.sec_flags)
        .map_err(|_| VerificationError::InvalidSecFlags(private.sec_flags))?;
    if flags.build_version < public.min_build_version {
        return Err(VerificationError::BuildVersionBelowMinimum);
    }
    Ok(VerifiedAssertion {
        platform: flags.platform,
        sec_level: flags.sec_level,
        sec_meta: flags.sec_meta,
    })
}

#[cfg(test)]
mod tests;
