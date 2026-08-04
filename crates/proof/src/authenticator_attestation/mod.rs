//! Authenticator Attestations (WIP-106).

use coset::{
    AsCborValue, CborSerializable, CoseKeyBuilder, CoseSign1, CoseSign1Builder, Header, Label,
    RegisteredLabelWithPrivate,
    cbor::value::Value,
    cwt::{ClaimsSet, ClaimsSetBuilder, Timestamp},
    iana,
};
use eddsa_babyjubjub::EdDSAPrivateKey;
use p256::{ecdsa::signature::Signer, elliptic_curve::sec1::ToEncodedPoint};
use world_id_primitives::{FieldElement, rp::RpId};

/// COSE algorithm identifier for `BabyJubJub-EdDSA-Poseidon2` (defined in WIP-106).
pub const COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2: i64 = -65537;

/// `eat_profile` claim value (RFC 9711 §4.3.2) identifying the Trust Anchor Key
/// Token format.
///
/// URI identifying the full EAT profile the token conforms to. For a Trust
/// Anchor Key Token, hashing is done with Poseidon2 and signatures with EdDSA
/// over the BabyJubJub curve.
pub const EAT_PROFILE_TRUST_ANCHOR_KEY: &str = "https://world.org/eat/takt/v1";

/// `eat_profile` claim value (RFC 9711 §4.3.2) identifying the Authenticator
/// Assertion Token format.
///
/// URI identifying the full EAT profile the token conforms to. For an
/// Authenticator Assertion Token, hashing is done with SHA-256 and signatures
/// with ECDSA over the P-256 curve (`ES256`).
pub const EAT_PROFILE_AUTHENTICATOR_ASSERTION: &str = "https://world.org/eat/aat/v1";

/// Maximum value for `sec_meta` (bits 48-51 of `sec_flags`; 4-bit bitmask).
pub const MAX_SEC_META: u8 = 0xF;

/// Maximum value for the provider-defined bits of `authenticator_meta` (2 bits).
pub const MAX_PROVIDER_BITS: u8 = 0b11;

/// Domain separator for the Trust Anchor Key Token `Poseidon2` message hash.
const TRUST_ANCHOR_KEY_DS: &[u8] = b"WORLD_ID_TAKT_V1";

/// CWT claim key for `aud` (RFC 8392).
const CWT_CLAIM_AUD: i64 = 3;
/// CWT claim key for `exp` (RFC 8392).
const CWT_CLAIM_EXP: i64 = 4;
/// CWT claim key for `nonce` (RFC 8392 registry).
const CWT_CLAIM_NONCE: i64 = 10;
/// CWT claim key for `eat_profile` (RFC 9711).
const CWT_CLAIM_EAT_PROFILE: i64 = 265;
/// CWT claim key for `cdh` (client data hash, WIP-106).
const CWT_CLAIM_CDH: i64 = -80_000;
/// CWT claim key for `authenticator_meta` (WIP-106).
const CWT_CLAIM_AUTHENTICATOR_META: i64 = -80_001;
/// CWT claim key for `sec_flags` (WIP-106).
const CWT_CLAIM_SEC_FLAGS: i64 = -70_000;

/// `cnf` confirmation method label for a `COSE_Key` (RFC 8747 §3.1).
const CNF_COSE_KEY: i64 = 1;

/// Label of the Trust Anchor Key Token in the AAT's `COSE_Sign1` unprotected
/// header (WIP-106 AAT section 6).
const HEADER_TAKT: &str = "takt";

/// Bit offsets of the `sec_flags` sub-fields (LSB-first packing).
const SEC_FLAGS_SEC_LEVEL_SHIFT: u64 = 8;
const SEC_FLAGS_BUILD_VERSION_SHIFT: u64 = 16;
const SEC_FLAGS_SEC_META_SHIFT: u64 = 48;

/// Bit offset of the provider-defined bits within `authenticator_meta`.
const AUTHENTICATOR_META_PROVIDER_SHIFT: u64 = 3;

/// Security level attributed to where the `assertion_key` was generated and stored.
///
/// Strict security-level ordering is not required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SecLevel {
    /// Unspecified, cannot be determined.
    Unspecified = 0,
    /// Key generated with hardware guarantees in a Secure Element.
    SecureElement = 1,
    /// Non-extractable platform key, software-enforced by the device manufacturer.
    PlatformKey = 3,
    /// Internally-verified security (only authorized parties, e.g. internal developers).
    InternallyVerified = 5,
    /// Software-based key.
    Software = 10,
}

/// Host platform where the proof is generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
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

/// User presence assertion (`authenticator_meta` bits 0-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UserPresence {
    /// Undetermined.
    Undetermined = 0b000,
    /// User is not physically present.
    NotPresent = 0b001,
    /// User is physically present, verified with a biometric check.
    PresentBiometric = 0b010,
    /// User has been physically present in the last 30 days.
    PresentLast30Days = 0b011,
    /// User has been physically present recently (less than 7 days).
    PresentRecently = 0b100,
}

/// Structured `authenticator_meta` payload: user presence plus two
/// provider-defined bits. Remaining bits are reserved and always zero.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatorMeta {
    /// User presence assertion (bits 0-2).
    pub user_presence: UserPresence,
    /// Provider-defined bits (bits 3-4); `0b00` is the nil value.
    pub provider_bits: u8,
}

impl AuthenticatorMeta {
    /// Packs the sub-fields into the claim value (LSB-first).
    fn packed(self) -> u64 {
        u64::from(self.user_presence as u8)
            | (u64::from(self.provider_bits) << AUTHENTICATOR_META_PROVIDER_SHIFT)
    }
}

/// Claims carried by a Trust Anchor Key Token.
#[derive(Debug, Clone, Copy)]
pub struct TrustAnchorKeyClaims {
    /// Expiration as seconds since the Unix epoch.
    pub exp: u64,
    /// The attested `assertion_key`, carried as a `COSE_Key` in the `cnf` claim.
    pub assertion_key: p256::PublicKey,
    /// Security level of the `assertion_key` (`sec_flags` bits 8-15).
    pub sec_level: SecLevel,
    /// Host platform where the proof is generated (`sec_flags` bits 0-7).
    pub platform: Platform,
    /// Monotonic build version defined by the Authenticator Provider
    /// (`sec_flags` bits 16-47).
    pub build_version: u32,
    /// Provider-defined bitmask (`sec_flags` bits 48-51).
    pub sec_meta: u8,
}

impl TrustAnchorKeyClaims {
    /// Packs the security attributes into the `sec_flags` claim value
    /// (LSB-first: platform, sec_level, build_version, sec_meta).
    fn sec_flags(&self) -> u64 {
        (self.platform as u64)
            | ((self.sec_level as u64) << SEC_FLAGS_SEC_LEVEL_SHIFT)
            | (u64::from(self.build_version) << SEC_FLAGS_BUILD_VERSION_SHIFT)
            | (u64::from(self.sec_meta) << SEC_FLAGS_SEC_META_SHIFT)
    }
}

/// Errors that can occur when generating an attestation token.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// The assertion key could not be converted to affine coordinates.
    #[error("assertion key is not a valid P-256 point")]
    InvalidAssertionKey,
    /// `sec_meta` exceeds the 4-bit limit mandated by WIP-106.
    #[error("sec_meta must carry at most 4 bits of data, got {0:#b}")]
    SecMetaTooLarge(u8),
    /// The provider bits of `authenticator_meta` exceed the 2-bit limit.
    #[error("authenticator_meta provider bits must carry at most 2 bits, got {0:#b}")]
    ProviderBitsTooLarge(u8),
    /// `aud` cannot use the fixed 4-byte CBOR encoding.
    #[error("aud {0} must be in [2^16, 2^32) for its fixed-width encoding")]
    AudOutOfRange(u64),
    /// `exp` cannot be represented as a CWT numeric date.
    #[error("exp {0} exceeds the representable CWT numeric date range")]
    ExpirationOutOfRange(u64),
    /// Key material could not be serialized.
    #[error("failed to encode key material: {0}")]
    KeyEncoding(String),
    /// CBOR serialization failed.
    #[error("failed to encode CBOR: {0}")]
    CborEncoding(String),
    /// A claim value could not be lowered into Poseidon2 field elements.
    #[error("failed to lower claims into field elements: {0}")]
    ClaimHashing(String),
    /// The nested Trust Anchor Key Token could not be parsed.
    #[error("invalid Trust Anchor Key Token: {0}")]
    InvalidTrustAnchorKeyToken(String),
    /// The signing key is not the key attested by the Trust Anchor Key Token.
    #[error("assertion key does not match the key attested by the Trust Anchor Key Token")]
    AssertionKeyMismatch,
}

/// A Trust Anchor Key Token (TAKT, WIP-106): an EAT attesting an
/// `assertion_key` through the `cnf` claim.
///
/// Construct with [`TrustAnchorKeyToken::new`]; [`TrustAnchorKeyToken::sign`]
/// signs the token with the Authenticator Provider's `trust_anchor_key` and
/// serializes it.
#[derive(Debug, Clone)]
pub struct TrustAnchorKeyToken {
    claims: TrustAnchorKeyClaims,
}

impl TrustAnchorKeyToken {
    /// Creates a Trust Anchor Key Token from validated claims.
    ///
    /// # Errors
    /// - [`AttestationError::SecMetaTooLarge`] if `sec_meta` carries more than 4 bits.
    /// - [`AttestationError::ExpirationOutOfRange`] if `exp` is not a valid CWT numeric date.
    pub fn new(claims: TrustAnchorKeyClaims) -> Result<Self, AttestationError> {
        if claims.sec_meta > MAX_SEC_META {
            return Err(AttestationError::SecMetaTooLarge(claims.sec_meta));
        }
        if i64::try_from(claims.exp).is_err() {
            return Err(AttestationError::ExpirationOutOfRange(claims.exp));
        }
        Ok(Self { claims })
    }

    /// Computes the digest of the token to be signed by the `trust_anchor_key`.
    ///
    /// The message is derived from the encoded claims set: each claim value in
    /// deterministic CBOR map-key order (RFC 8949 §4.2.1) is lowered into zero
    /// or more field elements (see [`claim_field_elements`]; non-field-element
    /// claims such as `eat_profile` are excluded per WIP-106), preceded by a
    /// domain-separator element in the Poseidon2 t8 permutation; the digest is
    /// element 1 of the permuted state.
    ///
    /// # Errors
    /// - [`AttestationError::ClaimHashing`] if a claim value has no defined field
    ///   element encoding or the values exceed the permutation width.
    /// - [`AttestationError::InvalidAssertionKey`] if the assertion key has no
    ///   affine coordinates.
    /// - [`AttestationError::CborEncoding`] on claim encoding failure.
    pub fn message_hash(&self) -> Result<FieldElement, AttestationError> {
        let claims = self
            .claims_set()?
            .to_cbor_value()
            .map_err(|e| AttestationError::CborEncoding(e.to_string()))?;
        let Value::Map(entries) = claims else {
            return Err(AttestationError::ClaimHashing(
                "claims set is not a CBOR map".to_string(),
            ));
        };

        let mut state = [*FieldElement::ZERO; 8];
        // The domain separator fits the field (16 bytes); `mod_order` cannot
        // reduce here but is the spec-mandated lowering.
        state[0] = *FieldElement::from_be_bytes_mod_order(TRUST_ANCHOR_KEY_DS);
        let mut slot = 1;
        for (key, value) in &entries {
            for element in claim_field_elements(key, value)? {
                let Some(target) = state.get_mut(slot) else {
                    return Err(AttestationError::ClaimHashing(
                        "claim values exceed the Poseidon2 t8 width".to_string(),
                    ));
                };
                *target = *element;
                slot += 1;
            }
        }
        poseidon2::bn254::t8::permutation_in_place(&mut state);
        Ok(state[1].into())
    }

    /// Signs the token with the Authenticator Provider's `trust_anchor_key` and
    /// serializes it as an untagged `COSE_Sign1` structure in deterministic CBOR.
    ///
    /// The protected header carries the `BabyJubJub-EdDSA-Poseidon2` algorithm and
    /// the `kid` (compressed `trust_anchor_key` public key); the signature field
    /// carries the EdDSA signature over [`TrustAnchorKeyToken::message_hash`] as
    /// `R || S`.
    ///
    /// # Errors
    /// - [`AttestationError::KeyEncoding`] on key serialization failure.
    /// - [`AttestationError::CborEncoding`] on serialization failure.
    pub fn sign(&self, trust_anchor_key: &EdDSAPrivateKey) -> Result<Vec<u8>, AttestationError> {
        let signature = trust_anchor_key
            .sign(*self.message_hash()?)
            .to_compressed_bytes()
            .map_err(|e| AttestationError::KeyEncoding(e.to_string()))?;
        let kid = trust_anchor_key
            .public()
            .to_compressed_bytes()
            .map_err(|e| AttestationError::KeyEncoding(e.to_string()))?;
        let payload = self
            .claims_set()?
            .to_vec()
            .map_err(|e| AttestationError::CborEncoding(e.to_string()))?;
        let protected = Header {
            alg: Some(RegisteredLabelWithPrivate::PrivateUse(
                COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2,
            )),
            key_id: kid.to_vec(),
            ..Header::default()
        };
        CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .signature(signature.to_vec())
            .build()
            .to_vec()
            .map_err(|e| AttestationError::CborEncoding(e.to_string()))
    }

    /// Builds the CWT claims set: the single source of truth for claim content
    /// and order.
    ///
    /// Claims are inserted in deterministic CBOR map-key order ([RFC 8949 §4.2](https://datatracker.ietf.org/doc/html/rfc8949#section-4.2))
    /// so the proving circuit can use constant offsets. `sec_flags` is an 8-byte
    /// byte string (64-bit big-endian packed bitfield) per WIP-106.
    fn claims_set(&self) -> Result<ClaimsSet, AttestationError> {
        let exp = i64::try_from(self.claims.exp)
            .map_err(|_| AttestationError::ExpirationOutOfRange(self.claims.exp))?;
        let (x, y) = assertion_key_coordinates(&self.claims.assertion_key)?;
        let assertion_cose_key =
            CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.to_vec(), y.to_vec())
                .build()
                .to_cbor_value()
                .map_err(|e| AttestationError::CborEncoding(e.to_string()))?;

        Ok(ClaimsSetBuilder::new()
            .expiration_time(Timestamp::WholeSeconds(exp))
            .claim(
                iana::CwtClaimName::Cnf,
                Value::Map(vec![(
                    Value::Integer(CNF_COSE_KEY.into()),
                    assertion_cose_key,
                )]),
            )
            .claim(
                iana::CwtClaimName::EatProfile,
                Value::Text(EAT_PROFILE_TRUST_ANCHOR_KEY.to_string()),
            )
            .private_claim(
                CWT_CLAIM_SEC_FLAGS,
                Value::Bytes(self.claims.sec_flags().to_be_bytes().to_vec()),
            )
            .build())
    }
}

/// Claims carried by an Authenticator Assertion Token.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatorAssertionClaims {
    /// The `rpId` of the requesting RP (CWT `aud`); MUST be in `[2^16, 2^32)`.
    pub aud: RpId,
    /// Expiration as seconds since the Unix epoch.
    pub exp: u64,
    /// The `ProofRequest` nonce binding the token to a specific request.
    pub nonce: FieldElement,
    /// Client data hash: an arbitrary commitment binding the token to its
    /// upstream use case. A nil value is 32 zero bytes.
    pub cdh: FieldElement,
    /// Structured integrity metadata for the proof.
    pub authenticator_meta: AuthenticatorMeta,
}

/// An Authenticator Assertion Token (AAT, WIP-106): the outer EAT signed by the
/// `assertion_key` with `ES256`, carrying the Trust Anchor Key Token that
/// attests that key in its unprotected header.
///
/// Construct with [`AuthenticatorAssertionToken::new`];
/// [`AuthenticatorAssertionToken::sign`] signs the token with the
/// `assertion_key` and serializes it.
#[derive(Debug, Clone)]
pub struct AuthenticatorAssertionToken {
    claims: AuthenticatorAssertionClaims,
    /// Serialized `COSE_Sign1` Trust Anchor Key Token, carried in the
    /// unprotected header and therefore outside the AAT signature.
    trust_anchor_key_token: Vec<u8>,
    /// Coordinates of the assertion key attested by the Trust Anchor Key
    /// Token's `cnf` claim; the signing key must match.
    attested_key: ([u8; 32], [u8; 32]),
}

impl AuthenticatorAssertionToken {
    /// Creates an Authenticator Assertion Token from validated claims and a
    /// signed Trust Anchor Key Token (as produced by
    /// [`TrustAnchorKeyToken::sign`]).
    ///
    /// # Errors
    /// - [`AttestationError::ProviderBitsTooLarge`] if the `authenticator_meta`
    ///   provider bits carry more than 2 bits.
    /// - [`AttestationError::AudOutOfRange`] if `aud` cannot use the fixed
    ///   4-byte CBOR encoding.
    /// - [`AttestationError::ExpirationOutOfRange`] if `exp` is not a valid CWT
    ///   numeric date.
    /// - [`AttestationError::InvalidTrustAnchorKeyToken`] if the Trust Anchor
    ///   Key Token cannot be parsed or carries no `cnf` claim.
    pub fn new(
        claims: AuthenticatorAssertionClaims,
        trust_anchor_key_token: Vec<u8>,
    ) -> Result<Self, AttestationError> {
        if claims.authenticator_meta.provider_bits > MAX_PROVIDER_BITS {
            return Err(AttestationError::ProviderBitsTooLarge(
                claims.authenticator_meta.provider_bits,
            ));
        }
        let aud = claims.aud.into_inner();
        if u16::try_from(aud).is_ok() || u32::try_from(aud).is_err() {
            return Err(AttestationError::AudOutOfRange(aud));
        }
        if i64::try_from(claims.exp).is_err() {
            return Err(AttestationError::ExpirationOutOfRange(claims.exp));
        }
        let attested_key = attested_key_coordinates(&trust_anchor_key_token)?;
        Ok(Self {
            claims,
            trust_anchor_key_token,
            attested_key,
        })
    }

    /// Signs the token with the `assertion_key` and serializes it as an untagged
    /// `COSE_Sign1` structure in deterministic CBOR.
    ///
    /// Unlike the Trust Anchor Key Token, the signature is a standard COSE
    /// `ES256` signature over the `Sig_structure` (RFC 9052 §4.4) with an empty
    /// `external_aad`, encoded as `r || s` (low-S normalized).
    ///
    /// # Errors
    /// - [`AttestationError::AssertionKeyMismatch`] if `assertion_key` is not the
    ///   key attested by the Trust Anchor Key Token's `cnf` claim.
    /// - [`AttestationError::CborEncoding`] on serialization failure.
    pub fn sign(&self, assertion_key: &p256::SecretKey) -> Result<Vec<u8>, AttestationError> {
        if assertion_key_coordinates(&assertion_key.public_key())? != self.attested_key {
            return Err(AttestationError::AssertionKeyMismatch);
        }
        let signing_key = p256::ecdsa::SigningKey::from(assertion_key);
        let protected = Header {
            alg: Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256)),
            ..Header::default()
        };
        // The TAKT rides in the *unprotected* header, so it is not covered by
        // this signature (WIP-106 AAT section 6). It is self-authenticating via
        // its own `trust_anchor_key` signature, and bound to this token solely
        // by the shared `assertion_key` — enforced above and re-checked
        // in-circuit. This mirrors RFC 9360's X.509 chain placement, and keeps
        // the signed payload free of the TAKT's bytes so verifying circuits
        // never have to reserialize it.
        let unprotected = Header {
            rest: vec![(
                Label::Text(HEADER_TAKT.to_string()),
                Value::Bytes(self.trust_anchor_key_token.clone()),
            )],
            ..Header::default()
        };
        CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(self.encode_claims()?)
            .create_signature(&[], |message| {
                let signature: p256::ecdsa::Signature = signing_key.sign(message);
                // Low-S normalization: mandated by WIP-106; removes ECDSA
                // malleability and matches verifiers that reject high-S
                // signatures (e.g. Noir's ecdsa gadgets).
                let signature = signature.normalize_s().unwrap_or(signature);
                signature.to_bytes().to_vec()
            })
            .build()
            .to_vec()
            .map_err(|e| AttestationError::CborEncoding(e.to_string()))
    }

    /// Encodes the CWT claims set as a deterministic CBOR map.
    ///
    /// Claims are inserted in deterministic CBOR map-key order ([RFC 8949 §4.2](https://datatracker.ietf.org/doc/html/rfc8949#section-4.2))
    /// so the proving circuit can use constant offsets. The map is built directly
    /// because coset's `ClaimsSet` only supports text values for `aud`, while this
    /// profile requires the `rpId`.
    fn encode_claims(&self) -> Result<Vec<u8>, AttestationError> {
        let exp = i64::try_from(self.claims.exp)
            .map_err(|_| AttestationError::ExpirationOutOfRange(self.claims.exp))?;
        let meta = FieldElement::from(self.claims.authenticator_meta.packed());
        let claims = Value::Map(vec![
            (
                Value::Integer(CWT_CLAIM_AUD.into()),
                Value::Integer(self.claims.aud.into_inner().into()),
            ),
            (
                Value::Integer(CWT_CLAIM_EXP.into()),
                Value::Integer(exp.into()),
            ),
            (
                Value::Integer(CWT_CLAIM_NONCE.into()),
                Value::Bytes(self.claims.nonce.to_be_bytes().to_vec()),
            ),
            (
                Value::Integer(CWT_CLAIM_EAT_PROFILE.into()),
                Value::Text(EAT_PROFILE_AUTHENTICATOR_ASSERTION.to_string()),
            ),
            (
                Value::Integer(CWT_CLAIM_CDH.into()),
                Value::Bytes(self.claims.cdh.to_be_bytes().to_vec()),
            ),
            (
                Value::Integer(CWT_CLAIM_AUTHENTICATOR_META.into()),
                Value::Bytes(meta.to_be_bytes().to_vec()),
            ),
        ]);
        let mut payload = Vec::new();
        coset::cbor::into_writer(&claims, &mut payload)
            .map_err(|e| AttestationError::CborEncoding(e.to_string()))?;
        Ok(payload)
    }
}

/// Extracts the attested key coordinates from the `cnf` claim of a serialized
/// Trust Anchor Key Token.
fn attested_key_coordinates(token: &[u8]) -> Result<([u8; 32], [u8; 32]), AttestationError> {
    let error = |reason: &str| AttestationError::InvalidTrustAnchorKeyToken(reason.to_string());
    let sign1 = CoseSign1::from_slice(token)
        .map_err(|e| AttestationError::InvalidTrustAnchorKeyToken(e.to_string()))?;
    let payload = sign1.payload.ok_or_else(|| error("missing payload"))?;
    let claims: Value = coset::cbor::from_reader(payload.as_slice())
        .map_err(|e| AttestationError::InvalidTrustAnchorKeyToken(e.to_string()))?;
    let entries = claims
        .as_map()
        .ok_or_else(|| error("claims set is not a CBOR map"))?;
    let cnf = entries
        .iter()
        .find(|(key, _)| key.as_integer() == Some((iana::CwtClaimName::Cnf as i64).into()))
        .map(|(_, value)| value)
        .ok_or_else(|| error("missing cnf claim"))?;
    cnf_coordinates(cnf).map_err(|e| AttestationError::InvalidTrustAnchorKeyToken(e.to_string()))
}

/// Lowers one claim value into field elements per WIP-106.
///
/// The `cnf` claim has explicit handling (see below); text claims (e.g.
/// `eat_profile`) are not field elements and are excluded from the signed
/// message; byte-string claims (e.g. `sec_flags`) are lowered as big-endian
/// integers; the rest are lowered as integers.
///
/// All conversions go through infallible `u64`/`u128` constructors so no value
/// can silently wrap around the field modulus.
fn claim_field_elements(key: &Value, value: &Value) -> Result<Vec<FieldElement>, AttestationError> {
    let claim_key = key
        .as_integer()
        .ok_or_else(|| AttestationError::ClaimHashing("claim key is not an integer".to_string()))?;

    // The `cnf` claim represents each coordinate (x, y) as a 128-bit big-endian
    // limb. Each coordinate is split into limbs as a P-256 point may exceed the
    // modulo of the BabyJubJub curve (~254 bits).
    if i128::from(claim_key) == i128::from(iana::CwtClaimName::Cnf as i64) {
        let (x, y) = cnf_coordinates(value)?;
        let [x_hi, x_lo] = coordinate_limbs(&x);
        let [y_hi, y_lo] = coordinate_limbs(&y);
        return Ok(vec![x_hi, x_lo, y_hi, y_lo]);
    }
    if value.is_text() {
        return Ok(vec![]);
    }
    if let Some(bytes) = value.as_bytes() {
        if bytes.len() > 16 {
            return Err(AttestationError::ClaimHashing(format!(
                "claim {claim_key:?} byte string is wider than 128 bits"
            )));
        }
        let mut buf = [0_u8; 16];
        buf[16 - bytes.len()..].copy_from_slice(bytes);
        return Ok(vec![FieldElement::from(u128::from_be_bytes(buf))]);
    }
    let integer = value.as_integer().ok_or_else(|| {
        AttestationError::ClaimHashing(format!("claim {claim_key:?} is not an integer"))
    })?;
    let integer = u64::try_from(i128::from(integer)).map_err(|_| {
        AttestationError::ClaimHashing(format!("claim {claim_key:?} is out of the u64 range"))
    })?;
    Ok(vec![FieldElement::from(integer)])
}

/// Splits a 32-byte big-endian coordinate into two 128-bit limbs.
fn coordinate_limbs(coordinate: &[u8; 32]) -> [FieldElement; 2] {
    let mut hi = [0_u8; 16];
    let mut lo = [0_u8; 16];
    hi.copy_from_slice(&coordinate[..16]);
    lo.copy_from_slice(&coordinate[16..]);
    [
        FieldElement::from(u128::from_be_bytes(hi)),
        FieldElement::from(u128::from_be_bytes(lo)),
    ]
}

/// Extracts the 32-byte P-256 coordinates from a `cnf` claim (`{1: COSE_Key}`).
fn cnf_coordinates(value: &Value) -> Result<([u8; 32], [u8; 32]), AttestationError> {
    let error = |reason: &str| AttestationError::ClaimHashing(format!("cnf claim: {reason}"));
    let confirmation = value.as_map().ok_or_else(|| error("not a map"))?;
    let cose_key = confirmation
        .iter()
        .find(|(label, _)| label.as_integer() == Some(CNF_COSE_KEY.into()))
        .and_then(|(_, key)| key.as_map())
        .ok_or_else(|| error("missing COSE_Key confirmation method"))?;
    let coordinate = |label: i64| {
        cose_key
            .iter()
            .find(|(l, _)| l.as_integer() == Some(label.into()))
            .and_then(|(_, v)| v.as_bytes())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .ok_or_else(|| error("missing 32-byte coordinate"))
    };
    Ok((
        coordinate(iana::Ec2KeyParameter::X as i64)?,
        coordinate(iana::Ec2KeyParameter::Y as i64)?,
    ))
}

/// Extracts the big-endian affine coordinates of the assertion key.
fn assertion_key_coordinates(
    assertion_key: &p256::PublicKey,
) -> Result<([u8; 32], [u8; 32]), AttestationError> {
    let point = assertion_key.to_encoded_point(false);
    let x = point.x().ok_or(AttestationError::InvalidAssertionKey)?;
    let y = point.y().ok_or(AttestationError::InvalidAssertionKey)?;
    Ok(((*x).into(), (*y).into()))
}

#[cfg(test)]
mod tests;
