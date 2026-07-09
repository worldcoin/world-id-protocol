//! Authenticator Attestations (WIP-106).

use coset::{
    AsCborValue, CborSerializable, CoseKeyBuilder, CoseSign1Builder, Header,
    RegisteredLabelWithPrivate,
    cbor::value::Value,
    cwt::{ClaimsSet, ClaimsSetBuilder, Timestamp},
    iana,
};
use eddsa_babyjubjub::EdDSAPrivateKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use world_id_primitives::FieldElement;

/// COSE algorithm identifier for `BabyJubJub-EdDSA-Poseidon2` (defined in WIP-106).
pub const COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2: i64 = -65537;

/// `eat_profile` claim value (RFC 9711 §4.3.2) identifying the Root of Trust Token format.
///
/// URI identifying the full EAT profile the token conforms to. For a Root of Trust
/// Token, hashing is done with Poseidon2 and signatures with EdDSA over the
/// BabyJubJub curve.
pub const EAT_PROFILE_ROOT_OF_TRUST: &str = "https://worldcoin.org/eat/rot/v1";

/// Maximum value for `sec_meta`, which MUST carry at most 2 bits of data.
pub const MAX_SEC_META: u8 = 0x3;

/// Domain separator for the Root of Trust Token `Poseidon2` message hash.
const ROOT_OF_TRUST_DS: &[u8] = b"WORLD_ID_WIP106_ROOT_OF_TRUST_V1";

/// CWT claim key for `sec_level`.
const CWT_CLAIM_SEC_LEVEL: i64 = -70_000;
/// CWT claim key for `platform`.
const CWT_CLAIM_PLATFORM: i64 = -70_001;
/// CWT claim key for `build_version`.
const CWT_CLAIM_BUILD_VERSION: i64 = -70_003;
/// CWT claim key for `sec_meta`.
const CWT_CLAIM_SEC_META: i64 = -70_005;

/// `cnf` confirmation method label for a `COSE_Key` (RFC 8747 §3.1).
const CNF_COSE_KEY: i64 = 1;

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

/// Claims carried by a Root of Trust Token.
#[derive(Debug, Clone, Copy)]
pub struct RootOfTrustClaims {
    /// Expiration as seconds since the Unix epoch.
    pub exp: u64,
    /// The attested `assertion_key`, carried as a `COSE_Key` in the `cnf` claim.
    pub assertion_key: p256::PublicKey,
    /// Security level of the `assertion_key`.
    pub sec_level: SecLevel,
    /// Host platform where the proof is generated.
    pub platform: Platform,
    /// Monotonic build version defined by the Authenticator Provider.
    pub build_version: u64,
    /// Provider-defined integrity metadata; MUST carry at most 2 bits.
    pub sec_meta: u8,
}

/// Errors that can occur when generating an attestation token.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// The assertion key could not be converted to affine coordinates.
    #[error("assertion key is not a valid P-256 point")]
    InvalidAssertionKey,
    /// `sec_meta` exceeds the 2-bit limit mandated by WIP-106.
    #[error("sec_meta must carry at most 2 bits of data, got {0:#b}")]
    SecMetaTooLarge(u8),
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
}

/// A Root of Trust Token (WIP-106): an EAT attesting an `assertion_key` through
/// the `cnf` claim.
///
/// Construct with [`RootOfTrustToken::new`]; [`RootOfTrustToken::sign`] signs the
/// token with the Authenticator Provider's `root_of_trust` key and serializes it.
#[derive(Debug, Clone)]
pub struct RootOfTrustToken {
    claims: RootOfTrustClaims,
}

impl RootOfTrustToken {
    /// Creates a Root of Trust Token from validated claims.
    ///
    /// # Errors
    /// - [`AttestationError::SecMetaTooLarge`] if `sec_meta` carries more than 2 bits.
    /// - [`AttestationError::ExpirationOutOfRange`] if `exp` is not a valid CWT numeric date.
    pub fn new(claims: RootOfTrustClaims) -> Result<Self, AttestationError> {
        if claims.sec_meta > MAX_SEC_META {
            return Err(AttestationError::SecMetaTooLarge(claims.sec_meta));
        }
        if i64::try_from(claims.exp).is_err() {
            return Err(AttestationError::ExpirationOutOfRange(claims.exp));
        }
        Ok(Self { claims })
    }

    /// Computes the digest of the token to be signed by the `root_of_trust` key.
    ///
    /// The message is derived from the encoded claims set: each claim value in deterministic
    /// CBOR map-key order (RFC 8949 §4.2.1) is lowered into zero or more field
    /// elements (see [`claim_field_elements`]; non-field-element claims such as
    /// `eat_profile` are excluded per WIP-106), preceded by a domain-separator
    /// element.
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

        let mut state = [*FieldElement::ZERO; 16];
        // Reduction is intentional here: the domain separator is an arbitrary
        // 32-byte tag, not a canonical field-element encoding.
        state[0] = *FieldElement::from_be_bytes_mod_order(ROOT_OF_TRUST_DS);
        let mut slot = 1;
        for (key, value) in &entries {
            for element in claim_field_elements(key, value)? {
                let Some(target) = state.get_mut(slot) else {
                    return Err(AttestationError::ClaimHashing(
                        "claim values exceed the Poseidon2 t16 width".to_string(),
                    ));
                };
                *target = *element;
                slot += 1;
            }
        }
        poseidon2::bn254::t16::permutation_in_place(&mut state);
        Ok(state[1].into())
    }

    /// Signs the token with the Authenticator Provider's `root_of_trust` key and
    /// serializes it as an untagged `COSE_Sign1` structure in deterministic CBOR.
    ///
    /// The protected header carries the `BabyJubJub-EdDSA-Poseidon2` algorithm and
    /// the `kid` (compressed `root_of_trust` public key); the signature field
    /// carries the EdDSA signature over [`RootOfTrustToken::message_hash`] as
    /// `R || S`.
    ///
    /// # Errors
    /// - [`AttestationError::KeyEncoding`] on key serialization failure.
    /// - [`AttestationError::CborEncoding`] on serialization failure.
    pub fn sign(&self, root_key: &EdDSAPrivateKey) -> Result<Vec<u8>, AttestationError> {
        let signature = root_key
            .sign(*self.message_hash()?)
            .to_compressed_bytes()
            .map_err(|e| AttestationError::KeyEncoding(e.to_string()))?;
        let kid = root_key
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
    /// so the proving circuit can use constant offsets.
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
                Value::Text(EAT_PROFILE_ROOT_OF_TRUST.to_string()),
            )
            .private_claim(
                CWT_CLAIM_SEC_LEVEL,
                Value::Integer((self.claims.sec_level as u64).into()),
            )
            .private_claim(
                CWT_CLAIM_PLATFORM,
                Value::Integer((self.claims.platform as u64).into()),
            )
            .private_claim(
                CWT_CLAIM_BUILD_VERSION,
                Value::Integer(self.claims.build_version.into()),
            )
            .private_claim(
                CWT_CLAIM_SEC_META,
                Value::Integer(self.claims.sec_meta.into()),
            )
            .build())
    }
}

/// Lowers one claim value into field elements per WIP-106.
///
/// The `cnf` claim has explicit handling (see below), text claims (e.g.
/// `eat_profile`) are not field elements and are excluded from the signed
/// message per WIP-106, and the rest are lowered as integers.
///
/// All conversions go through infallible `u64`/`u128` constructors so no value can
/// silently wrap around the field modulus.
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
