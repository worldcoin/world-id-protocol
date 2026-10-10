//! The Flamingo Token: a CWT in an untagged `COSE_Sign1` over a Poseidon2 digest.
//!
//! The signature covers [`FlamingoClaims::digest`], not the COSE `Sig_structure`, so a circuit
//! verifies the token without parsing CBOR.

use coset::{
    CborSerializable, CoseSign1, CoseSign1Builder, Header, RegisteredLabelWithPrivate,
    cbor::value::Value,
};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use world_id_primitives::{FieldElement, poseidon};

use crate::DS_SIGN;

/// COSE `alg` of a Flamingo Token (Private Use, `BabyJubJub-EdDSA-Poseidon2`).
pub const COSE_ALG_FLAMINGO_TOKEN: i64 = -65537;
/// The `eat_profile` claim of every Flamingo Token.
pub const EAT_PROFILE: &str = "https://world.org/eat/flamingo/v1";
/// Compared entries a token carries.
pub const MAX_COMPARED: usize = 4;

/// RFC 9711 `eat_profile`.
const CLAIM_EAT_PROFILE: i64 = 265;
/// `compared_entry_hash_k` is `CLAIM_COMPARED_ENTRY_HASH - k`.
const CLAIM_COMPARED_ENTRY_HASH: i64 = -90_000;
const CLAIM_AUD: i64 = -90_004;
const CLAIM_NONCE: i64 = -90_005;
const CLAIM_AUTHENTICATOR_PROVIDER_KEY_HASH: i64 = -90_006;
const CLAIM_AAT_FLAGS: i64 = -90_007;
const CLAIM_HAS_AAT: i64 = -90_008;
const CLAIM_NOW: i64 = -90_009;
const CLAIM_ENGINE_CONFIG_HASH: i64 = -90_010;

/// Why a Flamingo Token could not be built or verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// The bytes are not the canonical encoding of a Flamingo Token.
    #[error("not a canonical Flamingo Token encoding")]
    Malformed,
    /// The protected header names another algorithm.
    #[error("unexpected COSE algorithm")]
    UnexpectedAlgorithm,
    /// The signature does not verify under the given key.
    #[error("invalid Flamingo Token signature")]
    SignatureInvalid,
    /// Key, signature or CBOR could not be encoded.
    #[error("encoding failed")]
    Encoding,
}

/// The public values of a verified AAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AatClaims {
    /// WIP-106 hash of the `authenticator_provider_key`.
    pub authenticator_provider_key_hash: FieldElement,
    /// `sec_flags` layout with `min_build_version` in place of `build_version`.
    pub aat_flags: u64,
    /// The AAT's `now`, in seconds since the Unix epoch.
    pub now: u32,
}

impl AatClaims {
    /// The values a token carries without an AAT.
    const ZERO: Self = Self {
        authenticator_provider_key_hash: FieldElement::ZERO,
        aat_flags: 0,
        now: 0,
    };
}

/// The claims a Flamingo Token signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlamingoClaims {
    /// `R(SHA-256(data))` per compared entry, `0` past the last one.
    pub compared_entry_hashes: [FieldElement; MAX_COMPARED],
    /// The request's `aud`.
    pub aud: FieldElement,
    /// The request's `nonce`.
    pub nonce: FieldElement,
    /// `None` encodes `has_aat = 0` with every AAT claim zero.
    pub aat: Option<AatClaims>,
    /// See [`engine_config_hash`](crate::engine_config_hash).
    pub engine_config_hash: FieldElement,
}

impl FlamingoClaims {
    /// The signed digest, `H_16(DS_SIGN; now, compared_entry_hash_0..3, aud, nonce,
    /// authenticator_provider_key_hash, aat_flags, has_aat, engine_config_hash)`.
    #[must_use]
    pub fn digest(&self) -> FieldElement {
        let aat = self.aat.unwrap_or(AatClaims::ZERO);
        let [c0, c1, c2, c3] = self.compared_entry_hashes;
        // The last four rate slots of the `t=16` state stay zero.
        let zero = FieldElement::ZERO;
        poseidon::hash(
            DS_SIGN,
            [
                u64::from(aat.now).into(),
                c0,
                c1,
                c2,
                c3,
                self.aud,
                self.nonce,
                aat.authenticator_provider_key_hash,
                aat.aat_flags.into(),
                u64::from(self.aat.is_some()).into(),
                self.engine_config_hash,
                zero,
                zero,
                zero,
                zero,
            ],
        )
    }

    /// Signs the claims and encodes the token.
    ///
    /// # Errors
    /// Fails when the key, signature or CBOR cannot be encoded.
    pub fn sign(&self, key: &EdDSAPrivateKey) -> Result<FlamingoToken, TokenError> {
        FlamingoToken::new(self, &key.sign(*self.digest()), &key.public())
    }

    fn payload(&self) -> Result<Vec<u8>, TokenError> {
        let field = |key: i64, value: FieldElement| {
            (
                Value::Integer(key.into()),
                Value::Bytes(value.to_be_bytes().to_vec()),
            )
        };
        let uint =
            |key: i64, value: u64| (Value::Integer(key.into()), Value::Integer(value.into()));
        let aat = self.aat.unwrap_or(AatClaims::ZERO);

        // Bytewise order of the encoded keys: 265 first, then the negatives by magnitude.
        let mut entries = vec![(
            Value::Integer(CLAIM_EAT_PROFILE.into()),
            Value::Text(EAT_PROFILE.into()),
        )];
        entries.extend(
            (0i64..)
                .zip(self.compared_entry_hashes)
                .map(|(k, hash)| field(CLAIM_COMPARED_ENTRY_HASH - k, hash)),
        );
        entries.extend([
            field(CLAIM_AUD, self.aud),
            field(CLAIM_NONCE, self.nonce),
            field(
                CLAIM_AUTHENTICATOR_PROVIDER_KEY_HASH,
                aat.authenticator_provider_key_hash,
            ),
            uint(CLAIM_AAT_FLAGS, aat.aat_flags),
            uint(CLAIM_HAS_AAT, u64::from(self.aat.is_some())),
            uint(CLAIM_NOW, u64::from(aat.now)),
            field(CLAIM_ENGINE_CONFIG_HASH, self.engine_config_hash),
        ]);

        let mut encoded = Vec::new();
        coset::cbor::into_writer(&Value::Map(entries), &mut encoded)
            .map_err(|_| TokenError::Encoding)?;
        Ok(encoded)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, TokenError> {
        let value: Value = coset::cbor::from_reader(payload).map_err(|_| TokenError::Malformed)?;
        let entries = value.as_map().ok_or(TokenError::Malformed)?;
        let claim = |key: i64| {
            entries
                .iter()
                .find(|(k, _)| k.as_integer() == Some(key.into()))
                .map(|(_, v)| v)
                .ok_or(TokenError::Malformed)
        };
        // Only the canonical 32-byte big-endian encoding of a field element.
        let field = |key: i64| {
            claim(key)?
                .as_bytes()
                .and_then(|bytes| <&[u8; 32]>::try_from(bytes.as_slice()).ok())
                .and_then(|bytes| FieldElement::from_be_bytes(bytes).ok())
                .ok_or(TokenError::Malformed)
        };
        let uint = |key: i64| {
            claim(key)?
                .as_integer()
                .and_then(|value| u64::try_from(value).ok())
                .ok_or(TokenError::Malformed)
        };

        let mut compared_entry_hashes = [FieldElement::ZERO; MAX_COMPARED];
        for (k, hash) in (0i64..).zip(&mut compared_entry_hashes) {
            *hash = field(CLAIM_COMPARED_ENTRY_HASH - k)?;
        }
        let aat = AatClaims {
            authenticator_provider_key_hash: field(CLAIM_AUTHENTICATOR_PROVIDER_KEY_HASH)?,
            aat_flags: uint(CLAIM_AAT_FLAGS)?,
            now: u32::try_from(uint(CLAIM_NOW)?).map_err(|_| TokenError::Malformed)?,
        };
        let aat = match uint(CLAIM_HAS_AAT)? {
            1 => Some(aat),
            0 if aat == AatClaims::ZERO => None,
            _ => return Err(TokenError::Malformed),
        };
        let claims = Self {
            compared_entry_hashes,
            aud: field(CLAIM_AUD)?,
            nonce: field(CLAIM_NONCE)?,
            aat,
            engine_config_hash: field(CLAIM_ENGINE_CONFIG_HASH)?,
        };

        // Re-encoding pins the exact claim set, the profile and deterministic CBOR.
        if claims.payload()? != payload {
            return Err(TokenError::Malformed);
        }
        Ok(claims)
    }
}

/// The encoded `COSE_Sign1` of a Flamingo Token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlamingoToken(Vec<u8>);

impl FlamingoToken {
    /// Encodes a token from claims and a signature over their [`FlamingoClaims::digest`].
    ///
    /// # Errors
    /// Fails when the key, signature or CBOR cannot be encoded.
    pub fn new(
        claims: &FlamingoClaims,
        signature: &EdDSASignature,
        signing_public_key: &EdDSAPublicKey,
    ) -> Result<Self, TokenError> {
        let signature = signature
            .to_compressed_bytes()
            .map_err(|_| TokenError::Encoding)?;
        let key_id = signing_public_key
            .to_compressed_bytes()
            .map_err(|_| TokenError::Encoding)?;
        let protected = Header {
            alg: Some(RegisteredLabelWithPrivate::PrivateUse(
                COSE_ALG_FLAMINGO_TOKEN,
            )),
            key_id: key_id.to_vec(),
            ..Header::default()
        };

        CoseSign1Builder::new()
            .protected(protected)
            .payload(claims.payload()?)
            .signature(signature.to_vec())
            .build()
            .to_vec()
            .map(Self)
            .map_err(|_| TokenError::Encoding)
    }

    /// Wraps encoded token bytes without checking them.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrows the encoded token.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the encoded token.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Decodes the token and verifies its signature under `signing_public_key`.
    ///
    /// Accepts only the exact encoding [`Self::new`] produces, so `kid`, the headers and the
    /// signature bytes cannot be altered without invalidating the token.
    ///
    /// # Errors
    /// Fails on any framing, claim or algorithm mismatch, or an invalid signature.
    pub fn verify(
        &self,
        signing_public_key: &EdDSAPublicKey,
    ) -> Result<FlamingoClaims, TokenError> {
        let sign1 = CoseSign1::from_slice(&self.0).map_err(|_| TokenError::Malformed)?;
        match sign1.protected.header.alg {
            Some(RegisteredLabelWithPrivate::PrivateUse(COSE_ALG_FLAMINGO_TOKEN)) => {}
            _ => return Err(TokenError::UnexpectedAlgorithm),
        }

        let claims =
            FlamingoClaims::from_payload(sign1.payload.as_deref().ok_or(TokenError::Malformed)?)?;
        let signature = <[u8; 64]>::try_from(sign1.signature.as_slice())
            .ok()
            .and_then(|bytes| EdDSASignature::from_compressed_bytes(bytes).ok())
            .ok_or(TokenError::Malformed)?;

        if !signing_public_key.verify(*claims.digest(), &signature) {
            return Err(TokenError::SignatureInvalid);
        }
        // The signature covers only the claims; re-encoding pins the envelope too.
        if Self::new(&claims, &signature, signing_public_key)? != *self {
            return Err(TokenError::Malformed);
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests;
