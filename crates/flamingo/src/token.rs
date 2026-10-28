//! The Flamingo Token: a CWT in an untagged `COSE_Sign1` over a Poseidon2 digest.
//!
//! The signature covers [`FlamingoClaims::digest`], not the COSE `Sig_structure`, so a circuit
//! verifies the token without parsing CBOR.

use coset::{Header, RegisteredLabelWithPrivate};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};
use world_id_primitives::{
    FieldElement,
    cbor::{self, CLAIM_EAT_PROFILE, CborError, Fields, Value},
    poseidon,
};

use crate::DS_SIGN;

/// The `eat_profile` claim of every Flamingo Token.
pub const EAT_PROFILE: &str = "https://world.org/eat/flamingo/v1";
/// Compared entries a token carries.
pub const MAX_COMPARED: usize = 4;

/// `compared_entry_hash_k` is `CLAIM_COMPARED_ENTRY_HASH - k`.
const CLAIM_COMPARED_ENTRY_HASH: i64 = -90_000;
const CLAIM_AUD: i64 = -90_004;
const CLAIM_NONCE: i64 = -90_005;
const CLAIM_TRUST_ANCHOR_KEY_HASH: i64 = -90_006;
const CLAIM_AAT_FLAGS: i64 = -90_007;
const CLAIM_HAS_AAT: i64 = -90_008;
const CLAIM_NOW: i64 = -90_009;
const CLAIM_ENGINE_CONFIG_HASH: i64 = -90_010;
const CLAIM_BILLING_NULLIFIER: i64 = -90_011;

/// Why a Flamingo Token could not be built or verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// The bytes are not the canonical encoding of a Flamingo Token.
    #[error("not a canonical Flamingo Token encoding")]
    Malformed,
    /// The protected header names another algorithm.
    #[error("unexpected COSE algorithm")]
    UnexpectedAlgorithm,
    /// The token's `kid` is not the given key.
    #[error("Flamingo Token kid does not match the key")]
    KeyMismatch,
    /// The signature does not verify under the given key.
    #[error("invalid Flamingo Token signature")]
    SignatureInvalid,
    /// Key, signature or CBOR could not be encoded.
    #[error("encoding failed")]
    Encoding,
}

/// The public values of a verified AAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlamingoAatClaims {
    /// WIP-106 hash of the `trust_anchor_key` that signed the TAKT.
    pub trust_anchor_key_hash: FieldElement,
    /// `sec_flags` layout with `min_build_version` in place of `build_version`, and
    /// `authenticator_meta` in bits 52-56.
    pub aat_flags: u64,
    /// The AAT's `now`, in seconds since the Unix epoch.
    pub now: u32,
}

impl FlamingoAatClaims {
    /// The values a token carries without an AAT.
    const ZERO: Self = Self {
        trust_anchor_key_hash: FieldElement::ZERO,
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
    pub aat: Option<FlamingoAatClaims>,
    /// See [`engine_config_hash`](crate::engine_config_hash).
    pub engine_config_hash: FieldElement,
    /// The WIP-107 `billingNullifier` the Verifier checked, or `0` for an RP it does not bill.
    pub billing_nullifier: FieldElement,
}

impl FlamingoClaims {
    /// The signed digest, `H_16(DS_SIGN; now, compared_entry_hash_0..3, aud, nonce,
    /// trust_anchor_key_hash, aat_flags, has_aat, engine_config_hash, billing_nullifier)`.
    #[must_use]
    pub fn digest(&self) -> FieldElement {
        let aat = self.aat.unwrap_or(FlamingoAatClaims::ZERO);
        let [c0, c1, c2, c3] = self.compared_entry_hashes;
        // The last three rate slots of the `t=16` state stay zero.
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
                aat.trust_anchor_key_hash,
                aat.aat_flags.into(),
                u64::from(self.aat.is_some()).into(),
                self.engine_config_hash,
                self.billing_nullifier,
                zero,
                zero,
                zero,
            ],
        )
    }

    fn payload(&self) -> Vec<u8> {
        let field = |key: i64, value: FieldElement| (key.into(), cbor::field_element(value));
        let uint = |key: i64, value: u64| (key.into(), Value::Integer(value.into()));
        let aat = self.aat.unwrap_or(FlamingoAatClaims::ZERO);

        let mut entries = vec![(CLAIM_EAT_PROFILE.into(), Value::Text(EAT_PROFILE.into()))];
        entries.extend(
            (0i64..)
                .zip(self.compared_entry_hashes)
                .map(|(k, hash)| field(CLAIM_COMPARED_ENTRY_HASH - k, hash)),
        );
        entries.extend([
            field(CLAIM_AUD, self.aud),
            field(CLAIM_NONCE, self.nonce),
            field(CLAIM_TRUST_ANCHOR_KEY_HASH, aat.trust_anchor_key_hash),
            uint(CLAIM_AAT_FLAGS, aat.aat_flags),
            uint(CLAIM_HAS_AAT, u64::from(self.aat.is_some())),
            uint(CLAIM_NOW, u64::from(aat.now)),
            field(CLAIM_ENGINE_CONFIG_HASH, self.engine_config_hash),
            field(CLAIM_BILLING_NULLIFIER, self.billing_nullifier),
        ]);
        cbor::encode(&cbor::map(entries))
    }

    /// Reads the claims set in canonical key order: 265, then the negative keys by magnitude.
    fn from_value(value: Value) -> Result<Self, TokenError> {
        let mut claims = Fields::of(value, "Flamingo Token claims")?;
        claims.text(CLAIM_EAT_PROFILE, EAT_PROFILE)?;
        let mut compared_entry_hashes = [FieldElement::ZERO; MAX_COMPARED];
        for (k, hash) in (0i64..).zip(&mut compared_entry_hashes) {
            *hash = claims.field_element(CLAIM_COMPARED_ENTRY_HASH - k)?;
        }
        let aud = claims.field_element(CLAIM_AUD)?;
        let nonce = claims.field_element(CLAIM_NONCE)?;
        let trust_anchor_key_hash = claims.field_element(CLAIM_TRUST_ANCHOR_KEY_HASH)?;
        let aat_flags = claims.uint(CLAIM_AAT_FLAGS)?;
        let has_aat: u8 = claims.uint(CLAIM_HAS_AAT)?;
        let now = claims.uint(CLAIM_NOW)?;
        let engine_config_hash = claims.field_element(CLAIM_ENGINE_CONFIG_HASH)?;
        let billing_nullifier = claims.field_element(CLAIM_BILLING_NULLIFIER)?;
        claims.finish()?;

        let aat = FlamingoAatClaims {
            trust_anchor_key_hash,
            aat_flags,
            now,
        };
        let aat = match has_aat {
            1 => Some(aat),
            0 if aat == FlamingoAatClaims::ZERO => None,
            _ => return Err(TokenError::Malformed),
        };
        Ok(Self {
            compared_entry_hashes,
            aud,
            nonce,
            aat,
            engine_config_hash,
            billing_nullifier,
        })
    }
}

/// A signed Flamingo Token (WIP-201 §3.6). Decoded and canonical; verify it before trusting the
/// claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlamingoToken {
    claims: FlamingoClaims,
    /// Compressed signing public key, the protected header's `kid`.
    kid: [u8; 32],
    /// Compressed `EdDSA` signature over [`FlamingoClaims::digest`].
    signature: [u8; 64],
}

impl FlamingoToken {
    /// Signs `claims` with the Verifier's signing key.
    ///
    /// # Errors
    /// [`TokenError::Encoding`] if the key or signature cannot be compressed.
    pub fn sign(claims: FlamingoClaims, signing_key: &EdDSAPrivateKey) -> Result<Self, TokenError> {
        Ok(Self {
            claims,
            kid: signing_key
                .public()
                .to_compressed_bytes()
                .map_err(|_| TokenError::Encoding)?,
            signature: signing_key
                .sign(*claims.digest())
                .to_compressed_bytes()
                .map_err(|_| TokenError::Encoding)?,
        })
    }

    /// The claims, unverified. Use [`Self::verify`] to check them.
    #[must_use]
    pub const fn claims(&self) -> &FlamingoClaims {
        &self.claims
    }

    /// The `kid`: the compressed key that signed the token.
    #[must_use]
    pub const fn kid(&self) -> [u8; 32] {
        self.kid
    }

    /// The CWT encoding: protected header `{1: -65537, 4: kid}`, an empty unprotected header, the
    /// claims set and the compressed signature.
    ///
    /// # Errors
    /// [`TokenError::Encoding`] if the protected header cannot be encoded.
    pub fn to_cwt(&self) -> Result<Vec<u8>, TokenError> {
        let protected = Header {
            alg: Some(RegisteredLabelWithPrivate::PrivateUse(
                cbor::COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2,
            )),
            key_id: self.kid.to_vec(),
            ..Header::default()
        };
        cbor::encode_sign1(protected, self.claims.payload(), self.signature.to_vec())
            .map_err(|_| TokenError::Encoding)
    }

    /// Decodes a token from its CWT encoding, rejecting anything but the canonical encoding. Does
    /// not verify the signature.
    ///
    /// # Errors
    /// [`TokenError::UnexpectedAlgorithm`] for another `alg`, [`TokenError::Malformed`] for any
    /// other encoding.
    pub fn from_cwt(cwt: &[u8]) -> Result<Self, TokenError> {
        let (protected, payload, signature) = cbor::decode_sign1(cwt, ..)?;
        if protected.alg
            != Some(RegisteredLabelWithPrivate::PrivateUse(
                cbor::COSE_ALG_BABYJUBJUB_EDDSA_POSEIDON2,
            ))
        {
            return Err(TokenError::UnexpectedAlgorithm);
        }
        let kid: [u8; 32] = protected
            .key_id
            .try_into()
            .map_err(|_| TokenError::Malformed)?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| TokenError::Malformed)?;
        EdDSASignature::from_compressed_bytes(signature).map_err(|_| TokenError::Malformed)?;
        let token = Self {
            claims: FlamingoClaims::from_value(payload)?,
            kid,
            signature,
        };
        // Other header parameters and non-canonical CBOR fail the re-encoding check.
        if token.to_cwt()? != cwt {
            return Err(TokenError::Malformed);
        }
        Ok(token)
    }

    /// Verifies the token under `signing_public_key` and returns its claims.
    ///
    /// # Errors
    /// [`TokenError::KeyMismatch`] if `kid` is another key's, [`TokenError::SignatureInvalid`] if
    /// the signature does not verify.
    pub fn verify(
        &self,
        signing_public_key: &EdDSAPublicKey,
    ) -> Result<&FlamingoClaims, TokenError> {
        if signing_public_key.to_compressed_bytes().ok() != Some(self.kid) {
            return Err(TokenError::KeyMismatch);
        }
        let signature = EdDSASignature::from_compressed_bytes(self.signature)
            .map_err(|_| TokenError::SignatureInvalid)?;
        if !signing_public_key.verify(*self.claims.digest(), &signature) {
            return Err(TokenError::SignatureInvalid);
        }
        Ok(&self.claims)
    }
}

impl From<CborError> for TokenError {
    fn from(_: CborError) -> Self {
        Self::Malformed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DS_ENGINE, engine_config_hash};
    use coset::{CborSerializable as _, CoseSign1, CoseSign1Builder};
    use sha2::{Digest, Sha256};

    // WIP-201 Appendix A1.
    const ENGINE_CONFIG_HASH: &str =
        "2f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d";
    const TRUST_ANCHOR_KEY_HASH: &str =
        "14b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d8";
    const DIGEST_WITH_AAT: &str =
        "137d97fa13ab493e7cfb9f732abd43e5808e8c7ac5b0353973c944e871293c50";
    const DIGEST_WITHOUT_AAT: &str =
        "108e2e05c6330f9c3feafd0aa64f213ca71b8573aa71705e8c9b4490c7e2a494";
    // The digests and CWTs follow the 12-input `SIGN2` digest and come from this implementation;
    // Appendix A1 still lists the 11-input values. The billed vector signs `billing_nullifier = 7`
    // over the AAT claims.
    const DIGEST_BILLED: &str = "154bc1daab533df76072bdd1c404d284008855a8717c86776e5f2c0137bd817f";
    const KID: &str = "f2d46cc6aa89d38add66256beb34e089ebd1e33951c5085b3c228ed5dd8f1c12";
    const CWT_WITH_AAT: &str = "84582aa2013a00010000045820f2d46cc6aa89d38add66256beb34e089ebd1e33951c5085b3c228ed5dd8f1c12a05901a4ad190109782168747470733a2f2f776f726c642e6f72672f6561742f666c616d696e676f2f76313a00015f8f582021e9fe96ff18807a727830c56281c96af824005400bcb8ef0f463b34cb20c4153a00015f905820010cff8544f0007179c076ddb49de551bd5743797bfe05cb3b26f55c696f507b3a00015f9158202abb4a81875eb0e308f0fbfb8c0a0f57e77243e095b145ae7973e0b2771e044d3a00015f92582000000000000000000000000000000000000000000000000000000000000000003a00015f93582000000000000000000000000000000000000000000000000000000000001d6bb63a00015f945820000000000000000000000000000000000000000000000000000000000000002a3a00015f95582014b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d83a00015f961b00a3000007d601023a00015f97013a00015f981a6a4d39f03a00015f9958202f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d3a00015f9a5820000000000000000000000000000000000000000000000000000000000000000058405271d485d07872b7d354123c8d6122fee09a7d5f0d6cff8e0101bd5693e4c2aaa8edebb6384ef1ecee2fbfa85a2d089e5cf8899505a846c042628057053c2c01";
    const CWT_WITHOUT_AAT: &str = "84582aa2013a00010000045820f2d46cc6aa89d38add66256beb34e089ebd1e33951c5085b3c228ed5dd8f1c12a0590198ad190109782168747470733a2f2f776f726c642e6f72672f6561742f666c616d696e676f2f76313a00015f8f582021e9fe96ff18807a727830c56281c96af824005400bcb8ef0f463b34cb20c4153a00015f905820010cff8544f0007179c076ddb49de551bd5743797bfe05cb3b26f55c696f507b3a00015f9158202abb4a81875eb0e308f0fbfb8c0a0f57e77243e095b145ae7973e0b2771e044d3a00015f92582000000000000000000000000000000000000000000000000000000000000000003a00015f93582000000000000000000000000000000000000000000000000000000000001d6bb63a00015f945820000000000000000000000000000000000000000000000000000000000000002a3a00015f95582000000000000000000000000000000000000000000000000000000000000000003a00015f96003a00015f97003a00015f98003a00015f9958202f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d3a00015f9a582000000000000000000000000000000000000000000000000000000000000000005840633facb3212adcd28cc2df0399767911256a2900381968899bdc890e77804c9009249d1460843d05c81dd2512caed792c1155738473915fb507af993f3d2a601";
    const CWT_BILLED: &str = "84582aa2013a00010000045820f2d46cc6aa89d38add66256beb34e089ebd1e33951c5085b3c228ed5dd8f1c12a05901a4ad190109782168747470733a2f2f776f726c642e6f72672f6561742f666c616d696e676f2f76313a00015f8f582021e9fe96ff18807a727830c56281c96af824005400bcb8ef0f463b34cb20c4153a00015f905820010cff8544f0007179c076ddb49de551bd5743797bfe05cb3b26f55c696f507b3a00015f9158202abb4a81875eb0e308f0fbfb8c0a0f57e77243e095b145ae7973e0b2771e044d3a00015f92582000000000000000000000000000000000000000000000000000000000000000003a00015f93582000000000000000000000000000000000000000000000000000000000001d6bb63a00015f945820000000000000000000000000000000000000000000000000000000000000002a3a00015f95582014b904063236db16ecda3a3fa9aaa42b3f605706baa2fdb25afeab8df8f252d83a00015f961b00a3000007d601023a00015f97013a00015f981a6a4d39f03a00015f9958202f0bcb30b9051ec78ed6ac1bb206c612546c6ad9872ad0463e55984e2c78ad1d3a00015f9a58200000000000000000000000000000000000000000000000000000000000000007584051976fd09f1b8095620f3e0e2a581a856fab5940a0c86da80def14c0e44bac8a5c8a8bd6d27c3797d3d8889f5dfe2dea5ab774611f315c8334d2f644c9a74e02";

    fn hex_field(hex: &str) -> FieldElement {
        FieldElement::from_be_bytes(&hex::decode(hex).unwrap().try_into().unwrap()).unwrap()
    }

    fn sha256_field(bytes: &[u8]) -> FieldElement {
        FieldElement::from_digest(&Sha256::digest(bytes).into())
    }

    fn signing_key() -> EdDSAPrivateKey {
        EdDSAPrivateKey::from_bytes([0x15; 32])
    }

    fn claims(aat: Option<FlamingoAatClaims>) -> FlamingoClaims {
        FlamingoClaims {
            compared_entry_hashes: [
                sha256_field(b"credential image"),
                sha256_field(b"live image"),
                sha256_field(b"challenge image"),
                FieldElement::ZERO,
            ],
            aud: 1_928_118u64.into(),
            nonce: 42u64.into(),
            aat,
            engine_config_hash: hex_field(ENGINE_CONFIG_HASH),
            billing_nullifier: FieldElement::ZERO,
        }
    }

    fn with_aat() -> FlamingoClaims {
        claims(Some(FlamingoAatClaims {
            trust_anchor_key_hash: hex_field(TRUST_ANCHOR_KEY_HASH),
            aat_flags: 0x00a3_0000_07d6_0102,
            now: 1_783_446_000,
        }))
    }

    fn sign(claims: &FlamingoClaims) -> FlamingoToken {
        FlamingoToken::sign(*claims, &signing_key()).unwrap()
    }

    /// Decodes and verifies `cwt` under the test signing key.
    fn verify(cwt: &[u8]) -> Result<FlamingoClaims, TokenError> {
        FlamingoToken::from_cwt(cwt)?
            .verify(&signing_key().public())
            .copied()
    }

    #[test]
    fn domain_separators_match_the_spec() {
        assert_eq!(
            (*DS_SIGN.as_field_element()).to_string(),
            "32666492934021899305490112043451072005703909679517234"
        );
        assert_eq!(
            (*DS_ENGINE.as_field_element()).to_string(),
            "8362622191109606222205468683123474433460185506268139077"
        );
    }

    #[test]
    fn engine_config_hash_matches_the_vector() {
        assert_eq!(
            engine_config_hash(&[0x2a; 32], 1, 2),
            hex_field(ENGINE_CONFIG_HASH)
        );
    }

    #[test]
    fn tokens_match_the_vectors() {
        assert_eq!(
            hex::encode(signing_key().public().to_compressed_bytes().unwrap()),
            KID
        );
        for (claims, digest, cwt) in [
            (with_aat(), DIGEST_WITH_AAT, CWT_WITH_AAT),
            (claims(None), DIGEST_WITHOUT_AAT, CWT_WITHOUT_AAT),
            (
                FlamingoClaims {
                    billing_nullifier: 7u64.into(),
                    ..with_aat()
                },
                DIGEST_BILLED,
                CWT_BILLED,
            ),
        ] {
            assert_eq!(claims.digest(), hex_field(digest));
            let token = sign(&claims);
            assert_eq!(hex::encode(token.to_cwt().unwrap()), cwt);
            assert_eq!(FlamingoToken::from_cwt(&token.to_cwt().unwrap()), Ok(token));
            assert_eq!(verify(&hex::decode(cwt).unwrap()), Ok(claims));
        }
    }

    #[test]
    fn rejects_another_key() {
        let other = EdDSAPrivateKey::from_bytes([0x16; 32]).public();
        assert_eq!(
            sign(&with_aat()).verify(&other),
            Err(TokenError::KeyMismatch)
        );
    }

    #[test]
    fn every_claim_is_in_the_digest() {
        let base = with_aat();
        let one = FieldElement::ONE;
        let aat = base.aat.unwrap();
        let mut changed = vec![
            FlamingoClaims { aud: one, ..base },
            FlamingoClaims { nonce: one, ..base },
            FlamingoClaims {
                engine_config_hash: one,
                ..base
            },
            FlamingoClaims { aat: None, ..base },
            FlamingoClaims {
                billing_nullifier: one,
                ..base
            },
        ];
        for k in 0..MAX_COMPARED {
            let mut claims = base;
            claims.compared_entry_hashes[k] = one;
            changed.push(claims);
        }
        for aat in [
            FlamingoAatClaims {
                trust_anchor_key_hash: one,
                ..aat
            },
            FlamingoAatClaims {
                aat_flags: 1,
                ..aat
            },
            FlamingoAatClaims { now: 1, ..aat },
        ] {
            changed.push(FlamingoClaims {
                aat: Some(aat),
                ..base
            });
        }
        for claims in changed {
            assert_ne!(claims.digest(), base.digest());
        }
    }

    /// Re-encodes a valid token with `payload` in place of its claims.
    fn resign(payload: Vec<(Value, Value)>) -> Vec<u8> {
        let sign1 = CoseSign1::from_slice(&sign(&with_aat()).to_cwt().unwrap()).unwrap();
        let mut encoded = Vec::new();
        coset::cbor::into_writer(&Value::Map(payload), &mut encoded).unwrap();
        CoseSign1Builder::new()
            .protected(sign1.protected.header)
            .payload(encoded)
            .signature(sign1.signature)
            .build()
            .to_vec()
            .unwrap()
    }

    fn payload(claims: &FlamingoClaims) -> Vec<(Value, Value)> {
        coset::cbor::from_reader::<Value, _>(claims.payload().as_slice())
            .unwrap()
            .into_map()
            .unwrap()
    }

    #[test]
    fn rejects_payloads_that_are_not_the_exact_claim_set() {
        let mut extra = payload(&with_aat());
        extra.push((Value::Integer(1.into()), Value::Integer(1.into())));
        let mut reordered = payload(&with_aat());
        reordered.swap(1, 2);
        let mut profile = payload(&with_aat());
        profile[0].1 = Value::Text("https://example.org".into());
        let mut missing = payload(&with_aat());
        missing.pop();
        let mut has_aat = payload(&with_aat());
        has_aat[9].1 = Value::Integer(2.into());
        let mut stray_aat = payload(&claims(None));
        stray_aat[10].1 = Value::Integer(1.into());
        let mut non_canonical = payload(&with_aat());
        non_canonical[5].1 = Value::Bytes(vec![0xff; 32]);

        for payload in [
            extra,
            reordered,
            profile,
            missing,
            has_aat,
            stray_aat,
            non_canonical,
        ] {
            assert_eq!(
                FlamingoToken::from_cwt(&resign(payload)),
                Err(TokenError::Malformed)
            );
        }
    }

    #[test]
    fn rejects_another_algorithm() {
        let mut sign1 = CoseSign1::from_slice(&sign(&with_aat()).to_cwt().unwrap()).unwrap();
        sign1.protected.header.alg = Some(RegisteredLabelWithPrivate::PrivateUse(-65538));
        sign1.protected.original_data = None;
        assert_eq!(
            FlamingoToken::from_cwt(&sign1.to_vec().unwrap()),
            Err(TokenError::UnexpectedAlgorithm)
        );
    }

    #[test]
    fn rejects_an_altered_envelope() {
        let mut unprotected = CoseSign1::from_slice(&sign(&with_aat()).to_cwt().unwrap()).unwrap();
        unprotected.unprotected.key_id = vec![1];
        let mut short_kid = CoseSign1::from_slice(&sign(&with_aat()).to_cwt().unwrap()).unwrap();
        short_kid.protected.header.key_id = vec![0; 31];
        short_kid.protected.original_data = None;
        for sign1 in [unprotected, short_kid] {
            assert_eq!(
                FlamingoToken::from_cwt(&sign1.to_vec().unwrap()),
                Err(TokenError::Malformed)
            );
        }

        // Another well-formed kid decodes, but names another key.
        let mut kid = CoseSign1::from_slice(&sign(&with_aat()).to_cwt().unwrap()).unwrap();
        kid.protected.header.key_id = vec![0; 32];
        kid.protected.original_data = None;
        assert_eq!(verify(&kid.to_vec().unwrap()), Err(TokenError::KeyMismatch));
    }
}
