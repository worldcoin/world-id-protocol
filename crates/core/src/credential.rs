#[cfg(feature = "issuer")]
use crate::EdDSAPrivateKey;
use crate::EdDSAPublicKey;
use eyre::bail;
use poseidon2::{Poseidon2, POSEIDON2_BN254_T16_PARAMS};

use crate::{Credential, CredentialVersion, FieldElement};

/// Introduces hashing and signing capabilities to the `Credential` type.
pub trait HashableCredential {
    /// Get the claims hash of the credential.
    ///
    /// # Errors
    /// Will error if there are more claims than the maximum allowed.
    /// Will error if the claims cannot be lowered into the field. Should not occur in practice.
    fn claims_hash(&self) -> Result<FieldElement, eyre::Error>;

    // Computes the specifically designed hash of the credential for the given version.
    ///
    /// The hash is signed by the issuer to provide authenticity for the credential.
    ///
    /// # Errors
    /// - Will error if there are more claims than the maximum allowed.
    /// - Will error if the claims cannot be lowered into the field. Should not occur in practice.
    fn hash(&self) -> Result<FieldElement, eyre::Error>;

    /// Sign the credential.
    ///
    /// # Errors
    /// Will error if the credential cannot be hashed.
    #[cfg(feature = "issuer")]
    fn sign(self, signer: &EdDSAPrivateKey) -> Result<Self, eyre::Error>
    where
        Self: Sized;

    /// Verify the signature of the credential against the issuer public key and expected hash.
    ///
    /// # Errors
    /// Will error if the credential is not signed.
    /// Will error if the credential cannot be hashed.
    fn verify_signature(
        &self,
        expected_issuer_pubkey: &EdDSAPublicKey,
    ) -> Result<bool, eyre::Error>;
}

impl HashableCredential for Credential {
    fn claims_hash(&self) -> Result<FieldElement, eyre::Error> {
        let hasher = Poseidon2::new(&POSEIDON2_BN254_T16_PARAMS);
        if self.claims.len() > Self::MAX_CLAIMS {
            bail!("There can be at most {} claims", Self::MAX_CLAIMS);
        }
        let mut input = [*FieldElement::ZERO; Self::MAX_CLAIMS];
        for (i, claim) in self.claims.iter().enumerate() {
            input[i] = **claim;
        }
        hasher.permutation_in_place(&mut input);
        Ok(input[1].into())
    }

    fn hash(&self) -> Result<FieldElement, eyre::Error> {
        match self.version {
            CredentialVersion::V1 => {
                let hasher = Poseidon2::<_, 8, 5>::default();
                let mut input = [
                    *self.get_cred_ds(),
                    self.issuer_schema_id.into(),
                    self.account_id.into(),
                    self.genesis_issued_at.into(),
                    self.expires_at.into(),
                    *self.claims_hash()?,
                    *self.associated_data_hash,
                    *FieldElement::ZERO,
                ];
                hasher.permutation_in_place(&mut input);
                Ok(input[1].into())
            }
        }
    }

    #[cfg(feature = "issuer")]
    fn sign(self, signer: &EdDSAPrivateKey) -> Result<Self, eyre::Error> {
        let mut credential = self;
        credential.signature = Some(signer.sign(*credential.hash()?));
        credential.issuer = signer.public();
        Ok(credential)
    }

    fn verify_signature(
        &self,
        expected_issuer_pubkey: &EdDSAPublicKey,
    ) -> Result<bool, eyre::Error> {
        if &self.issuer != expected_issuer_pubkey {
            return Err(eyre::eyre!(
                "Issuer public key does not match expected public key"
            ));
        }
        if let Some(signature) = &self.signature {
            return Ok(self.issuer.verify(*self.hash()?, signature));
        }
        Err(eyre::eyre!("Credential not signed"))
    }
}

#[cfg(feature = "issuer")]
#[cfg(test)]
mod tests {
    use super::*;
    use ruint::aliases::U256;

    #[allow(clippy::unreadable_literal)]
    #[test]
    fn test_credential_builder_and_json_export() {
        let credential = Credential::new()
            .version(CredentialVersion::V1)
            .issuer_schema_id(123)
            .account_id(456)
            .genesis_issued_at(1234567890)
            .expires_at(1234567890 + 86_400)
            .claim(0, U256::from(999))
            .unwrap()
            .associated_data_hash(U256::from(42))
            .unwrap();

        let issuer_sk = EdDSAPrivateKey::from_bytes([0; 32]);
        let credential = credential.sign(&issuer_sk).unwrap();

        assert_eq!(credential.account_id, 456);
        assert!(credential.signature.is_some());

        let json = serde_json::to_string(&credential).unwrap();

        let parsed: Credential = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&parsed).unwrap();

        assert_eq!(json, json2);

        let issuer_public_key = issuer_sk.public();
        let verified = issuer_public_key.verify(
            *credential.hash().unwrap(),
            credential.signature.as_ref().unwrap(),
        );
        assert!(verified);

        let verified = credential.verify_signature(&issuer_public_key).unwrap();
        assert!(verified);
    }
}
