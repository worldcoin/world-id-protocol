//! The Credential struct.

use serde::{Deserialize, Serialize};

use crate::primitives::BaseField;

/// Version representation of the `Credential` struct
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum CredentialVersion {
    V1 = 1,
}

/// Base representation of a `Credential` in the World ID Protocol.
///
/// A credential is generally a verifiable digital statement about a subject.
///
/// In the case of World ID these statements are about humans, with the most common
/// credentials being Orb verification or document verification.
#[derive(Debug, Serialize, Deserialize)]
pub struct Credential {
    /// Version representation of this structure
    version: CredentialVersion,
    /// Unique credential type id that is used to lookup of verifying information
    type_id: u64,
    /// World ID to which the credential is issued. This ID comes from the `AccountRegistry`.
    account_id: u64,
    /// Timestamp of first issuance of this credential (unix seconds)
    genesis_issued_at: u64,
    /// Expiration timestamp (unix seconds)
    expires_at: u64,
    /// These are concrete statements that the issuer attests about the receiver.
    /// Could be just commitments to data (e.g. passport image) or
    /// the value directly (e.g. date of birth)
    claims: Claims,
    /// If needed, can be used as commitment to the underlying data.
    /// This can be useful to tie multiple proofs about the same data together.
    associated_data_hash: BaseField,
}

/// A collection of claims about a subject.
///
/// A claim is an arbitrary statement about a subject asserted by an Issuer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims(pub [BaseField; 16]);

impl Claims {
    /// Create new claims array initialized with zeros
    #[must_use]
    pub const fn new() -> Self {
        Self([BaseField::ZERO; 16])
    }

    /// Set a claim at the given index
    ///
    /// # Errors
    ///
    /// Returns an error if the index is out of bounds.
    pub fn set_claim(&mut self, index: usize, value: BaseField) -> Result<(), String> {
        if index >= 16 {
            return Err(format!("Claim index {index} out of bounds"));
        }
        self.0[index] = value;
        Ok(())
    }

    /// Get a claim at the given index
    ///
    /// # Errors
    ///
    /// Returns an error if the index is out of bounds.
    pub fn get_claim(&self, index: usize) -> Result<BaseField, String> {
        if index >= 16 {
            return Err(format!("Claim index {index} out of bounds",));
        }
        Ok(self.0[index])
    }

    /// Check if a claim slot is empty (`BaseField::ZERO`)
    ///
    /// # Errors
    ///
    /// Returns an error if the index is out of bounds.
    pub fn is_empty(&self, index: usize) -> Result<bool, String> {
        if index >= 16 {
            return Err(format!("Claim index {index} out of bounds"));
        }
        Ok(self.0[index] == BaseField::ZERO)
    }
}

impl Default for Claims {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_set_get() {
        let mut claims = Claims::new();
        let test_value = BaseField::from(42u64);

        claims.set_claim(0, test_value).unwrap();
        assert_eq!(claims.get_claim(0).unwrap(), test_value);
        assert!(!claims.is_empty(0).unwrap());

        // Other slots should still be empty
        for i in 1..16 {
            assert!(claims.is_empty(i).unwrap());
        }
    }

    #[test]
    fn test_claims_bounds_checking() {
        let mut claims = Claims::new();

        // Should fail for out of bounds index
        assert!(claims.set_claim(16, BaseField::from(1u64)).is_err());
        assert!(claims.get_claim(16).is_err());
        assert!(claims.is_empty(16).is_err());
    }
}
