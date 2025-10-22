use eddsa_babyjubjub::EdDSAPublicKey;
use serde::{Deserialize, Serialize};

use crate::FieldElement;

/// The maximum number of authenticator public keys that can be registered at any time
/// per World ID Account.
///
/// This constrained is introduced to maintain proof performance reasonable even
/// in devices with limited resources.
pub static MAX_AUTHENTICATOR_KEYS: usize = 7;

/// A set of **off-chain** authenticator public keys for a World ID Account.
///
/// Each World ID Account has a number of public keys for each authorized authenticator;
/// a commitment to the entire set of public keys is stored in the `AccountRegistry` contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorPublicKeySet([EdDSAPublicKey; MAX_AUTHENTICATOR_KEYS]);

impl AuthenticatorPublicKeySet {
    /// Converts the set of public keys to a set of field elements where
    /// each item is the x and y coordinates of the public key as a pair.
    #[must_use]
    pub fn to_field_elements(self) -> [[FieldElement; 2]; MAX_AUTHENTICATOR_KEYS] {
        self.0.map(|k| [k.pk.x.into(), k.pk.y.into()])
    }
}
