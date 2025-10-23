use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use serde::{Deserialize, Serialize};

use crate::FieldElement;

/// The maximum number of authenticator public keys that can be registered at any time
/// per World ID Account.
///
/// This constrained is introduced to maintain proof performance reasonable even
/// in devices with limited resources.
pub const MAX_AUTHENTICATOR_KEYS: usize = 7;

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

/// Enables entities that sign messages within the Protocol for use with the ZK circuits.
///
/// This is in particular used by Authenticators to authorize requests for nullifier generation.
pub trait ProtocolSigner {
    /// Signs a message with the protocol signer using the `EdDSA` scheme (**off-chain** signer), for use
    /// with the Protocol ZK circuits.
    fn sign(&self, message: FieldElement) -> EdDSASignature
    where
        Self: Sized + Send + Sync;
}
