use crate::PrimitiveError;
use alloy::{primitives::Address, signers::local::PrivateKeySigner};
use eddsa_babyjubjub::{EdDSAPrivateKey, EdDSAPublicKey};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// Domain-separation tag used to derive the on-chain `SECP256K1` signing key from the master seed.
const ONCHAIN_KEY_DERIVATION_TAG: &[u8] = b"world-id-protocol/signer/onchain/v1";
/// Domain-separation tag used to derive the off-chain `EdDSA` signing key from the master seed.
const OFFCHAIN_KEY_DERIVATION_TAG: &[u8] = b"world-id-protocol/signer/offchain/v1";

/// The inner signer which can sign requests for both on-chain and off-chain operations. Both issuers and authenticators use this.
///
/// The on-chain and off-chain keys are derived from the same master seed via a
/// domain-separated SHA-256 KDF, so leaking either signing key does not let an
/// attacker recover the master seed (one-way hash) and therefore does not allow
/// recovery of the other key.
///
/// Both keys are zeroized on drop.
#[derive(Debug)]
pub struct Signer {
    /// An on-chain `SECP256K1` private key. This key is used to sign operations that are validated on-chain (see `WorldIDRegistry` or `CredentialSchemaIssuerRegistry`).
    onchain_signer: PrivateKeySigner,
    /// An off-chain `EdDSA` private key. This key is used to sign operations that are validated off-chain, primarily within Zero-Knowledge Circuits.
    offchain_signer: SecretBox<EdDSAPrivateKey>,
}

impl Signer {
    /// Initializes a new signer from a 32-byte master seed.
    ///
    /// The on-chain (`SECP256K1`) and off-chain (`EdDSA` on `BabyJubJub`) signing keys
    /// are derived independently from `master_seed` via `SHA-256(domain_tag || master_seed)`,
    /// so the two keys are not linkable: compromising one does not reveal the master seed
    /// and therefore does not let an attacker derive the other key.
    ///
    /// # Errors
    /// Returns `PrimitiveError::InvalidInput` if `master_seed` is not exactly 32 bytes,
    /// or if the derived on-chain private key is rejected by `SECP256K1` (negligibly
    /// probable for a uniformly random seed).
    pub fn from_seed_bytes(master_seed: &[u8]) -> Result<Self, PrimitiveError> {
        if master_seed.len() != 32 {
            return Err(PrimitiveError::InvalidInput {
                attribute: "seed".to_string(),
                reason: format!("must be 32 bytes, got {} bytes", master_seed.len()),
            });
        }

        let onchain_seed = derive_subkey(ONCHAIN_KEY_DERIVATION_TAG, master_seed);
        let offchain_seed = derive_subkey(OFFCHAIN_KEY_DERIVATION_TAG, master_seed);

        let onchain_signer =
            PrivateKeySigner::from_bytes(&(*onchain_seed).into()).map_err(|e| {
                PrimitiveError::InvalidInput {
                    attribute: "seed".to_string(),
                    reason: format!("invalid derived on-chain private key: {e}"),
                }
            })?;
        let offchain_signer = SecretBox::new(Box::new(EdDSAPrivateKey::from_bytes(*offchain_seed)));

        Ok(Self {
            onchain_signer,
            offchain_signer,
        })
    }

    /// Returns a mutable reference to the internal signer.
    #[expect(
        clippy::missing_const_for_fn,
        reason = "cannot be initialized at compile time"
    )]
    pub fn onchain_signer(&self) -> &PrivateKeySigner {
        &self.onchain_signer
    }

    /// Returns a reference to the internal offchain signer.
    pub const fn offchain_signer_private_key(&self) -> &SecretBox<EdDSAPrivateKey> {
        &self.offchain_signer
    }

    /// Returns the address of the on-chain signer.
    pub const fn onchain_signer_address(&self) -> Address {
        self.onchain_signer.address()
    }

    /// Returns the public key of the off-chain signer.
    pub fn offchain_signer_pubkey(&self) -> EdDSAPublicKey {
        self.offchain_signer.expose_secret().public()
    }
}

/// Derives a 32-byte subkey from `master_seed` under a domain-separation `tag` using
/// `SHA-256(tag || master_seed)`.
///
/// The output is wrapped in [`Zeroizing`] so the derived secret bytes are wiped
/// from memory when the value is dropped.
fn derive_subkey(tag: &[u8], master_seed: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(master_seed);
    let digest = hasher.finalize();

    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED_A: [u8; 32] = [0x11; 32];
    const TEST_SEED_B: [u8; 32] = [0x22; 32];

    #[test]
    fn from_seed_bytes_rejects_wrong_length() {
        let err = Signer::from_seed_bytes(&[0u8; 31]).unwrap_err();
        assert!(matches!(err, PrimitiveError::InvalidInput { .. }));

        let err = Signer::from_seed_bytes(&[0u8; 33]).unwrap_err();
        assert!(matches!(err, PrimitiveError::InvalidInput { .. }));
    }

    #[test]
    fn from_seed_bytes_is_deterministic() {
        let s1 = Signer::from_seed_bytes(&TEST_SEED_A).unwrap();
        let s2 = Signer::from_seed_bytes(&TEST_SEED_A).unwrap();

        assert_eq!(s1.onchain_signer_address(), s2.onchain_signer_address());
        assert_eq!(
            s1.offchain_signer_pubkey().pk,
            s2.offchain_signer_pubkey().pk
        );
    }

    #[test]
    fn different_master_seeds_produce_different_keys() {
        let s1 = Signer::from_seed_bytes(&TEST_SEED_A).unwrap();
        let s2 = Signer::from_seed_bytes(&TEST_SEED_B).unwrap();

        assert_ne!(s1.onchain_signer_address(), s2.onchain_signer_address());
        assert_ne!(
            s1.offchain_signer_pubkey().pk,
            s2.offchain_signer_pubkey().pk
        );
    }

    /// Regression test for the linkability finding: the raw 32-byte master seed must
    /// not be reused as either signing key. The bytes fed into the on-chain signer
    /// and the bytes fed into the off-chain signer must both differ from the master
    /// seed and from each other.
    #[test]
    fn onchain_and_offchain_keys_are_unlinked_from_master_seed() {
        let master = TEST_SEED_A;

        let onchain_seed = derive_subkey(ONCHAIN_KEY_DERIVATION_TAG, &master);
        let offchain_seed = derive_subkey(OFFCHAIN_KEY_DERIVATION_TAG, &master);

        assert_ne!(*onchain_seed, master);
        assert_ne!(*offchain_seed, master);
        assert_ne!(*onchain_seed, *offchain_seed);

        let signer = Signer::from_seed_bytes(&master).unwrap();
        let onchain_from_derived = PrivateKeySigner::from_bytes(&(*onchain_seed).into()).unwrap();
        let offchain_signer_derived = EdDSAPrivateKey::from_bytes(*offchain_seed);
        assert_eq!(
            signer.onchain_signer_address(),
            onchain_from_derived.address(),
            "on-chain key must come from the derived sub-seed, not the master seed",
        );
        assert_eq!(
            signer.offchain_signer_pubkey(),
            offchain_signer_derived.public(),
            "off-chain key must come from the derived sub-seed, not the master seed",
        )
    }
}
