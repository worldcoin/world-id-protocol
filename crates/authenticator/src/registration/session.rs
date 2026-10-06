//! Session secrets and transport encryption (WIP-109 §3.3 and §3.5).

use std::fmt;

use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce, aead::Aead as _};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use rand::{RngCore as _, rngs::OsRng as RandOsRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const REQUEST_ID_INFO: &[u8] = b"WORLD-ID/WIP-109/REQUESTID";
const TRANSPORT_SECRET_INFO: &[u8] = b"WORLD-ID/WIP-109/TRANSPORTSECRET";
const RESPONSE_INFO: &[u8] = b"WORLD-ID/WIP-109/RESPONSE";

/// The length in bytes of an AES-256-GCM nonce.
const NONCE_LEN: usize = 12;

/// The length in bytes of an X-Wing encapsulation key.
pub const RESPONSE_PUBLIC_KEY_LEN: usize = 1216;

/// The 32-byte secret a Requesting Authenticator generates for each registration attempt.
///
/// Every other session value is derived from it: the bridge [`RequestId`] and the
/// [`TransportKey`] that encrypts the request. It travels to the Approving Authenticator inside
/// the [`PairingUri`](super::PairingUri), which therefore is a bearer secret.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PairingSecret([u8; 32]);

impl PairingSecret {
    /// Generates a fresh pairing secret from the operating system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        RandOsRng.fill_bytes(&mut secret);
        Self(secret)
    }

    /// Wraps raw secret bytes, e.g. ones parsed from a Pairing URI or restored after a restart.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw secret bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives the id that addresses both the request and the response on the bridge.
    #[must_use]
    pub fn request_id(&self) -> RequestId {
        RequestId(*self.derive(REQUEST_ID_INFO))
    }

    /// Derives the key that encrypts the registration request.
    #[must_use]
    pub fn transport_key(&self) -> TransportKey {
        TransportKey(self.derive(TRANSPORT_SECRET_INFO))
    }

    fn derive(&self, info: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut okm = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, &self.0)
            .expand(info, okm.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        okm
    }
}

impl fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingSecret(REDACTED)")
    }
}

/// The bridge id of a registration session, derived from its [`PairingSecret`].
///
/// It is displayed as 64 lowercase hex characters, which is also the JSON-RPC `id` of the
/// registration request and its response.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId([u8; 32]);

impl RequestId {
    /// Returns the raw HKDF output, as committed to in the
    /// [`RegistrationDigest`](super::RegistrationDigest).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RequestId({self})")
    }
}

/// An encrypted message as carried by the bridge: a base64 `iv` and a base64 `payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// The standard padded base64 nonce, or the empty string for sealed responses.
    pub iv: String,
    /// The standard padded base64 ciphertext.
    pub payload: String,
}

/// The AES-256-GCM key that protects the registration request in transit.
///
/// Anyone who saw the Pairing URI can derive it, so it only protects the request from the
/// bridge. The request holds nothing but public keys and a label.
pub struct TransportKey(pub(super) Zeroizing<[u8; 32]>);

impl TransportKey {
    /// Encrypts `plaintext` under a fresh random nonce.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Encrypt`] if AES-GCM rejects the input, which only happens for
    /// plaintexts larger than about 64 GiB.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedPayload, TransportError> {
        let mut nonce = [0u8; NONCE_LEN];
        RandOsRng.fill_bytes(&mut nonce);
        let ciphertext = Aes256Gcm::new(self.0.as_ref().into())
            .encrypt(&Nonce::from(nonce), plaintext)
            .map_err(|_| TransportError::Encrypt)?;
        Ok(EncryptedPayload {
            iv: STANDARD.encode(nonce),
            payload: STANDARD.encode(ciphertext),
        })
    }

    /// Decrypts a payload produced by [`TransportKey::encrypt`].
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Encoding`] if `iv` or `payload` is not standard padded base64
    /// or the nonce is not 12 bytes, and [`TransportError::Decrypt`] if authentication fails.
    pub fn decrypt(&self, encrypted: &EncryptedPayload) -> Result<Vec<u8>, TransportError> {
        let nonce: [u8; NONCE_LEN] = STANDARD
            .decode(&encrypted.iv)
            .map_err(|_| TransportError::Encoding)?
            .try_into()
            .map_err(|_| TransportError::Encoding)?;
        let ciphertext = STANDARD
            .decode(&encrypted.payload)
            .map_err(|_| TransportError::Encoding)?;
        Aes256Gcm::new(self.0.as_ref().into())
            .decrypt(&Nonce::from(nonce), ciphertext.as_slice())
            .map_err(|_| TransportError::Decrypt)
    }
}

impl fmt::Debug for TransportKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransportKey(REDACTED)")
    }
}

/// The ephemeral X-Wing key pair a Requesting Authenticator generates to receive the response.
///
/// The response carries the credential vault, so it is sealed to the public half, whose secret
/// half never leaves the Requesting Authenticator. A Pairing URI alone is not enough to read it.
#[derive(Clone)]
pub struct ResponseSecretKey(quantum_box::SecretKey);

impl ResponseSecretKey {
    /// Generates a fresh key pair from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Rng`] if the operating system CSPRNG is unavailable.
    pub fn generate() -> Result<Self, TransportError> {
        quantum_box::SecretKey::generate()
            .map(Self)
            .map_err(|_| TransportError::Rng)
    }

    /// Deterministically derives the key pair from a 32-byte seed, e.g. to restore a session
    /// after a restart.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(quantum_box::SecretKey::from_seed(seed))
    }

    /// Returns the public half, sent in the registration request.
    #[must_use]
    pub fn public_key(&self) -> ResponsePublicKey {
        ResponsePublicKey(self.0.public_key())
    }

    /// Opens a response sealed with [`ResponsePublicKey::seal`].
    ///
    /// `iv` is ignored, as it is unused for sealed responses.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Encoding`] if `payload` is not standard padded base64, and
    /// [`TransportError::Decrypt`] if the sealed bytes are malformed, use another header, or
    /// fail authentication.
    pub fn unseal(&self, sealed: &EncryptedPayload) -> Result<Vec<u8>, TransportError> {
        let sealed = STANDARD
            .decode(&sealed.payload)
            .map_err(|_| TransportError::Encoding)?;
        quantum_box::SecretKey::unseal(&self.0, &sealed, Some(RESPONSE_INFO))
            .map_err(|_| TransportError::Decrypt)
    }
}

impl fmt::Debug for ResponseSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResponseSecretKey(REDACTED)")
    }
}

/// The public X-Wing encapsulation key a response is sealed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponsePublicKey(quantum_box::PublicKey);

impl ResponsePublicKey {
    /// Parses a raw 1216-byte X-Wing encapsulation key.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidPublicKey`] if the bytes are not a valid key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TransportError> {
        quantum_box::PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| TransportError::InvalidPublicKey)
    }

    /// Returns the raw 1216-byte encapsulation key.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Seals `plaintext` so that only the holder of the matching [`ResponseSecretKey`] can open
    /// it. The result has an empty `iv`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Rng`] if the operating system CSPRNG is unavailable, and
    /// [`TransportError::Encrypt`] if sealing fails.
    pub fn seal(&self, plaintext: &[u8]) -> Result<EncryptedPayload, TransportError> {
        let sealed = quantum_box::PublicKey::seal(&self.0, plaintext, Some(RESPONSE_INFO))
            .map_err(|e| match e {
                quantum_box::Error::Rng => TransportError::Rng,
                _ => TransportError::Encrypt,
            })?;
        Ok(EncryptedPayload {
            iv: String::new(),
            payload: STANDARD.encode(sealed),
        })
    }
}

/// Errors from encrypting, decrypting or parsing WIP-109 transport values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// The operating system CSPRNG is unavailable.
    #[error("operating system CSPRNG is unavailable")]
    Rng,
    /// Encryption failed.
    #[error("encryption failed")]
    Encrypt,
    /// The ciphertext is malformed or failed authentication.
    #[error("decryption failed")]
    Decrypt,
    /// The `iv` or `payload` is not valid base64, or the nonce has the wrong length.
    #[error("invalid base64 or nonce length in the encrypted payload")]
    Encoding,
    /// The response public key is not a valid X-Wing encapsulation key.
    #[error("invalid response public key")]
    InvalidPublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivations_are_deterministic_and_distinct() {
        let secret = PairingSecret::from_bytes([7; 32]);
        assert_eq!(secret.request_id(), secret.request_id());
        assert_ne!(
            secret.request_id().as_bytes(),
            secret.transport_key().0.as_ref()
        );
        assert_ne!(
            secret.request_id(),
            PairingSecret::from_bytes([8; 32]).request_id()
        );
        assert_eq!(secret.request_id().to_string().len(), 64);
    }

    #[test]
    fn transport_round_trips_and_detects_tampering() {
        let key = PairingSecret::generate().transport_key();
        let encrypted = key.encrypt(b"hello").unwrap();
        assert_eq!(STANDARD.decode(&encrypted.iv).unwrap().len(), NONCE_LEN);
        assert_eq!(key.decrypt(&encrypted).unwrap(), b"hello");

        let other_key = PairingSecret::generate().transport_key();
        assert_eq!(other_key.decrypt(&encrypted), Err(TransportError::Decrypt));

        let mut short_iv = encrypted.clone();
        short_iv.iv = STANDARD.encode([0u8; 8]);
        assert_eq!(key.decrypt(&short_iv), Err(TransportError::Encoding));

        let mut not_base64 = encrypted;
        not_base64.payload = "***".into();
        assert_eq!(key.decrypt(&not_base64), Err(TransportError::Encoding));
    }

    #[test]
    fn sealed_response_round_trips_only_for_the_recipient() {
        let recipient = ResponseSecretKey::from_seed(&[1; 32]);
        let sealed = recipient.public_key().seal(b"vault").unwrap();
        assert_eq!(sealed.iv, "");

        let raw = STANDARD.decode(&sealed.payload).unwrap();
        assert_eq!(raw[..7], [0x02, 0x64, 0x7a, 0x00, 0x01, 0x00, 0x03]);
        assert_eq!(recipient.unseal(&sealed).unwrap(), b"vault");

        let other = ResponseSecretKey::from_seed(&[2; 32]);
        assert_eq!(other.unseal(&sealed), Err(TransportError::Decrypt));
    }

    #[test]
    fn sealed_response_rejects_other_headers() {
        let recipient = ResponseSecretKey::from_seed(&[1; 32]);
        let sealed = recipient.public_key().seal(b"vault").unwrap();
        let mut raw = STANDARD.decode(&sealed.payload).unwrap();
        raw[6] = 0x01;
        let tampered = EncryptedPayload {
            iv: String::new(),
            payload: STANDARD.encode(raw),
        };
        assert_eq!(recipient.unseal(&tampered), Err(TransportError::Decrypt));
    }

    #[test]
    fn response_public_key_round_trips() {
        let public_key = ResponseSecretKey::from_seed(&[3; 32]).public_key();
        let bytes = public_key.to_bytes();
        assert_eq!(bytes.len(), RESPONSE_PUBLIC_KEY_LEN);
        assert_eq!(ResponsePublicKey::from_bytes(&bytes).unwrap(), public_key);
        assert_eq!(
            ResponsePublicKey::from_bytes(&bytes[1..]),
            Err(TransportError::InvalidPublicKey)
        );
    }
}
