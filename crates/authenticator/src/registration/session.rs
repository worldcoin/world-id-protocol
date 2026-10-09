//! Session secrets and transport encryption (WIP-109 §3.3 and §3.5).

use std::fmt;

use aes_gcm::{
    Aes256Gcm, KeyInit as _, Nonce,
    aead::{Aead as _, Payload},
};
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
/// It determines the bridge [`RequestId`] and combines with the [`PairingCode`] to derive the
/// [`TransportKey`]. It travels to the Approving Authenticator inside
/// the [`PairingUri`](super::PairingUri), which therefore is a bearer secret.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PairingSecret([u8; 32]);

impl PairingSecret {
    /// Generates a fresh pairing secret from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Rng`] if randomness is unavailable.
    pub fn generate() -> Result<Self, TransportError> {
        let mut secret = Self([0u8; 32]);
        RandOsRng
            .try_fill_bytes(&mut secret.0)
            .map_err(|_| TransportError::Rng)?;
        Ok(secret)
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

    /// Derives the transport key from this secret and the independently transferred code.
    ///
    /// Performs Argon2id with 64 MiB of memory; callers should derive once per code attempt.
    /// Returns [`TransportError::KeyDerivation`] if Argon2id fails.
    pub fn transport_key(&self, code: &PairingCode) -> Result<TransportKey, TransportError> {
        let params = argon2::Params::new(65536, 3, 4, Some(32))
            .expect("WIP-109 Argon2 parameters are valid");
        let argon =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        // Argon2id password `pairing_secret || code`, salted with the raw request id.
        let mut password = Zeroizing::new([0u8; 38]);
        password[..32].copy_from_slice(&self.0);
        password[32..].copy_from_slice(&code.0);
        let request_id = self.request_id();
        let mut input = Zeroizing::new([0u8; 64]);
        input[..32].copy_from_slice(&self.0);
        let mut memory =
            Zeroizing::new(vec![argon2::Block::default(); argon.params().block_count()]);
        argon
            .hash_password_into_with_memory(
                password.as_ref(),
                request_id.as_bytes(),
                &mut input[32..],
                &mut *memory,
            )
            .map_err(|_| TransportError::KeyDerivation)?;
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, input.as_ref())
            .expand(TRANSPORT_SECRET_INFO, key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Ok(TransportKey { key, request_id })
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

/// A six-letter code transferred manually between authenticators.
///
/// Generation samples uniformly from uppercase ASCII letters. Parsing accepts either case and
/// ignores spaces and hyphens; every other character is rejected.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PairingCode([u8; 6]);

impl PairingCode {
    /// Generates an independent code using rejection sampling from the OS CSPRNG.
    ///
    /// Returns [`TransportError::Rng`] if randomness is unavailable.
    pub fn generate() -> Result<Self, TransportError> {
        let mut code = Zeroizing::new([0; 6]);
        for letter in code.iter_mut() {
            loop {
                let mut byte = [0];
                RandOsRng
                    .try_fill_bytes(&mut byte)
                    .map_err(|_| TransportError::Rng)?;
                if byte[0] < 234 {
                    *letter = b'A' + byte[0] % 26;
                    break;
                }
            }
        }
        Ok(Self(*code))
    }

    /// Exposes the secret code for display after the bridge reports `retrieved`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("pairing code contains only ASCII letters")
    }
}

impl std::str::FromStr for PairingCode {
    type Err = TransportError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut code = Zeroizing::new([0; 6]);
        let mut len = 0;
        for byte in input.bytes().filter(|b| !matches!(b, b' ' | b'-')) {
            if !byte.is_ascii_alphabetic() || len == code.len() {
                return Err(TransportError::InvalidPairingCode);
            }
            code[len] = byte.to_ascii_uppercase();
            len += 1;
        }
        if len != code.len() {
            return Err(TransportError::InvalidPairingCode);
        }
        Ok(Self(*code))
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingCode(REDACTED)")
    }
}

/// The code-bound AES-256-GCM key authenticating both directions of a pairing session.
pub struct TransportKey {
    pub(super) key: Zeroizing<[u8; 32]>,
    request_id: RequestId,
}

impl TransportKey {
    /// Encrypts a request with a fresh nonce and request/session-bound associated data.
    /// Returns an error if randomness or encryption fails.
    pub fn encrypt_request(&self, plaintext: &[u8]) -> Result<EncryptedPayload, TransportError> {
        self.encrypt(&self.request_id, b"WORLD-ID/WIP-109/REQUEST", plaintext)
    }

    /// Authenticates a request before returning its plaintext for parsing.
    /// Returns an error for malformed encoding or failed authentication.
    pub fn decrypt_request(&self, encrypted: &EncryptedPayload) -> Result<Vec<u8>, TransportError> {
        self.decrypt(&self.request_id, b"WORLD-ID/WIP-109/REQUEST", encrypted)
    }

    /// Seals a response to its recipient, then authenticates the sealed bytes with the code-bound key.
    /// Returns an error if randomness or either encryption layer fails.
    pub fn encrypt_response(
        &self,
        recipient: &ResponsePublicKey,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, TransportError> {
        let sealed = quantum_box::PublicKey::seal(&recipient.0, plaintext, Some(RESPONSE_INFO))
            .map_err(|e| match e {
                quantum_box::Error::Rng => TransportError::Rng,
                _ => TransportError::Encrypt,
            })?;
        self.encrypt(&self.request_id, RESPONSE_INFO, &sealed)
    }

    /// Authenticates the outer envelope before opening the recipient's HPKE seal.
    /// The plaintext may carry the credential vault, so it is zeroized on drop.
    /// Returns an error for malformed encoding or failed authentication at either layer.
    pub fn decrypt_response(
        &self,
        recipient: &ResponseSecretKey,
        encrypted: &EncryptedPayload,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        let sealed = self.decrypt(&self.request_id, RESPONSE_INFO, encrypted)?;
        if !sealed.starts_with(&[0x02, 0x64, 0x7a, 0x00, 0x01, 0x00, 0x03]) {
            return Err(TransportError::Decrypt);
        }
        quantum_box::SecretKey::unseal(&recipient.0, &sealed, Some(RESPONSE_INFO))
            .map(Zeroizing::new)
            .map_err(|_| TransportError::Decrypt)
    }

    fn encrypt(
        &self,
        id: &RequestId,
        label: &[u8],
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, TransportError> {
        let mut nonce = [0u8; NONCE_LEN];
        RandOsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| TransportError::Rng)?;
        let aad = [label, id.as_bytes()].concat();
        let ciphertext = Aes256Gcm::new((&*self.key).into())
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| TransportError::Encrypt)?;
        Ok(EncryptedPayload {
            iv: STANDARD.encode(nonce),
            payload: STANDARD.encode(ciphertext),
        })
    }

    fn decrypt(
        &self,
        id: &RequestId,
        label: &[u8],
        encrypted: &EncryptedPayload,
    ) -> Result<Vec<u8>, TransportError> {
        let nonce: [u8; NONCE_LEN] = STANDARD
            .decode(&encrypted.iv)
            .map_err(|_| TransportError::Encoding)?
            .try_into()
            .map_err(|_| TransportError::Encoding)?;
        let ciphertext = STANDARD
            .decode(&encrypted.payload)
            .map_err(|_| TransportError::Encoding)?;
        if ciphertext.len() < 16 {
            return Err(TransportError::Encoding);
        }
        let aad = [label, id.as_bytes()].concat();
        Aes256Gcm::new((&*self.key).into())
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| TransportError::Decrypt)
    }
}

impl fmt::Debug for TransportKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransportKey(REDACTED)")
    }
}

/// The bridge id of a registration session, derived from its [`PairingSecret`].
///
/// It is displayed as 64 lowercase hex characters, which is also the message `id` of the
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
    /// The standard padded base64 nonce, for either direction.
    pub iv: String,
    /// The standard padded base64 ciphertext.
    pub payload: String,
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
}

/// Errors from encrypting, decrypting or parsing WIP-109 transport values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// The manually entered code is not six ASCII letters after normalization.
    #[error("pairing code must contain six ASCII letters")]
    InvalidPairingCode,
    /// Deriving the code-bound transport key failed.
    #[error("pairing transport key derivation failed")]
    KeyDerivation,
    /// The operating system CSPRNG is unavailable.
    #[error("operating system CSPRNG is unavailable")]
    Rng,
    /// Encryption failed.
    #[error("encryption failed")]
    Encrypt,
    /// The ciphertext is malformed or failed authentication.
    #[error("decryption failed")]
    Decrypt,
    /// The `iv` or `payload` is not valid base64, the nonce has the wrong length, or the
    /// ciphertext is shorter than the authentication tag.
    #[error("invalid base64, nonce length or ciphertext length in the encrypted payload")]
    Encoding,
    /// The response public key is not a valid X-Wing encapsulation key.
    #[error("invalid response public key")]
    InvalidPublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_code_normalizes_only_ascii_and_redacts_debug() {
        let code: PairingCode = " qj-tw pk ".parse().unwrap();
        assert_eq!(code.as_str(), "QJTWPK");
        assert_eq!(format!("{code:?}"), "PairingCode(REDACTED)");
        for invalid in [
            "ABCDE", "ABCDEFG", "ABC1EF", "ABC\tDEF", "ÄBCDEF", "ＡBCDEF",
        ] {
            assert!(invalid.parse::<PairingCode>().is_err());
        }
        assert!(
            PairingCode::generate()
                .unwrap()
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_uppercase())
        );
    }

    #[test]
    fn transport_authenticates_code_session_direction_and_recipient() {
        let secret = PairingSecret::from_bytes([7; 32]);
        let code = "QJTWPK".parse().unwrap();
        let key = secret.transport_key(&code).unwrap();
        let wrong_code = secret.transport_key(&"ABCDEF".parse().unwrap()).unwrap();
        let other_session = PairingSecret::from_bytes([8; 32])
            .transport_key(&code)
            .unwrap();
        let request = key.encrypt_request(b"request").unwrap();
        let wrong_id = TransportKey {
            key: key.key.clone(),
            request_id: other_session.request_id,
        };
        assert_eq!(
            wrong_id.decrypt_request(&request),
            Err(TransportError::Decrypt)
        );
        let mut tampered = request.clone();
        let mut ciphertext = STANDARD.decode(&tampered.payload).unwrap();
        ciphertext[0] ^= 1;
        tampered.payload = STANDARD.encode(ciphertext);
        assert_eq!(key.decrypt_request(&tampered), Err(TransportError::Decrypt));
        assert_eq!(key.decrypt_request(&request).unwrap(), b"request");
        assert_eq!(
            wrong_code.decrypt_request(&request),
            Err(TransportError::Decrypt)
        );
        assert_eq!(
            other_session.decrypt_request(&request),
            Err(TransportError::Decrypt)
        );
        let recipient = ResponseSecretKey::from_seed(&[1; 32]);
        let response = key
            .encrypt_response(&recipient.public_key(), b"response")
            .unwrap();
        assert_eq!(STANDARD.decode(&response.iv).unwrap().len(), 12);
        assert_eq!(
            key.decrypt_response(&recipient, &response)
                .unwrap()
                .as_slice(),
            b"response"
        );
        assert_eq!(key.decrypt_request(&response), Err(TransportError::Decrypt));
        assert_eq!(
            key.decrypt_response(&recipient, &request),
            Err(TransportError::Decrypt)
        );
        assert_eq!(
            wrong_code.decrypt_response(&recipient, &response),
            Err(TransportError::Decrypt)
        );
        assert_eq!(
            key.decrypt_response(&ResponseSecretKey::from_seed(&[2; 32]), &response),
            Err(TransportError::Decrypt)
        );
        let mut malformed = response.clone();
        malformed.iv.clear();
        assert_eq!(
            key.decrypt_response(&recipient, &malformed),
            Err(TransportError::Encoding)
        );
        malformed = response.clone();
        malformed.payload = STANDARD.encode([0; 15]);
        assert_eq!(
            key.decrypt_response(&recipient, &malformed),
            Err(TransportError::Encoding)
        );
        malformed = response;
        malformed.payload = "***".into();
        assert_eq!(
            key.decrypt_response(&recipient, &malformed),
            Err(TransportError::Encoding)
        );
        let wrong_header = key
            .encrypt(&secret.request_id(), RESPONSE_INFO, &[0; 32])
            .unwrap();
        assert_eq!(
            key.decrypt_response(&recipient, &wrong_header),
            Err(TransportError::Decrypt)
        );
    }
}
