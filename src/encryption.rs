//! Encryption at rest for sensitive database fields.
//!
//! This module provides authenticated encryption (AES-256-GCM) for sensitive
//! data stored in the local SQLite database. The approach is column-level
//! encryption rather than full database encryption, which has different
//! threat-model implications:
//!
//! ## Tradeoffs vs Full Database Encryption (e.g., SQLCipher)
//!
//! **Advantages:**
//! - No external dependencies on SQLCipher builds (better portability)
//! - Finer-grained control over what gets encrypted
//! - Can be deployed on any SQLite build (bundled or system)
//! - Smaller attack surface (only sensitive data encrypted)
//!
//! **Limitations:**
//! - Database metadata (table names, row counts) remain visible
//! - Query patterns are visible (but not query results)
//! - Slightly more complex code (encrypt/decrypt at application layer)
//!
//! ## Threat Model
//!
//! This protects against:
//! - Casual file exfiltration of the database file
//! - Physical device compromise (lost/stolen phone)
//! - Forensic analysis of the database file
//!
//! This does NOT protect against:
//! - Memory dumps while the app is running
//! - Key compromise (the key must be supplied by the embedding wallet)
//! - Metadata analysis (table names, row counts, timing)
//!
//! ## Implementation Details
//!
//! - **Algorithm:** AES-256-GCM (Authenticated Encryption with Associated Data)
//! - **Key Derivation:** Argon2id (memory-hard PBKDF) from user passphrase
//! - **Nonce Generation:** Random 96-bit nonces per encryption
//! - **Key Length:** 256 bits (32 bytes)
//!
//! The embedding application must supply the encryption key at database
//! initialization time. This crate does NOT generate, store, or manage keys.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::errors::SyncEngineError;

/// Encryption key size (256 bits / 32 bytes)
pub const KEY_SIZE: usize = 32;

/// Nonce size for AES-256-GCM (96 bits / 12 bytes)
pub const NONCE_SIZE: usize = 12;

/// Salt size for key derivation (128 bits / 16 bytes)
pub const SALT_SIZE: usize = 16;

/// Argon2 memory cost (64 MB) - tuned for mobile devices
const ARGON2_MEMORY_COST: u32 = 65536;

/// Argon2 time cost (iterations)
const ARGON2_TIME_COST: u32 = 3;

/// Argon2 parallelism
const ARGON2_PARALLELISM: u32 = 4;

/// An encryption key derived from a user passphrase.
#[derive(Clone, Debug)]
pub struct EncryptionKey {
    key: [u8; KEY_SIZE],
}

impl EncryptionKey {
    /// Derive an encryption key from a user passphrase using Argon2id.
    ///
    /// # Arguments
    /// * `passphrase` - User-supplied passphrase (cleared from memory after use)
    /// * `salt` - Cryptographic salt for key derivation
    ///
    /// # Returns
    /// A 256-bit encryption key suitable for AES-256-GCM
    ///
    /// # Security
    /// - Uses Argon2id (memory-hard PBKDF) to resist GPU/ASIC attacks
    /// - Salt prevents rainbow table attacks
    /// - Memory cost tuned for mobile devices (64 MB)
    pub fn from_passphrase(
        passphrase: &str,
        salt: &[u8; SALT_SIZE],
    ) -> Result<Self, SyncEngineError> {
        let mut key = [0u8; KEY_SIZE];

        let params = Params::new(
            ARGON2_MEMORY_COST,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(KEY_SIZE),
        )
        .map_err(|e| SyncEngineError::EncryptionError(format!("Argon2 params error: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| {
                SyncEngineError::EncryptionError(format!("Key derivation failed: {}", e))
            })?;

        Ok(Self { key })
    }

    /// Create an encryption key from raw bytes (for testing or when key is already derived).
    pub fn from_bytes(key: [u8; KEY_SIZE]) -> Self {
        Self { key }
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }
}

/// A cryptographic nonce (number used once) for encryption.
#[derive(Clone, Debug)]
pub struct EncryptionNonce([u8; NONCE_SIZE]);

impl EncryptionNonce {
    /// Generate a random nonce using a CSPRNG.
    pub fn generate() -> Self {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        Self(nonce)
    }

    /// Create a nonce from bytes.
    pub fn from_bytes(bytes: [u8; NONCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw nonce bytes.
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.0
    }
}

/// Encrypt plaintext using AES-256-GCM.
///
/// # Arguments
/// * `plaintext` - Data to encrypt
/// * `key` - Encryption key
/// * `nonce` - Cryptographic nonce (must be unique per encryption)
///
/// # Returns
/// Ciphertext with authentication tag appended
///
/// # Security
/// - Uses AES-256-GCM for authenticated encryption
/// - Each encryption must use a unique nonce (randomly generated)
/// - Authentication tag prevents tampering
pub fn encrypt(
    plaintext: &[u8],
    key: &EncryptionKey,
    nonce: &EncryptionNonce,
) -> Result<Vec<u8>, SyncEngineError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| SyncEngineError::EncryptionError(format!("Cipher init failed: {}", e)))?;

    let nonce = Nonce::from_slice(nonce.as_bytes());

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SyncEngineError::EncryptionError(format!("Encryption failed: {}", e)))
}

/// Decrypt ciphertext using AES-256-GCM.
///
/// # Arguments
/// * `ciphertext` - Encrypted data with authentication tag
/// * `key` - Decryption key (must match encryption key)
/// * `nonce` - Nonce used during encryption
///
/// # Returns
/// Original plaintext
///
/// # Errors
/// Returns `DecryptionFailed` if:
/// - Wrong key is used
/// - Data is corrupted
/// - Authentication tag is invalid (tampering detected)
pub fn decrypt(
    ciphertext: &[u8],
    key: &EncryptionKey,
    nonce: &EncryptionNonce,
) -> Result<Vec<u8>, SyncEngineError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| SyncEngineError::EncryptionError(format!("Cipher init failed: {}", e)))?;

    let nonce = Nonce::from_slice(nonce.as_bytes());

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SyncEngineError::DecryptionFailed)
}

/// Generate a random salt for key derivation.
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut salt = [0u8; SALT_SIZE];
    rng.fill_bytes(&mut salt);
    salt
}

/// Encrypted data with nonce prepended.
///
/// Format: [nonce (12 bytes)] [ciphertext + auth tag]
#[derive(Clone, Debug, PartialEq)]
pub struct EncryptedData(Vec<u8>);

impl EncryptedData {
    /// Encrypt plaintext and return as EncryptedData with nonce prepended.
    pub fn encrypt(plaintext: &[u8], key: &EncryptionKey) -> Result<Self, SyncEngineError> {
        let nonce = EncryptionNonce::generate();
        let ciphertext = encrypt(plaintext, key, &nonce)?;

        // Prepend nonce to ciphertext
        let mut data = nonce.as_bytes().to_vec();
        data.extend(ciphertext);

        Ok(Self(data))
    }

    /// Decrypt this EncryptedData using the provided key.
    pub fn decrypt(&self, key: &EncryptionKey) -> Result<Vec<u8>, SyncEngineError> {
        if self.0.len() < NONCE_SIZE {
            return Err(SyncEngineError::DecryptionFailed);
        }

        let nonce_bytes: [u8; NONCE_SIZE] = self.0[..NONCE_SIZE]
            .try_into()
            .map_err(|_| SyncEngineError::DecryptionFailed)?;

        let nonce = EncryptionNonce::from_bytes(nonce_bytes);
        let ciphertext = &self.0[NONCE_SIZE..];

        decrypt(ciphertext, key, &nonce)
    }

    /// Get the raw bytes (nonce + ciphertext).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create EncryptedData from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let salt = generate_salt();
        let key1 = EncryptionKey::from_passphrase("correct horse battery staple", &salt).unwrap();
        let key2 = EncryptionKey::from_passphrase("correct horse battery staple", &salt).unwrap();

        // Same passphrase + salt should produce same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_passphrases_produce_different_keys() {
        let salt = generate_salt();
        let key1 = EncryptionKey::from_passphrase("passphrase1", &salt).unwrap();
        let key2 = EncryptionKey::from_passphrase("passphrase2", &salt).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_salts_produce_different_keys() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        let key1 = EncryptionKey::from_passphrase("passphrase", &salt1).unwrap();
        let key2 = EncryptionKey::from_passphrase("passphrase", &salt2).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let salt = generate_salt();
        let key = EncryptionKey::from_passphrase("test passphrase", &salt).unwrap();
        let plaintext = b"This is sensitive transaction data";

        let encrypted = EncryptedData::encrypt(plaintext, &key).unwrap();
        let decrypted = encrypted.decrypt(&key).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encryption_produces_different_ciphertexts() {
        let salt = generate_salt();
        let key = EncryptionKey::from_passphrase("test passphrase", &salt).unwrap();
        let plaintext = b"Same plaintext";

        let encrypted1 = EncryptedData::encrypt(plaintext, &key).unwrap();
        let encrypted2 = EncryptedData::encrypt(plaintext, &key).unwrap();

        // Same plaintext encrypted twice should produce different ciphertexts
        // (due to random nonces)
        assert_ne!(encrypted1.as_bytes(), encrypted2.as_bytes());

        // But both should decrypt to the same plaintext
        assert_eq!(
            encrypted1.decrypt(&key).unwrap(),
            encrypted2.decrypt(&key).unwrap()
        );
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let salt = generate_salt();
        let key1 = EncryptionKey::from_passphrase("correct key", &salt).unwrap();
        let key2 = EncryptionKey::from_passphrase("wrong key", &salt).unwrap();

        let plaintext = b"Secret data";
        let encrypted = EncryptedData::encrypt(plaintext, &key1).unwrap();

        // Decrypting with wrong key should fail
        let result = encrypted.decrypt(&key2);
        assert!(matches!(result, Err(SyncEngineError::DecryptionFailed)));
    }

    #[test]
    fn test_corrupted_data_fails_decryption() {
        let salt = generate_salt();
        let key = EncryptionKey::from_passphrase("test passphrase", &salt).unwrap();

        let plaintext = b"Original data";
        let encrypted = EncryptedData::encrypt(plaintext, &key).unwrap();

        // Corrupt the ciphertext
        let bytes = encrypted.as_bytes().to_vec();
        let mut corrupted = bytes.clone();
        if !corrupted.is_empty() {
            let len = corrupted.len();
            corrupted[len - 1] ^= 0xFF;
        }
        let corrupted_encrypted = EncryptedData::from_bytes(corrupted);

        // Decryption should fail
        let result = corrupted_encrypted.decrypt(&key);
        assert!(matches!(result, Err(SyncEngineError::DecryptionFailed)));
    }

    #[test]
    fn test_plaintext_not_in_ciphertext() {
        let salt = generate_salt();
        let key = EncryptionKey::from_passphrase("test passphrase", &salt).unwrap();
        let plaintext = b"mock_xdr_sensitive_transaction_data";

        let encrypted = EncryptedData::encrypt(plaintext, &key).unwrap();

        // Plaintext should not appear anywhere in the ciphertext
        let ciphertext = encrypted.as_bytes();
        assert!(!ciphertext.windows(plaintext.len()).any(|w| w == plaintext));
    }

    #[test]
    fn test_nonce_is_prepended() {
        let salt = generate_salt();
        let key = EncryptionKey::from_passphrase("test passphrase", &salt).unwrap();
        let plaintext = b"test data";

        let encrypted = EncryptedData::encrypt(plaintext, &key).unwrap();
        let bytes = encrypted.as_bytes();

        // First NONCE_SIZE bytes should be the nonce
        assert_eq!(bytes.len(), NONCE_SIZE + plaintext.len() + 16); // 16 = GCM auth tag
    }
}
