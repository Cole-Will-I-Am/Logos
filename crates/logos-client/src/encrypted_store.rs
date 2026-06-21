//! Encrypted-at-rest client store.
//!
//! The on-disk format is a small JSON envelope:
//!
//! ```json
//! {
//!   "version": 2,
//!   "salt": [bytes],
//!   "nonce": [bytes],
//!   "ciphertext": [bytes]
//! }
//! ```
//!
//! The user's password is stretched with **Argon2id** to a 32-byte file-encryption
//! key. The inner plaintext (the original Store JSON) is encrypted with
//! ChaCha20-Poly1305. The AEAD tag is appended to the ciphertext by
//! `chacha20poly1305`.
//!
//! If no password is supplied we fall back to an empty password so the API stays
//! usable in test/dev settings, but the real iOS/CLI entry points must supply
//! a user-chosen passphrase. EXPERIMENTAL — UNAUDITED.

use argon2::{password_hash::rand_core::RngCore, Argon2};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const STORE_VERSION: u32 = 2;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum StoreEncryptionError {
    #[error("invalid store version")]
    BadVersion,
    #[error("argon2 error: {0}")]
    Argon2(String),
    #[error("decryption failed (bad password or corrupt store)")]
    Decrypt,
    #[error("serialization failed")]
    Serialize,
}

#[derive(Serialize, Deserialize)]
struct EncryptedStoreFile {
    version: u32,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Stretch a user password into a 32-byte ChaCha20-Poly1305 key with Argon2id.
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], StoreEncryptionError> {
    let mut okm = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut okm)
        .map_err(|e| StoreEncryptionError::Argon2(e.to_string()))?;
    Ok(okm)
}

/// Encrypt `plaintext` (the Store JSON) under `password`.
pub fn encrypt_store(
    password: Option<&str>,
    plaintext: &[u8],
) -> Result<Vec<u8>, StoreEncryptionError> {
    let password = password.unwrap_or("");

    // Generate a fresh 128-bit salt and 96-bit nonce.
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key_bytes = derive_key(password, &salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| StoreEncryptionError::Decrypt)?;

    // Build the on-disk envelope before zeroizing local key material.
    let file = EncryptedStoreFile {
        version: STORE_VERSION,
        salt: salt.to_vec(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    };

    // Defensive zeroization of key material held in local buffers.
    // The nonce is stored in the file (publicly readable metadata), so only
    // the in-memory copy is cleared here.
    key_bytes.zeroize();
    nonce_bytes.zeroize();

    serde_json::to_vec_pretty(&file).map_err(|_| StoreEncryptionError::Serialize)
}

/// Decrypt a Store JSON blob from the encrypted file bytes.
pub fn decrypt_store(
    password: Option<&str>,
    file_bytes: &[u8],
) -> Result<Vec<u8>, StoreEncryptionError> {
    let password = password.unwrap_or("");
    let file: EncryptedStoreFile =
        serde_json::from_slice(file_bytes).map_err(|_| StoreEncryptionError::Serialize)?;
    if file.version != STORE_VERSION {
        return Err(StoreEncryptionError::BadVersion);
    }
    if file.nonce.len() != NONCE_LEN {
        return Err(StoreEncryptionError::Decrypt);
    }

    let mut key_bytes = derive_key(password, &file.salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&file.nonce);

    let plaintext = cipher
        .decrypt(nonce, file.ciphertext.as_ref())
        .map_err(|_| StoreEncryptionError::Decrypt)?;

    key_bytes.zeroize();

    Ok(plaintext)
}

/// True if `file_bytes` is an encrypted-store envelope (vs a legacy/plaintext Store
/// JSON). Lets `Client::load` keep reading pre-encryption stores so existing installs
/// aren't bricked by the format change.
pub fn is_encrypted(file_bytes: &[u8]) -> bool {
    serde_json::from_slice::<EncryptedStoreFile>(file_bytes)
        .map(|f| f.version == STORE_VERSION)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"{\n  \"username\": \"alice\"\n}";
        let encrypted = encrypt_store(Some("correct horse battery staple"), plaintext).unwrap();
        let decrypted = decrypt_store(Some("correct horse battery staple"), &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_password_fails() {
        let plaintext = b"secret store";
        let encrypted = encrypt_store(Some("good"), plaintext).unwrap();
        assert!(decrypt_store(Some("bad"), &encrypted).is_err());
    }

    #[test]
    fn empty_password_is_allowed_for_tests() {
        let plaintext = b"{}";
        let encrypted = encrypt_store(None, plaintext).unwrap();
        let decrypted = decrypt_store(None, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn format_detection_distinguishes_plaintext_from_encrypted() {
        // A legacy/plaintext Store JSON must NOT be seen as encrypted, so existing
        // (pre-encryption) installs keep loading. Encrypted envelopes must be detected.
        let legacy = br#"{"username":"alice","identity_secret":[1,2,3]}"#;
        assert!(!is_encrypted(legacy));
        let enc = encrypt_store(Some("pw"), b"{}").unwrap();
        assert!(is_encrypted(&enc));
    }
}
