//! ML-KEM-1024 (FIPS 203) wrapper exposing a clean byte-oriented interface for
//! the post-quantum half of the PQXDH hybrid handshake. Parameters chosen to
//! match Signal's PQXDH (ML-KEM-1024 / NIST Level 5).
//!
//! Wraps the audited-primitive `ml-kem` (RustCrypto) crate; we add no novel
//! cryptography here, only encoding glue. We use the crate's no-RNG-argument
//! convenience methods (system RNG) to avoid a `rand_core` version split.

use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport, KeyInit, TryKeyInit};
use ml_kem::{DecapsulationKey1024 as Dk, EncapsulationKey1024 as Ek, Kem, MlKem1024};

use crate::IdentityError;

/// 32-byte ML-KEM shared secret (fed into the PQXDH KDF alongside the X25519 DH legs).
pub type KemSharedSecret = [u8; 32];

/// Public encapsulation key (published in the prekey bundle, ~1.5 KB).
pub struct KemPublic(Ek);

/// Secret decapsulation key (held by the recipient).
pub struct KemSecret(Dk);

/// KEM ciphertext produced by the initiator (~1.5 KB).
#[derive(Clone)]
pub struct KemCiphertext(pub Vec<u8>);

/// Generate a fresh ML-KEM-1024 keypair (system RNG).
pub fn generate() -> (KemSecret, KemPublic) {
    let (dk, ek) = MlKem1024::generate_keypair();
    (KemSecret(dk), KemPublic(ek))
}

impl KemPublic {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        Ek::new_from_slice(bytes)
            .map(KemPublic)
            .map_err(|_| IdentityError::BadLength)
    }

    /// Encapsulate to this public key: returns ciphertext + shared secret.
    pub fn encapsulate(&self) -> Result<(KemCiphertext, KemSharedSecret), IdentityError> {
        let (ct, ss) = self.0.encapsulate();
        let mut shared = [0u8; 32];
        shared.copy_from_slice(ss.as_ref());
        Ok((KemCiphertext(ct.to_vec()), shared))
    }
}

impl KemSecret {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        Dk::new_from_slice(bytes)
            .map(KemSecret)
            .map_err(|_| IdentityError::BadLength)
    }

    pub fn decapsulate(&self, ct: &KemCiphertext) -> Result<KemSharedSecret, IdentityError> {
        let ss = self
            .0
            .decapsulate_slice(&ct.0)
            .map_err(|_| IdentityError::Kem("decapsulate failed".into()))?;
        let mut shared = [0u8; 32];
        shared.copy_from_slice(ss.as_ref());
        Ok(shared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_encaps_decaps_agree() {
        let (sk, pk) = generate();
        let (ct, ss_send) = pk.encapsulate().unwrap();
        let ss_recv = sk.decapsulate(&ct).unwrap();
        assert_eq!(ss_send, ss_recv);
    }

    #[test]
    fn kem_public_roundtrip_bytes() {
        let (_, pk) = generate();
        let bytes = pk.to_bytes();
        let pk2 = KemPublic::from_bytes(&bytes).unwrap();
        assert_eq!(pk.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn kem_secret_roundtrip_bytes() {
        let (sk, pk) = generate();
        let sk2 = KemSecret::from_bytes(&sk.to_bytes()).unwrap();
        let (ct, ss) = pk.encapsulate().unwrap();
        assert_eq!(sk2.decapsulate(&ct).unwrap(), ss);
    }
}
