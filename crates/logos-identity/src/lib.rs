//! Logos identity layer: long-term identity keys, prekey bundles, and the
//! post-quantum KEM prekeys consumed by the PQXDH handshake.
//!
//! Identity model (documented deviation from Signal): each identity holds a
//! separate **Ed25519** signing key and **X25519** DH key, rather than a single
//! Curve25519 key used via XEdDSA. This keeps us on the audited `*-dalek` APIs
//! without a custom XEdDSA implementation. Usernames are the public handle; no
//! phone numbers anywhere.
//!
//! EXPERIMENTAL — UNAUDITED. Do not use for real secrets. See repository README.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::ZeroizeOnDrop;

pub mod kem;
pub use kem::{KemCiphertext, KemPublic, KemSecret, KemSharedSecret};

/// 32-byte raw public-key encoding used throughout the wire format.
pub type Bytes32 = [u8; 32];

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid key length")]
    BadLength,
    #[error("malformed key")]
    MalformedKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("kem error: {0}")]
    Kem(String),
}

/// Public half of an identity, safe to publish. `ed` verifies signatures; `dh`
/// is the long-term X25519 key used in the handshake DH legs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityPublic {
    pub ed: Bytes32,
    pub dh: Bytes32,
}

impl IdentityPublic {
    pub fn verifying_key(&self) -> Result<VerifyingKey, IdentityError> {
        VerifyingKey::from_bytes(&self.ed).map_err(|_| IdentityError::MalformedKey)
    }
    pub fn dh_public(&self) -> X25519Public {
        X25519Public::from(self.dh)
    }
    /// Stable bytes for hashing / safety numbers.
    pub fn encode(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.ed);
        out[32..].copy_from_slice(&self.dh);
        out
    }
}

/// Long-term identity secret. Never leaves the device; zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct IdentityKeyPair {
    signing: SigningKey,
    #[zeroize(skip)]
    dh_public: X25519Public,
    dh_secret: X25519Secret,
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let dh_secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
        let dh_public = X25519Public::from(&dh_secret);
        Self {
            signing,
            dh_public,
            dh_secret,
        }
    }

    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            ed: self.signing.verifying_key().to_bytes(),
            dh: self.dh_public.to_bytes(),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    pub fn dh_secret(&self) -> &X25519Secret {
        &self.dh_secret
    }

    /// Serialize the secret material for the encrypted client store.
    pub fn to_secret_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.signing.to_bytes());
        out[32..].copy_from_slice(&self.dh_secret.to_bytes());
        out
    }

    pub fn from_secret_bytes(bytes: &[u8; 64]) -> Self {
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&bytes[..32]);
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&bytes[32..]);
        let signing = SigningKey::from_bytes(&ed);
        let dh_secret = X25519Secret::from(dh);
        let dh_public = X25519Public::from(&dh_secret);
        Self {
            signing,
            dh_public,
            dh_secret,
        }
    }
}

/// Verify an Ed25519 signature against an identity public key.
pub fn verify(id: &IdentityPublic, msg: &[u8], sig: &[u8]) -> Result<(), IdentityError> {
    let vk = id.verifying_key()?;
    let sig_arr: [u8; 64] = sig.try_into().map_err(|_| IdentityError::BadLength)?;
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify(msg, &signature)
        .map_err(|_| IdentityError::BadSignature)
}

/// An X25519 prekey signed by the identity (medium-term "signed prekey").
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedPreKeyPublic {
    pub id: u32,
    pub public: Bytes32,
    pub signature: Vec<u8>,
}

/// A single-use X25519 prekey (no signature; covered by the signed prekey + handshake).
#[derive(Clone, Serialize, Deserialize)]
pub struct OneTimePreKeyPublic {
    pub id: u32,
    pub public: Bytes32,
}

/// A post-quantum (ML-KEM-1024) prekey, signed by the identity.
#[derive(Clone, Serialize, Deserialize)]
pub struct KemPreKeyPublic {
    pub id: u32,
    pub public: Vec<u8>,
    pub signature: Vec<u8>,
}

/// What a recipient publishes to the directory and a sender fetches to start
/// a session. Contains everything needed to run PQXDH offline.
#[derive(Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub username: String,
    pub identity: IdentityPublic,
    pub signed_prekey: SignedPreKeyPublic,
    pub one_time_prekey: Option<OneTimePreKeyPublic>,
    pub kem_prekey: KemPreKeyPublic,
}

/// Domain-separated, identity-bound message a prekey signature covers (F-10):
/// binds purpose/version, the owning identity, the key id, and the key bytes —
/// so a signature can't be lifted onto a different key, id, identity, or use.
pub fn prekey_sig_msg(
    domain: &[u8],
    identity: &IdentityPublic,
    key_id: u32,
    key_bytes: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(domain.len() + 64 + 4 + key_bytes.len());
    v.extend_from_slice(domain);
    v.extend_from_slice(&identity.encode());
    v.extend_from_slice(&key_id.to_be_bytes());
    v.extend_from_slice(key_bytes);
    v
}

const SPK_DOMAIN: &[u8] = b"LogosSignedPreKeyv1";
const KEM_DOMAIN: &[u8] = b"LogosKemPreKeyv1";

impl PreKeyBundle {
    /// Verify the signed-prekey and kem-prekey signatures bind to this identity.
    pub fn verify(&self) -> Result<(), IdentityError> {
        verify(
            &self.identity,
            &prekey_sig_msg(
                SPK_DOMAIN,
                &self.identity,
                self.signed_prekey.id,
                &self.signed_prekey.public,
            ),
            &self.signed_prekey.signature,
        )?;
        verify(
            &self.identity,
            &prekey_sig_msg(
                KEM_DOMAIN,
                &self.identity,
                self.kem_prekey.id,
                &self.kem_prekey.public,
            ),
            &self.kem_prekey.signature,
        )?;
        Ok(())
    }
}

/// Secret prekey material held by the recipient (kept in the client store).
pub struct SignedPreKeySecret {
    pub id: u32,
    pub secret: X25519Secret,
}

pub struct OneTimePreKeySecret {
    pub id: u32,
    pub secret: X25519Secret,
}

pub struct KemPreKeySecret {
    pub id: u32,
    pub secret: KemSecret,
}

/// Generate a freshly signed X25519 prekey.
pub fn new_signed_prekey(
    id: u32,
    identity: &IdentityKeyPair,
) -> (SignedPreKeyPublic, SignedPreKeySecret) {
    let secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
    let public = X25519Public::from(&secret).to_bytes();
    let signature = identity
        .sign(&prekey_sig_msg(SPK_DOMAIN, &identity.public(), id, &public))
        .to_vec();
    (
        SignedPreKeyPublic {
            id,
            public,
            signature,
        },
        SignedPreKeySecret { id, secret },
    )
}

pub fn new_one_time_prekey(id: u32) -> (OneTimePreKeyPublic, OneTimePreKeySecret) {
    let secret = X25519Secret::random_from_rng(rand::rngs::OsRng);
    let public = X25519Public::from(&secret).to_bytes();
    (
        OneTimePreKeyPublic { id, public },
        OneTimePreKeySecret { id, secret },
    )
}

pub fn new_kem_prekey(id: u32, identity: &IdentityKeyPair) -> (KemPreKeyPublic, KemPreKeySecret) {
    let (secret, public) = kem::generate();
    let public_bytes = public.to_bytes();
    let signature = identity
        .sign(&prekey_sig_msg(
            KEM_DOMAIN,
            &identity.public(),
            id,
            &public_bytes,
        ))
        .to_vec();
    (
        KemPreKeyPublic {
            id,
            public: public_bytes,
            signature,
        },
        KemPreKeySecret { id, secret },
    )
}

/// A human-comparable safety number derived from both identities (Signal-style):
/// SHA-256 over the sorted identity encodings, rendered as 12 groups of 5 digits.
pub fn safety_number(a: &IdentityPublic, b: &IdentityPublic) -> String {
    let (first, second) = {
        let (ea, eb) = (a.encode(), b.encode());
        if ea <= eb {
            (ea, eb)
        } else {
            (eb, ea)
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(b"logos-safety-number-v1");
    hasher.update(first);
    hasher.update(second);
    let digest = hasher.finalize();

    let mut out = String::new();
    for chunk in digest.chunks(5).take(6) {
        let mut acc: u64 = 0;
        for &byte in chunk {
            acc = acc.wrapping_mul(256).wrapping_add(byte as u64);
        }
        out.push_str(&format!("{:05} ", acc % 100_000));
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_sign_verify_roundtrip() {
        let id = IdentityKeyPair::generate();
        let pubk = id.public();
        let msg = b"hello logos";
        let sig = id.sign(msg);
        assert!(verify(&pubk, msg, &sig).is_ok());
        let mut bad = sig;
        bad[0] ^= 0xff;
        assert!(verify(&pubk, msg, &bad).is_err());
    }

    #[test]
    fn identity_secret_roundtrip() {
        let id = IdentityKeyPair::generate();
        let bytes = id.to_secret_bytes();
        let restored = IdentityKeyPair::from_secret_bytes(&bytes);
        assert_eq!(id.public(), restored.public());
    }

    #[test]
    fn prekey_bundle_verifies() {
        let id = IdentityKeyPair::generate();
        let (spk, _) = new_signed_prekey(1, &id);
        let (otk, _) = new_one_time_prekey(7);
        let (kpk, _) = new_kem_prekey(1, &id);
        let bundle = PreKeyBundle {
            username: "alice".into(),
            identity: id.public(),
            signed_prekey: spk,
            one_time_prekey: Some(otk),
            kem_prekey: kpk,
        };
        assert!(bundle.verify().is_ok());
    }

    #[test]
    fn tampered_prekey_rejected() {
        let id = IdentityKeyPair::generate();
        let (mut spk, _) = new_signed_prekey(1, &id);
        spk.public[0] ^= 0xff;
        let (kpk, _) = new_kem_prekey(1, &id);
        let bundle = PreKeyBundle {
            username: "alice".into(),
            identity: id.public(),
            signed_prekey: spk,
            one_time_prekey: None,
            kem_prekey: kpk,
        };
        assert!(bundle.verify().is_err());
    }

    #[test]
    fn safety_number_is_symmetric_and_stable() {
        let a = IdentityKeyPair::generate().public();
        let b = IdentityKeyPair::generate().public();
        assert_eq!(safety_number(&a, &b), safety_number(&b, &a));
        assert_eq!(safety_number(&a, &b).len(), 6 * 5 + 5); // "12345 " * 6 trimmed
    }
}
