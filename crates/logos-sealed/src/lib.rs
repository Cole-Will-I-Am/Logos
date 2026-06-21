//! Sealed sender: hide the sender's identity from the relay.
//!
//! The server issues a short-lived **sender certificate** (Ed25519-signed,
//! binding username ↔ identity key ↔ expiry). The sender encrypts that
//! certificate plus the inner payload to the recipient's identity DH key using
//! an ephemeral-X25519 + ChaCha20-Poly1305 envelope. The relay sees only an
//! opaque blob addressed to a mailbox — never who sent it. Only the recipient,
//! after decrypting, learns (and cryptographically verifies) the sender.
//!
//! EXPERIMENTAL — UNAUDITED.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use logos_identity::IdentityPublic;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum SealedError {
    #[error("decryption failed")]
    Decrypt,
    #[error("certificate signature invalid")]
    BadCertificate,
    #[error("certificate expired")]
    Expired,
    #[error("malformed sealed content")]
    Malformed,
    #[error("bad key length")]
    BadKey,
}

/// Server-signed attestation that `sender_username` controls `sender_identity`.
#[derive(Clone, Serialize, Deserialize)]
pub struct SenderCertificate {
    pub sender_username: String,
    pub sender_identity: IdentityPublic,
    pub expires_unix: u64,
    pub server_signature: Vec<u8>,
}

impl SenderCertificate {
    fn signed_bytes(username: &str, identity: &IdentityPublic, expires: u64) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"LogosSenderCertv1");
        v.extend_from_slice(username.as_bytes());
        v.push(0);
        v.extend_from_slice(&identity.encode());
        v.extend_from_slice(&expires.to_be_bytes());
        v
    }
}

/// Issued by the registration service (holds the server signing key).
pub fn issue_certificate(
    server_signing_seed: &[u8; 32],
    username: &str,
    identity: &IdentityPublic,
    expires_unix: u64,
) -> SenderCertificate {
    let signing = SigningKey::from_bytes(server_signing_seed);
    let msg = SenderCertificate::signed_bytes(username, identity, expires_unix);
    SenderCertificate {
        sender_username: username.to_string(),
        sender_identity: *identity,
        expires_unix,
        server_signature: signing.sign(&msg).to_bytes().to_vec(),
    }
}

pub fn verify_certificate(
    cert: &SenderCertificate,
    server_verifying: &[u8; 32],
    now_unix: u64,
) -> Result<(), SealedError> {
    if cert.expires_unix < now_unix {
        return Err(SealedError::Expired);
    }
    let vk = VerifyingKey::from_bytes(server_verifying).map_err(|_| SealedError::BadKey)?;
    let sig_arr: [u8; 64] = cert
        .server_signature
        .as_slice()
        .try_into()
        .map_err(|_| SealedError::BadCertificate)?;
    let sig = Signature::from_bytes(&sig_arr);
    let msg = SenderCertificate::signed_bytes(
        &cert.sender_username,
        &cert.sender_identity,
        cert.expires_unix,
    );
    vk.verify(&msg, &sig)
        .map_err(|_| SealedError::BadCertificate)
}

/// Opaque envelope handed to the relay.
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedEnvelope {
    pub ephemeral_pub: [u8; 32],
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SealedContent {
    cert: SenderCertificate,
    payload: Vec<u8>,
}

fn kdf(shared: &[u8; 32], eph_pub: &[u8; 32], recipient_pub: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(eph_pub);
    salt.extend_from_slice(recipient_pub);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = [0u8; 44];
    hk.expand(b"LogosSealedSenderv1", &mut okm)
        .expect("hkdf len ok");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    okm.zeroize();
    salt.zeroize();
    (key, nonce)
}

/// Seal a payload to the recipient's identity DH key, hiding the sender.
pub fn seal(
    recipient_identity_dh_pub: &[u8; 32],
    cert: &SenderCertificate,
    payload: &[u8],
) -> Result<SealedEnvelope, SealedError> {
    let eph = X25519Secret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = X25519Public::from(&eph).to_bytes();
    let mut shared = eph
        .diffie_hellman(&X25519Public::from(*recipient_identity_dh_pub))
        .to_bytes();
    let (mut key, mut nonce) = kdf(&shared, &eph_pub, recipient_identity_dh_pub);

    let content = SealedContent {
        cert: cert.clone(),
        payload: payload.to_vec(),
    };
    let mut plaintext = postcard::to_allocvec(&content).map_err(|_| SealedError::Malformed)?;

    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(&eph_pub);
    ad.extend_from_slice(recipient_identity_dh_pub);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &ad,
            },
        )
        .map_err(|_| SealedError::Decrypt)?;

    key.zeroize();
    nonce.zeroize();
    plaintext.zeroize();
    shared.zeroize();

    Ok(SealedEnvelope {
        ephemeral_pub: eph_pub,
        ciphertext,
    })
}

/// Unseal: recover and verify the sender certificate and the inner payload.
pub fn unseal(
    recipient_identity_dh_priv: &[u8; 32],
    env: &SealedEnvelope,
    server_verifying: &[u8; 32],
    now_unix: u64,
) -> Result<(SenderCertificate, Vec<u8>), SealedError> {
    let secret = X25519Secret::from(*recipient_identity_dh_priv);
    let recipient_pub = X25519Public::from(&secret).to_bytes();
    let mut shared = secret
        .diffie_hellman(&X25519Public::from(env.ephemeral_pub))
        .to_bytes();
    let (mut key, mut nonce) = kdf(&shared, &env.ephemeral_pub, &recipient_pub);

    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(&env.ephemeral_pub);
    ad.extend_from_slice(&recipient_pub);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &env.ciphertext,
                aad: &ad,
            },
        )
        .map_err(|_| SealedError::Decrypt)?;

    key.zeroize();
    nonce.zeroize();
    shared.zeroize();

    let content: SealedContent =
        postcard::from_bytes(&plaintext).map_err(|_| SealedError::Malformed)?;
    plaintext.zeroize();
    verify_certificate(&content.cert, server_verifying, now_unix)?;
    Ok((content.cert, content.payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use logos_identity::IdentityKeyPair;

    fn server_keys() -> ([u8; 32], [u8; 32]) {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        (sk.to_bytes(), sk.verifying_key().to_bytes())
    }

    #[test]
    fn seal_unseal_roundtrip_hides_then_reveals_sender() {
        let (srv_seed, srv_vk) = server_keys();
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let cert = issue_certificate(&srv_seed, "alice", &alice.public(), 10_000);

        let env = seal(&bob.public().dh, &cert, b"ratchet bytes here").unwrap();
        let (recovered, payload) = unseal(
            &bob.to_secret_bytes()[32..].try_into().unwrap(),
            &env,
            &srv_vk,
            1,
        )
        .unwrap();

        assert_eq!(recovered.sender_username, "alice");
        assert_eq!(recovered.sender_identity, alice.public());
        assert_eq!(payload, b"ratchet bytes here");
    }

    #[test]
    fn forged_certificate_rejected() {
        let (_srv_seed, srv_vk) = server_keys();
        let (other_seed, _other_vk) = server_keys(); // attacker's key, not the real server's
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let cert = issue_certificate(&other_seed, "alice", &alice.public(), 10_000);
        let env = seal(&bob.public().dh, &cert, b"x").unwrap();
        let bob_dh: [u8; 32] = bob.to_secret_bytes()[32..].try_into().unwrap();
        assert!(matches!(
            unseal(&bob_dh, &env, &srv_vk, 1),
            Err(SealedError::BadCertificate)
        ));
    }

    #[test]
    fn expired_certificate_rejected() {
        let (srv_seed, srv_vk) = server_keys();
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let cert = issue_certificate(&srv_seed, "alice", &alice.public(), 100);
        let env = seal(&bob.public().dh, &cert, b"x").unwrap();
        let bob_dh: [u8; 32] = bob.to_secret_bytes()[32..].try_into().unwrap();
        assert!(matches!(
            unseal(&bob_dh, &env, &srv_vk, 9_999),
            Err(SealedError::Expired)
        ));
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let (srv_seed, srv_vk) = server_keys();
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let eve = IdentityKeyPair::generate();
        let cert = issue_certificate(&srv_seed, "alice", &alice.public(), 10_000);
        let env = seal(&bob.public().dh, &cert, b"secret").unwrap();
        let eve_dh: [u8; 32] = eve.to_secret_bytes()[32..].try_into().unwrap();
        assert!(unseal(&eve_dh, &env, &srv_vk, 1).is_err());
    }
}
