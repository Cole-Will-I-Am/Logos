//! Wire types and endpoint helpers shared by the Logos relay and clients.
//!
//! The relay is minimal-trust: it sees registration data (public keys), opaque
//! sealed envelopes addressed to a mailbox id, and issues sender certificates.
//! It never sees plaintext or (thanks to sealed sender) message senders.

use logos_identity::{IdentityPublic, KemPreKeyPublic, OneTimePreKeyPublic, SignedPreKeyPublic};
use logos_pqxdh::InitialMessage;
use logos_ratchet::RatchetMessage;
use logos_sealed::{SealedEnvelope, SenderCertificate};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// POST /v1/register — publish identity + prekeys to the directory.
#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub identity: IdentityPublic,
    pub signed_prekey: SignedPreKeyPublic,
    pub kem_prekey: KemPreKeyPublic,
    pub one_time_prekeys: Vec<OneTimePreKeyPublic>,
    /// Identity signature over `registration_signed_bytes`, proving key control.
    pub registration_sig: Vec<u8>,
}

pub fn registration_signed_bytes(username: &str, identity: &IdentityPublic) -> Vec<u8> {
    let mut v = b"LogosRegisterv1".to_vec();
    v.extend_from_slice(username.as_bytes());
    v.push(0);
    v.extend_from_slice(&identity.encode());
    v
}

/// GET /v1/directory/:username — a prekey bundle (consumes one one-time prekey).
#[derive(Clone, Serialize, Deserialize)]
pub struct DirectoryResponse {
    pub bundle: logos_identity::PreKeyBundle,
}

/// POST /v1/cert — request a sealed-sender certificate.
#[derive(Clone, Serialize, Deserialize)]
pub struct CertRequest {
    pub username: String,
    pub identity: IdentityPublic,
    pub sig: Vec<u8>,
}

pub fn cert_signed_bytes(username: &str, identity: &IdentityPublic) -> Vec<u8> {
    let mut v = b"LogosCertReqv1".to_vec();
    v.extend_from_slice(username.as_bytes());
    v.push(0);
    v.extend_from_slice(&identity.encode());
    v
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CertResponse {
    pub certificate: SenderCertificate,
}

/// GET /v1/server-key — the server's Ed25519 verifying key (to check sender certs).
#[derive(Clone, Serialize, Deserialize)]
pub struct ServerKeyResponse {
    pub verifying_key: [u8; 32],
}

/// The inner (sealed) payload exchanged between clients.
#[derive(Clone, Serialize, Deserialize)]
pub enum OuterMessage {
    /// First message of a session: carries the PQXDH initial message + first ratchet message.
    Prekey {
        initial: InitialMessage,
        ratchet: RatchetMessage,
    },
    /// Subsequent messages on an established session.
    Normal { ratchet: RatchetMessage },
}

/// POST /v1/mailbox/:id — enqueue an opaque sealed envelope.
#[derive(Clone, Serialize, Deserialize)]
pub struct PostEnvelope {
    pub envelope: SealedEnvelope,
}

/// GET /v1/mailbox/:id — fetch + delete queued envelopes (delete-on-deliver).
#[derive(Clone, Serialize, Deserialize)]
pub struct FetchResponse {
    pub envelopes: Vec<SealedEnvelope>,
}

/// Opaque, stable per-recipient mailbox id derived from the recipient's identity
/// DH key. (Phase 1 limitation: stable, not blinded/rotating — see PROTOCOL.md.)
pub fn mailbox_id(recipient_identity_dh: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"logos-mailbox-v1");
    h.update(recipient_identity_dh);
    hex::encode(h.finalize())
}
