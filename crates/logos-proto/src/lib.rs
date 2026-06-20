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
    /// Pool of one-time ML-KEM prekeys (consumed one-per-handshake) (F-05).
    pub kem_prekeys: Vec<KemPreKeyPublic>,
    /// Reusable last-resort ML-KEM prekey, used only when the one-time pool is empty.
    pub last_resort_kem_prekey: KemPreKeyPublic,
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

/// POST /v1/mailbox/:id — enqueue an opaque sealed envelope (sender→relay).
#[derive(Clone, Serialize, Deserialize)]
pub struct PostEnvelope {
    pub envelope: SealedEnvelope,
}

/// A queued envelope with a server-assigned id (for ACK-based deletion).
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredEnvelope {
    pub id: u64,
    pub envelope: SealedEnvelope,
}

/// POST /v1/fetch — authenticated mailbox read (does NOT delete). The server
/// derives the mailbox from the proven identity, so only the identity-key holder
/// can read it (F-04). `sig` is over `fetch_signed_bytes`.
#[derive(Clone, Serialize, Deserialize)]
pub struct FetchRequest {
    pub identity: IdentityPublic,
    pub sig: Vec<u8>,
}

pub fn fetch_signed_bytes(identity: &IdentityPublic) -> Vec<u8> {
    let mut v = b"LogosFetchv1".to_vec();
    v.extend_from_slice(&identity.encode());
    v
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FetchResponse {
    pub envelopes: Vec<StoredEnvelope>,
}

/// POST /v1/ack — authenticated delete of specific envelope ids, only after the
/// client has durably processed them (F-07). `sig` is over `ack_signed_bytes`.
#[derive(Clone, Serialize, Deserialize)]
pub struct AckRequest {
    pub identity: IdentityPublic,
    pub ids: Vec<u64>,
    pub sig: Vec<u8>,
}

pub fn ack_signed_bytes(identity: &IdentityPublic, ids: &[u64]) -> Vec<u8> {
    let mut v = b"LogosAckv1".to_vec();
    v.extend_from_slice(&identity.encode());
    for id in ids {
        v.extend_from_slice(&id.to_be_bytes());
    }
    v
}

/// Opaque, stable per-recipient mailbox id derived from the recipient's **full
/// identity** (`ed || dh`).
///
/// It must include the Ed25519 key, not just the X25519 DH key: `/v1/fetch` and
/// `/v1/ack` prove control of the mailbox by verifying an Ed25519 signature over
/// the requester's identity. If the mailbox were keyed by the DH key alone, an
/// attacker could present `{ed: attacker_ed, dh: victim_dh}`, sign with their own
/// Ed25519 key (signature valid), and the server would derive the *victim's*
/// mailbox — letting anyone read/drain another user's mailbox. Binding the id to
/// `ed` ties mailbox ownership to the key that actually authorizes reads.
/// (Phase 1 limitation: stable, not blinded/rotating — see PROTOCOL.md.)
pub fn mailbox_id(recipient: &IdentityPublic) -> String {
    let mut h = Sha256::new();
    h.update(b"logos-mailbox-v1");
    h.update(recipient.encode());
    hex::encode(h.finalize())
}
