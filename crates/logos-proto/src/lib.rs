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

/// Canonical username grammar, shared by the relay and clients so they agree on
/// what is registrable. Usernames are the public handle (no phone numbers), so we
/// keep them deliberately narrow to limit homograph/confusable abuse: **lowercase
/// ASCII**, must start with a letter, then letters / digits / underscore,
/// `USERNAME_MIN`..=`USERNAME_MAX` characters. A richer free-text *display name*
/// (separate from this canonical handle) is a future addition.
pub const USERNAME_MIN: usize = 3;
pub const USERNAME_MAX: usize = 32;

const RESERVED_USERNAMES: &[&str] = &[
    "admin",
    "administrator",
    "logos",
    "system",
    "support",
    "root",
    "relay",
    "server",
    "null",
    "none",
    "everyone",
    "all",
    "me",
    "you",
];

/// Validate a canonical username. `Ok(())` if registrable, else a human-readable
/// reason. Both the client (pre-flight, for a clear message) and the relay
/// (authoritative) call this.
pub fn validate_username(name: &str) -> Result<(), &'static str> {
    let len = name.len(); // ASCII-only grammar ⇒ byte length == char count once charset passes
    if len < USERNAME_MIN {
        return Err("username is too short (minimum 3 characters)");
    }
    if len > USERNAME_MAX {
        return Err("username is too long (maximum 32 characters)");
    }
    match name.chars().next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return Err("username must start with a lowercase letter (a–z)"),
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err("username may only contain lowercase letters, digits, and underscores");
    }
    if RESERVED_USERNAMES.contains(&name) {
        return Err("that username is reserved");
    }
    Ok(())
}

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
///
/// `Prekey`/`Normal` are the 1:1 channel and are unchanged on the wire (so existing
/// clients keep interoperating). `GroupCtrl`/`Group` add E2EE group chats (P4.0a):
/// the control plane rides the pairwise Double Ratchet, the data plane uses sender
/// keys. A client that predates groups will simply fail to parse the new variants and
/// drop them — but it only ever receives them if a group peer sends to it.
#[derive(Clone, Serialize, Deserialize)]
pub enum OuterMessage {
    /// First message of a session: carries the PQXDH initial message + first ratchet message.
    Prekey {
        initial: InitialMessage,
        ratchet: RatchetMessage,
    },
    /// Subsequent messages on an established session.
    Normal { ratchet: RatchetMessage },
    /// Group **control** plane (sender-key distribution, invites), carried encrypted
    /// over the pairwise Double Ratchet so it inherits the 1:1 identity binding.
    /// `initial` is `Some` iff this envelope also establishes the pairwise session
    /// (the group analogue of `Prekey`).
    GroupCtrl {
        initial: Option<InitialMessage>,
        ratchet: RatchetMessage,
    },
    /// Group **data** plane: a sender-key-encrypted message. Not wrapped in the
    /// pairwise ratchet — the recipient decrypts it with the sender's distributed
    /// sender key for `group_id`, after verifying `signature` (sender's per-group
    /// Ed25519 key) over the group id, iteration, and ciphertext. `signature` is a
    /// 64-byte Ed25519 signature (kept as `Vec<u8>` since serde arrays stop at 32).
    Group {
        group_id: [u8; 16],
        iteration: u32,
        ciphertext: Vec<u8>,
        signature: Vec<u8>,
    },
}

/// Stable hex rendering of a 16-byte group id, used as the client store's map key and
/// for display.
pub fn group_id_hex(id: &[u8; 16]) -> String {
    hex::encode(id)
}

/// Shared metadata for an E2EE group (sender-key v1). Members/admins are usernames;
/// each client resolves and TOFU-pins the real identities itself (the creator's view
/// is advisory, never trusted for sealing). Name/avatar are not cryptographically
/// bound in v1 (a malicious relay can show divergent names) — MLS (P4.1) fixes this.
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupMeta {
    pub id: [u8; 16],
    pub name: String,
    pub members: Vec<String>,
    pub admins: Vec<String>,
    pub created_unix: u64,
}

/// A member's sender key as distributed to peers: the current chain key + iteration
/// (so a later joiner can't read history) and the per-group Ed25519 signing public key.
#[derive(Clone, Serialize, Deserialize)]
pub struct SenderKeyDist {
    pub chain_key: [u8; 32],
    pub iteration: u32,
    pub signing_pub: [u8; 32],
}

/// Control-plane message carried (encrypted) over a pairwise session to bootstrap and
/// maintain a sender-key group.
#[derive(Clone, Serialize, Deserialize)]
pub enum GroupControl {
    /// Sent by the creator to each initial member: full group metadata + the creator's
    /// sender key. A recipient that doesn't know the group creates it locally and
    /// distributes its own sender key to the other members.
    Invite {
        group: GroupMeta,
        sender_key: SenderKeyDist,
    },
    /// A member publishing their own sender key for an already-known group.
    SenderKey {
        group_id: [u8; 16],
        sender_key: SenderKeyDist,
    },
}

/// Domain-separated bytes a group message's per-message Ed25519 signature covers:
/// binds the group, position, and ciphertext so a signature can't be lifted across
/// groups/positions, and another member (who shares the chain key) can't forge or
/// alter a message and have it attributed to the real sender.
pub fn group_message_signed_bytes(
    group_id: &[u8; 16],
    iteration: u32,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut v = b"LogosGroupMsgv1".to_vec();
    v.extend_from_slice(group_id);
    v.extend_from_slice(&iteration.to_be_bytes());
    v.extend_from_slice(ciphertext);
    v
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

/// POST /v1/replenish — publish fresh one-time prekeys for an existing identity.
#[derive(Clone, Serialize, Deserialize)]
pub struct ReplenishRequest {
    pub username: String,
    pub identity: IdentityPublic,
    pub one_time_prekeys: Vec<OneTimePreKeyPublic>,
    pub kem_prekeys: Vec<KemPreKeyPublic>,
    pub sig: Vec<u8>,
}

pub fn replenish_signed_bytes(username: &str, identity: &IdentityPublic) -> Vec<u8> {
    let mut v = b"LogosReplenishv1".to_vec();
    v.extend_from_slice(username.as_bytes());
    v.push(0);
    v.extend_from_slice(&identity.encode());
    v
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

#[cfg(test)]
mod username_tests {
    use super::validate_username;

    #[test]
    fn accepts_valid_usernames() {
        for u in ["alice", "bob_42", "a1b", "x".repeat(32).as_str()] {
            assert!(validate_username(u).is_ok(), "should accept {u}");
        }
    }

    #[test]
    fn rejects_invalid_usernames() {
        for u in [
            "ab",            // too short
            &"x".repeat(33), // too long
            "Alice",         // uppercase
            "1abc",          // must start with a letter
            "a b",           // space
            "a-b",           // hyphen not allowed
            "naïve",         // non-ASCII
            "admin",         // reserved
        ] {
            assert!(validate_username(u).is_err(), "should reject {u}");
        }
    }
}
