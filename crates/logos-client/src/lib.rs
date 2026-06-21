//! Logos client engine — ties identity, PQXDH, the Double Ratchet, and sealed
//! sender together and talks to the relay. The public API is **synchronous** and
//! uses plain types (strings/bytes) so it can be wrapped for an iOS app (Swift
//! via UniFFI / an xcframework) without async leaking across the FFI boundary.
//!
//! EXPERIMENTAL — UNAUDITED.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[doc(hidden)]
pub mod encrypted_store;

use logos_identity::{
    new_kem_prekey, new_one_time_prekey, new_signed_prekey, verify_ed25519, GroupSigningKey,
    IdentityKeyPair, IdentityPublic, KemSecret,
};
use logos_pqxdh::{initiate, respond, InitialMessage};
use logos_proto::{
    ack_signed_bytes, cert_signed_bytes, fetch_signed_bytes, group_id_hex,
    group_message_signed_bytes, mailbox_id, registration_signed_bytes, replenish_signed_bytes,
    validate_username, AckRequest, CertRequest, CertResponse, DirectoryResponse, FetchRequest,
    FetchResponse, GroupControl, GroupMeta, OuterMessage, PostEnvelope, RegisterRequest,
    ReplenishRequest, SenderKeyDist, ServerKeyResponse,
};
use logos_ratchet::{senderkey, RatchetState};
use logos_sealed::{seal, unseal, SealedEnvelope, SenderCertificate};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

const ONE_TIME_PREKEY_COUNT: u32 = 20;
const KEM_PREKEY_COUNT: u32 = 10;
/// Reserved id for the reusable last-resort ML-KEM prekey (one-time ids start at 1).
const LAST_RESORT_KEM_ID: u32 = 0;

/// Hard ceiling on any relay response body the client will deserialize. A
/// malicious/compromised relay cannot force unbounded buffering before the
/// caller sees a parse failure (F-08 sibling).
const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Max envelopes returned in a single `/v1/fetch` call. Extra envelopes remain
/// on the server and are fetched on the next poll.
const MAX_FETCH_ENVELOPES: usize = 1_000;

/// Drop a quarantined (no-session) envelope after this many poll attempts so a peer
/// can't permanently pin a victim's mailbox with undeliverable messages (red-team M4).
const MAX_QUARANTINE_ATTEMPTS: u32 = 5;

/// Bound on remembered consumed-initial fingerprints (red-team M3 replay protection).
const MAX_SEEN_INITIALS: usize = 512;

/// When our published one-time prekey pools drop to or below these watermarks, the
/// client tops them back up to the full counts and republishes via `POST /v1/replenish`
/// (M1). Prekeys are minted only at registration today, so without this they drain to
/// the reusable last-resort KEM and silently lose initial-message forward secrecy —
/// which group setup (many pairwise handshakes at once) accelerates.
const OTK_LOW_WATERMARK: usize = 5;
const KEM_LOW_WATERMARK: usize = 3;

/// Soft cap on group size for sender-key v1 (join/remove cost is O(N)). Enforced
/// client-side; the relay has no group concept (per-member posting), so it can't
/// enforce this server-side.
const MAX_GROUP_SIZE: usize = 32;

/// Bound on buffered sender keys that arrived before their group invite, so an
/// out-of-order bootstrap still completes — FIFO-evicted past this.
const MAX_PENDING_GROUP_KEYS: usize = 256;

/// Errors from the client engine. The variants the UI must treat differently are
/// **typed** (not stringly): `IdentityChanged` drives the high-friction identity
/// interstitial, `NotRegistered` an "unknown user" message, `Network` a retry. The
/// FFI maps these 1:1 onto `LogosError` (see `logos-ffi`).
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// A TOFU-pinned contact's identity key changed — possible relay
    /// key-substitution / impersonation (F-02/F-03). Surfaced distinctly so the UI
    /// never shows it as a generic send failure.
    #[error("identity for '{peer}' changed — refusing (possible impersonation/MITM)")]
    IdentityChanged { peer: String },
    /// The peer has no directory entry on this relay (not registered / typo).
    #[error("'{peer}' isn't registered on this relay")]
    NotRegistered { peer: String },
    /// The chosen username is already registered on this relay (HTTP 409). Surfaced
    /// distinctly so onboarding says "pick another name" instead of a misleading
    /// "can't reach the relay" (the relay was reached — it refused the name).
    #[error("the username '{username}' is already taken on this relay")]
    UsernameTaken { username: String },
    /// A recovery phrase failed to parse (wrong word count, misspelling, or a bad
    /// BIP39 checksum). Surfaced distinctly so restore can say "check the words".
    #[error("that recovery phrase isn't valid — check the words and try again")]
    InvalidRecoveryPhrase,
    /// The chosen username doesn't match the canonical grammar. `reason` is a
    /// human-readable explanation (length / charset / reserved).
    #[error("{reason}")]
    InvalidUsername { reason: String },
    /// Transport-level failure reaching the relay. Retryable.
    #[error("network error: {0}")]
    Network(String),
    /// Anything else (protocol, crypto, store, parse).
    #[error("logos-client: {0}")]
    Other(String),
}

impl ClientError {
    fn other(s: impl Into<String>) -> Self {
        ClientError::Other(s.into())
    }
}

type Result<T> = std::result::Result<T, ClientError>;

/// Wrap a non-network error (io / serde / crypto) as `Other`.
fn err<E: std::fmt::Display>(e: E) -> ClientError {
    ClientError::Other(e.to_string())
}

/// Wrap a relay transport error as `Network`.
fn net(e: reqwest::Error) -> ClientError {
    ClientError::Network(e.to_string())
}

fn now() -> u64 {
    // Saturate to 0 if the clock is before the epoch rather than panicking — a
    // panic across the iOS FFI would crash the app.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Stable fingerprint of an inbound initial (handshake) message, for replay
/// detection (red-team M3). A replayed envelope is byte-identical → same
/// fingerprint; a genuine re-handshake uses a fresh ephemeral → different one.
fn initial_fingerprint(
    initial: &InitialMessage,
    ratchet: &logos_ratchet::RatchetMessage,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"logos-initial-fp-v1");
    if let Ok(b) = serde_json::to_vec(initial) {
        h.update(&b);
    }
    if let Ok(b) = serde_json::to_vec(ratchet) {
        h.update(&b);
    }
    h.finalize().into()
}

/// Blocking HTTP client with bounded connect/total timeouts so a slow or hung
/// relay (an in-scope adversary) cannot wedge a call forever — important across
/// the iOS FFI, where this runs under a `Mutex<Client>`. Falls back to the
/// default client if the builder fails (it shouldn't).
fn http_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new())
}

/// Read a relay response with a hard byte cap. Fails closed: if the server
/// advertises a body larger than `MAX_RESPONSE_BODY_BYTES`, or if the streamed
/// body exceeds it, we return a `Network` error instead of buffering forever.
fn read_body_with_limit(resp: reqwest::blocking::Response, limit: usize) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len as usize > limit {
            return Err(ClientError::Network(format!(
                "response body too large (advertised {len} > {limit})"
            )));
        }
    }
    use std::io::Read;
    let mut out = Vec::with_capacity(4096);
    let mut take = resp.take(limit as u64 + 1);
    take.read_to_end(&mut out)
        .map_err(|e| ClientError::Network(e.to_string()))?;
    if out.len() > limit {
        return Err(ClientError::Network(format!(
            "response body exceeded {limit} byte cap"
        )));
    }
    Ok(out)
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct OtkSecret {
    #[zeroize(skip)]
    id: u32,
    secret: [u8; 32],
}

/// A stored ML-KEM prekey secret (one-time or last-resort) (F-05).
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct KemSecretRec {
    #[zeroize(skip)]
    id: u32,
    secret: Vec<u8>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Session {
    ratchet: RatchetState,
    /// Full peer identity (`ed` + `dh`). The `dh` half seals envelopes to the
    /// peer; the full identity derives the peer's mailbox id (which must bind the
    /// Ed25519 key — see `logos_proto::mailbox_id`).
    #[zeroize(skip)]
    peer_identity: IdentityPublic,
    #[zeroize(skip)]
    sent_initial: bool,
    #[zeroize(skip)]
    pending_initial: Option<InitialMessage>,
}

/// On-disk client state. Phase-1: stored as plaintext JSON — encryption-at-rest
/// (Argon2id-wrapped) is a tracked follow-up; local-device security is partly
/// out of scope per the threat model.
#[derive(Serialize, Deserialize)]
struct Store {
    username: String,
    identity_secret: Vec<u8>,
    /// 32-byte master seed the identity was derived from (HKDF → Ed25519 + X25519).
    /// Encoded as the BIP39 recovery phrase. `None` for legacy identities created
    /// before recovery phrases existed (they predate seed-derivation and cannot
    /// produce a phrase). `#[serde(default)]` so those stores keep deserializing.
    #[serde(default)]
    identity_seed: Option<[u8; 32]>,
    signed_prekey_id: u32,
    signed_prekey_secret: [u8; 32],
    kem_one_time: Vec<KemSecretRec>,
    kem_last_resort: KemSecretRec,
    one_time: Vec<OtkSecret>,
    sessions: HashMap<String, Session>,
    /// TOFU-pinned identity per username (F-02/F-03): detects/blocks a relay
    /// swapping a known contact's identity key.
    #[serde(default)]
    contacts: HashMap<String, IdentityPublic>,
    /// Per-contact verification state. Kept separate from `contacts` so existing
    /// stores (which only have `contacts`) deserialize unchanged.
    #[serde(default)]
    verifications: HashMap<String, Verification>,
    server_vk: Option<[u8; 32]>,
    cert: Option<SenderCertificate>,
    /// Fingerprints of consumed initial (handshake) messages, so a replay of a
    /// captured initial is rejected even after `reset_session` clears the live
    /// session (red-team M3). Bounded FIFO.
    #[serde(default)]
    seen_initials: VecDeque<[u8; 32]>,
    /// Per-envelope-id quarantine attempt counts; an undeliverable (no-session)
    /// envelope is ACK-dropped after `MAX_QUARANTINE_ATTEMPTS` so a peer can't pin
    /// the mailbox forever (red-team M4).
    #[serde(default)]
    quarantine: HashMap<u64, u32>,
    /// Monotonic next-id counters for *replenished* one-time prekeys (M1), so a
    /// freshly minted prekey never reuses an id still live on the relay. `0`
    /// (legacy/default) means "uninitialized" and is lazily set past the max
    /// existing id on first replenish.
    #[serde(default)]
    next_one_time_id: u32,
    #[serde(default)]
    next_kem_id: u32,
    /// E2EE group state (P4.0a), keyed by hex group id. `#[serde(default)]` so older
    /// stores (which have no groups) keep deserializing.
    #[serde(default)]
    groups: HashMap<String, GroupRecord>,
    /// Sender keys received before their group's invite, buffered for out-of-order
    /// bootstrap delivery (bounded FIFO).
    #[serde(default)]
    pending_group_keys: Vec<PendingSenderKey>,
}

impl Drop for Store {
    fn drop(&mut self) {
        // Zeroize secret material before the store is freed. Public metadata
        // (username, ids, pinned identities, certificates) is intentionally
        // skipped — it carries no key material.
        self.identity_secret.zeroize();
        if let Some(seed) = self.identity_seed.as_mut() {
            seed.zeroize();
        }
        self.signed_prekey_secret.zeroize();
        for rec in &mut self.kem_one_time {
            rec.zeroize();
        }
        self.kem_last_resort.zeroize();
        for rec in &mut self.one_time {
            rec.zeroize();
        }
        for session in self.sessions.values_mut() {
            session.ratchet.zeroize();
        }
        // Group secrets: the per-group signing seed (plain array) plus any buffered
        // sender-chain keys. The send/receive chains themselves are `ZeroizeOnDrop`,
        // so they clear when the records drop with the map.
        for rec in self.groups.values_mut() {
            rec.my_signing_secret.zeroize();
        }
        for p in &mut self.pending_group_keys {
            p.dist.chain_key.zeroize();
        }
    }
}
/// Safety-number confirmation + identity-change tracking for one contact.
#[derive(Serialize, Deserialize, Clone, Default)]
struct Verification {
    verified: bool,
    verified_at: Option<u64>,
    #[serde(default)]
    changes: u32,
}

/// Per-group state for sender-key group chats (P4.0a). `my_sender` is our own
/// forward-ratcheting send chain; `peers` holds one receiver chain + signing public
/// key per other member. `my_signing_secret` is the 32-byte seed of our per-group
/// Ed25519 signing key (zeroized in `Store::drop`; the chains zeroize themselves).
#[derive(Serialize, Deserialize)]
struct GroupRecord {
    meta: GroupMeta,
    my_signing_secret: [u8; 32],
    my_sender: senderkey::SenderChain,
    peers: HashMap<String, PeerSender>,
    /// Members we've already sent our sender key to (avoids re-sending every poll).
    #[serde(default)]
    distributed: HashSet<String>,
}

#[derive(Serialize, Deserialize)]
struct PeerSender {
    signing_pub: [u8; 32],
    chain: senderkey::ReceiverChain,
}

/// A sender key that arrived before its group's invite; applied once the invite
/// creates the group (handles out-of-order bootstrap delivery).
#[derive(Serialize, Deserialize)]
struct PendingSenderKey {
    group_id: [u8; 16],
    from: String,
    dist: SenderKeyDist,
}

/// A received, decrypted message. `group` is `Some(group_id_hex)` for a group message
/// and `None` for a 1:1 message.
pub struct Incoming {
    pub from: String,
    pub text: String,
    pub group: Option<String>,
}

/// Summary of a group the client belongs to (for listing / UI).
pub struct GroupInfo {
    pub id: String,
    pub name: String,
    pub members: Vec<String>,
    pub admins: Vec<String>,
}

pub struct Client {
    store: Store,
    path: PathBuf,
    server_url: String,
    http: reqwest::blocking::Client,
    /// Store encryption password (Argon2id). `None` is allowed only for
    /// tests/dev.
    password: Option<String>,
}

/// BIP39 encoding of the 32-byte identity master seed as a 24-word recovery phrase.
mod recovery {
    use super::ClientError;
    use bip39::Mnemonic;

    /// What a recovery phrase decodes to. Modern (seed-derived) identities back up as
    /// a 24-word phrase of their 32-byte master `Seed`. Legacy identities (created
    /// before seed-derivation, so no seed exists) back up their full 64-byte secret
    /// as a 48-word phrase (two 24-word BIP39 mnemonics) — `FullKey` — so they can
    /// still be backed up and restored without losing the identity.
    pub enum RecoveredSecret {
        Seed([u8; 32]),
        FullKey([u8; 64]),
    }

    /// Encode a 32-byte chunk as a 24-word English BIP39 phrase.
    pub fn seed_to_phrase(seed: &[u8; 32]) -> String {
        Mnemonic::from_entropy(seed)
            .expect("32 bytes is valid BIP39 entropy")
            .to_string()
    }

    /// Encode a legacy 64-byte identity secret as a 48-word phrase (two 24-word
    /// halves), for identities that have no master seed.
    pub fn key_to_phrase(key: &[u8; 64]) -> String {
        let mut first = [0u8; 32];
        first.copy_from_slice(&key[..32]);
        let mut second = [0u8; 32];
        second.copy_from_slice(&key[32..]);
        format!("{} {}", seed_to_phrase(&first), seed_to_phrase(&second))
    }

    fn one_chunk(phrase: &str) -> Result<[u8; 32], ClientError> {
        let mnemonic =
            Mnemonic::parse_normalized(phrase).map_err(|_| ClientError::InvalidRecoveryPhrase)?;
        let entropy = mnemonic.to_entropy();
        if entropy.len() != 32 {
            return Err(ClientError::InvalidRecoveryPhrase);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&entropy);
        Ok(out)
    }

    /// Decode a recovery phrase: 24 words → `Seed`, 48 words → `FullKey`. Each
    /// 24-word half carries its own BIP39 checksum, so typos are caught.
    pub fn phrase_to_secret(phrase: &str) -> Result<RecoveredSecret, ClientError> {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        match words.len() {
            24 => Ok(RecoveredSecret::Seed(one_chunk(phrase)?)),
            48 => {
                let first = one_chunk(&words[..24].join(" "))?;
                let second = one_chunk(&words[24..].join(" "))?;
                let mut key = [0u8; 64];
                key[..32].copy_from_slice(&first);
                key[32..].copy_from_slice(&second);
                Ok(RecoveredSecret::FullKey(key))
            }
            _ => Err(ClientError::InvalidRecoveryPhrase),
        }
    }
}

impl Client {
    /// Create a new identity, register it with the relay, and persist to `path`.
    ///
    /// The identity is derived from a fresh 32-byte master seed, so it can be
    /// backed up as a 24-word BIP39 recovery phrase (see `export_recovery_phrase`)
    /// and later restored on a new device with `restore`. `password` is stretched
    /// with Argon2id to encrypt the store at rest; `None` is accepted for tests/dev
    /// but must not be used for real accounts.
    pub fn create(
        path: impl AsRef<Path>,
        server_url: &str,
        username: &str,
        password: Option<&str>,
    ) -> Result<Self> {
        let (identity, seed) = IdentityKeyPair::generate_seeded();
        Self::register_identity(
            path.as_ref(),
            server_url,
            username,
            password,
            identity,
            Some(seed),
        )
    }

    /// Restore an identity from its 24-word BIP39 `recovery_phrase` and re-register
    /// it on `server_url` under `username`. The same seed reproduces the same keys,
    /// so the relay accepts the re-registration (idempotent for a matching identity)
    /// and contacts who pinned this identity see no key-change warning.
    ///
    /// Recovers the IDENTITY + username only — NOT message history, the contact
    /// list, or device-local verification state (those never leave the device).
    pub fn restore(
        path: impl AsRef<Path>,
        server_url: &str,
        username: &str,
        recovery_phrase: &str,
        password: Option<&str>,
    ) -> Result<Self> {
        // 24 words → a seed-derived identity; 48 words → a legacy full-key identity.
        let (identity, seed) = match recovery::phrase_to_secret(recovery_phrase)? {
            recovery::RecoveredSecret::Seed(seed) => {
                (IdentityKeyPair::from_seed(&seed), Some(seed))
            }
            recovery::RecoveredSecret::FullKey(key) => {
                (IdentityKeyPair::from_secret_bytes(&key), None)
            }
        };
        Self::register_identity(
            path.as_ref(),
            server_url,
            username,
            password,
            identity,
            seed,
        )
    }

    /// This identity's recovery phrase: **24 words** for a seed-derived identity, or
    /// **48 words** (the full 64-byte secret) for a legacy identity that predates
    /// seed-derivation — so every identity can be backed up without being abandoned.
    pub fn export_recovery_phrase(&self) -> Result<String> {
        match &self.store.identity_seed {
            Some(seed) => Ok(recovery::seed_to_phrase(seed)),
            None => {
                let key: [u8; 64] = self
                    .store
                    .identity_secret
                    .as_slice()
                    .try_into()
                    .map_err(|_| ClientError::other("corrupt identity secret"))?;
                Ok(recovery::key_to_phrase(&key))
            }
        }
    }

    /// Shared registration path for `create`/`restore`: mint fresh prekeys, register
    /// `identity` under `username`, fetch the server key + sealed-sender cert, and
    /// persist. `seed` is the identity's master seed (kept for the recovery phrase).
    fn register_identity(
        path: &Path,
        server_url: &str,
        username: &str,
        password: Option<&str>,
        identity: IdentityKeyPair,
        seed: Option<[u8; 32]>,
    ) -> Result<Self> {
        // Pre-flight the username locally so an invalid handle gives a precise
        // message instead of a relay 400 (which would read as "can't reach").
        if let Err(reason) = validate_username(username) {
            return Err(ClientError::InvalidUsername {
                reason: reason.to_string(),
            });
        }
        let (spk_pub, spk_sec) = new_signed_prekey(1, &identity);
        let mut otk_pub = Vec::new();
        let mut otk_sec = Vec::new();
        for id in 1..=ONE_TIME_PREKEY_COUNT {
            let (p, s) = new_one_time_prekey(id);
            otk_pub.push(p);
            otk_sec.push(OtkSecret {
                id,
                secret: s.secret.to_bytes(),
            });
        }

        // One-time ML-KEM prekeys (ids 1..) + a reusable last-resort (id 0) (F-05).
        let mut kem_pub = Vec::new();
        let mut kem_one_time = Vec::new();
        for id in 1..=KEM_PREKEY_COUNT {
            let (p, s) = new_kem_prekey(id, &identity);
            kem_pub.push(p);
            kem_one_time.push(KemSecretRec {
                id,
                secret: s.secret.to_bytes(),
            });
        }
        let (last_resort_pub, last_resort_sec) = new_kem_prekey(LAST_RESORT_KEM_ID, &identity);
        let kem_last_resort = KemSecretRec {
            id: LAST_RESORT_KEM_ID,
            secret: last_resort_sec.secret.to_bytes(),
        };

        let reg_sig = identity.sign(&registration_signed_bytes(username, &identity.public()));
        let req = RegisterRequest {
            username: username.to_string(),
            identity: identity.public(),
            signed_prekey: spk_pub,
            kem_prekeys: kem_pub,
            last_resort_kem_prekey: last_resort_pub,
            one_time_prekeys: otk_pub,
            registration_sig: reg_sig.to_vec(),
        };

        let http = http_client();
        let reg_resp = http
            .post(format!("{server_url}/v1/register"))
            .json(&req)
            .send()
            .map_err(net)?;
        // A 409 means the relay was reached and refused the name — surface it as a
        // distinct, actionable error rather than a generic transport failure.
        if reg_resp.status() == reqwest::StatusCode::CONFLICT {
            return Err(ClientError::UsernameTaken {
                username: username.to_string(),
            });
        }
        reg_resp.error_for_status().map_err(net)?;

        let sk_resp = http
            .get(format!("{server_url}/v1/server-key"))
            .send()
            .map_err(net)?;
        let server_vk: ServerKeyResponse =
            serde_json::from_slice(&read_body_with_limit(sk_resp, MAX_RESPONSE_BODY_BYTES)?)
                .map_err(err)?;

        let store = Store {
            username: username.to_string(),
            identity_secret: identity.to_secret_bytes().to_vec(),
            identity_seed: seed,
            signed_prekey_id: 1,
            signed_prekey_secret: spk_sec.secret.to_bytes(),
            kem_one_time,
            kem_last_resort,
            one_time: otk_sec,
            sessions: HashMap::new(),
            contacts: HashMap::new(),
            verifications: HashMap::new(),
            server_vk: Some(server_vk.verifying_key),
            cert: None,
            seen_initials: VecDeque::new(),
            quarantine: HashMap::new(),
            next_one_time_id: ONE_TIME_PREKEY_COUNT + 1,
            next_kem_id: KEM_PREKEY_COUNT + 1,
            groups: HashMap::new(),
            pending_group_keys: Vec::new(),
        };
        let mut me = Self {
            store,
            path: path.to_path_buf(),
            server_url: server_url.to_string(),
            http,
            password: password.map(|p| p.to_string()),
        };
        // F-06: acquire the sealed-sender certificate at registration time, so its
        // issuance isn't correlated by the relay with a later send.
        me.ensure_cert()?;
        me.save()?;
        Ok(me)
    }

    /// Load an existing client from `path`.
    ///
    /// Validates structural invariants the rest of the engine relies on (e.g. the
    /// 64-byte identity secret) so a corrupt/tampered store surfaces a recoverable
    /// error here rather than panicking on first use (which, across the iOS FFI
    /// boundary, would crash the app).
    /// Load an existing client from `path`.
    ///
    /// Decrypts the Argon2id-wrapped store with `password`. Use the same
    /// password that was passed to `create`.
    pub fn load(path: impl AsRef<Path>, server_url: &str, password: Option<&str>) -> Result<Self> {
        let file_bytes = std::fs::read(path.as_ref()).map_err(err)?;
        // Format-detect so legacy/plaintext stores (every pre-encryption install) and
        // no-password installs keep loading. Only an encrypted envelope is decrypted.
        let plaintext = if encrypted_store::is_encrypted(&file_bytes) {
            encrypted_store::decrypt_store(password, &file_bytes)
                .map_err(|e| ClientError::other(format!("store decryption failed: {e}")))?
        } else {
            file_bytes
        };
        let store: Store = serde_json::from_slice(&plaintext).map_err(err)?;
        if store.identity_secret.len() != 64 {
            return Err(ClientError::other(format!(
                "corrupt store: identity_secret is {} bytes (expected 64)",
                store.identity_secret.len()
            )));
        }
        Ok(Self {
            store,
            path: path.as_ref().to_path_buf(),
            server_url: server_url.to_string(),
            http: http_client(),
            password: password.map(|p| p.to_string()),
        })
    }

    pub fn username(&self) -> &str {
        &self.store.username
    }

    /// Diagnostic/test only: the number of unused one-time X25519 and ML-KEM prekey
    /// secrets the client currently holds locally. Used by the M1 replenishment test
    /// to assert the pool refills after inbound handshakes drain it.
    #[doc(hidden)]
    pub fn local_prekey_counts(&self) -> (usize, usize) {
        (self.store.one_time.len(), self.store.kem_one_time.len())
    }

    fn identity(&self) -> IdentityKeyPair {
        let mut arr: [u8; 64] = self
            .store
            .identity_secret
            .as_slice()
            .try_into()
            .expect("64-byte identity secret");
        let kp = IdentityKeyPair::from_secret_bytes(&arr);
        arr.zeroize(); // L3: clear the transient full-secret copy
        kp
    }

    fn identity_dh_priv(&self) -> [u8; 32] {
        self.store.identity_secret[32..].try_into().unwrap()
    }

    /// Our mailbox id (where peers deliver to us).
    pub fn mailbox(&self) -> String {
        mailbox_id(&self.identity().public())
    }

    /// Persist the store atomically: write to a temp file, then rename over the
    /// target. `std::fs::write` truncates in place, so a crash mid-write would
    /// corrupt the entire store (identity + sessions + prekeys); rename on the
    /// same directory is atomic and leaves the old store intact on failure.
    fn save(&self) -> Result<()> {
        let plaintext = serde_json::to_vec_pretty(&self.store).map_err(err)?;
        // No password → legacy plaintext store (iOS relies on FileProtection); a real
        // password → Argon2id + ChaCha20-Poly1305 envelope. `load` format-detects, so
        // first save after setting a password migrates a plaintext store to encrypted.
        let file_bytes = match self.password.as_deref() {
            Some(pw) => encrypted_store::encrypt_store(Some(pw), &plaintext)
                .map_err(|e| ClientError::other(format!("store encryption failed: {e}")))?,
            None => plaintext,
        };
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, file_bytes).map_err(err)?;
        std::fs::rename(&tmp, &self.path).map_err(err)
    }

    fn ensure_cert(&mut self) -> Result<SenderCertificate> {
        if let Some(cert) = &self.store.cert {
            if cert.expires_unix > now() + 60 {
                return Ok(cert.clone());
            }
        }
        let identity = self.identity();
        let sig = identity.sign(&cert_signed_bytes(&self.store.username, &identity.public()));
        let req = CertRequest {
            username: self.store.username.clone(),
            identity: identity.public(),
            sig: sig.to_vec(),
        };
        let cert_resp = self
            .http
            .post(format!("{}/v1/cert", self.server_url))
            .json(&req)
            .send()
            .map_err(net)?
            .error_for_status()
            .map_err(net)?;
        let resp: CertResponse =
            serde_json::from_slice(&read_body_with_limit(cert_resp, MAX_RESPONSE_BODY_BYTES)?)
                .map_err(err)?;
        self.store.cert = Some(resp.certificate.clone());
        Ok(resp.certificate)
    }

    fn ensure_session(&mut self, to: &str) -> Result<()> {
        if self.store.sessions.contains_key(to) {
            return Ok(());
        }
        let http_resp = self
            .http
            .get(format!("{}/v1/directory/{to}", self.server_url))
            .send()
            .map_err(net)?;
        let http_resp = match http_resp.error_for_status() {
            Ok(r) => r,
            // 404 = the relay has no directory entry for this username — a normal
            // "unknown user" (typo / not on Logos yet), not a transport failure.
            Err(e) if e.status() == Some(reqwest::StatusCode::NOT_FOUND) => {
                return Err(ClientError::NotRegistered {
                    peer: to.to_string(),
                });
            }
            Err(e) => return Err(net(e)),
        };
        let resp: DirectoryResponse =
            serde_json::from_slice(&read_body_with_limit(http_resp, MAX_RESPONSE_BODY_BYTES)?)
                .map_err(err)?;
        let bundle = resp.bundle;
        // F-02/F-03: TOFU-pin the recipient identity from the directory; refuse if
        // it changed from a previously seen value (possible relay key-substitution).
        self.pin_identity(to, &bundle.identity)?;
        let init = initiate(&self.identity(), &bundle).map_err(err)?;
        let ratchet = RatchetState::init_initiator(init.root_key, init.responder_signed_prekey_pub);
        self.store.sessions.insert(
            to.to_string(),
            Session {
                ratchet,
                peer_identity: bundle.identity,
                sent_initial: false,
                pending_initial: Some(init.initial_message.clone()),
            },
        );
        Ok(())
    }

    /// Top the published one-time prekey pools back up when they run low, and
    /// publish the fresh prekeys to the relay (M1). Best-effort: callers ignore a
    /// network failure and retry on the next poll.
    ///
    /// The new prekey **secrets are persisted before their publics are posted**, so
    /// a crash mid-replenish can never leave the relay handing out a prekey whose
    /// secret we don't hold (same durability rule as `send`).
    fn maybe_replenish_prekeys(&mut self) -> Result<()> {
        let otk_needed = self.store.one_time.len() <= OTK_LOW_WATERMARK;
        let kem_needed = self.store.kem_one_time.len() <= KEM_LOW_WATERMARK;
        if !otk_needed && !kem_needed {
            return Ok(());
        }
        let identity = self.identity();

        let mut otk_pub = Vec::new();
        if otk_needed {
            // Lazily initialize the id counter for legacy stores (default 0) past any
            // existing id so a replenished prekey can't collide with a live one.
            if self.store.next_one_time_id == 0 {
                self.store.next_one_time_id = self
                    .store
                    .one_time
                    .iter()
                    .map(|o| o.id)
                    .max()
                    .unwrap_or(0)
                    .max(ONE_TIME_PREKEY_COUNT)
                    + 1;
            }
            let deficit = ONE_TIME_PREKEY_COUNT as usize - self.store.one_time.len();
            for _ in 0..deficit {
                let id = self.store.next_one_time_id;
                self.store.next_one_time_id += 1;
                let (p, s) = new_one_time_prekey(id);
                otk_pub.push(p);
                self.store.one_time.push(OtkSecret {
                    id,
                    secret: s.secret.to_bytes(),
                });
            }
        }

        let mut kem_pub = Vec::new();
        if kem_needed {
            if self.store.next_kem_id == 0 {
                self.store.next_kem_id = self
                    .store
                    .kem_one_time
                    .iter()
                    .map(|k| k.id)
                    .max()
                    .unwrap_or(0)
                    .max(KEM_PREKEY_COUNT)
                    + 1;
            }
            let deficit = KEM_PREKEY_COUNT as usize - self.store.kem_one_time.len();
            for _ in 0..deficit {
                let id = self.store.next_kem_id;
                self.store.next_kem_id += 1;
                let (p, s) = new_kem_prekey(id, &identity);
                kem_pub.push(p);
                self.store.kem_one_time.push(KemSecretRec {
                    id,
                    secret: s.secret.to_bytes(),
                });
            }
        }

        // Persist the new secrets BEFORE publishing their publics (durability).
        self.save()?;

        let sig = identity
            .sign(&replenish_signed_bytes(
                &self.store.username,
                &identity.public(),
            ))
            .to_vec();
        let req = ReplenishRequest {
            username: self.store.username.clone(),
            identity: identity.public(),
            one_time_prekeys: otk_pub,
            kem_prekeys: kem_pub,
            sig,
        };
        self.http
            .post(format!("{}/v1/replenish", self.server_url))
            .json(&req)
            .send()
            .map_err(net)?
            .error_for_status()
            .map_err(net)?;
        Ok(())
    }

    /// Encrypt and deliver a 1:1 `message` to `to`.
    pub fn send(&mut self, to: &str, message: &str) -> Result<()> {
        self.deliver_pairwise(to, message.as_bytes(), false)
    }

    /// Send a group control message (invite / sender-key distribution) to `to` over
    /// the pairwise Double Ratchet, so it's E2EE and bound to the 1:1 identity.
    fn send_group_control(&mut self, to: &str, ctrl: &GroupControl) -> Result<()> {
        let bytes = serde_json::to_vec(ctrl).map_err(err)?;
        self.deliver_pairwise(to, &bytes, true)
    }

    /// Shared pairwise delivery for 1:1 text (`control == false`) and group control
    /// messages (`control == true`): encrypt `plaintext` under the peer's Double
    /// Ratchet, wrap it in the right `OuterMessage` variant, seal, and post.
    ///
    /// encrypt() advances the sending chain (consuming one message key, whose derived
    /// AEAD key+nonce are deterministic). That advance MUST be durable BEFORE the
    /// ciphertext leaves the device: a crash between a successful POST and save() would
    /// roll the chain back and reuse the same key+nonce on different plaintext — a
    /// catastrophic two-time-pad/forgery break. `sent_initial` flips only after a
    /// successful POST, so a failed first delivery re-sends as a fresh prekey message.
    fn deliver_pairwise(&mut self, to: &str, plaintext: &[u8], control: bool) -> Result<()> {
        self.ensure_session(to)?;
        let cert = self.ensure_cert()?;

        let session = self.store.sessions.get_mut(to).expect("session ensured");
        let ratchet_msg = session.ratchet.encrypt(plaintext, b"");
        let is_initial = !session.sent_initial;
        let initial = if is_initial {
            Some(
                session
                    .pending_initial
                    .clone()
                    .ok_or_else(|| ClientError::other("missing initial"))?,
            )
        } else {
            None
        };
        let outer = if control {
            OuterMessage::GroupCtrl {
                initial,
                ratchet: ratchet_msg,
            }
        } else if is_initial {
            OuterMessage::Prekey {
                initial: initial.expect("is_initial implies a pending initial"),
                ratchet: ratchet_msg,
            }
        } else {
            OuterMessage::Normal {
                ratchet: ratchet_msg,
            }
        };
        let peer_identity = session.peer_identity;

        let outer_bytes = serde_json::to_vec(&outer).map_err(err)?;
        let envelope = seal(&peer_identity.dh, &cert, &outer_bytes).map_err(err)?;
        let id = mailbox_id(&peer_identity);

        self.save()?;
        self.http
            .post(format!("{}/v1/mailbox/{id}", self.server_url))
            .json(&PostEnvelope { envelope })
            .send()
            .map_err(net)?
            .error_for_status()
            .map_err(net)?;
        if is_initial {
            if let Some(s) = self.store.sessions.get_mut(to) {
                s.sent_initial = true;
            }
            self.save()?;
        }
        Ok(())
    }

    /// Fetch, decrypt, and return all pending messages.
    ///
    /// Fetch is authenticated by the identity key and does not delete (F-04);
    /// envelopes are processed independently and only those that succeed are
    /// ACKed (deleted) on the server (F-07).
    pub fn recv(&mut self) -> Result<Vec<Incoming>> {
        let identity = self.identity();
        let id_pub = identity.public();
        let fetch_sig = identity.sign(&fetch_signed_bytes(&id_pub)).to_vec();
        let fetch_resp = self
            .http
            .post(format!("{}/v1/fetch", self.server_url))
            .json(&FetchRequest {
                identity: id_pub,
                sig: fetch_sig,
            })
            .send()
            .map_err(net)?
            .error_for_status()
            .map_err(net)?;
        let resp_bytes = read_body_with_limit(fetch_resp, MAX_RESPONSE_BODY_BYTES)?;
        let mut resp: FetchResponse = serde_json::from_slice(&resp_bytes).map_err(err)?;
        resp.envelopes.truncate(MAX_FETCH_ENVELOPES);

        let server_vk = self
            .store
            .server_vk
            .ok_or_else(|| ClientError::other("no server key"))?;
        let dh_priv = self.identity_dh_priv();
        let mut out = Vec::new();
        let mut acked: Vec<u64> = Vec::new();

        for stored in &resp.envelopes {
            match self.process_envelope(&stored.envelope, &server_vk, &dh_priv) {
                // A new message: deliver to the caller and ACK (delete) it.
                Ok(Some(inc)) => {
                    out.push(inc);
                    acked.push(stored.id);
                    self.store.quarantine.remove(&stored.id);
                }
                // A handled duplicate/replay (already-consumed message, or a prekey
                // re-establishment for a session we already have): nothing to show,
                // but ACK it so it cannot stick on the server forever and be
                // re-fetched on every poll.
                Ok(None) => {
                    acked.push(stored.id);
                    self.store.quarantine.remove(&stored.id);
                }
                // Undecryptable for a recoverable reason (e.g. a Normal message that
                // arrived ahead of its establishing prekey message): quarantine —
                // leave it on the server for a later attempt. M4: but bound the
                // attempts so a peer can't pin the mailbox with envelopes that will
                // NEVER have a session — ACK-drop after MAX_QUARANTINE_ATTEMPTS.
                Err(_) => {
                    let n = self.store.quarantine.entry(stored.id).or_insert(0);
                    *n += 1;
                    if *n >= MAX_QUARANTINE_ATTEMPTS {
                        acked.push(stored.id);
                        self.store.quarantine.remove(&stored.id);
                    }
                }
            }
        }
        // L5: persist advanced state (ratchets, consumed prekeys, quarantine counts)
        // before ACKing. A save FAILURE must not silently drop the just-decrypted
        // batch: still return `out` to the caller (the UI persists its own history),
        // and skip the ACK so the envelopes remain on the server for a later attempt.
        let saved = self.save().is_ok();

        // ACK is best-effort and only when state was durably saved: the messages in
        // `out` are already processed, so a failed ACK must NOT discard them.
        if saved && !acked.is_empty() {
            let ack_sig = identity.sign(&ack_signed_bytes(&id_pub, &acked)).to_vec();
            let _ = self
                .http
                .post(format!("{}/v1/ack", self.server_url))
                .json(&AckRequest {
                    identity: id_pub,
                    ids: acked,
                    sig: ack_sig,
                })
                .send()
                .and_then(|r| r.error_for_status());
        }

        // Group bootstrap: send our sender key to any members we still owe it to.
        // Best-effort and idempotent; retried each poll until every pair is covered.
        self.redistribute_group_keys();

        // M1: if inbound prekey messages drained our published pool, top it back up
        // and republish. Best-effort — a failure just retries on the next poll and
        // must not drop the messages we already decrypted.
        let _ = self.maybe_replenish_prekeys();
        Ok(out)
    }

    /// Process one inbound envelope.
    ///
    /// `Ok(Some)` is a new message to deliver (and ACK); `Ok(None)` is a handled
    /// envelope to ACK (delete) but not deliver — a duplicate/replay, or garbage
    /// we can never make progress on (failed unseal / unparseable inner payload),
    /// which we drop so it cannot accumulate and be re-fetched on every poll;
    /// `Err` means quarantine (leave on the server for a later attempt, e.g. a
    /// Normal message that arrived ahead of its establishing prekey message).
    fn process_envelope(
        &mut self,
        env: &SealedEnvelope,
        server_vk: &[u8; 32],
        dh_priv: &[u8; 32],
    ) -> Result<Option<Incoming>> {
        // A forged/garbage/expired envelope (sealed sender is open to any poster)
        // will never become decryptable — ACK-drop it rather than quarantine.
        let (cert, payload) = match unseal(dh_priv, env, server_vk, now()) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let from = cert.sender_username.clone();
        let outer: OuterMessage = match serde_json::from_slice(&payload) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        match outer {
            OuterMessage::Prekey { initial, ratchet } => {
                match self.decrypt_pairwise(&cert, Some(initial), ratchet)? {
                    Some(pt) => Ok(Some(Incoming {
                        from,
                        text: String::from_utf8_lossy(&pt).into_owned(),
                        group: None,
                    })),
                    None => Ok(None),
                }
            }
            OuterMessage::Normal { ratchet } => {
                match self.decrypt_pairwise(&cert, None, ratchet)? {
                    Some(pt) => Ok(Some(Incoming {
                        from,
                        text: String::from_utf8_lossy(&pt).into_owned(),
                        group: None,
                    })),
                    None => Ok(None),
                }
            }
            // Group control plane: decrypted over the pairwise session, then applied
            // (invite / sender-key distribution). Not surfaced as a chat message.
            OuterMessage::GroupCtrl { initial, ratchet } => {
                match self.decrypt_pairwise(&cert, initial, ratchet)? {
                    Some(pt) => self.handle_group_control(&from, &pt),
                    None => Ok(None),
                }
            }
            // Group data plane: sender-key-encrypted, authenticated by the sender's
            // per-group Ed25519 signature.
            OuterMessage::Group {
                group_id,
                iteration,
                ciphertext,
                signature,
            } => self.process_group_message(&from, group_id, iteration, &ciphertext, &signature),
        }
    }

    /// TOFU identity pinning: first sighting is recorded; a later mismatch is
    /// refused (F-02/F-03). Real continuous verification needs key transparency.
    fn pin_identity(&mut self, username: &str, identity: &IdentityPublic) -> Result<()> {
        match self.store.contacts.get(username) {
            Some(known) if known != identity => {
                // Record the change and drop any prior verification, then refuse.
                let v = self
                    .store
                    .verifications
                    .entry(username.to_string())
                    .or_default();
                v.changes += 1;
                v.verified = false;
                v.verified_at = None;
                let _ = self.save();
                Err(ClientError::IdentityChanged {
                    peer: username.to_string(),
                })
            }
            Some(_) => Ok(()),
            None => {
                self.store.contacts.insert(username.to_string(), *identity);
                Ok(())
            }
        }
    }

    // ---- contact verification (safety numbers + TOFU change tracking) ----

    /// The human-comparable safety number for `peer`, or `None` if no identity is
    /// pinned yet (no session has been established).
    pub fn safety_number(&self, peer: &str) -> Option<String> {
        let me = self.identity().public();
        self.store
            .contacts
            .get(peer)
            .map(|theirs| logos_identity::safety_number(&me, theirs))
    }

    pub fn is_verified(&self, peer: &str) -> bool {
        self.store
            .verifications
            .get(peer)
            .is_some_and(|v| v.verified)
    }

    pub fn verified_at(&self, peer: &str) -> Option<u64> {
        self.store
            .verifications
            .get(peer)
            .and_then(|v| v.verified_at)
    }

    pub fn key_changes(&self, peer: &str) -> u32 {
        self.store.verifications.get(peer).map_or(0, |v| v.changes)
    }

    /// Mark `peer` verified (after the user compared safety numbers out-of-band).
    pub fn mark_verified(&mut self, peer: &str) -> Result<()> {
        if !self.store.contacts.contains_key(peer) {
            return Err(ClientError::other("no pinned identity to verify yet"));
        }
        let v = self
            .store
            .verifications
            .entry(peer.to_string())
            .or_default();
        v.verified = true;
        v.verified_at = Some(now());
        self.save()
    }

    /// Recovery: accept that `peer` legitimately changed identity (e.g. reinstalled).
    /// Drops the pin + session so the next message re-pins the current identity, and
    /// clears verification (the change stays counted in history).
    pub fn reset_peer_identity(&mut self, peer: &str) -> Result<()> {
        self.store.contacts.remove(peer);
        self.store.sessions.remove(peer);
        if let Some(v) = self.store.verifications.get_mut(peer) {
            v.verified = false;
            v.verified_at = None;
        }
        self.save()
    }

    /// Re-establish a stale session after a contact restored their identity from a
    /// recovery phrase (or reinstalled with the SAME identity). Drops ONLY the local
    /// session — the TOFU pin and verification are kept, because the identity key is
    /// unchanged. This lets the contact's next handshake be accepted instead of
    /// dropped as a replay against the existing session (see `process_envelope`).
    /// The contact must send again afterward to complete the re-handshake.
    pub fn reset_session(&mut self, peer: &str) -> Result<()> {
        self.store.sessions.remove(peer);
        self.save()
    }

    /// Record a consumed initial-message fingerprint (bounded FIFO) for M3 replay
    /// rejection. Persisted with the next `save()`.
    fn remember_initial(&mut self, fp: [u8; 32]) {
        if self.store.seen_initials.contains(&fp) {
            return;
        }
        self.store.seen_initials.push_back(fp);
        while self.store.seen_initials.len() > MAX_SEEN_INITIALS {
            self.store.seen_initials.pop_front();
        }
    }

    // ---- E2EE group chat (sender-key v1, P4.0a) ----

    /// Create a new E2EE group named `name` with `members` (usernames, excluding
    /// self). Generates our per-group sender + signing keys, records the group, and
    /// invites each member (group metadata + our sender key) over their pairwise
    /// session. Returns the hex group id.
    pub fn create_group(&mut self, name: &str, members: &[&str]) -> Result<String> {
        let name = name.trim();
        if name.is_empty() || name.len() > 128 {
            return Err(ClientError::other("group name must be 1..=128 characters"));
        }
        let me = self.store.username.clone();
        let mut roster: Vec<String> = Vec::new();
        for &m in members {
            if me == m || roster.iter().any(|r| *r == m) {
                continue;
            }
            if validate_username(m).is_err() {
                return Err(ClientError::InvalidUsername {
                    reason: format!("'{m}' is not a valid username"),
                });
            }
            roster.push(m.to_string());
        }
        if roster.is_empty() {
            return Err(ClientError::other(
                "a group needs at least one other member",
            ));
        }
        if roster.len() + 1 > MAX_GROUP_SIZE {
            return Err(ClientError::other(format!(
                "group too large (max {MAX_GROUP_SIZE} members)"
            )));
        }

        let mut all_members = vec![me.clone()];
        all_members.extend(roster.iter().cloned());

        let mut group_id = [0u8; 16];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut group_id);
        let gid_hex = group_id_hex(&group_id);

        let my_signing = GroupSigningKey::generate();
        let my_sender = senderkey::SenderChain::generate();
        let invite_dist = SenderKeyDist {
            chain_key: my_sender.chain_key(),
            iteration: my_sender.iteration(),
            signing_pub: my_signing.public_bytes(),
        };
        let meta = GroupMeta {
            id: group_id,
            name: name.to_string(),
            members: all_members,
            admins: vec![me.clone()],
            created_unix: now(),
        };

        // Invite every member (metadata + our sender key) over their pairwise session.
        for member in &roster {
            self.send_group_control(
                member,
                &GroupControl::Invite {
                    group: meta.clone(),
                    sender_key: invite_dist.clone(),
                },
            )?;
        }

        // The invite carried our sender key, so every invited member is "distributed to".
        let distributed: HashSet<String> = roster.iter().cloned().collect();
        self.store.groups.insert(
            gid_hex.clone(),
            GroupRecord {
                meta,
                my_signing_secret: my_signing.secret_bytes(),
                my_sender,
                peers: HashMap::new(),
                distributed,
            },
        );
        self.save()?;
        Ok(gid_hex)
    }

    /// Encrypt and deliver `message` to every member of the group (by hex id). One
    /// sender-key ciphertext is signed once and posted to each member's mailbox
    /// (per-member fan-out; the relay has no group concept in v1).
    pub fn send_group(&mut self, group_id_hex_str: &str, message: &str) -> Result<()> {
        let (group_id, members, signing_secret) = {
            let rec = self
                .store
                .groups
                .get(group_id_hex_str)
                .ok_or_else(|| ClientError::other("unknown group"))?;
            let me = &self.store.username;
            let members: Vec<String> = rec
                .meta
                .members
                .iter()
                .filter(|m| *m != me)
                .cloned()
                .collect();
            (rec.meta.id, members, rec.my_signing_secret)
        };

        // Advance our sender chain (durably persisted before any POST) and sign.
        let (iteration, ciphertext) = {
            let rec = self
                .store
                .groups
                .get_mut(group_id_hex_str)
                .expect("group present");
            rec.my_sender.encrypt(message.as_bytes(), &group_id)
        };
        let signing = GroupSigningKey::from_secret(&signing_secret);
        let signature = signing
            .sign(&group_message_signed_bytes(
                &group_id,
                iteration,
                &ciphertext,
            ))
            .to_vec();
        let outer = OuterMessage::Group {
            group_id,
            iteration,
            ciphertext,
            signature,
        };
        let outer_bytes = serde_json::to_vec(&outer).map_err(err)?;
        let cert = self.ensure_cert()?;

        // Persist the advanced sender chain BEFORE any POST: never reuse an
        // iteration's key on different plaintext.
        self.save()?;

        for member in members {
            let peer_identity = self.peer_identity_for(&member)?;
            let envelope = seal(&peer_identity.dh, &cert, &outer_bytes).map_err(err)?;
            let id = mailbox_id(&peer_identity);
            self.http
                .post(format!("{}/v1/mailbox/{id}", self.server_url))
                .json(&PostEnvelope { envelope })
                .send()
                .map_err(net)?
                .error_for_status()
                .map_err(net)?;
        }
        Ok(())
    }

    /// The groups this client belongs to.
    pub fn groups(&self) -> Vec<GroupInfo> {
        self.store
            .groups
            .values()
            .map(|r| GroupInfo {
                id: group_id_hex(&r.meta.id),
                name: r.meta.name.clone(),
                members: r.meta.members.clone(),
                admins: r.meta.admins.clone(),
            })
            .collect()
    }

    /// Member usernames of a group (by hex id), or `None` if we're not in it.
    pub fn group_members(&self, group_id_hex_str: &str) -> Option<Vec<String>> {
        self.store
            .groups
            .get(group_id_hex_str)
            .map(|r| r.meta.members.clone())
    }

    /// Resolve a peer's identity for sealing — from the TOFU pin if present, else by
    /// establishing a session (which fetches + pins it from the directory).
    fn peer_identity_for(&mut self, user: &str) -> Result<IdentityPublic> {
        if let Some(id) = self.store.contacts.get(user) {
            return Ok(*id);
        }
        self.ensure_session(user)?;
        self.store
            .contacts
            .get(user)
            .copied()
            .ok_or_else(|| ClientError::other("no identity for member"))
    }

    /// Handle a decrypted group control message received over a pairwise session.
    fn handle_group_control(&mut self, from: &str, plaintext: &[u8]) -> Result<Option<Incoming>> {
        let ctrl: GroupControl = match serde_json::from_slice(plaintext) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        match ctrl {
            GroupControl::Invite { group, sender_key } => {
                self.handle_invite(from, group, sender_key)
            }
            GroupControl::SenderKey {
                group_id,
                sender_key,
            } => {
                let gid_hex = group_id_hex(&group_id);
                if self.store.groups.contains_key(&gid_hex) {
                    self.insert_peer_sender(&gid_hex, from, &sender_key);
                } else {
                    self.stash_pending_key(group_id, from, sender_key);
                }
                let _ = self.save();
                Ok(None)
            }
        }
    }

    /// Process a group invite: if the group is new, create our state, drain any
    /// early-arriving sender keys, and distribute our own sender key to the other
    /// members. Idempotent on a duplicate invite.
    fn handle_invite(
        &mut self,
        from: &str,
        group: GroupMeta,
        sender_key: SenderKeyDist,
    ) -> Result<Option<Incoming>> {
        // The inviter must be a listed member (the cert already proved who `from` is),
        // and we must be in the roster.
        if !group.members.iter().any(|m| *m == from) {
            return Ok(None);
        }
        let me = self.store.username.clone();
        if !group.members.contains(&me) {
            return Ok(None);
        }
        let gid_hex = group_id_hex(&group.id);
        if self.store.groups.contains_key(&gid_hex) {
            // Duplicate invite: record the inviter's sender key if we lack it.
            self.insert_peer_sender(&gid_hex, from, &sender_key);
            let _ = self.save();
            return Ok(None);
        }

        let my_signing = GroupSigningKey::generate();
        let my_sender = senderkey::SenderChain::generate();
        let mut peers = HashMap::new();
        peers.insert(
            from.to_string(),
            PeerSender {
                signing_pub: sender_key.signing_pub,
                chain: senderkey::ReceiverChain::new(sender_key.chain_key, sender_key.iteration),
            },
        );
        let group_id = group.id;
        self.store.groups.insert(
            gid_hex.clone(),
            GroupRecord {
                meta: group,
                my_signing_secret: my_signing.secret_bytes(),
                my_sender,
                peers,
                distributed: HashSet::new(),
            },
        );
        // Apply any sender keys that arrived before this invite. Sending OUR key to the
        // other members is left to the post-recv redistribution (which respects the
        // canonical-initiator rule to avoid simultaneous session establishment).
        self.drain_pending_keys(&gid_hex, &group_id);
        self.save()?;
        Ok(None)
    }

    /// Record a peer's sender key for a known group (first one wins; a duplicate
    /// distribution is ignored so it can't reset an already-advanced receive chain).
    fn insert_peer_sender(&mut self, gid_hex: &str, from: &str, dist: &SenderKeyDist) {
        if let Some(rec) = self.store.groups.get_mut(gid_hex) {
            if !rec.meta.members.iter().any(|m| *m == from) {
                return;
            }
            rec.peers
                .entry(from.to_string())
                .or_insert_with(|| PeerSender {
                    signing_pub: dist.signing_pub,
                    chain: senderkey::ReceiverChain::new(dist.chain_key, dist.iteration),
                });
        }
    }

    /// Buffer a sender key whose group we don't know yet (invite not arrived).
    fn stash_pending_key(&mut self, group_id: [u8; 16], from: &str, dist: SenderKeyDist) {
        if let Some(p) = self
            .store
            .pending_group_keys
            .iter_mut()
            .find(|p| p.group_id == group_id && p.from == from)
        {
            p.dist = dist;
            return;
        }
        if self.store.pending_group_keys.len() >= MAX_PENDING_GROUP_KEYS {
            self.store.pending_group_keys.remove(0);
        }
        self.store.pending_group_keys.push(PendingSenderKey {
            group_id,
            from: from.to_string(),
            dist,
        });
    }

    /// Apply and remove any buffered sender keys for a newly created group.
    fn drain_pending_keys(&mut self, gid_hex: &str, group_id: &[u8; 16]) {
        let matching: Vec<PendingSenderKey> = {
            let mut keep = Vec::new();
            let mut take = Vec::new();
            for p in self.store.pending_group_keys.drain(..) {
                if &p.group_id == group_id {
                    take.push(p);
                } else {
                    keep.push(p);
                }
            }
            self.store.pending_group_keys = keep;
            take
        };
        for p in matching {
            self.insert_peer_sender(gid_hex, &p.from, &p.dist);
        }
    }

    /// Send our sender key to any group members we haven't distributed to yet. To
    /// avoid two members simultaneously initiating a pairwise session to each other
    /// (which the replay guard would make both drop), we only INITIATE when we're the
    /// canonical initiator (`me < member`); otherwise we wait until a session exists
    /// (the peer initiates and we reply over it). Called at the end of `recv`, so it
    /// retries across polls until every member has our key. Best-effort per member.
    fn redistribute_group_keys(&mut self) {
        let me = self.store.username.clone();
        let mut work: Vec<(String, [u8; 16], String, SenderKeyDist)> = Vec::new();
        for (gid_hex, rec) in &self.store.groups {
            let dist = SenderKeyDist {
                chain_key: rec.my_sender.chain_key(),
                iteration: rec.my_sender.iteration(),
                signing_pub: GroupSigningKey::from_secret(&rec.my_signing_secret).public_bytes(),
            };
            for m in &rec.meta.members {
                if *m == me || rec.distributed.contains(m) {
                    continue;
                }
                if self.store.sessions.contains_key(m) || me < *m {
                    work.push((gid_hex.clone(), rec.meta.id, m.clone(), dist.clone()));
                }
            }
        }
        for (gid_hex, group_id, member, dist) in work {
            if self
                .send_group_control(
                    &member,
                    &GroupControl::SenderKey {
                        group_id,
                        sender_key: dist,
                    },
                )
                .is_ok()
            {
                if let Some(rec) = self.store.groups.get_mut(&gid_hex) {
                    rec.distributed.insert(member);
                }
            }
        }
    }

    /// Decrypt and authenticate an inbound group (sender-key) message.
    fn process_group_message(
        &mut self,
        from: &str,
        group_id: [u8; 16],
        iteration: u32,
        ciphertext: &[u8],
        signature: &[u8],
    ) -> Result<Option<Incoming>> {
        let gid_hex = group_id_hex(&group_id);
        // Unknown group: keep for a later attempt (the invite may be in flight).
        if !self.store.groups.contains_key(&gid_hex) {
            return Err(ClientError::other("unknown group"));
        }
        let sig_arr: [u8; 64] = match signature.try_into() {
            Ok(a) => a,
            Err(_) => return Ok(None),
        };
        // No sender key yet: quarantine (distribution may still be in flight).
        let signing_pub = match self
            .store
            .groups
            .get(&gid_hex)
            .and_then(|r| r.peers.get(from))
        {
            Some(p) => p.signing_pub,
            None => return Err(ClientError::other("no sender key for group sender")),
        };
        // Verify the per-group signature BEFORE decrypting — every member knows the
        // symmetric chain key, so only the signature proves the true sender. A bad
        // signature is a forgery: drop it.
        if !verify_ed25519(
            &signing_pub,
            &group_message_signed_bytes(&group_id, iteration, ciphertext),
            &sig_arr,
        ) {
            return Ok(None);
        }
        let rec = self.store.groups.get_mut(&gid_hex).expect("group present");
        let peer = rec.peers.get_mut(from).expect("sender key present");
        match peer.chain.decrypt(iteration, ciphertext, &group_id) {
            Ok(pt) => Ok(Some(Incoming {
                from: from.to_string(),
                text: String::from_utf8_lossy(&pt).into_owned(),
                group: Some(gid_hex),
            })),
            // Replay / already-consumed / too-far-ahead: drop (ACK).
            Err(_) => Ok(None),
        }
    }

    /// Decrypt the pairwise-ratchet payload of a `Prekey`/`Normal`/`GroupCtrl`
    /// envelope from `cert.sender_username`. `Ok(Some(bytes))` delivers the plaintext,
    /// `Ok(None)` is a replay/duplicate to ACK-drop, and `Err` means no session yet
    /// (quarantine for a later attempt).
    fn decrypt_pairwise(
        &mut self,
        cert: &SenderCertificate,
        initial: Option<InitialMessage>,
        ratchet: logos_ratchet::RatchetMessage,
    ) -> Result<Option<Vec<u8>>> {
        let from = cert.sender_username.clone();
        match initial {
            Some(initial) => {
                // An inbound session-initiation must never reset an EXISTING session
                // (a replayed initial re-derives the same root key with the reusable
                // last-resort KEM). A genuine re-key needs an explicit session reset.
                if self.store.sessions.contains_key(&from) {
                    return Ok(None);
                }
                // M3: reject a replayed initial even after `reset_session`.
                let fp = initial_fingerprint(&initial, &ratchet);
                if self.store.seen_initials.contains(&fp) {
                    return Ok(None);
                }
                let pt = self.establish_and_decrypt(cert, initial, ratchet)?;
                self.remember_initial(fp);
                Ok(Some(pt))
            }
            None => match self.store.sessions.get_mut(&from) {
                Some(session) => match session.ratchet.decrypt(&ratchet, b"") {
                    Ok(pt) => Ok(Some(pt)),
                    // A Normal message that no longer decrypts on a live session is a
                    // replay/corrupt duplicate — ACK-and-drop.
                    Err(_) => Ok(None),
                },
                // No session yet: may be reordered ahead of its prekey — quarantine.
                None => Err(ClientError::other(format!("no session for {from}"))),
            },
        }
    }

    fn establish_and_decrypt(
        &mut self,
        cert: &SenderCertificate,
        initial: InitialMessage,
        ratchet_msg: logos_ratchet::RatchetMessage,
    ) -> Result<Vec<u8>> {
        // F-02/F-03: the sealed-sender cert is only delivery authorization. The
        // real sender identity is the PQXDH initiator identity (proven by the
        // handshake DH legs). Bind them, then TOFU-pin — so a malicious relay
        // can't forge a cert to impersonate or hijack a known contact's session.
        if cert.sender_identity != initial.initiator_identity {
            return Err(ClientError::other(
                "sender certificate identity does not match handshake identity",
            ));
        }
        self.pin_identity(&cert.sender_username, &cert.sender_identity)?;
        if initial.signed_prekey_id != self.store.signed_prekey_id {
            return Err(ClientError::other("unknown signed prekey id"));
        }
        // Resolve the one-time prekeys the initiator selected, but do NOT consume
        // them yet — only after the whole handshake + first ratchet decrypt
        // succeeds. Consuming up front let a malformed/forged prekey message
        // permanently burn a victim's one-time prekeys (F-05 transactional fix).
        let otk = match initial.one_time_prekey_id {
            Some(otk_id) => {
                let pos = self
                    .store
                    .one_time
                    .iter()
                    .position(|o| o.id == otk_id)
                    .ok_or_else(|| ClientError::other("unknown one-time prekey id"))?;
                Some((pos, self.store.one_time[pos].secret))
            }
            None => None,
        };
        let one_time_priv = otk.as_ref().map(|(_, s)| *s);
        // The reusable last-resort KEM prekey is kept; a one-time KEM prekey is
        // consumed only on success (tracked by index here).
        let kem_one_time_pos = if initial.kem_prekey_id == self.store.kem_last_resort.id {
            None
        } else {
            Some(
                self.store
                    .kem_one_time
                    .iter()
                    .position(|k| k.id == initial.kem_prekey_id)
                    .ok_or_else(|| ClientError::other("unknown kem prekey id"))?,
            )
        };
        let kem_secret = match kem_one_time_pos {
            None => KemSecret::from_bytes(&self.store.kem_last_resort.secret).map_err(err)?,
            Some(pos) => {
                KemSecret::from_bytes(&self.store.kem_one_time[pos].secret).map_err(err)?
            }
        };
        let resp = respond(
            &self.identity(),
            self.store.signed_prekey_secret,
            one_time_priv,
            &kem_secret,
            &initial,
        )
        .map_err(err)?;
        let mut ratchet = RatchetState::init_responder(resp.root_key, resp.signed_prekey_priv);
        let pt = ratchet.decrypt(&ratchet_msg, b"").map_err(err)?;

        // Success: now commit the one-time prekey consumption and the new session.
        if let Some((pos, _)) = otk {
            self.store.one_time.remove(pos);
        }
        if let Some(pos) = kem_one_time_pos {
            self.store.kem_one_time.remove(pos);
        }
        self.store.sessions.insert(
            cert.sender_username.clone(),
            Session {
                ratchet,
                peer_identity: cert.sender_identity,
                sent_initial: true,
                pending_initial: None,
            },
        );
        Ok(pt)
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::{recovery, ClientError};

    #[test]
    fn phrase_roundtrip_is_24_words_and_recovers_the_seed() {
        let seed = [7u8; 32];
        let phrase = recovery::seed_to_phrase(&seed);
        assert_eq!(phrase.split_whitespace().count(), 24);
        match recovery::phrase_to_secret(&phrase).unwrap() {
            recovery::RecoveredSecret::Seed(s) => assert_eq!(s, seed),
            _ => panic!("24 words must decode to a seed"),
        }
    }

    #[test]
    fn invalid_phrase_is_rejected() {
        // Not real wordlist words.
        assert!(matches!(
            recovery::phrase_to_secret("not a valid recovery phrase at all please"),
            Err(ClientError::InvalidRecoveryPhrase)
        ));
        // Valid words but a wrong checksum (canonical all-zero entropy ends in
        // "art", so "abandon" x24 must fail the checksum).
        let phrase = "abandon ".repeat(24);
        assert!(recovery::phrase_to_secret(phrase.trim()).is_err());
    }

    #[test]
    fn legacy_full_key_roundtrips_as_48_words() {
        // Distinct halves so a swap would be caught.
        let mut key = [0u8; 64];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let phrase = recovery::key_to_phrase(&key);
        assert_eq!(phrase.split_whitespace().count(), 48);
        match recovery::phrase_to_secret(&phrase).unwrap() {
            recovery::RecoveredSecret::FullKey(k) => assert_eq!(k, key),
            _ => panic!("48 words must decode to FullKey"),
        }
        // A 24-word phrase still decodes to a seed.
        let seed = [9u8; 32];
        assert!(matches!(
            recovery::phrase_to_secret(&recovery::seed_to_phrase(&seed)).unwrap(),
            recovery::RecoveredSecret::Seed(s) if s == seed
        ));
    }
}
