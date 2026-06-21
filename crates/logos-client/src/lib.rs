//! Logos client engine — ties identity, PQXDH, the Double Ratchet, and sealed
//! sender together and talks to the relay. The public API is **synchronous** and
//! uses plain types (strings/bytes) so it can be wrapped for an iOS app (Swift
//! via UniFFI / an xcframework) without async leaking across the FFI boundary.
//!
//! EXPERIMENTAL — UNAUDITED.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[doc(hidden)]
pub mod encrypted_store;

use logos_identity::{
    new_kem_prekey, new_one_time_prekey, new_signed_prekey, IdentityKeyPair, IdentityPublic,
    KemSecret,
};
use logos_pqxdh::{initiate, respond, InitialMessage};
use logos_proto::{
    ack_signed_bytes, cert_signed_bytes, fetch_signed_bytes, mailbox_id, registration_signed_bytes,
    AckRequest, CertRequest, CertResponse, DirectoryResponse, FetchRequest, FetchResponse,
    OuterMessage, PostEnvelope, RegisterRequest, ServerKeyResponse,
};
use logos_ratchet::RatchetState;
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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
}

impl Drop for Store {
    fn drop(&mut self) {
        // Zeroize secret material before the store is freed. Public metadata
        // (username, ids, pinned identities, certificates) is intentionally
        // skipped — it carries no key material.
        self.identity_secret.zeroize();
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

/// A received, decrypted message.
pub struct Incoming {
    pub from: String,
    pub text: String,
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

impl Client {
    /// Create a new identity, register it with the relay, and persist to `path`.
    /// Create a new identity, register it with the relay, and persist to `path`.
    ///
    /// `password` is stretched with Argon2id to encrypt the store at rest. A
    /// `None` password is accepted for tests/dev but must not be used for real
    /// accounts.
    pub fn create(
        path: impl AsRef<Path>,
        server_url: &str,
        username: &str,
        password: Option<&str>,
    ) -> Result<Self> {
        let identity = IdentityKeyPair::generate();
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
        };
        let mut me = Self {
            store,
            path: path.as_ref().to_path_buf(),
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

    fn identity(&self) -> IdentityKeyPair {
        let arr: [u8; 64] = self
            .store
            .identity_secret
            .as_slice()
            .try_into()
            .expect("64-byte identity secret");
        IdentityKeyPair::from_secret_bytes(&arr)
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

    /// Encrypt and deliver `message` to `to`.
    pub fn send(&mut self, to: &str, message: &str) -> Result<()> {
        self.ensure_session(to)?;
        let cert = self.ensure_cert()?;

        let session = self.store.sessions.get_mut(to).expect("session ensured");
        // encrypt() advances the sending chain (consumes one message key, whose
        // derived AEAD key+nonce are deterministic). That advance MUST be made
        // durable BEFORE the ciphertext leaves the device: otherwise a crash
        // between a successful POST and save() would roll the chain back, and the
        // next send would reuse the same key+nonce on different plaintext — a
        // catastrophic two-time-pad/forgery break of ChaCha20-Poly1305.
        let ratchet_msg = session.ratchet.encrypt(message.as_bytes(), b"");
        let is_initial = !session.sent_initial;
        let outer = if is_initial {
            let initial = session
                .pending_initial
                .clone()
                .ok_or_else(|| ClientError::other("missing initial"))?;
            OuterMessage::Prekey {
                initial,
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

        // Persist the advanced ratchet before transmitting. `sent_initial` is left
        // false until the POST succeeds, so if delivery fails the message is
        // re-sent as a fresh prekey message (with the next, distinct key) rather
        // than being lost or causing key reuse.
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

        for stored in resp.envelopes {
            match self.process_envelope(&stored.envelope, &server_vk, &dh_priv) {
                // A new message: deliver to the caller and ACK (delete) it.
                Ok(Some(inc)) => {
                    out.push(inc);
                    acked.push(stored.id);
                }
                // A handled duplicate/replay (already-consumed message, or a prekey
                // re-establishment for a session we already have): nothing to show,
                // but ACK it so it cannot stick on the server forever and be
                // re-fetched on every poll.
                Ok(None) => acked.push(stored.id),
                // Undecryptable for a recoverable reason (e.g. a Normal message that
                // arrived ahead of its establishing prekey message): quarantine —
                // leave it on the server (not ACKed) for a later attempt.
                Err(_) => {}
            }
        }
        // State (advanced ratchets, consumed prekeys) is durably persisted before
        // we ACK — so a message is never deleted on the server before we can
        // re-derive it.
        self.save()?;

        // ACK is best-effort: the messages in `out` are already durably processed,
        // so a failed ACK must NOT discard them (that would silently lose already-
        // decrypted messages). Un-ACKed ids simply remain on the server and are
        // re-fetched next time; already-consumed ones then ACK-drop harmlessly.
        if !acked.is_empty() {
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
                // Never let an inbound prekey (session-initiation) message reset an
                // EXISTING session. Otherwise a replayed initial envelope — which
                // re-derives the same root key whenever the handshake used the
                // reusable last-resort KEM prekey / no one-time X25519 prekey —
                // would clobber the live ratchet and break the conversation. A
                // genuine re-key requires an explicit, out-of-band session reset.
                if self.store.sessions.contains_key(&from) {
                    return Ok(None);
                }
                let text = self.establish_and_decrypt(&cert, initial, ratchet)?;
                Ok(Some(Incoming { from, text }))
            }
            OuterMessage::Normal { ratchet } => {
                match self.store.sessions.get_mut(&from) {
                    Some(session) => match session.ratchet.decrypt(&ratchet, b"") {
                        Ok(pt) => Ok(Some(Incoming {
                            from,
                            text: String::from_utf8_lossy(&pt).into_owned(),
                        })),
                        // The transactional ratchet left state untouched. A Normal
                        // message that no longer decrypts on a live session is a
                        // replay/corrupt duplicate (the real one was already
                        // consumed) — ACK-and-drop so it can't stick forever.
                        Err(_) => Ok(None),
                    },
                    // No session yet: this may be a message reordered ahead of its
                    // establishing prekey message — keep it for a later attempt.
                    None => Err(ClientError::other(format!("no session for {from}"))),
                }
            }
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

    fn establish_and_decrypt(
        &mut self,
        cert: &SenderCertificate,
        initial: InitialMessage,
        ratchet_msg: logos_ratchet::RatchetMessage,
    ) -> Result<String> {
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
        Ok(String::from_utf8_lossy(&pt).into_owned())
    }
}
