//! Logos relay — a minimal-trust store-and-forward server.
//!
//! It holds: a public-key directory (username → identity + prekeys), per-mailbox
//! queues of **opaque sealed envelopes** (delete-on-deliver), and an Ed25519 key
//! used only to issue sealed-sender certificates. It never sees message plaintext
//! and, thanks to sealed sender, never sees who sent a delivered message.
//!
//! Phase-1 store is in-memory (one process). Persistence (redb) and TTL sweeping
//! are deferred — the trust/visibility properties are identical.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use ed25519_dalek::SigningKey;
use logos_identity::{
    verify, IdentityPublic, KemPreKeyPublic, OneTimePreKeyPublic, PreKeyBundle, SignedPreKeyPublic,
};
use logos_proto::{
    ack_signed_bytes, cert_signed_bytes, fetch_signed_bytes, mailbox_id, registration_signed_bytes,
    AckRequest, CertRequest, CertResponse, DirectoryResponse, FetchRequest, FetchResponse,
    PostEnvelope, RegisterRequest, ServerKeyResponse, StoredEnvelope,
};
use logos_sealed::issue_certificate;

const CERT_TTL_SECS: u64 = 24 * 60 * 60;

/// Bound per-mailbox queue length so an unauthenticated poster cannot grow the
/// store without limit (`/v1/mailbox/{id}` is intentionally open so any sender
/// can deliver). This caps disk/memory blast radius to one mailbox; real abuse
/// resistance (auth, rate limits, TTL sweep) is tracked separately.
const MAX_MAILBOX_MESSAGES: usize = 4096;

struct DirEntry {
    identity: IdentityPublic,
    signed_prekey: SignedPreKeyPublic,
    /// One-time ML-KEM prekeys (consumed per handshake), with a reusable fallback.
    kem_one_time: VecDeque<KemPreKeyPublic>,
    last_resort_kem: KemPreKeyPublic,
    one_time: VecDeque<OneTimePreKeyPublic>,
}

struct Inner {
    directory: HashMap<String, DirEntry>,
    mailboxes: HashMap<String, Vec<StoredEnvelope>>,
    next_id: u64,
    server_seed: [u8; 32],
    server_vk: [u8; 32],
}

#[derive(Clone)]
pub struct AppState(Arc<Mutex<Inner>>);

fn state_from_seed(seed: [u8; 32]) -> AppState {
    let signing = SigningKey::from_bytes(&seed);
    AppState(Arc::new(Mutex::new(Inner {
        directory: HashMap::new(),
        mailboxes: HashMap::new(),
        next_id: 0,
        server_seed: signing.to_bytes(),
        server_vk: signing.verifying_key().to_bytes(),
    })))
}

/// In-memory state with an ephemeral signing key (used by tests).
pub fn new_state() -> AppState {
    state_from_seed(SigningKey::generate(&mut rand::rngs::OsRng).to_bytes())
}

/// Persist the sealed-sender signing key at `path` so a relay restart keeps the
/// same `server_vk` that clients have pinned (F-13).
///
/// A key is generated and written **only** when the file is genuinely absent. A
/// present-but-invalid file (wrong length, unreadable) is a fatal startup error
/// rather than being silently overwritten — silently rotating the signing key
/// would invalidate every sender certificate clients have pinned and destroy the
/// (possibly recoverable) original key. Generated keys are written `0600`.
pub fn new_state_at(path: &str) -> std::io::Result<AppState> {
    let seed: [u8; 32] = match std::fs::read(path) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        Ok(b) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "server key file {path} is present but {} bytes (expected 32) — refusing to \
                     overwrite and rotate the signing key; move it aside to rotate intentionally",
                    b.len()
                ),
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let s = SigningKey::generate(&mut rand::rngs::OsRng).to_bytes();
            write_key_file(path, &s)?;
            s
        }
        Err(e) => return Err(e),
    };
    Ok(state_from_seed(seed))
}

/// Write a freshly generated signing key, restricting it to owner-only (`0600`)
/// on Unix. The seed can mint sender certificates, so it must not be world-readable.
fn write_key_file(path: &str, seed: &[u8; 32]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(seed)?;
        f.flush()
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, seed)
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/register", post(register))
        .route("/v1/directory/{username}", get(directory))
        .route("/v1/cert", post(cert))
        .route("/v1/server-key", get(server_key))
        .route("/v1/mailbox/{id}", post(post_mailbox))
        .route("/v1/fetch", post(fetch))
        .route("/v1/ack", post(ack))
        .with_state(state)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

type ApiError = (StatusCode, String);

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<StatusCode, ApiError> {
    let msg = registration_signed_bytes(&req.username, &req.identity);
    verify(&req.identity, &msg, &req.registration_sig).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "bad registration signature".into(),
        )
    })?;

    let mut inner = state.0.lock().unwrap();
    if let Some(existing) = inner.directory.get(&req.username) {
        if existing.identity != req.identity {
            return Err((StatusCode::CONFLICT, "username taken".into()));
        }
    }
    inner.directory.insert(
        req.username.clone(),
        DirEntry {
            identity: req.identity,
            signed_prekey: req.signed_prekey,
            kem_one_time: req.kem_prekeys.into_iter().collect(),
            last_resort_kem: req.last_resort_kem_prekey,
            one_time: req.one_time_prekeys.into_iter().collect(),
        },
    );
    Ok(StatusCode::OK)
}

async fn directory(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<Json<DirectoryResponse>, ApiError> {
    let mut inner = state.0.lock().unwrap();
    let entry = inner
        .directory
        .get_mut(&username)
        .ok_or((StatusCode::NOT_FOUND, "unknown user".into()))?;
    let one_time_prekey = entry.one_time.pop_front();
    // Consume a one-time ML-KEM prekey if available, else fall back to last-resort (F-05).
    let kem_prekey = entry
        .kem_one_time
        .pop_front()
        .unwrap_or_else(|| entry.last_resort_kem.clone());
    let bundle = PreKeyBundle {
        username: username.clone(),
        identity: entry.identity,
        signed_prekey: entry.signed_prekey.clone(),
        one_time_prekey,
        kem_prekey,
    };
    Ok(Json(DirectoryResponse { bundle }))
}

async fn cert(
    State(state): State<AppState>,
    Json(req): Json<CertRequest>,
) -> Result<Json<CertResponse>, ApiError> {
    let msg = cert_signed_bytes(&req.username, &req.identity);
    verify(&req.identity, &msg, &req.sig).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "bad cert request signature".into(),
        )
    })?;

    let inner = state.0.lock().unwrap();
    match inner.directory.get(&req.username) {
        Some(e) if e.identity == req.identity => {}
        _ => return Err((StatusCode::FORBIDDEN, "identity not registered".into())),
    }
    let certificate = issue_certificate(
        &inner.server_seed,
        &req.username,
        &req.identity,
        now() + CERT_TTL_SECS,
    );
    Ok(Json(CertResponse { certificate }))
}

async fn server_key(State(state): State<AppState>) -> Json<ServerKeyResponse> {
    let inner = state.0.lock().unwrap();
    Json(ServerKeyResponse {
        verifying_key: inner.server_vk,
    })
}

async fn post_mailbox(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<PostEnvelope>,
) -> StatusCode {
    let mut inner = state.0.lock().unwrap();
    let msg_id = inner.next_id;
    let queue = inner.mailboxes.entry(id).or_default();
    if queue.len() >= MAX_MAILBOX_MESSAGES {
        // Mailbox full: refuse rather than grow without bound. The owner drains
        // it via fetch + ACK.
        return StatusCode::INSUFFICIENT_STORAGE;
    }
    queue.push(StoredEnvelope {
        id: msg_id,
        envelope: req.envelope,
    });
    inner.next_id += 1;
    StatusCode::OK
}

/// Authenticated read (F-04): the caller proves control of the identity key, and
/// the server derives the mailbox from it — so only the owner can read. Does NOT
/// delete (F-07); the client deletes via /v1/ack after durably processing.
async fn fetch(
    State(state): State<AppState>,
    Json(req): Json<FetchRequest>,
) -> Result<Json<FetchResponse>, ApiError> {
    verify(&req.identity, &fetch_signed_bytes(&req.identity), &req.sig)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "bad fetch signature".into()))?;
    let mb = mailbox_id(&req.identity);
    let inner = state.0.lock().unwrap();
    let envelopes = inner.mailboxes.get(&mb).cloned().unwrap_or_default();
    Ok(Json(FetchResponse { envelopes }))
}

/// Authenticated delete of specific envelope ids (F-07), only after the client
/// has durably processed them.
async fn ack(
    State(state): State<AppState>,
    Json(req): Json<AckRequest>,
) -> Result<StatusCode, ApiError> {
    verify(
        &req.identity,
        &ack_signed_bytes(&req.identity, &req.ids),
        &req.sig,
    )
    .map_err(|_| (StatusCode::UNAUTHORIZED, "bad ack signature".into()))?;
    let mb = mailbox_id(&req.identity);
    let mut inner = state.0.lock().unwrap();
    if let Some(q) = inner.mailboxes.get_mut(&mb) {
        q.retain(|e| !req.ids.contains(&e.id));
    }
    Ok(StatusCode::OK)
}

/// Run the relay on `addr` until the process exits, persisting the signing key
/// at `key_path` so restarts keep the same `server_vk`.
pub async fn run(addr: std::net::SocketAddr, key_path: &str) -> std::io::Result<()> {
    let state = new_state_at(key_path)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, build_router(state)).await
}
