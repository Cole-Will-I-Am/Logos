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
    cert_signed_bytes, registration_signed_bytes, CertRequest, CertResponse, DirectoryResponse,
    FetchResponse, PostEnvelope, RegisterRequest, ServerKeyResponse,
};
use logos_sealed::{issue_certificate, SealedEnvelope};

const CERT_TTL_SECS: u64 = 24 * 60 * 60;

struct DirEntry {
    identity: IdentityPublic,
    signed_prekey: SignedPreKeyPublic,
    kem_prekey: KemPreKeyPublic,
    one_time: VecDeque<OneTimePreKeyPublic>,
}

struct Inner {
    directory: HashMap<String, DirEntry>,
    mailboxes: HashMap<String, Vec<SealedEnvelope>>,
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
pub fn new_state_at(path: &str) -> AppState {
    let seed: [u8; 32] = match std::fs::read(path) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => {
            let s = SigningKey::generate(&mut rand::rngs::OsRng).to_bytes();
            let _ = std::fs::write(path, s);
            s
        }
    };
    state_from_seed(seed)
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/register", post(register))
        .route("/v1/directory/{username}", get(directory))
        .route("/v1/cert", post(cert))
        .route("/v1/server-key", get(server_key))
        .route("/v1/mailbox/{id}", post(post_mailbox).get(get_mailbox))
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
            kem_prekey: req.kem_prekey,
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
    let bundle = PreKeyBundle {
        username: username.clone(),
        identity: entry.identity,
        signed_prekey: entry.signed_prekey.clone(),
        one_time_prekey,
        kem_prekey: entry.kem_prekey.clone(),
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
    inner.mailboxes.entry(id).or_default().push(req.envelope);
    StatusCode::OK
}

async fn get_mailbox(State(state): State<AppState>, Path(id): Path<String>) -> Json<FetchResponse> {
    let mut inner = state.0.lock().unwrap();
    // delete-on-deliver: hand back everything queued and clear it.
    let envelopes = inner.mailboxes.remove(&id).unwrap_or_default();
    Json(FetchResponse { envelopes })
}

/// Run the relay on `addr` until the process exits, persisting the signing key
/// at `key_path` so restarts keep the same `server_vk`.
pub async fn run(addr: std::net::SocketAddr, key_path: &str) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, build_router(new_state_at(key_path))).await
}
